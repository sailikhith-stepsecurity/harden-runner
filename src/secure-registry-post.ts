import * as core from "@actions/core";
import * as cp from "child_process";
import * as fs from "fs";
import * as path from "path";
import { STEPSECURITY_API_URL } from "./configs";
import { describeRegistry, findEnv, unscopedRegistry } from "./npmrc";

const SUMMARY_TIMEOUT_MS = 5000;
const REVOKE_TIMEOUT_MS = 5000;
// Audit rows reach the summary through a queue, so an empty first answer is
// asked again once after this delay.
const SUMMARY_RETRY_DELAY_MS = 3000;
// Keeps the job summary readable when a job pulls many fresh versions.
const MAX_ROWS = 50;
const MAX_VERSIONS_SHOWN = 5;

const LOCKFILE_NAMES = ["package-lock.json", "npm-shrinkwrap.json"];

// Summary ecosystem values are registry paths; the input keys differ.
const ECOSYSTEM_CONFIG_KEYS: Record<string, string> = { javascript: "npm" };

export interface PostState {
  token: string;
  registryUrl?: string;
}

export interface ControlResult {
  name: string;
  reason?: string;
}

export interface HeldPackage {
  ecosystem: string;
  package: string;
  versions: string[];
  controls: ControlResult[];
}

export interface BlockedVersion {
  ecosystem: string;
  package: string;
  version: string;
  controls: ControlResult[];
}

export interface RunSummary {
  held: HeldPackage[];
  blocked: BlockedVersion[];
}

// Returns what the pre step left for this step, or undefined when it
// configured nothing.
export function readPostState(env: NodeJS.ProcessEnv): PostState | undefined {
  const token = env.STATE_srToken;
  if (!token) {
    return undefined;
  }
  return { token, registryUrl: env.STATE_srRegistryUrl || undefined };
}

function sameRegistry(a: string, b: string): boolean {
  try {
    const x = new URL(a);
    const y = new URL(b);
    return (
      x.origin === y.origin &&
      x.pathname.replace(/\/+$/, "") === y.pathname.replace(/\/+$/, "")
    );
  } catch {
    return false;
  }
}

// Describes how npm's registry moved away from ours after the pre step, or
// returns undefined when npm still uses it. actions/setup-node with
// registry-url replaces our registry= line in the same file.
export function registryOverride(
  env: NodeJS.ProcessEnv,
  registryUrl: string
): string | undefined {
  const envRegistry = findEnv(env, "npm_config_registry");
  if (envRegistry) {
    return `${envRegistry.key} is set to ${describeRegistry(envRegistry.value)}`;
  }
  const userConfig = findEnv(env, "npm_config_userconfig");
  if (!userConfig) {
    return "NPM_CONFIG_USERCONFIG is no longer set";
  }
  if (!fs.existsSync(userConfig.value)) {
    return `${userConfig.value} no longer exists`;
  }
  const registry = unscopedRegistry(fs.readFileSync(userConfig.value, "utf8"));
  if (registry === undefined) {
    return `${userConfig.value} no longer sets a registry`;
  }
  if (!sameRegistry(registry, registryUrl)) {
    return `${userConfig.value} now sets registry to ${describeRegistry(registry)}`;
  }
  return undefined;
}

// In container jobs the workspace belongs to another user, and
// actions/checkout removes its safe.directory entry in its own post step,
// which runs before this one. The workspace is trusted here, but settings
// that run commands (fsmonitor, external diff) stay off.
function git(cwd: string, args: string[]): string[] {
  const safe = ["-c", `safe.directory=${cwd}`, "-c", "core.fsmonitor=false"];
  const out = cp.execFileSync("git", [...safe, ...args], {
    cwd,
    encoding: "utf8",
    timeout: 10000,
    stdio: ["ignore", "pipe", "ignore"],
    maxBuffer: 10 * 1024 * 1024,
  });
  return out.split("\0").filter((f) => f !== "");
}

// Lists files the job changed: edited, staged or new, plus anything in
// commits made since the checkout, since a job that commits its lockfile
// leaves a clean tree behind.
export function changedFiles(workspace: string, sha?: string): string[] {
  const files = new Set<string>();
  const add = (args: string[]) => {
    for (const f of git(workspace, args)) files.add(f);
  };
  add(["ls-files", "-z", "--modified", "--others", "--exclude-standard"]);
  add(["diff", "-z", "--no-ext-diff", "--name-only", "--cached"]);
  if (sha) {
    try {
      add(["diff", "-z", "--no-ext-diff", "--name-only", sha, "HEAD"]);
    } catch (e) {
      core.debug(`secure-registry: unable to diff against ${sha}: ${e}`);
    }
  }
  return [...files];
}

// Returns the changed npm lockfiles that record package URLs on our host.
// Those fail with E401 anywhere the run token is not configured.
export function leakedLockfiles(
  workspace: string,
  files: string[],
  registryHost: string
): string[] {
  const needle = `//${registryHost}/`;
  return files
    .filter((f) => LOCKFILE_NAMES.includes(path.basename(f)))
    .filter((f) => !f.split(/[\\/]/).includes("node_modules"))
    .filter((f) => {
      const full = path.join(workspace, f);
      try {
        return fs.statSync(full).isFile() && fs.readFileSync(full, "utf8").includes(needle);
      } catch {
        return false;
      }
    })
    .sort();
}

function checkLockfiles(registryUrl: string) {
  const workspace = process.env.GITHUB_WORKSPACE;
  if (!workspace) {
    return;
  }
  let host: string;
  try {
    host = new URL(registryUrl).host;
  } catch {
    return;
  }
  let files: string[];
  try {
    files = changedFiles(workspace, process.env.GITHUB_SHA);
  } catch (e) {
    // No checkout, or git refuses the workspace (owner mismatch in containers).
    core.debug(`secure-registry: skipping the lockfile check: ${e}`);
    return;
  }
  for (const file of leakedLockfiles(workspace, files, host)) {
    core.warning(
      `secure-registry: ${file} now has package URLs on ${host}. ` +
        `Do not commit it from this job as is: installs that do not use this run's ` +
        `registry token fail with E401. To keep lockfiles portable, add ` +
        `"lockfile-resolved: omit" under npm in the secure-registry input.`,
      { file }
    );
  }
}

async function getSummary(token: string): Promise<RunSummary | undefined> {
  const resp = await fetch(`${STEPSECURITY_API_URL}/secure-registry/sessions/summary`, {
    headers: { authorization: `Bearer ${token}` },
    signal: AbortSignal.timeout(SUMMARY_TIMEOUT_MS),
  });
  if (resp.status !== 200) {
    core.info(`secure-registry: could not read the run summary (HTTP ${resp.status})`);
    return undefined;
  }
  const body = (await resp.json()) as Partial<RunSummary>;
  return { held: body.held ?? [], blocked: body.blocked ?? [] };
}

function isEmpty(summary: RunSummary): boolean {
  return summary.held.length === 0 && summary.blocked.length === 0;
}

export async function fetchSummary(
  token: string,
  sleep: (ms: number) => Promise<void> = (ms) => new Promise((r) => setTimeout(r, ms))
): Promise<RunSummary | undefined> {
  const first = await getSummary(token);
  if (!first || !isEmpty(first)) {
    return first;
  }
  await sleep(SUMMARY_RETRY_DELAY_MS);
  return (await getSummary(token)) ?? first;
}

export async function revokeToken(token: string): Promise<void> {
  try {
    const resp = await fetch(`${STEPSECURITY_API_URL}/secure-registry/sessions/revoke`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(REVOKE_TIMEOUT_MS),
    });
    if (resp.status === 204) {
      core.info("secure-registry: run token revoked");
      return;
    }
    let code = "";
    try {
      code = ((await resp.json()) as { code?: string })?.code ?? "";
    } catch {
      // Not JSON; the status is enough.
    }
    core.info(
      `secure-registry: could not revoke the run token (HTTP ${resp.status}${code ? `, ${code}` : ""}); it expires on its own`
    );
  } catch (e) {
    core.info(
      `secure-registry: could not revoke the run token (${e instanceof Error ? e.message : e}); it expires on its own`
    );
  }
}

// Parses a Go duration as printed by secure-registry ("18h10m0s") into minutes.
function parseGoDuration(value: string): number | undefined {
  const re = /(\d+(?:\.\d+)?)(h|m|s)/g;
  let minutes = 0;
  let consumed = 0;
  for (const m of value.matchAll(re)) {
    const n = Number(m[1]);
    minutes += m[2] === "h" ? n * 60 : m[2] === "m" ? n : n / 60;
    consumed += m[0].length;
  }
  return consumed === value.length && consumed > 0 ? minutes : undefined;
}

function formatMinutes(total: number): string {
  const rounded = Math.max(0, Math.round(total));
  const h = Math.floor(rounded / 60);
  const m = rounded % 60;
  if (h === 0) return `${m}m`;
  return m === 0 ? `${h}h` : `${h}h${m}m`;
}

// Reads the age and cooldown window out of a cooldown block reason, such as
// "x@1.0.0 was published 18h10m0s ago, which is within the 2-day cooldown period".
export function cooldownTiming(reason: string): { age: string; clearsIn?: string } | undefined {
  const published = /published (\S+) ago/.exec(reason);
  const age = published ? parseGoDuration(published[1]) : undefined;
  if (age === undefined) {
    return undefined;
  }
  const window = /within the (\d+)-day cooldown/.exec(reason);
  if (!window) {
    return { age: formatMinutes(age) };
  }
  return {
    age: formatMinutes(age),
    clearsIn: formatMinutes(Number(window[1]) * 24 * 60 - age),
  };
}

function parseVersion(v: string): { core: number[]; pre: string[] } {
  const [main, ...rest] = v.split("+")[0].split("-");
  return {
    core: main.split(".").map((p) => Number(p) || 0),
    pre: rest.length ? rest.join("-").split(".") : [],
  };
}

function compareIdentifiers(a: string, b: string): number {
  const an = /^\d+$/.test(a);
  const bn = /^\d+$/.test(b);
  if (an && bn) return Number(a) - Number(b);
  if (an) return -1;
  if (bn) return 1;
  return a < b ? -1 : a > b ? 1 : 0;
}

// Semver precedence, enough to pick the newest of a package's versions.
export function compareVersions(a: string, b: string): number {
  const x = parseVersion(a);
  const y = parseVersion(b);
  for (let i = 0; i < 3; i++) {
    const d = (x.core[i] ?? 0) - (y.core[i] ?? 0);
    if (d !== 0) return d;
  }
  if (!x.pre.length || !y.pre.length) {
    return y.pre.length - x.pre.length;
  }
  for (let i = 0; i < Math.min(x.pre.length, y.pre.length); i++) {
    const d = compareIdentifiers(x.pre[i], y.pre[i]);
    if (d !== 0) return d;
  }
  return x.pre.length - y.pre.length;
}

function cell(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

function controlNames(controls: ControlResult[]): string {
  return controls.map((c) => c.name).join(", ") || "unknown";
}

function onlyCooldown(controls: ControlResult[]): boolean {
  return controls.length > 0 && controls.every((c) => c.name === "cooldown");
}

function blockedDetails(b: BlockedVersion): string {
  const parts: string[] = [];
  for (const c of b.controls) {
    const timing = c.name === "cooldown" && c.reason ? cooldownTiming(c.reason) : undefined;
    if (timing) {
      parts.push(
        `published ${timing.age} ago${timing.clearsIn ? `, clears in ${timing.clearsIn}` : ""}`
      );
    } else if (c.reason) {
      parts.push(c.reason);
    }
  }
  return parts.join("; ");
}

// Picks one exact version per held or blocked package that cooldown alone
// kept out: the version npm asked to download, or else the newest hidden
// one. A single release keeps later releases covered by cooldown.
export function suggestedExemptions(summary: RunSummary): Map<string, string[]> {
  const byKey = new Map<string, Set<string>>();
  const covered = new Set<string>();
  const add = (ecosystem: string, spec: string) => {
    const key = ECOSYSTEM_CONFIG_KEYS[ecosystem];
    if (!key) return;
    if (!byKey.has(key)) byKey.set(key, new Set());
    byKey.get(key)!.add(spec);
  };
  for (const b of summary.blocked) {
    covered.add(`${b.ecosystem}\0${b.package}`);
    if (onlyCooldown(b.controls) && b.version) {
      add(b.ecosystem, `${b.package}@${b.version}`);
    }
  }
  for (const h of summary.held) {
    if (covered.has(`${h.ecosystem}\0${h.package}`)) continue;
    if (!onlyCooldown(h.controls) || h.versions.length === 0) continue;
    const newest = [...h.versions].sort(compareVersions).pop()!;
    add(h.ecosystem, `${h.package}@${newest}`);
  }
  const out = new Map<string, string[]>();
  for (const [key, specs] of byKey) out.set(key, [...specs].sort());
  return out;
}

function exemptionSnippet(exemptions: Map<string, string[]>): string {
  const lines = ["secure-registry: |"];
  for (const [key, specs] of exemptions) {
    lines.push(`  ${key}:`, "    cooldown:", "      exemptions:");
    for (const spec of specs) lines.push(`        - "${spec}"`);
  }
  return lines.join("\n");
}

function truncated<T>(items: T[], render: (item: T) => string): string[] {
  const rows = items.slice(0, MAX_ROWS).map(render);
  if (items.length > MAX_ROWS) {
    rows.push(`| ... and ${items.length - MAX_ROWS} more | | |`);
  }
  return rows;
}

// Renders the job summary section, or undefined when nothing was held or
// blocked.
export function renderSummary(summary: RunSummary): string | undefined {
  if (isEmpty(summary)) {
    return undefined;
  }
  const out: string[] = ["### Secure registry: package versions held or blocked", ""];

  if (summary.held.length > 0) {
    out.push(
      "**Held.** These versions were hidden from npm, so it used an older version or failed with ETARGET (\"No matching version found\").",
      "",
      "| Package | Hidden versions | Reason |",
      "|---|---|---|",
      ...truncated(summary.held, (h) => {
        const sorted = [...h.versions].sort(compareVersions).reverse();
        const shown = sorted.slice(0, MAX_VERSIONS_SHOWN).map((v) => `\`${v}\``).join(", ");
        const more = sorted.length > MAX_VERSIONS_SHOWN ? ` and ${sorted.length - MAX_VERSIONS_SHOWN} more` : "";
        const reason = h.controls.map((c) => c.reason || c.name).join("; ");
        return `| \`${cell(h.package)}\` | ${shown}${more} | ${cell(reason)} |`;
      }),
      ""
    );
  }

  if (summary.blocked.length > 0) {
    out.push(
      "**Blocked.** Downloads of these versions were refused.",
      "",
      "| Version | Control | Details |",
      "|---|---|---|",
      ...truncated(
        summary.blocked,
        (b) => `| \`${cell(b.package)}@${cell(b.version)}\` | ${cell(controlNames(b.controls))} | ${cell(blockedDetails(b))} |`
      ),
      ""
    );
  }

  const exemptions = suggestedExemptions(summary);
  if (exemptions.size > 0) {
    out.push(
      "To allow these versions now, add them to the `secure-registry` input, merged with any settings you already have. Each entry allows that one release only, so later releases stay covered. You can also rerun the job once the cooldown has passed.",
      "",
      "```yaml",
      exemptionSnippet(exemptions),
      "```",
      ""
    );
  }
  if (summary.blocked.some((b) => b.controls.some((c) => c.name === "compromised"))) {
    out.push("Versions blocked as compromised cannot be exempted.", "");
  }
  out.push("_Requests from the last moments of the job may be missing from this list._", "");
  return out.join("\n");
}

async function reportRun(state: PostState & { registryUrl: string }) {
  const override = registryOverride(process.env, state.registryUrl);
  if (override) {
    core.notice(
      `secure-registry: npm stopped using secure-registry during this job (${override}), ` +
        `so installs after that change were not checked. actions/setup-node with ` +
        `registry-url: https://registry.npmjs.org after Harden-Runner does this.`
    );
  }

  checkLockfiles(state.registryUrl);

  const summary = await fetchSummary(state.token);
  if (!summary) {
    return;
  }
  const markdown = renderSummary(summary);
  if (!markdown) {
    core.info("secure-registry: no package versions were held or blocked");
    return;
  }
  core.info(
    `secure-registry: ${summary.held.length} package(s) held, ${summary.blocked.length} version(s) blocked, see the job summary`
  );
  await core.summary.addRaw(markdown, true).write();
}

// Reports what secure-registry did in this job, then revokes the run token.
// Skips quietly when the pre step configured nothing, and never fails the
// job.
export async function finishSecureRegistry(): Promise<void> {
  const state = readPostState(process.env);
  if (!state) {
    return;
  }
  // Masks registered in the pre step cover the job, but this is cheap.
  core.setSecret(state.token);

  try {
    if (state.registryUrl) {
      await reportRun({ ...state, registryUrl: state.registryUrl });
    }
  } catch (e) {
    core.info(`secure-registry: post-step report failed: ${e instanceof Error ? e.message : e}`);
  } finally {
    // After the summary: revoking first would make the summary call fail.
    await revokeToken(state.token);
  }
}
