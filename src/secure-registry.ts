import * as core from "@actions/core";
import * as cp from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { EOL } from "os";
import { context } from "@actions/github";
import { isGHES } from "./common";
import { SECURE_REGISTRY_AUDIENCE, STEPSECURITY_API_URL } from "./configs";
import {
  describeRegistry,
  findEnv,
  isDefaultRegistry,
  mergeNpmrc,
  unscopedRegistry,
} from "./npmrc";

// Session creation hits a Lambda that also writes DynamoDB and reads Secrets
// Manager, so allow more than the 3s used for the other API calls.
const SESSION_TIMEOUT_MS = 10000;

const SKIP_SUFFIX = "npm stays on the default registry.";

interface SessionNotice {
  source?: string;
  path?: string;
  code?: string;
  message: string;
}

interface SessionResponse {
  token?: string;
  expires_at?: number;
  edition?: string;
  registries?: Record<string, string>;
  config?: Record<string, { lockfile_resolved?: string }>;
  notices?: SessionNotice[];
}

interface SessionError {
  code?: string;
  error?: string;
  reason?: string;
}

export interface SessionHttpResult {
  status: number;
  body: unknown;
  retryAfter?: string;
}

export interface SecureRegistryResult {
  // "<host>:<port>" of the registry npm now uses, for allowed-endpoints.
  registryEndpoint?: string;
}

interface NpmSource {
  path: string;
  content: string;
  // The env var that named the source file, if any, so the export reuses it
  // instead of leaving two conflicting spellings set.
  envKey?: string;
}

type Preflight = { ok: true; source: NpmSource } | { ok: false; reason: string };

// Returns the raw input to send to the session API, or undefined when the
// feature is off. The action applies no defaults of its own.
export function secureRegistryInput(raw: string): string | undefined {
  const value = raw.trim();
  if (value === "" || value.toLowerCase() === "false") {
    return undefined;
  }
  return value;
}

interface EventPayload {
  repository?: { full_name?: string };
  pull_request?: { head?: { repo?: { full_name?: string } | null } };
}

// GitHub gives fork pull_request runs no OIDC token even with id-token: write.
export function missingTokenReason(eventName: string, payload: EventPayload): string {
  if (eventName === "pull_request") {
    const head = payload?.pull_request?.head?.repo?.full_name;
    const base = payload?.repository?.full_name;
    if (!head || head !== base) {
      return "fork pull request, no OIDC token available";
    }
  }
  return 'add "permissions: id-token: write" to this job to enable it';
}

function npmGlobalConfigPath(env: NodeJS.ProcessEnv): string | undefined {
  const fromEnv = findEnv(env, "npm_config_globalconfig");
  if (fromEnv) {
    return fromEnv.value;
  }
  try {
    const out = cp.execSync("npm config get globalconfig", {
      encoding: "utf8",
      timeout: 5000,
      stdio: ["ignore", "pipe", "ignore"],
    });
    return out.trim() || undefined;
  } catch (e) {
    core.debug(`secure-registry: unable to locate the global npm config: ${e}`);
    return undefined;
  }
}

// Decides, before any token is minted, whether npm can be switched without
// overriding a registry the user configured on purpose.
export function npmPreflight(
  env: NodeJS.ProcessEnv,
  homeDir: string,
  globalConfigPath: (env: NodeJS.ProcessEnv) => string | undefined = npmGlobalConfigPath
): Preflight {
  const envRegistry = findEnv(env, "npm_config_registry");
  if (envRegistry) {
    return {
      ok: false,
      reason: `${envRegistry.key} is set (${describeRegistry(envRegistry.value)})`,
    };
  }

  const userConfig = findEnv(env, "npm_config_userconfig");
  const sourcePath = userConfig ? userConfig.value : path.join(homeDir, ".npmrc");
  const content = fs.existsSync(sourcePath)
    ? fs.readFileSync(sourcePath, "utf8")
    : "";
  const userRegistry = unscopedRegistry(content);
  if (userRegistry !== undefined && !isDefaultRegistry(userRegistry)) {
    return {
      ok: false,
      reason: `${sourcePath} sets registry to ${describeRegistry(userRegistry)}`,
    };
  }

  const globalPath = globalConfigPath(env);
  if (globalPath) {
    try {
      if (fs.existsSync(globalPath)) {
        const globalRegistry = unscopedRegistry(fs.readFileSync(globalPath, "utf8"));
        if (globalRegistry !== undefined && !isDefaultRegistry(globalRegistry)) {
          return {
            ok: false,
            reason: `the global npm config ${globalPath} sets registry to ${describeRegistry(globalRegistry)}`,
          };
        }
      }
    } catch (e) {
      core.debug(`secure-registry: unable to read ${globalPath}: ${e}`);
    }
  }

  return {
    ok: true,
    source: { path: sourcePath, content, envKey: userConfig?.key },
  };
}

function errorCode(body: unknown): string | undefined {
  return (body as SessionError | undefined)?.code;
}

async function postSession(
  idToken: string,
  config: string
): Promise<SessionHttpResult> {
  const resp = await fetch(`${STEPSECURITY_API_URL}/secure-registry/sessions`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ oidc_token: idToken, config }),
    signal: AbortSignal.timeout(SESSION_TIMEOUT_MS),
  });
  let body: unknown;
  try {
    body = await resp.json();
  } catch {
    body = undefined;
  }
  return {
    status: resp.status,
    body,
    retryAfter: resp.headers.get("retry-after") ?? undefined,
  };
}

// The OIDC token lives 300s, so it is requested right before the call. An
// expired token is retried once with a fresh one; nothing else is retried.
export async function createSession(
  config: string,
  getIDToken: () => Promise<string>
): Promise<SessionHttpResult> {
  let result = await postSession(await getIDToken(), config);
  if (result.status === 401 && errorCode(result.body) === "oidc_expired") {
    core.info("secure-registry: OIDC token expired before the session was created, retrying with a new token");
    result = await postSession(await getIDToken(), config);
  }
  return result;
}

// Expected configuration states are notices; service problems are warnings.
// Neither fails the job.
export function describeSessionFailure(
  result: SessionHttpResult
): { level: "notice" | "warning"; message: string } {
  const err = (result.body ?? {}) as SessionError;
  switch (err.code) {
    case "not_eligible":
      if (err.reason === "visibility") {
        return { level: "notice", message: "the community edition is available for public repositories only" };
      }
      if (err.reason === "runner") {
        return { level: "notice", message: "the community edition is available on GitHub-hosted runners only" };
      }
      return { level: "notice", message: `this run is not eligible (${err.reason || "no reason given"})` };
    case "enterprise_not_supported":
      return { level: "notice", message: "not yet available for organizations with a StepSecurity subscription" };
    case "rate_limited":
      return {
        level: "warning",
        message: `session rate limit reached${result.retryAfter ? `, retry after ${result.retryAfter}s` : ""}`,
      };
    case "oidc_expired":
      return { level: "warning", message: "the OIDC token expired again before a session could be created" };
    case "oidc_replayed":
    case "oidc_invalid":
      return { level: "warning", message: `the session API rejected the OIDC token (${err.code})` };
    case "unavailable":
      return { level: "warning", message: "the session API is unavailable" };
    default:
      return {
        level: "warning",
        message: `session request failed with HTTP ${result.status}${err.code ? ` (${err.code}: ${err.error})` : ""}`,
      };
  }
}

function skipNotice(reason: string) {
  core.notice(`secure-registry: ${reason}. ${SKIP_SUFFIX}`);
}

function skipWarning(reason: string) {
  core.warning(`secure-registry: ${reason}. ${SKIP_SUFFIX}`);
}

function saveState(name: string, value: string) {
  fs.appendFileSync(process.env.GITHUB_STATE, `${name}=${value}${EOL}`, {
    encoding: "utf8",
  });
}

// Never logs the token: it is masked before this runs and is not part of
// any field printed here.
function printSession(session: SessionResponse) {
  core.startGroup("secure-registry session");
  core.info(`edition: ${session.edition}`);
  if (session.expires_at) {
    core.info(`expires at: ${new Date(session.expires_at * 1000).toISOString()}`);
  }
  core.info(`registries: ${JSON.stringify(session.registries ?? {})}`);
  core.info(`resolved config:\n${JSON.stringify(session.config ?? {}, null, 2)}`);
  core.endGroup();

  for (const notice of session.notices ?? []) {
    core.notice(
      `secure-registry: ${notice.message}${notice.path ? ` (${notice.path})` : ""}`
    );
  }
}

async function configureNpm(config: string): Promise<SecureRegistryResult> {
  if (isGHES()) {
    skipNotice("not supported on GitHub Enterprise Server yet");
    return {};
  }

  const runnerTemp = process.env.RUNNER_TEMP;
  if (!runnerTemp) {
    skipNotice("RUNNER_TEMP is not set");
    return {};
  }

  const preflight = npmPreflight(process.env, os.homedir());
  if (preflight.ok === false) {
    skipNotice(preflight.reason);
    return {};
  }

  if (!process.env.ACTIONS_ID_TOKEN_REQUEST_URL) {
    skipNotice(missingTokenReason(context.eventName, context.payload as EventPayload));
    return {};
  }

  const result = await createSession(config, () =>
    core.getIDToken(SECURE_REGISTRY_AUDIENCE)
  );
  if (result.status !== 200 && result.status !== 201) {
    const failure = describeSessionFailure(result);
    if (failure.level === "notice") {
      skipNotice(failure.message);
    } else {
      skipWarning(failure.message);
    }
    return {};
  }

  const session = (result.body ?? {}) as SessionResponse;
  if (session.token) {
    core.setSecret(session.token);
  }
  printSession(session);

  if (!session.token) {
    if (result.status === 201) {
      skipWarning("the session API returned no token");
    } else {
      core.info("secure-registry: every ecosystem is off, nothing to configure");
    }
    return {};
  }

  // Saved before anything else can fail, so the post step can always revoke.
  saveState("srToken", session.token);
  saveState("srEdition", session.edition ?? "");

  for (const ecosystem of Object.keys(session.registries ?? {})) {
    if (ecosystem !== "npm") {
      core.info(`secure-registry: this version of Harden-Runner configures npm only, ignoring ${ecosystem}`);
    }
  }

  const registryUrl = session.registries?.npm;
  if (!registryUrl) {
    core.info("secure-registry: npm is off, nothing to configure");
    return {};
  }
  let registry: URL;
  try {
    registry = new URL(registryUrl);
  } catch {
    skipWarning(`the session API returned an invalid npm registry URL`);
    return {};
  }
  if (registry.protocol !== "https:") {
    skipWarning(`the session API returned a non-https npm registry URL`);
    return {};
  }

  const target = path.join(runnerTemp, ".npmrc");
  const content = mergeNpmrc(preflight.source.content, {
    registryUrl,
    token: session.token,
    omitLockfileResolved: session.config?.npm?.lockfile_resolved === "omit",
  });
  fs.writeFileSync(target, content, { encoding: "utf8", mode: 0o600 });
  // mode only applies when the file is created; setup-node may have created it.
  fs.chmodSync(target, 0o600);
  core.exportVariable(preflight.source.envKey ?? "NPM_CONFIG_USERCONFIG", target);

  saveState("srRegistryUrl", registryUrl);
  saveState("srNpmrcPath", target);

  if (preflight.source.content !== "") {
    core.info(`secure-registry: merged existing npm config from ${preflight.source.path}`);
  }
  core.info(`secure-registry: npm installs now go through ${registry.origin}${registry.pathname}`);

  return { registryEndpoint: `${registry.hostname}:${registry.port || "443"}` };
}

// Points npm at secure-registry for the rest of the job. Fails open: any
// problem leaves npm on its default registry and never fails the job.
export async function setupSecureRegistry(): Promise<SecureRegistryResult> {
  const config = secureRegistryInput(core.getInput("secure-registry"));
  if (config === undefined) {
    return {};
  }

  try {
    return await configureNpm(config);
  } catch (e) {
    skipWarning(`setup failed: ${e instanceof Error ? e.message : e}`);
    return {};
  }
}
