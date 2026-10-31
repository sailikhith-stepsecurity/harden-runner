import * as core from "@actions/core";
import * as cp from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { STEPSECURITY_API_URL } from "./configs";
import {
  RunSummary,
  changedFiles,
  compareVersions,
  cooldownTiming,
  fetchSummary,
  finishSecureRegistry,
  leakedLockfiles,
  readPostState,
  registryOverride,
  renderSummary,
  revokeToken,
  suggestedExemptions,
} from "./secure-registry-post";

jest.mock("@actions/core", () => ({
  ...jest.requireActual("@actions/core"),
  setSecret: jest.fn(),
  notice: jest.fn(),
  warning: jest.fn(),
  info: jest.fn(),
  debug: jest.fn(),
}));

const mockedCore = core as jest.Mocked<typeof core>;

const TOKEN = `step_srci_${"a".repeat(48)}_${"b".repeat(32)}`;
const HOST = "community.registry-int.stepsecurity.io";
const REGISTRY = `https://${HOST}/javascript/`;
const SUMMARY_URL = `${STEPSECURITY_API_URL}/secure-registry/sessions/summary`;
const REVOKE_URL = `${STEPSECURITY_API_URL}/secure-registry/sessions/revoke`;

const ORIGINAL_ENV = { ...process.env };
const ORIGINAL_FETCH = globalThis.fetch;

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in ORIGINAL_ENV)) delete process.env[key];
  }
  Object.assign(process.env, ORIGINAL_ENV);
}

let tmp: string;
let fetchCalls: Array<{ url: string; method: string; auth: string | null }>;

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function noContent(): Response {
  return new Response(null, { status: 204 });
}

// Each fetch call consumes one entry.
function mockFetchSequence(entries: Array<Response | Error>) {
  let i = 0;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const headers = new Headers(init?.headers);
    fetchCalls.push({ url: String(input), method: init?.method ?? "GET", auth: headers.get("authorization") });
    const entry = entries[i++];
    if (!entry) throw new Error("fetch called more times than expected");
    if (entry instanceof Error) throw entry;
    return entry;
  }) as typeof fetch;
}

function logged(): string {
  const fns = [mockedCore.info, mockedCore.notice, mockedCore.warning, mockedCore.debug] as jest.Mock[];
  return fns.flatMap((fn) => fn.mock.calls.map((args) => args.map(String).join(" "))).join("\n");
}

const EMPTY = { held: [], blocked: [], may_be_incomplete: true };

const COOLDOWN_REASON = "left-pad@1.3.1 was published 14h0m0s ago, which is within the 2-day cooldown period";

const SUMMARY: RunSummary = {
  held: [
    {
      ecosystem: "javascript",
      package: "typescript",
      versions: ["7.1.0-dev.20261030.1", "7.1.0-dev.20261029.1", "7.0.2"],
      controls: [{ name: "cooldown", reason: "3 version(s) filtered by cooldown period" }],
    },
  ],
  blocked: [
    {
      ecosystem: "javascript",
      package: "left-pad",
      version: "1.3.1",
      controls: [{ name: "cooldown", reason: COOLDOWN_REASON }],
    },
    {
      ecosystem: "javascript",
      package: "debug",
      version: "4.3.4",
      controls: [{ name: "compromised", reason: "debug@4.3.4 is a known compromised version" }],
    },
  ],
};

beforeEach(() => {
  jest.clearAllMocks();
  restoreEnv();
  for (const key of Object.keys(process.env)) {
    if (key.toLowerCase().startsWith("npm_config_")) delete process.env[key];
  }
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sr-post-test-"));
  fetchCalls = [];
});

afterEach(() => {
  restoreEnv();
  globalThis.fetch = ORIGINAL_FETCH;
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe("readPostState", () => {
  test("nothing configured", () => {
    expect(readPostState({})).toBeUndefined();
    expect(readPostState({ STATE_srToken: "" })).toBeUndefined();
  });

  test("token without a registry", () => {
    expect(readPostState({ STATE_srToken: TOKEN })).toEqual({ token: TOKEN, registryUrl: undefined });
  });

  test("token and registry", () => {
    expect(readPostState({ STATE_srToken: TOKEN, STATE_srRegistryUrl: REGISTRY })).toEqual({
      token: TOKEN,
      registryUrl: REGISTRY,
    });
  });
});

describe("registryOverride", () => {
  function npmrc(content: string): string {
    const file = path.join(tmp, ".npmrc");
    fs.writeFileSync(file, content);
    return file;
  }

  test("still on our registry", () => {
    const file = npmrc(`registry=${REGISTRY}\n//${HOST}/javascript/:_authToken=${TOKEN}\n`);
    expect(registryOverride({ NPM_CONFIG_USERCONFIG: file }, REGISTRY)).toBeUndefined();
  });

  test("trailing slash difference is the same registry", () => {
    const file = npmrc(`registry=https://${HOST}/javascript\n`);
    expect(registryOverride({ NPM_CONFIG_USERCONFIG: file }, REGISTRY)).toBeUndefined();
  });

  test("lowercase env var is honored", () => {
    const file = npmrc(`registry=${REGISTRY}\n`);
    expect(registryOverride({ npm_config_userconfig: file }, REGISTRY)).toBeUndefined();
  });

  test("setup-node replaced our registry line", () => {
    const file = npmrc(
      `//${HOST}/javascript/:_authToken=${TOKEN}\n//registry.npmjs.org/:_authToken=\${NODE_AUTH_TOKEN}\nregistry=https://registry.npmjs.org/\n`
    );
    expect(registryOverride({ NPM_CONFIG_USERCONFIG: file }, REGISTRY)).toBe(
      `${file} now sets registry to registry.npmjs.org`
    );
  });

  test("registry line removed", () => {
    const file = npmrc("save-exact=true\n");
    expect(registryOverride({ NPM_CONFIG_USERCONFIG: file }, REGISTRY)).toBe(`${file} no longer sets a registry`);
  });

  test("NPM_CONFIG_REGISTRY set later", () => {
    const file = npmrc(`registry=${REGISTRY}\n`);
    expect(
      registryOverride({ NPM_CONFIG_USERCONFIG: file, NPM_CONFIG_REGISTRY: "https://user:pw@mirror.example/" }, REGISTRY)
    ).toBe("NPM_CONFIG_REGISTRY is set to mirror.example");
  });

  test("user config unset", () => {
    expect(registryOverride({}, REGISTRY)).toBe("NPM_CONFIG_USERCONFIG is no longer set");
  });

  test("user config file deleted", () => {
    const file = path.join(tmp, "gone");
    expect(registryOverride({ NPM_CONFIG_USERCONFIG: file }, REGISTRY)).toBe(`${file} no longer exists`);
  });
});

describe("lockfiles", () => {
  function run(args: string[], cwd: string) {
    cp.execFileSync("git", args, { cwd, stdio: "ignore" });
  }

  let repo: string;
  let sha: string;

  beforeEach(() => {
    repo = path.join(tmp, "repo");
    fs.mkdirSync(path.join(repo, "pkg"), { recursive: true });
    run(["init", "-q"], repo);
    run(["config", "user.email", "test@example.com"], repo);
    run(["config", "user.name", "test"], repo);
    run(["config", "commit.gpgsign", "false"], repo);
    fs.writeFileSync(path.join(repo, ".gitignore"), "node_modules/\n");
    fs.writeFileSync(path.join(repo, "package-lock.json"), '{"resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz"}');
    fs.writeFileSync(path.join(repo, "pkg", "package-lock.json"), "{}");
    run(["add", "."], repo);
    run(["commit", "-q", "-m", "init"], repo);
    sha = cp.execFileSync("git", ["rev-parse", "HEAD"], { cwd: repo, encoding: "utf8" }).trim();
  });

  const leaked = `{"resolved": "https://${HOST}/javascript/a/-/a-1.0.0.tgz"}`;

  test("finds modified, untracked and committed lockfiles that use our host", () => {
    fs.writeFileSync(path.join(repo, "package-lock.json"), leaked);
    fs.mkdirSync(path.join(repo, "new"));
    fs.writeFileSync(path.join(repo, "new", "npm-shrinkwrap.json"), leaked);
    // Ignored, and npm's hidden lockfile is never committed.
    fs.mkdirSync(path.join(repo, "node_modules"));
    fs.writeFileSync(path.join(repo, "node_modules", ".package-lock.json"), leaked);

    fs.writeFileSync(path.join(repo, "pkg", "package-lock.json"), leaked);
    run(["commit", "-q", "-am", "update deps"], repo);
    fs.writeFileSync(path.join(repo, "package-lock.json"), leaked);

    const files = changedFiles(repo, sha);
    expect(leakedLockfiles(repo, files, HOST)).toEqual([
      "new/npm-shrinkwrap.json",
      "package-lock.json",
      "pkg/package-lock.json",
    ]);
  });

  test("ignores changed lockfiles on other hosts", () => {
    fs.writeFileSync(path.join(repo, "package-lock.json"), '{"resolved": "https://registry.npmjs.org/b/-/b-1.0.0.tgz"}');
    expect(leakedLockfiles(repo, changedFiles(repo, sha), HOST)).toEqual([]);
  });

  test("ignores unchanged lockfiles", () => {
    expect(leakedLockfiles(repo, changedFiles(repo, sha), HOST)).toEqual([]);
  });

  test("a SHA that is not in the repo still checks the working tree", () => {
    fs.writeFileSync(path.join(repo, "package-lock.json"), leaked);
    expect(leakedLockfiles(repo, changedFiles(repo, "0".repeat(40)), HOST)).toEqual(["package-lock.json"]);
  });

  test("not a git repository throws", () => {
    expect(() => changedFiles(tmp)).toThrow();
  });
});

describe("cooldownTiming", () => {
  test.each([
    [COOLDOWN_REASON, { age: "14h", clearsIn: "34h" }],
    ["x@1.0.0 was published 18h10m0s ago, which is within the 2-day cooldown period", { age: "18h10m", clearsIn: "29h50m" }],
    ["x@1.0.0 was published 45m0s ago, which is within the 1-day cooldown period", { age: "45m", clearsIn: "23h15m" }],
    ["x@1.0.0 was published 0s ago, which is within the cooldown period", { age: "0m" }],
    ["3 version(s) filtered by cooldown period", undefined],
    ["x@1.0.0 was published recently ago", undefined],
  ])("%j", (reason, expected) => {
    expect(cooldownTiming(reason)).toEqual(expected);
  });
});

describe("compareVersions", () => {
  test("sorts by semver precedence", () => {
    const versions = ["1.0.0", "1.0.0-alpha.1", "1.0.0-alpha", "1.0.0-beta", "0.9.12", "1.0.0-alpha.beta", "1.0.0-rc.1", "1.10.0", "1.2.0"];
    expect([...versions].sort(compareVersions)).toEqual([
      "0.9.12",
      "1.0.0-alpha",
      "1.0.0-alpha.1",
      "1.0.0-alpha.beta",
      "1.0.0-beta",
      "1.0.0-rc.1",
      "1.0.0",
      "1.2.0",
      "1.10.0",
    ]);
  });
});

describe("suggestedExemptions", () => {
  test("one version per package, cooldown only", () => {
    expect(suggestedExemptions(SUMMARY)).toEqual(
      new Map([["npm", ["left-pad@1.3.1", "typescript@7.1.0-dev.20261030.1"]]])
    );
  });

  test("a blocked version wins over the newest hidden one", () => {
    const summary: RunSummary = {
      held: [{ ecosystem: "javascript", package: "left-pad", versions: ["1.3.2", "1.3.1"], controls: [{ name: "cooldown" }] }],
      blocked: [{ ecosystem: "javascript", package: "left-pad", version: "1.3.1", controls: [{ name: "cooldown" }] }],
    };
    expect(suggestedExemptions(summary)).toEqual(new Map([["npm", ["left-pad@1.3.1"]]]));
  });

  test("nothing for compromised, mixed controls or unknown ecosystems", () => {
    const summary: RunSummary = {
      held: [{ ecosystem: "python", package: "requests", versions: ["9.0.0"], controls: [{ name: "cooldown" }] }],
      blocked: [
        { ecosystem: "javascript", package: "a", version: "1.0.0", controls: [{ name: "cooldown" }, { name: "compromised" }] },
        { ecosystem: "javascript", package: "b", version: "1.0.0", controls: [] },
      ],
    };
    expect(suggestedExemptions(summary).size).toBe(0);
  });
});

describe("renderSummary", () => {
  test("nothing held or blocked", () => {
    expect(renderSummary({ held: [], blocked: [] })).toBeUndefined();
  });

  test("held, blocked and the exemption snippet", () => {
    const md = renderSummary(SUMMARY)!;
    expect(md).toContain("| `typescript` | `7.1.0-dev.20261030.1`, `7.1.0-dev.20261029.1`, `7.0.2` | 3 version(s) filtered by cooldown period |");
    expect(md).toContain("| `left-pad@1.3.1` | cooldown | published 14h ago, clears in 34h |");
    expect(md).toContain("| `debug@4.3.4` | compromised | debug@4.3.4 is a known compromised version |");
    expect(md).toContain(
      [
        "```yaml",
        "secure-registry: |",
        "  npm:",
        "    cooldown:",
        "      exemptions:",
        '        - "left-pad@1.3.1"',
        '        - "typescript@7.1.0-dev.20261030.1"',
        "```",
      ].join("\n")
    );
    expect(md).toContain("compromised cannot be exempted");
  });

  test("no snippet when nothing can be exempted", () => {
    const md = renderSummary({ held: [], blocked: [SUMMARY.blocked[1]] })!;
    expect(md).not.toContain("```yaml");
  });

  test("long lists are cut", () => {
    const versions = Array.from({ length: 8 }, (_, i) => `1.0.${i}`);
    const blocked = Array.from({ length: 60 }, (_, i) => ({
      ecosystem: "javascript",
      package: `p${i}`,
      version: "1.0.0",
      controls: [{ name: "block_list", reason: "a|b" }],
    }));
    const md = renderSummary({
      held: [{ ecosystem: "javascript", package: "many", versions, controls: [{ name: "cooldown" }] }],
      blocked,
    })!;
    expect(md).toContain("`1.0.7`, `1.0.6`, `1.0.5`, `1.0.4`, `1.0.3` and 3 more");
    expect(md).toContain("| ... and 10 more | | |");
    expect(md).toContain("a\\|b");
  });
});

describe("fetchSummary", () => {
  const noSleep = jest.fn(async () => undefined);

  test("returns a non-empty first answer without retrying", async () => {
    mockFetchSequence([jsonResponse(200, { ...SUMMARY, may_be_incomplete: true })]);
    expect(await fetchSummary(TOKEN, noSleep)).toEqual(SUMMARY);
    expect(fetchCalls).toEqual([{ url: SUMMARY_URL, method: "GET", auth: `Bearer ${TOKEN}` }]);
    expect(noSleep).not.toHaveBeenCalled();
  });

  test("asks once more when the first answer is empty", async () => {
    mockFetchSequence([jsonResponse(200, EMPTY), jsonResponse(200, SUMMARY)]);
    expect(await fetchSummary(TOKEN, noSleep)).toEqual(SUMMARY);
    expect(fetchCalls).toHaveLength(2);
    expect(noSleep).toHaveBeenCalledTimes(1);
  });

  test("keeps the empty answer if the retry fails", async () => {
    mockFetchSequence([jsonResponse(200, EMPTY), jsonResponse(500, { code: "internal_error" })]);
    expect(await fetchSummary(TOKEN, noSleep)).toEqual({ held: [], blocked: [] });
  });

  test("an error status gives no summary", async () => {
    mockFetchSequence([jsonResponse(401, { code: "token_inactive" })]);
    expect(await fetchSummary(TOKEN, noSleep)).toBeUndefined();
    expect(logged()).toContain("could not read the run summary (HTTP 401)");
  });
});

describe("revokeToken", () => {
  test("204", async () => {
    mockFetchSequence([noContent()]);
    await revokeToken(TOKEN);
    expect(fetchCalls).toEqual([{ url: REVOKE_URL, method: "POST", auth: `Bearer ${TOKEN}` }]);
    expect(logged()).toContain("run token revoked");
  });

  test("error status is logged, not thrown", async () => {
    mockFetchSequence([jsonResponse(404, { code: "token_not_found" })]);
    await revokeToken(TOKEN);
    expect(logged()).toContain("could not revoke the run token (HTTP 404, token_not_found)");
    expect(mockedCore.warning).not.toHaveBeenCalled();
  });

  test("network error is logged, not thrown", async () => {
    mockFetchSequence([new Error("connect ECONNREFUSED")]);
    await revokeToken(TOKEN);
    expect(logged()).toContain("could not revoke the run token (connect ECONNREFUSED)");
  });
});

describe("finishSecureRegistry", () => {
  let summaryFile: string;
  let npmrcFile: string;

  beforeEach(() => {
    summaryFile = path.join(tmp, "step-summary.md");
    fs.writeFileSync(summaryFile, "");
    npmrcFile = path.join(tmp, ".npmrc");
    fs.writeFileSync(npmrcFile, `registry=${REGISTRY}\n`);
    process.env.GITHUB_STEP_SUMMARY = summaryFile;
    process.env.NPM_CONFIG_USERCONFIG = npmrcFile;
    process.env.STATE_srToken = TOKEN;
    process.env.STATE_srRegistryUrl = REGISTRY;
    // Not a git repository, so the lockfile check skips quietly.
    process.env.GITHUB_WORKSPACE = tmp;
  });

  test("does nothing when the pre step configured nothing", async () => {
    delete process.env.STATE_srToken;
    mockFetchSequence([]);
    await finishSecureRegistry();
    expect(fetchCalls).toHaveLength(0);
    expect(logged()).toBe("");
  });

  test("writes the job summary, then revokes", async () => {
    mockFetchSequence([jsonResponse(200, SUMMARY), noContent()]);
    await finishSecureRegistry();

    expect(fetchCalls.map((c) => c.url)).toEqual([SUMMARY_URL, REVOKE_URL]);
    expect(fs.readFileSync(summaryFile, "utf8")).toContain("left-pad@1.3.1");
    expect(mockedCore.setSecret).toHaveBeenCalledWith(TOKEN);
    expect(mockedCore.notice).not.toHaveBeenCalled();
    expect(mockedCore.warning).not.toHaveBeenCalled();
    expect(logged()).not.toContain(TOKEN);
  });

  test("only revokes when npm was not configured", async () => {
    delete process.env.STATE_srRegistryUrl;
    mockFetchSequence([noContent()]);
    await finishSecureRegistry();
    expect(fetchCalls.map((c) => c.url)).toEqual([REVOKE_URL]);
  });

  test("still revokes when the summary call throws", async () => {
    mockFetchSequence([new Error("socket hang up"), noContent()]);
    await finishSecureRegistry();
    expect(fetchCalls.map((c) => c.url)).toEqual([SUMMARY_URL, REVOKE_URL]);
    expect(logged()).toContain("post-step report failed: socket hang up");
    expect(fs.readFileSync(summaryFile, "utf8")).toBe("");
  });

  test("notice when setup-node replaced our registry", async () => {
    fs.writeFileSync(npmrcFile, "registry=https://registry.npmjs.org/\n");
    mockFetchSequence([jsonResponse(200, SUMMARY), noContent()]);
    await finishSecureRegistry();
    expect(mockedCore.notice).toHaveBeenCalledWith(
      expect.stringContaining(`npm stopped using secure-registry during this job (${npmrcFile} now sets registry to registry.npmjs.org)`)
    );
  });

  test("warning when a changed lockfile uses our host", async () => {
    const repo = path.join(tmp, "repo");
    fs.mkdirSync(repo);
    cp.execFileSync("git", ["init", "-q"], { cwd: repo });
    fs.writeFileSync(path.join(repo, "package-lock.json"), `{"resolved": "${REGISTRY}a/-/a-1.0.0.tgz"}`);
    process.env.GITHUB_WORKSPACE = repo;

    mockFetchSequence([jsonResponse(200, SUMMARY), noContent()]);
    await finishSecureRegistry();
    expect(mockedCore.warning).toHaveBeenCalledWith(
      expect.stringContaining(`package-lock.json now has package URLs on ${HOST}`),
      { file: "package-lock.json" }
    );
  });
});
