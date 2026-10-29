import * as core from "@actions/core";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { context } from "@actions/github";
import { SECURE_REGISTRY_AUDIENCE, STEPSECURITY_API_URL } from "./configs";
import {
  describeSessionFailure,
  missingTokenReason,
  secureRegistryInput,
  setupSecureRegistry,
} from "./secure-registry";

jest.mock("@actions/core", () => ({
  ...jest.requireActual("@actions/core"),
  getIDToken: jest.fn(),
  setSecret: jest.fn(),
  notice: jest.fn(),
  warning: jest.fn(),
  info: jest.fn(),
  debug: jest.fn(),
  startGroup: jest.fn(),
  endGroup: jest.fn(),
  exportVariable: jest.fn(),
}));

jest.mock("@actions/github", () => ({
  context: { eventName: "push", payload: {} },
}));

// os.homedir() reads the real environment, not the test's process.env.
jest.mock("os", () => ({
  ...jest.requireActual("os"),
  homedir: jest.fn(),
}));

const mockedCore = core as jest.Mocked<typeof core>;
const mockedHomedir = os.homedir as jest.MockedFunction<typeof os.homedir>;
const mutableContext = context as { eventName: string; payload: unknown };

const TOKEN = `step_srci_${"a".repeat(48)}_${"b".repeat(32)}`;
const REGISTRY = "https://community.registry-int.stepsecurity.io/javascript/";
const SESSION_URL = `${STEPSECURITY_API_URL}/secure-registry/sessions`;

const ORIGINAL_ENV = { ...process.env };
const ORIGINAL_FETCH = globalThis.fetch;

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in ORIGINAL_ENV)) delete process.env[key];
  }
  Object.assign(process.env, ORIGINAL_ENV);
}

let tmp: string;
let home: string;
let runnerTemp: string;
let stateFile: string;
let fetchCalls: Array<{ url: string; body: Record<string, unknown> }>;

function jsonResponse(
  status: number,
  body: unknown,
  headers: Record<string, string> = {}
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

function created(overrides: Record<string, unknown> = {}): Response {
  return jsonResponse(201, {
    token: TOKEN,
    expires_at: 1793300000,
    edition: "community",
    registries: { npm: REGISTRY },
    config: { npm: { mode: "enforce", cooldown: { days: 2, exemptions: [] }, compromised: true } },
    notices: [],
    ...overrides,
  });
}

// Each fetch call consumes one entry.
function mockFetchSequence(entries: Array<Response | Error>) {
  let i = 0;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    fetchCalls.push({ url: String(input), body: JSON.parse(String(init?.body)) });
    const entry = entries[i++];
    if (!entry) throw new Error("fetch called more times than expected");
    if (entry instanceof Error) throw entry;
    return entry;
  }) as typeof fetch;
}

function readState(): Record<string, string> {
  const state: Record<string, string> = {};
  for (const line of fs.readFileSync(stateFile, "utf8").split(os.EOL)) {
    const eq = line.indexOf("=");
    if (eq > 0) state[line.slice(0, eq)] = line.slice(eq + 1);
  }
  return state;
}

function logged(): string {
  const fns = [
    mockedCore.info,
    mockedCore.notice,
    mockedCore.warning,
    mockedCore.debug,
    mockedCore.startGroup,
  ] as jest.Mock[];
  return fns.flatMap((fn) => fn.mock.calls.map((args) => args.map(String).join(" "))).join("\n");
}

function npmrcPath() {
  return path.join(runnerTemp, ".npmrc");
}

beforeEach(() => {
  jest.clearAllMocks();
  restoreEnv();
  // npm sets npm_config_* for scripts it runs, including this test run.
  for (const key of Object.keys(process.env)) {
    if (key.toLowerCase().startsWith("npm_config_")) delete process.env[key];
  }

  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sr-test-"));
  home = path.join(tmp, "home");
  runnerTemp = path.join(tmp, "runner-temp");
  fs.mkdirSync(home);
  fs.mkdirSync(runnerTemp);
  stateFile = path.join(tmp, "state");
  fs.writeFileSync(stateFile, "");

  mockedHomedir.mockReturnValue(home);
  process.env.RUNNER_TEMP = runnerTemp;
  process.env.GITHUB_STATE = stateFile;
  process.env.GITHUB_SERVER_URL = "https://github.com";
  process.env.ACTIONS_ID_TOKEN_REQUEST_URL = "https://token.example/";
  process.env["INPUT_SECURE-REGISTRY"] = "true";
  // Keeps the preflight from running npm to find the global config.
  process.env.npm_config_globalconfig = path.join(tmp, "no-global-npmrc");

  mutableContext.eventName = "push";
  mutableContext.payload = {};

  mockedCore.getIDToken.mockResolvedValue("oidc-jwt");
  fetchCalls = [];
});

afterEach(() => {
  restoreEnv();
  globalThis.fetch = ORIGINAL_FETCH;
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe("secureRegistryInput", () => {
  test.each([
    ["", undefined],
    ["  ", undefined],
    ["false", undefined],
    ["FALSE", undefined],
    ["true", "true"],
    ["npm:\n  mode: audit", "npm:\n  mode: audit"],
  ])("%j -> %j", (raw, expected) => {
    expect(secureRegistryInput(raw)).toBe(expected);
  });
});

describe("missingTokenReason", () => {
  const repository = { full_name: "example-org/app" };

  test("fork pull request", () => {
    const payload = { repository, pull_request: { head: { repo: { full_name: "someone/app" } } } };
    expect(missingTokenReason("pull_request", payload)).toBe("fork pull request, no OIDC token available");
  });

  test("pull request from a deleted fork", () => {
    const payload = { repository, pull_request: { head: { repo: null } } };
    expect(missingTokenReason("pull_request", payload)).toBe("fork pull request, no OIDC token available");
  });

  test("same-repo pull request is a missing permission", () => {
    const payload = { repository, pull_request: { head: { repo: { full_name: "example-org/app" } } } };
    expect(missingTokenReason("pull_request", payload)).toContain("id-token: write");
  });

  test("push is a missing permission", () => {
    expect(missingTokenReason("push", { repository })).toContain("id-token: write");
  });
});

describe("describeSessionFailure", () => {
  test.each([
    [403, { code: "not_eligible", reason: "visibility" }, "notice", "public repositories only"],
    [403, { code: "not_eligible", reason: "runner" }, "notice", "GitHub-hosted runners only"],
    [403, { code: "enterprise_not_supported" }, "notice", "StepSecurity subscription"],
    [401, { code: "oidc_replayed" }, "warning", "rejected the OIDC token (oidc_replayed)"],
    [401, { code: "oidc_invalid" }, "warning", "rejected the OIDC token (oidc_invalid)"],
    [401, { code: "oidc_expired" }, "warning", "expired again"],
    [503, { code: "unavailable" }, "warning", "unavailable"],
    [500, { code: "internal_error", error: "failed to create session" }, "warning", "HTTP 500 (internal_error: failed to create session)"],
    [502, undefined, "warning", "HTTP 502"],
  ])("%d %j", (status, body, level, message) => {
    const failure = describeSessionFailure({ status, body });
    expect(failure.level).toBe(level);
    expect(failure.message).toContain(message);
  });

  test("rate limit includes Retry-After", () => {
    const failure = describeSessionFailure({ status: 429, body: { code: "rate_limited" }, retryAfter: "120" });
    expect(failure).toEqual({ level: "warning", message: "session rate limit reached, retry after 120s" });
  });
});

describe("setupSecureRegistry", () => {
  test.each(["", "false"])("does nothing when the input is %j", async (input) => {
    process.env["INPUT_SECURE-REGISTRY"] = input;
    mockFetchSequence([]);
    expect(await setupSecureRegistry()).toEqual({});
    expect(mockedCore.getIDToken).not.toHaveBeenCalled();
    expect(fetchCalls).toHaveLength(0);
    expect(logged()).toBe("");
  });

  test("configures npm from a new session", async () => {
    mockFetchSequence([created({ notices: [{ source: "workflow", path: "pypi", code: "unsupported_ecosystem", message: "pypi is not supported yet" }] })]);

    const result = await setupSecureRegistry();

    expect(result).toEqual({ registryEndpoint: "community.registry-int.stepsecurity.io:443" });
    expect(mockedCore.getIDToken).toHaveBeenCalledWith(SECURE_REGISTRY_AUDIENCE);
    expect(fetchCalls).toEqual([{ url: SESSION_URL, body: { oidc_token: "oidc-jwt", config: "true" } }]);

    expect(mockedCore.setSecret).toHaveBeenCalledWith(TOKEN);
    expect(mockedCore.setSecret.mock.invocationCallOrder[0]).toBeLessThan(
      mockedCore.startGroup.mock.invocationCallOrder[0]
    );
    expect(logged()).not.toContain(TOKEN);

    expect(fs.readFileSync(npmrcPath(), "utf8")).toBe(
      `registry=${REGISTRY}\n//community.registry-int.stepsecurity.io/javascript/:_authToken=${TOKEN}\n`
    );
    if (process.platform !== "win32") {
      expect(fs.statSync(npmrcPath()).mode & 0o777).toBe(0o600);
    }
    expect(mockedCore.exportVariable).toHaveBeenCalledWith("NPM_CONFIG_USERCONFIG", npmrcPath());

    expect(readState()).toEqual({
      srToken: TOKEN,
      srEdition: "community",
      srRegistryUrl: REGISTRY,
      srNpmrcPath: npmrcPath(),
    });
    expect(mockedCore.notice).toHaveBeenCalledWith("secure-registry: pypi is not supported yet (pypi)");
    expect(mockedCore.warning).not.toHaveBeenCalled();
  });

  test("merges the user's ~/.npmrc", async () => {
    fs.writeFileSync(
      path.join(home, ".npmrc"),
      "@example-org:registry=https://npm.pkg.github.com/\n//npm.pkg.github.com/:_authToken=${NODE_AUTH_TOKEN}\n"
    );
    mockFetchSequence([created()]);

    await setupSecureRegistry();

    expect(fs.readFileSync(npmrcPath(), "utf8")).toBe(
      [
        "@example-org:registry=https://npm.pkg.github.com/",
        "//npm.pkg.github.com/:_authToken=${NODE_AUTH_TOKEN}",
        `registry=${REGISTRY}`,
        `//community.registry-int.stepsecurity.io/javascript/:_authToken=${TOKEN}`,
      ].join("\n") + "\n"
    );
    // The user's own file is left untouched.
    expect(fs.readFileSync(path.join(home, ".npmrc"), "utf8")).not.toContain(TOKEN);
  });

  test("reads setup-node's file before overwriting the same path", async () => {
    fs.writeFileSync(
      npmrcPath(),
      "//registry.npmjs.org/:_authToken=${NODE_AUTH_TOKEN}\nregistry=https://registry.npmjs.org/\nalways-auth=false\n",
      { mode: 0o644 }
    );
    process.env.NPM_CONFIG_USERCONFIG = npmrcPath();
    mockFetchSequence([created()]);

    await setupSecureRegistry();

    expect(fs.readFileSync(npmrcPath(), "utf8")).toBe(
      [
        "//registry.npmjs.org/:_authToken=${NODE_AUTH_TOKEN}",
        "always-auth=false",
        `registry=${REGISTRY}`,
        `//community.registry-int.stepsecurity.io/javascript/:_authToken=${TOKEN}`,
      ].join("\n") + "\n"
    );
    if (process.platform !== "win32") {
      expect(fs.statSync(npmrcPath()).mode & 0o777).toBe(0o600);
    }
  });

  test("exports the same variable name the user config came from", async () => {
    const custom = path.join(tmp, "custom-npmrc");
    fs.writeFileSync(custom, "save-exact=true\n");
    process.env.npm_config_userconfig = custom;
    mockFetchSequence([created()]);

    await setupSecureRegistry();

    expect(mockedCore.exportVariable).toHaveBeenCalledWith("npm_config_userconfig", npmrcPath());
    expect(fs.readFileSync(npmrcPath(), "utf8").startsWith("save-exact=true\n")).toBe(true);
  });

  test("opts in to omit-lockfile-registry-resolved", async () => {
    mockFetchSequence([created({ config: { npm: { mode: "enforce", lockfile_resolved: "omit" } } })]);

    await setupSecureRegistry();

    expect(fs.readFileSync(npmrcPath(), "utf8")).toContain("\nomit-lockfile-registry-resolved=true\n");
  });

  describe("does not switch a registry the user chose", () => {
    test("NPM_CONFIG_REGISTRY is set", async () => {
      process.env.NPM_CONFIG_REGISTRY = "https://user:secret@mirror.example.com/npm/";
      mockFetchSequence([]);

      expect(await setupSecureRegistry()).toEqual({});
      expect(mockedCore.notice).toHaveBeenCalledWith(
        "secure-registry: NPM_CONFIG_REGISTRY is set (mirror.example.com). npm stays on the default registry."
      );
      expect(logged()).not.toContain("secret");
      expect(mockedCore.getIDToken).not.toHaveBeenCalled();
    });

    test("~/.npmrc points at a mirror", async () => {
      fs.writeFileSync(path.join(home, ".npmrc"), "registry=https://artifactory.example.com/api/npm/npm/\n");
      mockFetchSequence([]);

      expect(await setupSecureRegistry()).toEqual({});
      expect(mockedCore.notice.mock.calls[0][0]).toContain("sets registry to artifactory.example.com");
      expect(fs.existsSync(npmrcPath())).toBe(false);
      expect(mockedCore.getIDToken).not.toHaveBeenCalled();
    });

    test("the global npm config points at a mirror", async () => {
      fs.writeFileSync(process.env.npm_config_globalconfig, "registry=https://nexus.example.com/repository/npm/\n");
      mockFetchSequence([]);

      expect(await setupSecureRegistry()).toEqual({});
      expect(mockedCore.notice.mock.calls[0][0]).toContain("the global npm config");
      expect(mockedCore.getIDToken).not.toHaveBeenCalled();
    });
  });

  describe("no OIDC token", () => {
    test("fork pull request", async () => {
      delete process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
      mutableContext.eventName = "pull_request";
      mutableContext.payload = {
        repository: { full_name: "example-org/app" },
        pull_request: { head: { repo: { full_name: "someone/app" } } },
      };
      mockFetchSequence([]);

      expect(await setupSecureRegistry()).toEqual({});
      expect(mockedCore.notice).toHaveBeenCalledWith(
        "secure-registry: fork pull request, no OIDC token available. npm stays on the default registry."
      );
    });

    test("missing id-token permission", async () => {
      delete process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
      mockFetchSequence([]);

      expect(await setupSecureRegistry()).toEqual({});
      expect(mockedCore.notice.mock.calls[0][0]).toContain('add "permissions: id-token: write"');
    });
  });

  test("retries once with a new OIDC token when the first one expired", async () => {
    mockedCore.getIDToken.mockResolvedValueOnce("jwt-1").mockResolvedValueOnce("jwt-2");
    mockFetchSequence([jsonResponse(401, { code: "oidc_expired", error: "expired" }), created()]);

    expect(await setupSecureRegistry()).toEqual({ registryEndpoint: "community.registry-int.stepsecurity.io:443" });
    expect(fetchCalls.map((c) => c.body.oidc_token)).toEqual(["jwt-1", "jwt-2"]);
  });

  test("gives up after the second expired token", async () => {
    mockFetchSequence([
      jsonResponse(401, { code: "oidc_expired", error: "expired" }),
      jsonResponse(401, { code: "oidc_expired", error: "expired" }),
    ]);

    expect(await setupSecureRegistry()).toEqual({});
    expect(fetchCalls).toHaveLength(2);
    expect(mockedCore.warning.mock.calls[0][0]).toContain("expired again");
  });

  test.each([
    ["not eligible", jsonResponse(403, { code: "not_eligible", error: "x", reason: "visibility" }), "notice"],
    ["enterprise", jsonResponse(403, { code: "enterprise_not_supported", error: "x" }), "notice"],
    ["rate limited", jsonResponse(429, { code: "rate_limited", error: "x" }, { "retry-after": "120" }), "warning"],
    ["unavailable", jsonResponse(503, { code: "unavailable", error: "x" }), "warning"],
    ["internal error", jsonResponse(500, { code: "internal_error", error: "x" }), "warning"],
    ["non-JSON error", new Response("<html>bad gateway</html>", { status: 502 }), "warning"],
  ])("fails open: %s", async (_name, response, level) => {
    mockFetchSequence([response as Response]);

    expect(await setupSecureRegistry()).toEqual({});
    const annotate = level === "notice" ? mockedCore.notice : mockedCore.warning;
    expect(annotate).toHaveBeenCalledTimes(1);
    expect(annotate.mock.calls[0][0]).toMatch(/npm stays on the default registry\.$/);
    expect(fs.existsSync(npmrcPath())).toBe(false);
    expect(mockedCore.exportVariable).not.toHaveBeenCalled();
    expect(readState()).toEqual({});
  });

  test("fails open when the session API is unreachable", async () => {
    mockFetchSequence([new TypeError("fetch failed")]);

    expect(await setupSecureRegistry()).toEqual({});
    expect(mockedCore.warning).toHaveBeenCalledWith(
      "secure-registry: setup failed: fetch failed. npm stays on the default registry."
    );
  });

  test("fails open when the OIDC token cannot be fetched", async () => {
    mockedCore.getIDToken.mockRejectedValue(new Error("Failed to get ID Token"));
    mockFetchSequence([]);

    expect(await setupSecureRegistry()).toEqual({});
    expect(mockedCore.warning.mock.calls[0][0]).toContain("Failed to get ID Token");
  });

  test("200 without a token means every ecosystem is off", async () => {
    mockFetchSequence([jsonResponse(200, { edition: "community", registries: {}, config: {}, notices: [] })]);

    expect(await setupSecureRegistry()).toEqual({});
    expect(mockedCore.info).toHaveBeenCalledWith("secure-registry: every ecosystem is off, nothing to configure");
    expect(mockedCore.warning).not.toHaveBeenCalled();
    expect(fs.existsSync(npmrcPath())).toBe(false);
    expect(readState()).toEqual({});
  });

  test("201 without a token is a warning", async () => {
    mockFetchSequence([jsonResponse(201, { edition: "community", registries: { npm: REGISTRY } })]);

    expect(await setupSecureRegistry()).toEqual({});
    expect(mockedCore.warning.mock.calls[0][0]).toContain("returned no token");
  });

  test("keeps the token for revoke when the registry URL is not https", async () => {
    mockFetchSequence([created({ registries: { npm: "http://community.registry-int.stepsecurity.io/javascript/" } })]);

    expect(await setupSecureRegistry()).toEqual({});
    expect(mockedCore.warning.mock.calls[0][0]).toContain("non-https");
    expect(fs.existsSync(npmrcPath())).toBe(false);
    expect(readState()).toEqual({ srToken: TOKEN, srEdition: "community" });
  });

  test("ignores ecosystems other than npm", async () => {
    mockFetchSequence([created({ registries: { npm: REGISTRY, pypi: "https://community.registry-int.stepsecurity.io/python/" } })]);

    expect(await setupSecureRegistry()).toEqual({ registryEndpoint: "community.registry-int.stepsecurity.io:443" });
    expect(mockedCore.info).toHaveBeenCalledWith(
      "secure-registry: this version of Harden-Runner configures npm only, ignoring pypi"
    );
  });

  test("skips GitHub Enterprise Server", async () => {
    process.env.GITHUB_SERVER_URL = "https://ghes.example.com";
    mockFetchSequence([]);

    expect(await setupSecureRegistry()).toEqual({});
    expect(mockedCore.notice.mock.calls[0][0]).toContain("GitHub Enterprise Server");
    expect(mockedCore.getIDToken).not.toHaveBeenCalled();
  });

  test("skips when RUNNER_TEMP is not set", async () => {
    delete process.env.RUNNER_TEMP;
    mockFetchSequence([]);

    expect(await setupSecureRegistry()).toEqual({});
    expect(mockedCore.notice.mock.calls[0][0]).toContain("RUNNER_TEMP is not set");
  });

  test("fails open when something throws after the session is created", async () => {
    process.env.GITHUB_STATE = path.join(tmp, "missing-dir", "state");
    mockFetchSequence([created()]);

    expect(await setupSecureRegistry()).toEqual({});
    expect(mockedCore.warning.mock.calls[0][0]).toMatch(/^secure-registry: setup failed: .*npm stays on the default registry\.$/);
    expect(logged()).not.toContain(TOKEN);
  });
});
