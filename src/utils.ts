import * as cp from "child_process";
import * as fs from "fs";
import * as os from "os";

export function isPlatformSupported(platform: NodeJS.Platform) {
  switch (platform) {
    case "linux":
    case "win32":
    case "darwin":
      return true;

    default:
      return false;
  }
}

// Resolves the user the runner process is executing as. Some runner
// environments (e.g. AWS CodeBuild-hosted runners) do not set the USER
// environment variable.
export function getRunnerUser(): string | undefined {
  if (process.env.USER) {
    return process.env.USER;
  }
  try {
    return os.userInfo().username;
  } catch {
    return undefined;
  }
}

export function chownForFolder(newOwner: string | undefined, target: string) {
  if (!newOwner) {
    console.log(`Unable to determine runner user; skipping chown of ${target}`);
    return;
  }
  let cmd = "sudo";
  let args = ["chown", "-R", newOwner, target];
  cp.execFileSync(cmd, args);
}

export function isAgentInstalled(platform: NodeJS.Platform) {
  switch (platform) {
    case "linux":
      return fs.existsSync("/home/agent/agent.status");
    case "win32":
      return fs.existsSync("C:\\agent\\agent.status");
    case "darwin":
      return fs.existsSync("/opt/step-security/agent.status");
    default:
      return false;
  }
}

export function shouldDeployAgentOnSelfHosted(
  deployOnSelfHostedVm: boolean,
  isContainer: boolean,
  agentAlreadyInstalled: boolean
): boolean {
  return deployOnSelfHostedVm && !isContainer && !agentAlreadyInstalled;
}

export type ThirdPartyRunnerProvider = "depot" | "namespace" | "warp" | "blacksmith" | "bitrise" | "codebuild";

export function detectThirdPartyRunnerProvider(): ThirdPartyRunnerProvider | null {
  if (process.env["DEPOT_RUNNER"] === "1") return "depot";
  if (process.env["NAMESPACE_GITHUB_RUNTIME"]) return "namespace";
  if (process.env["BITRISE_IO"]) return "bitrise";
  if (process.env["CODEBUILD_RUNNER_TYPE"] === "GITHUB") return "codebuild";
  const runnerName = process.env["RUNNER_NAME"] ?? "";
  if (runnerName.startsWith("warp-")) return "warp";
  if (runnerName.startsWith("blacksmith-")) return "blacksmith";
  return null;
}

// Returns the SCM state of a Windows service ("RUNNING", "STOPPED",
// "STOP_PENDING", ...), or null when the service is not installed. sc.exe
// exits non-zero with error 1060 in that case, which is not an error here.
export function getWindowsServiceState(name: string): string | null {
  try {
    const output = cp.execFileSync("sc.exe", ["query", name], {
      encoding: "utf8",
      windowsHide: true,
    });
    const match = output.match(/STATE\s+:\s+\d+\s+(\w+)/);
    return match ? match[1] : null;
  } catch {
    return null;
  }
}

// Stops and deletes a Windows service, waiting for each transition to settle.
// Never throws; a failure here should not fail the job.
export async function removeWindowsService(name: string): Promise<void> {
  if (getWindowsServiceState(name) === null) {
    return;
  }

  try {
    cp.execFileSync("sc.exe", ["stop", name], {
      encoding: "utf8",
      windowsHide: true,
    });
  } catch (error) {
    // Already stopped (or stopping) exits non-zero; the poll below settles it.
    console.log(`sc.exe stop ${name}: ${error.message}`);
  }

  for (let i = 0; i < 20; i++) {
    const state = getWindowsServiceState(name);
    if (state === null || state === "STOPPED") {
      break;
    }
    await serviceSleep(500);
  }

  try {
    cp.execFileSync("sc.exe", ["delete", name], {
      encoding: "utf8",
      windowsHide: true,
    });
  } catch (error) {
    console.log(`sc.exe delete ${name}: ${error.message}`);
    return;
  }

  // Wait for DELETE_PENDING to clear so a subsequent create does not fail.
  for (let i = 0; i < 10; i++) {
    if (getWindowsServiceState(name) === null) {
      break;
    }
    await serviceSleep(500);
  }
}

function serviceSleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function getAnnotationLogs(platform: NodeJS.Platform) {
  switch (platform) {
    case "linux":
      return fs.readFileSync("/home/agent/annotation.log", "utf8");
    case "win32":
      return fs.readFileSync("C:\\agent\\annotation.log", "utf8");
    case "darwin":
      return fs.readFileSync("/opt/step-security/annotation.log", "utf8");
    default:
      throw new Error("platform not supported");
  }
}
