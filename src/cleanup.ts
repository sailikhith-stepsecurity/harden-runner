import * as fs from "fs";
import * as cp from "child_process";
import * as path from "path";
import * as common from "./common";
import isDocker from "is-docker";
import { isARCRunner } from "./arc-runner";
import { isGithubHosted } from "./tls-inspect";
import { context } from "@actions/github";
(async () => {
  console.log("[harden-runner] post-step");

  const customProperties = context?.payload?.repository?.custom_properties || {};
  if (customProperties["skip-harden-runner"] === "true") {
    console.log("Skipping harden-runner: custom property 'skip-harden-runner' is set to 'true'");
    return;
  }

  // Check platform support
  if (process.platform !== "linux" && process.platform !== "win32") {
    console.log(common.UNSUPPORTED_PLATFORM_MESSAGE);
    return;
  }

  // Linux-specific checks
  if (process.platform === "linux") {
    if (isGithubHosted() && isDocker()) {
      console.log(common.CONTAINER_MESSAGE);
      return;
    }
  }

  if (isARCRunner()) {
    console.log(`[!] ${common.ARC_RUNNER_MESSAGE}`);
    return;
  }

  if (process.env.STATE_selfHosted === "true") {
    return;
  }

  if (process.env.STATE_customVMImage === "true") {
    return;
  }

  if (process.platform === "linux" && process.env.STATE_isTLS === "false" && process.arch === "arm64") {
    return;
  }

  if (
    String(process.env.STATE_monitorStatusCode) ===
    common.STATUS_HARDEN_RUNNER_UNAVAILABLE
  ) {
    console.log(common.HARDEN_RUNNER_UNAVAILABLE_MESSAGE);
    return;
  }

  // Platform-specific cleanup
  if (process.platform === "win32") {
    // Windows cleanup
    const agentDir = process.env.STATE_agentDir || "C:\\agent";
    const postEventFile = path.join(agentDir, "post_event.json");

    if (isGithubHosted() && fs.existsSync(postEventFile)) {
      console.log("Post step already executed, skipping");
      return;
    }

    // Write post event
    fs.writeFileSync(postEventFile, JSON.stringify({ event: "post" }));

    // Wait for done file
    const doneFile = path.join(agentDir, "done.json");
    let counter = 0;
    while (true) {
      if (!fs.existsSync(doneFile)) {
        counter++;
        if (counter > 10) {
          console.log("timed out");
          break;
        }
        await sleep(1000);
      } else {
        break;
      }
    }

    // Display agent log
    const log = path.join(agentDir, "agent.log");
    if (fs.existsSync(log)) {
      console.log("log:");
      var content = fs.readFileSync(log, "utf-8");
      console.log(content);
    }

    // Display agent status
    const status = path.join(agentDir, "agent.status");
    if (fs.existsSync(status)) {
      console.log("status:");
      var content = fs.readFileSync(status, "utf-8");
      console.log(content);
    }

    // Stop agent process
    const pidFile = path.join(agentDir, "agent.pid");
    if (fs.existsSync(pidFile)) {
      try {
        const pid = fs.readFileSync(pidFile, "utf-8").trim();

        if (!pid || pid === "") {
          console.log("Warning: PID file is empty. Agent may not have started successfully.");
          console.log("Attempting to find and stop agent process by name...");

          try {
            // Try to stop by process name
            cp.execSync(
              `powershell -Command "Get-Process -Name 'agent' -ErrorAction SilentlyContinue | Stop-Process -Force"`,
              { encoding: "utf8" }
            );
            console.log("Agent process stopped by name");
          } catch (stopError) {
            console.log("No agent process found running");
          }
        } else {
          console.log(`Stopping agent process with PID: ${pid}`);

          // Use PowerShell to stop the process
          cp.execSync(
            `powershell -Command "Stop-Process -Id ${pid} -Force -ErrorAction SilentlyContinue"`,
            { encoding: "utf8" }
          );

          console.log("Agent process stopped");
        }
      } catch (error) {
        console.log("Warning: Could not stop agent process:", error.message);
      }
    } else {
      console.log("Warning: PID file not found. Agent may not have started.");
      console.log("Attempting to find and stop agent process by name...");

      try {
        // Try to stop by process name
        cp.execSync(
          `powershell -Command "Get-Process -Name 'agent' -ErrorAction SilentlyContinue | Stop-Process -Force"`,
          { encoding: "utf8" }
        );
        console.log("Agent process stopped by name");
      } catch (stopError) {
        console.log("No agent process found running");
      }
    }
  } else {
    // Linux cleanup
    if (isGithubHosted() && fs.existsSync("/home/agent/post_event.json")) {
      console.log("Post step already executed, skipping");
      return;
    }

    fs.writeFileSync(
      "/home/agent/post_event.json",
      JSON.stringify({ event: "post" })
    );

    const doneFile = "/home/agent/done.json";
    let counter = 0;
    while (true) {
      if (!fs.existsSync(doneFile)) {
        counter++;
        if (counter > 10) {
          console.log("timed out");
          break;
        }
        await sleep(1000);
      } else {
        break;
      }
    }

    const log = "/home/agent/agent.log";
    if (fs.existsSync(log)) {
      console.log("log:");
      var content = fs.readFileSync(log, "utf-8");
      console.log(content);
    }

    const daemonLog = "/home/agent/daemon.log";
    if (fs.existsSync(daemonLog)) {
      console.log("daemonLog:");
      var content = fs.readFileSync(daemonLog, "utf-8");
      console.log(content);
    }

    var status = "/home/agent/agent.status";
    if (fs.existsSync(status)) {
      console.log("status:");
      var content = fs.readFileSync(status, "utf-8");
      console.log(content);
    }

    var disable_sudo = process.env.STATE_disableSudo;
    var disable_sudo_and_containers = process.env.STATE_disableSudoAndContainers;

    if (disable_sudo !== "true" && disable_sudo_and_containers !== "true") {
      try {
        var journalLog = cp.execSync(
          "sudo journalctl -u agent.service --lines=1000",
          {
            encoding: "utf8",
            maxBuffer: 1024 * 1024 * 10, // 10MB buffer
          }
        );
        console.log("agent.service log:");
        console.log(journalLog);
      } catch (error) {
        console.log("Warning: Could not fetch service logs:", error.message);
      }
    }
  }

  try {
    await common.addSummary();
  } catch (exception) {
    console.log(exception);
  }
})();

function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}
