import * as tc from "@actions/tool-cache";
import * as core from "@actions/core";
import * as cp from "child_process";
import * as path from "path";
import * as fs from "fs";
import { verifyChecksum } from "./checksum";
import { EOL } from "os";
import { ARM64_RUNNER_MESSAGE } from "./common";

export async function installAgent(
  isTLS: boolean,
  configStr: string
): Promise<boolean> {
  // Note: to avoid github rate limiting
  const token = core.getInput("token", { required: true });
  const auth = `token ${token}`;

  const variant = process.arch === "x64" ? "amd64" : "arm64";

  let downloadPath: string;

  fs.appendFileSync(process.env.GITHUB_STATE, `isTLS=${isTLS}${EOL}`, {
    encoding: "utf8",
  });

  if (isTLS) {
    downloadPath = await tc.downloadTool(
      `https://github.com/step-security/agent-ebpf/releases/download/v1.7.9/harden-runner_1.7.9_linux_${variant}.tar.gz`,
      undefined,
      auth
    );
  } else {
    if (variant === "arm64") {
      console.log(ARM64_RUNNER_MESSAGE);
      return false;
    }
    downloadPath = await tc.downloadTool(
      "https://github.com/step-security/agent/releases/download/v0.14.2/agent_0.14.2_linux_amd64.tar.gz",
      undefined,
      auth
    );
  }

  verifyChecksum(downloadPath, isTLS, variant);

  const extractPath = await tc.extractTar(downloadPath);

  let cmd = "cp",
    args = [path.join(extractPath, "agent"), "/home/agent/agent"];

  cp.execFileSync(cmd, args);

  cp.execSync("chmod +x /home/agent/agent");

  fs.writeFileSync("/home/agent/agent.json", configStr);

  cmd = "sudo";
  args = [
    "cp",
    path.join(__dirname, "agent.service"),
    "/etc/systemd/system/agent.service",
  ];
  cp.execFileSync(cmd, args);
  cp.execSync("sudo systemctl daemon-reload");
  cp.execSync("sudo service agent start", { timeout: 15000 });
  return true;
}

export async function installWindowsAgent(
  configStr: string
): Promise<boolean> {
  try {
    // Note: to avoid github rate limiting
    const token = core.getInput("token", { required: true });

    // Set up agent directory at C:\agent (mirrors Linux /home/agent)
    const agentDir = "C:\\agent";

    core.info(`Creating agent directory: ${agentDir}`);
    if (!fs.existsSync(agentDir)) {
      fs.mkdirSync(agentDir, { recursive: true });
    }

    fs.appendFileSync(
      process.env.GITHUB_STATE,
      `agentDir=${agentDir}${EOL}`,
      {
        encoding: "utf8",
      }
    );

    // Download Windows agent from private repository using gh CLI
    const repo = "sailikhith-stepsecurity/win-agent";
    const agentExePath = path.join(agentDir, "agent.exe");

    core.info(`Downloading Windows agent from ${repo}...`);

    try {
      // Set GH_TOKEN environment variable for gh CLI
      const ghEnv = { ...process.env, GH_TOKEN: token };

      // First, verify access to the repository
      core.info("Verifying access to repository...");
      try {
        const verifyRepoCmd = `gh repo view ${repo} --json nameWithOwner,isPrivate`;
        const repoInfo = cp.execSync(verifyRepoCmd, {
          encoding: "utf8",
          env: ghEnv,
        });
        core.info(`Repository access confirmed: ${repo}`);
        core.info(`Repository info: ${repoInfo}`);
      } catch (verifyError) {
        core.setFailed(
          `Cannot access repository ${repo}. Please ensure:\n` +
          `  1. The repository exists\n` +
          `  2. The token has 'repo' scope\n` +
          `  3. The token is passed via 'token' input\n` +
          `Error: ${verifyError.message}`
        );
        return false;
      }

      // Check for available releases
      core.info("Checking for available releases...");
      try {
        const listReleasesCmd = `gh release list --repo ${repo} --limit 5`;
        const releasesList = cp.execSync(listReleasesCmd, {
          encoding: "utf8",
          env: ghEnv,
        });
        if (releasesList.trim()) {
          core.info("Available releases:");
          core.info(releasesList);
        } else {
          core.setFailed(
            `No releases found in ${repo}.\n` +
            `Please create a release first:\n` +
            `  1. Go to https://github.com/${repo}/releases\n` +
            `  2. Create a new release with a tag (e.g., v0.0.1)\n` +
            `  3. Upload the windows-agent-amd64.exe binary`
          );
          return false;
        }
      } catch (listError) {
        core.setFailed(
          `Failed to list releases from ${repo}: ${listError.message}`
        );
        return false;
      }

      // Get latest release tag
      const getReleaseCmd = `gh release view --repo ${repo} --json tagName --jq .tagName`;
      const releaseTag = cp.execSync(getReleaseCmd, {
        encoding: "utf8",
        env: ghEnv,
      }).trim();

      if (!releaseTag) {
        core.setFailed(`No release found in ${repo}`);
        return false;
      }

      core.info(`Latest release: ${releaseTag}`);

      // Download the windows-agent-amd64.exe
      const downloadCmd = `gh release download ${releaseTag} --repo ${repo} --pattern "windows-agent-amd64.exe" --dir "${agentDir}" --clobber`;
      cp.execSync(downloadCmd, { env: ghEnv });

      // Rename to agent.exe
      const downloadedFile = path.join(agentDir, "windows-agent-amd64.exe");
      if (fs.existsSync(downloadedFile)) {
        fs.renameSync(downloadedFile, agentExePath);
        core.info(`Downloaded agent to: ${agentExePath}`);
      } else {
        core.setFailed("Failed to download windows-agent-amd64.exe");
        return false;
      }
    } catch (error) {
      core.setFailed(`Failed to download Windows agent: ${error.message}`);
      return false;
    }

    // Write config.json
    const configPath = path.join(agentDir, "config.json");
    fs.writeFileSync(configPath, configStr);
    core.info(`Created config file: ${configPath}`);

    // Install NSSM and use it to run agent as a Windows Service
    core.info("Installing Windows Agent as a service using NSSM...");

    const serviceName = "StepSecurityAgent";
    const logPath = path.join(agentDir, "agent.log");

    try {
      // PowerShell script to install NSSM, create and start service
      const serviceScript = `
$serviceName = "${serviceName}"
$agentPath = "${agentExePath}"
$agentDir = "${agentDir}"
$logPath = "${logPath}"

Write-Host "Installing NSSM (Non-Sucking Service Manager)..."

# Install NSSM using chocolatey
try {
  choco install nssm -y --no-progress
  if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to install NSSM via chocolatey"
    exit 1
  }
  Write-Host "NSSM installed successfully"
} catch {
  Write-Error "Error installing NSSM: $_"
  exit 1
}

# Refresh environment to get NSSM in PATH
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

Write-Host "Creating service: $serviceName"

# Check if service already exists and remove it
$existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existingService) {
  Write-Host "Service already exists, removing..."
  nssm stop $serviceName
  nssm remove $serviceName confirm
  Start-Sleep -Seconds 2
}

# Install service using NSSM
Write-Host "Installing service with NSSM..."
nssm install $serviceName "$agentPath"

if ($LASTEXITCODE -ne 0) {
  Write-Error "Failed to install service with NSSM"
  exit 1
}

# Configure service
Write-Host "Configuring service..."
nssm set $serviceName AppDirectory "$agentDir"
nssm set $serviceName AppStdout "$logPath"
nssm set $serviceName AppStderr "$logPath"
nssm set $serviceName DisplayName "StepSecurity Harden Runner Agent"
nssm set $serviceName Description "Security monitoring agent for GitHub Actions"

# Start the service
Write-Host "Starting service..."
nssm start $serviceName

if ($LASTEXITCODE -ne 0) {
  Write-Error "Failed to start service"
  nssm remove $serviceName confirm
  exit 1
}

Write-Host "Service started successfully"

# Wait a moment for service to initialize
Start-Sleep -Seconds 2

# Check service status
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service) {
  Write-Host "Service Status: $($service.Status)"
} else {
  Write-Warning "Could not retrieve service status"
}
`;

      const scriptPath = path.join(agentDir, "install-service.ps1");
      fs.writeFileSync(scriptPath, serviceScript);

      cp.execSync(`powershell -ExecutionPolicy Bypass -File "${scriptPath}"`, {
        stdio: "inherit",
      });

      core.info("Windows Agent service installed and started successfully");
      return true;
    } catch (error) {
      core.setFailed(
        `Failed to install Windows agent service: ${error.message}`
      );
      return false;
    }
  } catch (error) {
    core.setFailed(`Failed to install Windows agent: ${error.message}`);
    return false;
  }
}
