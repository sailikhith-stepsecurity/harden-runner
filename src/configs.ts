export const STEPSECURITY_ENV = "agent"; // agent or int

export const STEPSECURITY_API_URL = `https://${STEPSECURITY_ENV}.api.stepsecurity.io/v1`;

export const STEPSECURITY_TELEMETRY_URL =
  "https://prod.app-api.stepsecurity.io/v1";

export const STEPSECURITY_WEB_URL = "https://app.stepsecurity.io";

export interface StepSecurityUrls {
  apiUrl: string;
  telemetryUrl: string;
  webUrl: string;
}

export function getUrls(env?: string): StepSecurityUrls {
  if (!env || env.trim() === "") {
    return {
      apiUrl: STEPSECURITY_API_URL,
      telemetryUrl: STEPSECURITY_TELEMETRY_URL,
      webUrl: STEPSECURITY_WEB_URL,
    };
  }
  const e = env.trim();
  return {
    apiUrl: `https://api.${e}.stepsecurity.io/v1`,
    telemetryUrl: `https://telemetry.${e}.stepsecurity.io/v1`,
    webUrl: `https://${e}.stepsecurity.io`,
  };
}
