export interface Configuration {
  repo: string;
  run_id: string;
  correlation_id: string;
  working_directory: string;
  api_url: string;
  telemetry_url: string;
  allowed_endpoints: string;
  denied_endpoints: string;
  egress_policy: string;
  disable_telemetry: boolean;
  disable_sudo: boolean;
  disable_sudo_and_containers: boolean;
  disable_file_monitoring: boolean;
  is_github_hosted: boolean;
  private: string;
  is_debug: boolean;
  one_time_key: string;
  api_key: string;
  use_policy_store: boolean;
  deploy_on_self_hosted_vm: boolean;
  customer?: string;
  server_name?: string;
  is_ghes: boolean;
}

export interface PolicyResponse {
  owner?: string;
  policyName?: string;
  allowed_endpoints?: string[];
  denied_endpoints?: string[];
  disable_sudo?: boolean;
  disable_sudo_and_containers?: boolean;
  disable_file_monitoring?: boolean;
  disable_telemetry?: boolean;
  egress_policy?: string;
  policy_name?: string;
  // Only whether the policy enables secure-registry; its settings stay
  // server side and reach the job through the session API.
  secure_registry?: { enabled?: boolean };
}

// What the policy store returned for this job. policy is null when no policy
// with egress rules applies, exactly as before secure-registry existed, so
// the egress fallback does not change. secureRegistry is read on its own: a
// policy can enable secure-registry and set no egress rules.
export interface PolicyStoreResult {
  policy: PolicyResponse | null;
  secureRegistry: boolean;
  policyName: string;
}
