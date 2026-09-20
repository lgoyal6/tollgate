export type Algorithm = "sliding_window" | "token_bucket";

export interface Tenant {
  id: string;
  name: string;
  enabled: boolean;
  algorithm: Algorithm;
  rate: number;
  burst: number;
  window_ms: number;
  limit: number;
  active_keys: number;
  routes: number;
}

export interface Route {
  id: number;
  tenant_id: string;
  path_prefix: string;
  upstream: string;
  credential_set: boolean;
  credential_from: string;
}

export interface APIKey {
  id: string;
  tenant_id: string;
  status: "active" | "grace" | "revoked";
  created_at: string;
}

export interface Usage {
  requests: number;
  limited: number;
}

export interface Overview {
  tenants: Tenant[];
  routes: Route[];
  keys: APIKey[];
  usage: Record<string, Usage>;
}

export interface IssuedKey {
  key_id: string;
  key: string;
  tenant: string;
  note: string;
}
