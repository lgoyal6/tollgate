import type { Overview } from "./types";

export class AdminAPI {
  constructor(
    private readonly mount: string,
    private readonly token: string,
    private readonly transport: typeof fetch = fetch,
  ) {}

  async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const response = await this.transport(`${this.mount}/api${path}`, {
      method,
      headers: {
        Authorization: `Bearer ${this.token}`,
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await response.text();
    let payload: unknown = null;
    try {
      payload = text ? JSON.parse(text) : null;
    } catch {
      payload = { error: text };
    }
    if (!response.ok) {
      const message = typeof payload === "object" && payload !== null && "error" in payload
        ? String(payload.error)
        : `${response.status} ${response.statusText}`;
      throw new Error(message);
    }
    return payload as T;
  }

  overview(): Promise<Overview> {
    return this.request("GET", "/overview");
  }
}
