import { AdminAPI } from "./api";

describe("AdminAPI", () => {
  it("keeps the token in the authorization header and out of the URL", async () => {
    const transport = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
      new Response('{"tenants":[],"routes":[],"keys":[],"usage":{}}'));
    const api = new AdminAPI("/_admin", "secret-token", transport as typeof fetch);

    await api.overview();

    expect(transport).toHaveBeenCalledWith("/_admin/api/overview", expect.objectContaining({
      method: "GET",
      headers: expect.objectContaining({ Authorization: "Bearer secret-token" }),
    }));
    expect(transport.mock.calls[0][0]).not.toContain("secret-token");
  });

  it("surfaces the API error envelope without leaking response internals", async () => {
    const transport = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
      new Response('{"error":"invalid route"}', { status: 400 }));
    const api = new AdminAPI("/_admin", "token", transport as typeof fetch);

    await expect(api.request("POST", "/tenants", {})).rejects.toThrow("invalid route");
  });
});
