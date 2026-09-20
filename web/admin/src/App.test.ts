import { flushPromises, mount } from "@vue/test-utils";
import App from "./App.vue";
import type { Overview } from "./types";

const overview: Overview = {
  tenants: [{
    id: "alice", name: "Alice", enabled: true, algorithm: "sliding_window",
    rate: 1, burst: 100, window_ms: 60_000, limit: 100, active_keys: 1, routes: 1,
  }],
  routes: [{
    id: 7, tenant_id: "alice", path_prefix: "/anthropic/", upstream: "https://api.anthropic.com",
    credential_set: true, credential_from: "ANTHROPIC_API_KEY",
  }],
  keys: [{ id: "key-1", tenant_id: "alice", status: "active", created_at: "2026-09-19T00:00:00Z" }],
  usage: { alice: { requests: 12, limited: 3 } },
};

function reply(body: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  }));
}

async function unlocked(fetchMock: ReturnType<typeof vi.fn>) {
  vi.stubGlobal("fetch", fetchMock);
  const wrapper = mount(App, { props: { mountPath: "/_admin" } });
  await wrapper.get("#token").setValue("admin-secret");
  await wrapper.get("form").trigger("submit");
  await flushPromises();
  return wrapper;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("operator workflow", () => {
  it("unlocks against the real overview endpoint and forgets the token on lock", async () => {
    const fetchMock = vi.fn((_input: RequestInfo | URL, _init?: RequestInit) => reply(overview));
    const wrapper = await unlocked(fetchMock);

    expect(wrapper.find("#console-app").exists()).toBe(true);
    expect(wrapper.text()).toContain("Alice");
    expect(fetchMock).toHaveBeenCalledWith("/_admin/api/overview", expect.objectContaining({
      headers: expect.objectContaining({ Authorization: "Bearer admin-secret" }),
    }));
    expect(localStorage.length).toBe(0);

    await wrapper.get("#hdr-actions button:last-child").trigger("click");
    expect(wrapper.find("#gate-screen").exists()).toBe(true);
    expect(wrapper.find("#console-app").exists()).toBe(false);
  });

  it("creates a tenant through the typed workflow and refreshes the overview", async () => {
    const fetchMock = vi.fn((_input: RequestInfo | URL, _init?: RequestInit) => reply(overview))
      .mockImplementationOnce((_input: RequestInfo | URL, _init?: RequestInit) => reply(overview))
      .mockImplementationOnce((_input: RequestInfo | URL, _init?: RequestInit) => reply({ status: "created" }, 201))
      .mockImplementationOnce((_input: RequestInfo | URL, _init?: RequestInit) => reply(overview));
    const wrapper = await unlocked(fetchMock);

    await wrapper.get("#t-id").setValue("bob");
    await wrapper.get("#t-name").setValue("Bob");
    await wrapper.get("#t-id").element.closest("form")!.dispatchEvent(new Event("submit"));
    await flushPromises();

    const request = fetchMock.mock.calls[1]?.[1];
    expect(request?.body).toBeTypeOf("string");
    expect(fetchMock.mock.calls[1][0]).toBe("/_admin/api/tenants");
    expect(JSON.parse(String(request!.body))).toMatchObject({
      id: "bob", name: "Bob", algorithm: "sliding_window", limit: 100, window_ms: 60_000,
    });
  });

  it("requires confirmation before cutting off an enabled tenant", async () => {
    const fetchMock = vi.fn((_input: RequestInfo | URL, _init?: RequestInit) => reply(overview));
    const wrapper = await unlocked(fetchMock);
    vi.stubGlobal("confirm", vi.fn(() => false));

    const cutOff = wrapper.findAll("button").find((button) => button.text() === "Cut off");
    await cutOff!.trigger("click");
    await flushPromises();

    expect(confirm).toHaveBeenCalledWith(expect.stringContaining("Every key and route"));
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("does not rotate, revoke, or delete when the operator cancels", async () => {
    const fetchMock = vi.fn((_input: RequestInfo | URL, _init?: RequestInit) => reply(overview));
    const wrapper = await unlocked(fetchMock);
    vi.stubGlobal("confirm", vi.fn(() => false));

    for (const label of ["Rotate", "Revoke", "Delete"]) {
      const action = wrapper.findAll("button").find((button) => button.text() === label);
      await action!.trigger("click");
    }
    await flushPromises();

    expect(confirm).toHaveBeenCalledTimes(3);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("shows issued key material once and lets the operator clear it", async () => {
    const fetchMock = vi.fn((_input: RequestInfo | URL, _init?: RequestInit) => reply(overview))
      .mockImplementationOnce((_input: RequestInfo | URL, _init?: RequestInit) => reply(overview))
      .mockImplementationOnce((_input: RequestInfo | URL, _init?: RequestInit) => reply({ key_id: "key-2", key: "tg_key-2_secret", tenant: "alice", note: "shown once" }, 201))
      .mockImplementationOnce((_input: RequestInfo | URL, _init?: RequestInit) => reply(overview));
    vi.stubGlobal("scrollTo", vi.fn());
    const wrapper = await unlocked(fetchMock);

    const issue = wrapper.findAll("button").find((button) => button.text() === "Issue key");
    await issue!.trigger("click");
    await flushPromises();
    expect(wrapper.text()).toContain("tg_key-2_secret");

    const clear = wrapper.findAll("button").find((button) => button.text() === "I copied it");
    await clear!.trigger("click");
    expect(wrapper.text()).not.toContain("tg_key-2_secret");
  });
});
