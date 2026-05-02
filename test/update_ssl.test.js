const test = require("node:test");
const assert = require("node:assert/strict");

const {
  buildUpdatePayload,
  diffSecurityState,
  getDesiredSecurityState,
  normalizeHostUrl,
  parsePositiveInteger,
  resolveOptions,
  sanitizeLocation,
  shouldSkipBlockExploits,
} = require("../update_ssl");

function createHost(overrides = {}) {
  return {
    id: 7,
    domain_names: ["example.com", "Admin.EXAMPLE.com"],
    forward_scheme: "http",
    forward_host: "127.0.0.1",
    forward_port: 8080,
    certificate_id: 3,
    ssl_forced: false,
    hsts_enabled: false,
    hsts_subdomains: false,
    trust_forwarded_proto: true,
    http2_support: false,
    block_exploits: false,
    caching_enabled: false,
    allow_websocket_upgrade: false,
    access_list_id: null,
    advanced_config: "",
    enabled: true,
    meta: {
      letsencrypt_agree: false,
      nginx_online: true,
    },
    locations: [
      {
        id: 99,
        path: "/app",
        forward_scheme: "http",
        forward_host: "service",
        forward_port: 3000,
      },
    ],
    owner: {
      id: 1,
    },
    ...overrides,
  };
}

test("normalizeHostUrl strips trailing paths and validates protocol", () => {
  assert.equal(normalizeHostUrl("https://npm.internal:81/admin/"), "https://npm.internal:81");
  assert.throws(() => normalizeHostUrl("ftp://npm.internal"), /http or https/);
});

test("resolveOptions merges environment credentials and validates them", () => {
  const options = resolveOptions(
    {
      cacheAssets: false,
      hstsSubdomains: false,
      requestTimeout: 15000,
    },
    {
      NPM_HOST: "http://localhost:81/",
      NPM_EMAIL: "admin@example.com",
      NPM_PASSWORD: "secret",
    },
  );

  assert.equal(options.host, "http://localhost:81");
  assert.equal(options.email, "admin@example.com");
  assert.equal(options.password, "secret");
});

test("shouldSkipBlockExploits checks every domain name case-insensitively", () => {
  assert.equal(shouldSkipBlockExploits(["safe.example.com", "Tinyauth.example.com"]), true);
  assert.equal(shouldSkipBlockExploits(["safe.example.com", "Pocket-ID.example.com"]), false);
  assert.equal(shouldSkipBlockExploits(["safe.example.com"]), false);
});

test("getDesiredSecurityState preserves optional flags unless explicitly requested", () => {
  const host = createHost({
    block_exploits: true,
    caching_enabled: true,
    allow_websocket_upgrade: true,
  });
  const desired = getDesiredSecurityState(host, {
    hstsSubdomains: false,
    blockExploits: false,
    cacheAssets: false,
    enableWebsockets: false,
  });

  assert.deepEqual(desired, {
    ssl_forced: true,
    http2_support: true,
    hsts_enabled: true,
    hsts_subdomains: false,
    block_exploits: true,
    caching_enabled: true,
    allow_websocket_upgrade: true,
  });
});

test("buildUpdatePayload preserves supported host fields and sanitizes locations", () => {
  const host = createHost();
  const payload = buildUpdatePayload(host, {
    ssl_forced: true,
    http2_support: true,
    hsts_enabled: true,
    hsts_subdomains: true,
    block_exploits: true,
    caching_enabled: false,
    allow_websocket_upgrade: false,
  });

  assert.equal(payload.access_list_id, 0);
  assert.equal(payload.certificate_id, 3);
  assert.equal(payload.trust_forwarded_proto, true);
  assert.deepEqual(payload.meta, host.meta);
  assert.equal("owner" in payload, false);
  assert.deepEqual(payload.locations[0], sanitizeLocation(host.locations[0]));
});

test("diffSecurityState reports only changed security fields", () => {
  const changes = diffSecurityState(
    {
      ssl_forced: false,
      http2_support: false,
      hsts_enabled: true,
      hsts_subdomains: false,
      block_exploits: false,
      caching_enabled: false,
      allow_websocket_upgrade: false,
    },
    {
      ssl_forced: true,
      http2_support: true,
      hsts_enabled: true,
      hsts_subdomains: false,
      block_exploits: false,
      caching_enabled: true,
      allow_websocket_upgrade: false,
    },
  );

  assert.deepEqual(changes, [
    { field: "ssl_forced", before: false, after: true },
    { field: "http2_support", before: false, after: true },
    { field: "caching_enabled", before: false, after: true },
  ]);
});

test("parsePositiveInteger accepts positive integers only", () => {
  assert.equal(parsePositiveInteger("15000", "--request-timeout"), 15000);
  assert.throws(() => parsePositiveInteger("0", "--request-timeout"), /positive integer/);
});
