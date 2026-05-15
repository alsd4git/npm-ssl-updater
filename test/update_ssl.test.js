const test = require("node:test");
const assert = require("node:assert/strict");

const {
  buildAdvancedConfigUpdatePayload,
  buildProxyHostPayload,
  buildUpdatePayload,
  diffSecurityState,
  getDesiredSecurityState,
  findBestCertificate,
  findProxyHostByDomain,
  normalizeHostUrl,
  describeCertificate,
  parsePositiveInteger,
  resolveOptions,
  sanitizeLocation,
  shouldSkipBlockExploits,
  validateAdvancedConfigSelection,
  validateProxyHostSelection,
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
  assert.equal("advanced_config" in payload, false);
  assert.deepEqual(payload.locations[0], sanitizeLocation(host.locations[0]));
});

test("buildAdvancedConfigUpdatePayload emits a minimal snippet-only payload", () => {
  assert.deepEqual(buildAdvancedConfigUpdatePayload("proxy_set_header X-Real-IP $remote_addr;\r\n"), {
    advanced_config: "proxy_set_header X-Real-IP $remote_addr;",
  });
  assert.deepEqual(buildAdvancedConfigUpdatePayload(null), {
    advanced_config: "",
  });
});

test("findBestCertificate prefers exact matches over wildcard matches and newer expiry on ties", () => {
  const certificates = [
    {
      id: 10,
      domain_names: ["*.example.com"],
      expires_on: "2026-06-01 00:00:00",
      nice_name: "wildcard",
    },
    {
      id: 11,
      domain_names: ["forgejo.example.com"],
      expires_on: "2026-05-01 00:00:00",
      nice_name: "exact",
    },
    {
      id: 12,
      domain_names: ["forgejo.example.com"],
      expires_on: "2027-05-01 00:00:00",
      nice_name: "exact newer",
    },
  ];

  assert.equal(findBestCertificate(certificates, ["forgejo.example.com"])?.id, 12);
  assert.equal(findBestCertificate(certificates, ["other.example.com"])?.id, 10);
  assert.equal(findBestCertificate(certificates, ["missing.example.net"]), null);
});

test("describeCertificate and findProxyHostByDomain summarize NPM objects", () => {
  assert.match(
    describeCertificate({
      id: 16,
      domain_names: ["keepingyousafe.myaddr.tools"],
      expires_on: "2026-08-07 15:29:36",
    }),
    /keepingyousafe\.myaddr\.tools.*id 16/,
  );

  const hosts = [
    { id: 1, domain_names: ["example.com"] },
    { id: 2, domain_names: ["FORGEJO.EXAMPLE.COM"] },
  ];

  assert.equal(findProxyHostByDomain(hosts, "forgejo.example.com")?.id, 2);
  assert.equal(findProxyHostByDomain(hosts, "missing.example.com"), null);
});

test("buildProxyHostPayload sets hardened defaults and preserves existing host metadata", () => {
  const payload = buildProxyHostPayload({
    domainName: "forgejo.example.com",
    forwardScheme: "http",
    forwardHost: "forgejo",
    forwardPort: 3000,
    certificateId: 10,
    existingHost: createHost({
      access_list_id: 12,
      enabled: false,
      meta: { keep: true },
      locations: [{ id: 1, path: "/", forward_scheme: "http", forward_host: "forgejo", forward_port: 3000 }],
    }),
  });

  assert.deepEqual(payload.domain_names, ["forgejo.example.com"]);
  assert.equal(payload.forward_host, "forgejo");
  assert.equal(payload.forward_port, 3000);
  assert.equal(payload.certificate_id, 10);
  assert.equal(payload.ssl_forced, true);
  assert.equal(payload.hsts_enabled, true);
  assert.equal(payload.hsts_subdomains, true);
  assert.equal(payload.block_exploits, true);
  assert.equal(payload.caching_enabled, false);
  assert.equal(payload.allow_websocket_upgrade, true);
  assert.equal(payload.enabled, true);
  assert.equal(payload.access_list_id, 0);
  assert.deepEqual(payload.meta, { keep: true });
  assert.deepEqual(payload.locations[0], {
    id: 1,
    path: "/",
    forward_scheme: "http",
    forward_host: "forgejo",
    forward_port: 3000,
    forward_path: "",
    advanced_config: "",
  });
});

test("validateAdvancedConfigSelection requires the host id and file path together", () => {
  assert.doesNotThrow(() =>
    validateAdvancedConfigSelection({
      advancedConfigHostId: 36,
      advancedConfigFile: "./media/NPM-extraconf.conf",
    }),
  );
  assert.throws(
    () =>
      validateAdvancedConfigSelection({
        advancedConfigHostId: 36,
      }),
    /must be provided together/,
  );
  assert.throws(
    () =>
      validateAdvancedConfigSelection({
        advancedConfigFile: "./media/NPM-extraconf.conf",
      }),
    /must be provided together/,
  );
});

test("validateProxyHostSelection requires the proxy domain when proxy mode is enabled", () => {
  assert.doesNotThrow(() => validateProxyHostSelection({ upsertProxyHost: false }));
  assert.doesNotThrow(() => validateProxyHostSelection({ upsertProxyHost: true, proxyDomain: "forgejo.example.com" }));
  assert.throws(() => validateProxyHostSelection({ upsertProxyHost: true }), /proxy-domain/);
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
