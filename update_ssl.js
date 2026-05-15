#!/usr/bin/env node
require("dotenv").config({ quiet: true });

const { readFile } = require("node:fs/promises");
const { createInterface } = require("node:readline/promises");
const { stdin, stdout, stderr, exit, argv, env } = require("node:process");
const { URL } = require("node:url");
const { program } = require("commander");
const packageJson = require("./package.json");

const DEFAULT_TIMEOUT_MS = 15000;
const SECURITY_FIELDS = [
  "ssl_forced",
  "http2_support",
  "hsts_enabled",
  "hsts_subdomains",
  "block_exploits",
  "caching_enabled",
  "allow_websocket_upgrade",
];
const UPDATABLE_PROXY_HOST_FIELDS = [
  "domain_names",
  "forward_scheme",
  "forward_host",
  "forward_port",
  "certificate_id",
  "ssl_forced",
  "hsts_enabled",
  "hsts_subdomains",
  "trust_forwarded_proto",
  "http2_support",
  "block_exploits",
  "caching_enabled",
  "allow_websocket_upgrade",
  "access_list_id",
  "enabled",
  "meta",
  "locations",
];
const BLOCK_EXPLOITS_EXCEPTIONS = [
  "tinyauth",
];

program
  .name("npm-ssl-updater")
  .description("Harden Nginx Proxy Manager proxy hosts with Force SSL, HTTP/2, HSTS, and related options")
  .version(packageJson.version)
  .option("-H, --host <url>", "NPM address (e.g., http://localhost:81)")
  .option("-e, --email <email>", "NPM admin email")
  .option("-p, --password <password>", "NPM admin password")
  .option("--hsts-subdomains, --hsd", "Enable HSTS for subdomains as well", false)
  .option("--cache-assets, --ca", "Enable static asset caching")
  .option("--block-exploits, --bce", "Block common exploits")
  .option("--enable-websockets, --ws", "Enable WebSocket support")
  .option("-y, --yes", "Apply all pending changes without interactive confirmation", false)
  .option("--dry-run", "Show what would change without applying modifications", false)
  .option("--print-advanced", "Show the advanced_config section for each host", false)
  .option("--advanced-config-host-id <id>", "Update advanced_config for a single host ID", (value) =>
    parsePositiveInteger(value, "--advanced-config-host-id"))
  .option("--advanced-config-file <path>", "Path to a file containing the advanced_config snippet")
  .option("--advanced-config-dry-run", "Preview the advanced_config update without applying it", false)
  .option("--list-certificates", "Show a list of configured SSL certificates", false)
  .option("--upsert-proxy-host", "Create or update a proxy host with a matching certificate", false)
  .option("--proxy-domain <domain>", "Public proxy host domain, for example app.example.com")
  .option("--proxy-forward-host <host>", "Proxy upstream host", "app")
  .option(
    "--proxy-forward-port <port>",
    "Proxy upstream port",
    (value) => parsePositiveInteger(value, "--proxy-forward-port"),
    3000,
  )
  .option("--proxy-forward-scheme <scheme>", "Proxy upstream scheme", "http")
  .option(
    "--proxy-certificate-id <id>",
    "Use a specific certificate ID for the proxy host",
    (value) => parsePositiveInteger(value, "--proxy-certificate-id"),
  )
  .option(
    "--proxy-certificate-domain <domain>",
    "Certificate domain hint for the proxy host, defaults to the proxy domain",
  )
  .option("--proxy-advanced-config-file <path>", "Path to a proxy host advanced_config snippet")
  .option("--proxy-dry-run", "Preview the proxy host update without applying it", false)
  .option("-l, --list-domains", "Show a list of configured domains and their targets", false)
  .option(
    "--request-timeout <ms>",
    "HTTP timeout in milliseconds",
    (value) => parsePositiveInteger(value, "--request-timeout"),
    DEFAULT_TIMEOUT_MS,
  )
  .parse(argv);

function parsePositiveInteger(value, optionName) {
  const parsed = Number.parseInt(value, 10);

  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`${optionName} must be a positive integer.`);
  }

  return parsed;
}

function normalizeHostUrl(input) {
  let parsedUrl;

  try {
    parsedUrl = new URL(input);
  } catch {
    throw new Error("Host must be a valid absolute URL, for example http://localhost:81.");
  }

  if (!["http:", "https:"].includes(parsedUrl.protocol)) {
    throw new Error("Host must use the http or https protocol.");
  }

  parsedUrl.pathname = "";
  parsedUrl.search = "";
  parsedUrl.hash = "";

  return parsedUrl.toString().replace(/\/$/, "");
}

function validateEmail(email) {
  if (!email || !email.includes("@")) {
    throw new Error("Email must be a valid Nginx Proxy Manager admin email address.");
  }

  return email.trim();
}

function validatePassword(password) {
  if (!password || password.trim().length === 0) {
    throw new Error("Password cannot be empty.");
  }

  return password;
}

function warnOnCredentialMismatch(options, environment) {
  if (options.host && environment.NPM_HOST && options.host !== environment.NPM_HOST) {
    console.warn("Warning: --host differs from NPM_HOST in the environment.");
  }

  if (options.email && environment.NPM_EMAIL && options.email !== environment.NPM_EMAIL) {
    console.warn("Warning: --email differs from NPM_EMAIL in the environment.");
  }

  if (options.password && environment.NPM_PASSWORD && options.password !== environment.NPM_PASSWORD) {
    console.warn("Warning: --password differs from NPM_PASSWORD in the environment.");
  }
}

function resolveOptions(rawOptions, environment) {
  warnOnCredentialMismatch(rawOptions, environment);

  const merged = {
    ...rawOptions,
    host: rawOptions.host || environment.NPM_HOST,
    email: rawOptions.email || environment.NPM_EMAIL,
    password: rawOptions.password || environment.NPM_PASSWORD,
  };

  if (!merged.host || !merged.email || !merged.password) {
    throw new Error("Host, email, and password are required. Provide them via CLI flags or environment variables.");
  }

  return {
    ...merged,
    host: normalizeHostUrl(merged.host),
    email: validateEmail(merged.email),
    password: validatePassword(merged.password),
  };
}

function normalizeDomain(domain) {
  return String(domain || "").trim().toLowerCase();
}

function shouldSkipBlockExploits(domainNames) {
  return domainNames.some((domain) =>
    BLOCK_EXPLOITS_EXCEPTIONS.some((exception) => normalizeDomain(domain).includes(exception)),
  );
}

function toBoolean(value) {
  return value === true;
}

function pick(object, keys) {
  return keys.reduce((result, key) => {
    if (Object.prototype.hasOwnProperty.call(object, key)) {
      result[key] = object[key];
    }

    return result;
  }, {});
}

function sanitizeLocation(location) {
  return {
    id: location.id ?? null,
    path: location.path,
    forward_scheme: location.forward_scheme,
    forward_host: location.forward_host,
    forward_port: location.forward_port,
    forward_path: location.forward_path || "",
    advanced_config: location.advanced_config || "",
  };
}

function normalizeCertificateDomain(domain) {
  return normalizeDomain(domain);
}

function normalizeAdvancedConfigSnippet(advancedConfig) {
  return String(advancedConfig ?? "").replace(/\r\n?/g, "\n").replace(/\n+$/, "");
}

function buildAdvancedConfigUpdatePayload(advancedConfig) {
  return {
    advanced_config: normalizeAdvancedConfigSnippet(advancedConfig),
  };
}

function buildUpdatePayload(host, updatedFields) {
  const basePayload = pick(host, UPDATABLE_PROXY_HOST_FIELDS);

  return {
    ...basePayload,
    ...updatedFields,
    access_list_id: host.access_list_id ?? 0,
    certificate_id: host.certificate_id ?? 0,
    enabled: host.enabled ?? true,
    trust_forwarded_proto: toBoolean(host.trust_forwarded_proto),
    meta: host.meta && typeof host.meta === "object" ? { ...host.meta } : {},
    locations: Array.isArray(host.locations) ? host.locations.map(sanitizeLocation) : [],
  };
}

function getDesiredSecurityState(host, options) {
  const blockExploitsEnabled = options.blockExploits === true && !shouldSkipBlockExploits(host.domain_names);

  return {
    ssl_forced: true,
    http2_support: true,
    hsts_enabled: true,
    hsts_subdomains: options.hstsSubdomains === true,
    block_exploits: blockExploitsEnabled ? true : toBoolean(host.block_exploits),
    caching_enabled: options.cacheAssets === true ? true : toBoolean(host.caching_enabled),
    allow_websocket_upgrade: options.enableWebsockets === true ? true : toBoolean(host.allow_websocket_upgrade),
  };
}

function diffSecurityState(before, after) {
  return SECURITY_FIELDS.filter((field) => toBoolean(before[field]) !== toBoolean(after[field])).map((field) => ({
    field,
    before: toBoolean(before[field]),
    after: toBoolean(after[field]),
  }));
}

function printDiff(changes) {
  const emoji = (value) => (value ? "yes" : "no");

  for (const change of changes) {
    console.log(` - ${change.field.padEnd(24)} ${emoji(change.before)} -> ${emoji(change.after)}`);
  }
}

function listDomains(proxyHosts) {
  console.log("Configured domains:");
  console.log("--------------------------------------------------");

  for (const host of proxyHosts) {
    const domains = host.domain_names.join(", ");
    const forward = `${host.forward_scheme}://${host.forward_host}:${host.forward_port}`;
    console.log(` - ${domains} -> ${forward}`);
  }

  console.log("--------------------------------------------------");
}

function buildTokenRequestBody(options) {
  return {
    identity: options.email,
    secret: options.password,
  };
}

async function requestJson(url, init, timeoutMs) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      ...init,
      signal: controller.signal,
      headers: {
        Accept: "application/json",
        ...(init.headers || {}),
      },
    });

    const responseText = await response.text();
    const responseBody = responseText ? safeJsonParse(responseText) : null;

    if (!response.ok) {
      const detail =
        responseBody && typeof responseBody === "object"
          ? JSON.stringify(responseBody)
          : responseText || response.statusText;
      throw new Error(`HTTP ${response.status} ${response.statusText}: ${detail}`);
    }

    return responseBody;
  } catch (error) {
    if (error.name === "AbortError") {
      throw new Error(`Request timed out after ${timeoutMs}ms.`);
    }

    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}

function safeJsonParse(value) {
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}

async function login(options) {
  const response = await requestJson(
    `${options.host}/api/tokens`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(buildTokenRequestBody(options)),
    },
    options.requestTimeout,
  );

  if (!response || typeof response.token !== "string" || response.token.length === 0) {
    throw new Error("Authentication succeeded but no bearer token was returned.");
  }

  return response.token;
}

async function fetchProxyHosts(options, token) {
  const response = await requestJson(
    `${options.host}/api/nginx/proxy-hosts`,
    {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`,
      },
    },
    options.requestTimeout,
  );

  if (!Array.isArray(response)) {
    throw new Error("Unexpected API response: proxy host list is not an array.");
  }

  return response;
}

async function fetchCertificates(options, token) {
  const response = await requestJson(
    `${options.host}/api/nginx/certificates`,
    {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`,
      },
    },
    options.requestTimeout,
  );

  if (!Array.isArray(response)) {
    throw new Error("Unexpected API response: certificate list is not an array.");
  }

  return response;
}

async function updateProxyHost(options, token, hostId, payload) {
  return requestJson(
    `${options.host}/api/nginx/proxy-hosts/${hostId}`,
    {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    },
    options.requestTimeout,
  );
}

async function createProxyHost(options, token, payload) {
  return requestJson(
    `${options.host}/api/nginx/proxy-hosts`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    },
    options.requestTimeout,
  );
}

async function readAdvancedConfigFile(filePath) {
  if (typeof filePath !== "string" || filePath.trim().length === 0) {
    throw new Error("Advanced config file path cannot be empty.");
  }

  return readFile(filePath, "utf8");
}

function validateAdvancedConfigSelection(rawOptions) {
  const hasHostId = rawOptions.advancedConfigHostId !== undefined;
  const hasFile = rawOptions.advancedConfigFile !== undefined;

  if (hasHostId !== hasFile) {
    throw new Error("Both --advanced-config-host-id and --advanced-config-file must be provided together.");
  }
}

function validateProxyHostSelection(rawOptions) {
  if (!rawOptions.upsertProxyHost) {
    return;
  }

  if (!rawOptions.proxyDomain) {
    throw new Error("--proxy-domain must be provided when using --upsert-proxy-host.");
  }

  if (rawOptions.proxyAdvancedConfigFile && !rawOptions.proxyAdvancedConfigFile.trim()) {
    throw new Error("--proxy-advanced-config-file cannot be empty.");
  }
}

function findProxyHostById(proxyHosts, hostId) {
  return proxyHosts.find((host) => host && host.id === hostId) || null;
}

async function updateAdvancedConfig(options, token, hostId, advancedConfig) {
  return requestJson(
    `${options.host}/api/nginx/proxy-hosts/${hostId}`,
    {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(buildAdvancedConfigUpdatePayload(advancedConfig)),
    },
    options.requestTimeout,
  );
}

function findProxyHostByDomain(proxyHosts, domainName) {
  const normalizedTarget = normalizeDomain(domainName);

  return (
    proxyHosts.find((host) =>
      Array.isArray(host?.domain_names) &&
      host.domain_names.some((domain) => normalizeDomain(domain) === normalizedTarget),
    ) || null
  );
}

function parseCertificateExpiresOn(value) {
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? 0 : parsed;
}

function certificateDomainMatchScore(certificateDomain, targetDomain) {
  const normalizedCertificateDomain = normalizeCertificateDomain(certificateDomain);
  const normalizedTargetDomain = normalizeDomain(targetDomain);

  if (!normalizedCertificateDomain || !normalizedTargetDomain) {
    return 0;
  }

  if (normalizedCertificateDomain === normalizedTargetDomain) {
    return 3;
  }

  if (!normalizedCertificateDomain.startsWith("*.")) {
    return 0;
  }

  const wildcardSuffix = normalizedCertificateDomain.slice(2);
  if (!wildcardSuffix || !normalizedTargetDomain.endsWith(`.${wildcardSuffix}`)) {
    return 0;
  }

  const targetLabels = normalizedTargetDomain.split(".").length;
  const suffixLabels = wildcardSuffix.split(".").length;

  return targetLabels === suffixLabels + 1 ? 2 : 0;
}

function findBestCertificate(certificates, candidateDomains) {
  let bestCertificate = null;
  let bestScore = 0;
  let bestExpiresOn = 0;

  for (const certificate of certificates) {
    const certificateDomains = Array.isArray(certificate?.domain_names) ? certificate.domain_names : [];
    let certificateScore = 0;

    for (const candidateDomain of candidateDomains) {
      for (const certificateDomain of certificateDomains) {
        certificateScore = Math.max(certificateScore, certificateDomainMatchScore(certificateDomain, candidateDomain));
      }
    }

    if (certificateScore === 0) {
      continue;
    }

    const expiresOn = parseCertificateExpiresOn(certificate.expires_on);
    if (
      certificateScore > bestScore ||
      (certificateScore === bestScore && expiresOn > bestExpiresOn) ||
      (certificateScore === bestScore && expiresOn === bestExpiresOn && (certificate.id ?? 0) < (bestCertificate?.id ?? Number.MAX_SAFE_INTEGER))
    ) {
      bestCertificate = certificate;
      bestScore = certificateScore;
      bestExpiresOn = expiresOn;
    }
  }

  return bestCertificate;
}

function describeCertificate(certificate) {
  const domains = Array.isArray(certificate?.domain_names) && certificate.domain_names.length > 0
    ? certificate.domain_names.join(", ")
    : certificate?.nice_name || `certificate ${certificate?.id ?? "unknown"}`;

  const expiresOn = certificate?.expires_on ? `expires ${certificate.expires_on}` : "no expiry date";

  return `${domains} [id ${certificate?.id ?? "?"}, ${expiresOn}]`;
}

function listCertificates(certificates) {
  console.log("Configured certificates:");
  console.log("--------------------------------------------------");

  for (const certificate of certificates) {
    console.log(` - ${describeCertificate(certificate)}`);
  }

  console.log("--------------------------------------------------");
}

function buildProxyHostPayload({
  domainName,
  forwardScheme,
  forwardHost,
  forwardPort,
  certificateId,
  existingHost,
}) {
  const baseHost = existingHost || {
    access_list_id: 0,
    enabled: true,
    meta: {},
    locations: [],
    trust_forwarded_proto: true,
  };

  const payload = buildUpdatePayload(baseHost, {
    domain_names: [domainName],
    forward_scheme: forwardScheme,
    forward_host: forwardHost,
    forward_port: forwardPort,
    certificate_id: certificateId ?? 0,
    ssl_forced: true,
    hsts_enabled: true,
    hsts_subdomains: true,
    trust_forwarded_proto: true,
    http2_support: true,
    block_exploits: true,
    caching_enabled: false,
    allow_websocket_upgrade: true,
    access_list_id: 0,
    enabled: true,
  });

  return {
    ...payload,
    certificate_id: certificateId ?? 0,
    access_list_id: 0,
    enabled: true,
  };
}

function parseCertificateSelection(rawOptions) {
  if (rawOptions.proxyCertificateId !== undefined) {
    return {
      certificateId: rawOptions.proxyCertificateId,
      certificateDomain: null,
    };
  }

  return {
    certificateId: null,
    certificateDomain: rawOptions.proxyCertificateDomain || rawOptions.proxyDomain || null,
  };
}

async function resolveProxyHostCertificate(options, token, rawOptions) {
  const { certificateId, certificateDomain } = parseCertificateSelection(rawOptions);

  if (certificateId !== null) {
    const certificates = await fetchCertificates(options, token);
    const selectedCertificate = certificates.find((certificate) => certificate.id === certificateId);

    if (!selectedCertificate) {
      throw new Error(`Certificate ${certificateId} not found.`);
    }

    return selectedCertificate;
  }

  const certificates = await fetchCertificates(options, token);
  const candidateDomains = [certificateDomain, rawOptions.proxyDomain].filter(Boolean);
  const selectedCertificate = findBestCertificate(certificates, candidateDomains);

  if (!selectedCertificate) {
    console.warn(
      `Warning: no matching certificate found for ${candidateDomains.join(", ")}. The proxy host will be created without a certificate unless you pass --proxy-certificate-id.`,
    );
  }

  return selectedCertificate;
}

async function runProxyHostUpsert(rawOptions = program.opts(), environment = env) {
  const options = resolveOptions(rawOptions, environment);
  const proxyDomain = normalizeDomain(rawOptions.proxyDomain);
  const forwardHost = String(rawOptions.proxyForwardHost || "").trim();
  const forwardPort = parsePositiveInteger(rawOptions.proxyForwardPort, "--proxy-forward-port");
  const forwardScheme = String(rawOptions.proxyForwardScheme || "http").trim().toLowerCase();

  if (!proxyDomain) {
    throw new Error("--proxy-domain is required.");
  }

  if (!forwardHost) {
    throw new Error("--proxy-forward-host is required.");
  }

  if (!["http", "https"].includes(forwardScheme)) {
    throw new Error("--proxy-forward-scheme must be http or https.");
  }

  const token = await login(options);
  const proxyHosts = await fetchProxyHosts(options, token);
  const existingHost = findProxyHostByDomain(proxyHosts, proxyDomain);
  const selectedCertificate = await resolveProxyHostCertificate(options, token, rawOptions);
  const certificateId = selectedCertificate?.id ?? 0;
  const payload = buildProxyHostPayload({
    domainName: proxyDomain,
    forwardScheme,
    forwardHost,
    forwardPort,
    certificateId,
    existingHost,
  });

  const advancedConfig = rawOptions.proxyAdvancedConfigFile
    ? normalizeAdvancedConfigSnippet(await readAdvancedConfigFile(rawOptions.proxyAdvancedConfigFile))
    : null;

  const displayName = existingHost ? existingHost.domain_names.join(", ") : proxyDomain;

  console.log(`\nProxy host: ${displayName}`);
  console.log("--------------------------------------------------");
  console.log(`Domain       : ${proxyDomain}`);
  console.log(`Forward      : ${forwardScheme}://${forwardHost}:${forwardPort}`);
  console.log(`Certificate  : ${selectedCertificate ? describeCertificate(selectedCertificate) : "<none>"}`);
  console.log(`Create mode  : ${existingHost ? "update" : "create"}`);
  console.log("--------------------------------------------------");

  if (rawOptions.proxyDryRun) {
    console.log("   Dry-run mode: no changes applied.");
    return;
  }

  let hostId = existingHost?.id ?? null;

  if (hostId !== null) {
    await updateProxyHost(options, token, hostId, payload);
  } else {
    const created = await createProxyHost(options, token, payload);
    hostId = created?.id ?? null;

    if (hostId === null) {
      const refreshedHosts = await fetchProxyHosts(options, token);
      const refreshedHost = findProxyHostByDomain(refreshedHosts, proxyDomain);
      hostId = refreshedHost?.id ?? null;
    }
  }

  if (hostId === null) {
    throw new Error("Proxy host was created, but its ID could not be determined.");
  }

  if (advancedConfig !== null) {
    await updateAdvancedConfig(options, token, hostId, advancedConfig);
  }

  console.log("   Change applied.");
}

async function askForConfirmation() {
  if (!stdin.isTTY || !stdout.isTTY) {
    throw new Error("Interactive confirmation requires a TTY. Re-run with --yes or --dry-run.");
  }

  const readline = createInterface({ input: stdin, output: stdout });

  try {
    while (true) {
      const answer = (await readline.question("Apply changes? ([y]es / [n]o / [a]ll): ")).trim().toLowerCase();

      if (["y", "n", "a"].includes(answer)) {
        return answer;
      }

      console.log("Please answer with y, n, or a.");
    }
  } finally {
    readline.close();
  }
}

async function runAdvancedConfigUpdate(rawOptions = program.opts(), environment = env) {
  const options = resolveOptions(rawOptions, environment);
  const hostId = parsePositiveInteger(rawOptions.hostId, "--host-id");
  const advancedConfig = normalizeAdvancedConfigSnippet(await readAdvancedConfigFile(rawOptions.file));
  const token = await login(options);
  const proxyHosts = await fetchProxyHosts(options, token);
  const host = findProxyHostById(proxyHosts, hostId);

  if (!host) {
    throw new Error(`Proxy host ${hostId} not found.`);
  }

  const displayName = Array.isArray(host.domain_names) && host.domain_names.length > 0 ? host.domain_names.join(", ") : `host ${hostId}`;
  const currentAdvancedConfig = normalizeAdvancedConfigSnippet(host.advanced_config);

  if (currentAdvancedConfig === advancedConfig) {
    console.log(`Already compliant: ${displayName}`);
    return;
  }

  console.log(`\nAdvanced config: ${displayName}`);
  console.log("--------------------------------------------------");
  console.log(`Source file: ${rawOptions.file}`);
  console.log(`Current size: ${currentAdvancedConfig.length} chars`);
  console.log(`New size    : ${advancedConfig.length} chars`);
  console.log("--------------------------------------------------");

  if (rawOptions.dryRun) {
    console.log("   Dry-run mode: no changes applied.");
    return;
  }

  await updateAdvancedConfig(options, token, hostId, advancedConfig);
  console.log("   Change applied.");
}

async function run(rawOptions = program.opts(), environment = env) {
  if (argv.length <= 2 && !environment.NPM_HOST && !environment.NPM_EMAIL && !environment.NPM_PASSWORD) {
    program.help();
  }

  const options = resolveOptions(rawOptions, environment);

  validateAdvancedConfigSelection(options);
  validateProxyHostSelection(options);

  if (options.advancedConfigHostId !== undefined) {
    await runAdvancedConfigUpdate(
      {
        ...options,
        hostId: options.advancedConfigHostId,
        file: options.advancedConfigFile,
        dryRun: options.advancedConfigDryRun,
      },
      environment,
    );
    return;
  }

  if (options.listCertificates) {
    const token = await login(options);
    const certificates = await fetchCertificates(options, token);
    if (certificates.length === 0) {
      console.log("No certificates found.");
      return;
    }
    listCertificates(certificates);
    return;
  }

  if (options.upsertProxyHost) {
    await runProxyHostUpsert(options, environment);
    return;
  }

  const token = await login(options);
  const proxyHosts = await fetchProxyHosts(options, token);

  if (proxyHosts.length === 0) {
    console.log("No proxy hosts found.");
    return;
  }

  if (options.listDomains || argv.length <= 2) {
    listDomains(proxyHosts);
    return;
  }

  let applyToAll = options.yes === true;
  let changedHosts = 0;

  for (const host of proxyHosts) {
    if (!Array.isArray(host.domain_names) || host.domain_names.length === 0) {
      console.warn(`Skipping host ${host.id}: missing domain_names.`);
      continue;
    }

    const displayName = host.domain_names.join(", ");

    if (options.printAdvanced) {
      console.log(`\nAdvanced config for: ${displayName}`);
      console.log("--------------------------------------------------");
      console.log(host.advanced_config || "<empty>");
      console.log("--------------------------------------------------");
      continue;
    }

    const desiredState = getDesiredSecurityState(host, options);
    const changes = diffSecurityState(host, desiredState);

    if (changes.length === 0) {
      console.log(`Already compliant: ${displayName}`);
      continue;
    }

    console.log(`\nProxy: ${displayName}`);
    printDiff(changes);

    if (options.dryRun) {
      console.log("   Dry-run mode: no changes applied.");
      continue;
    }

    if (!applyToAll) {
      const answer = await askForConfirmation();

      if (answer === "n") {
        console.log("   Skipped.");
        continue;
      }

      if (answer === "a") {
        applyToAll = true;
      }
    }

    const payload = buildUpdatePayload(host, desiredState);

    try {
      await updateProxyHost(options, token, host.id, payload);
      changedHosts += 1;
      console.log("   Change applied.");
    } catch (error) {
      console.warn(`   Update failed: ${error.message}`);
    }
  }

  console.log(`\nCompleted. Updated ${changedHosts} host(s).`);
}

if (require.main === module) {
  run().catch((error) => {
    stderr.write(`Error: ${error.message}\n`);
    exit(1);
  });
}

module.exports = {
  BLOCK_EXPLOITS_EXCEPTIONS,
  DEFAULT_TIMEOUT_MS,
  SECURITY_FIELDS,
  UPDATABLE_PROXY_HOST_FIELDS,
  buildUpdatePayload,
  buildAdvancedConfigUpdatePayload,
  buildProxyHostPayload,
  diffSecurityState,
  describeCertificate,
  findProxyHostById,
  findProxyHostByDomain,
  findBestCertificate,
  getDesiredSecurityState,
  listDomains,
  listCertificates,
  normalizeHostUrl,
  normalizeCertificateDomain,
  parsePositiveInteger,
  requestJson,
  resolveOptions,
  run,
  runProxyHostUpsert,
  runAdvancedConfigUpdate,
  sanitizeLocation,
  shouldSkipBlockExploits,
  validateAdvancedConfigSelection,
  validateProxyHostSelection,
  updateAdvancedConfig,
};
