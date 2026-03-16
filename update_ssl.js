#!/usr/bin/env node
require("dotenv").config({ quiet: true });

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
  "advanced_config",
  "enabled",
  "meta",
  "locations",
];
const BLOCK_EXPLOITS_EXCEPTIONS = [
  "tinyauth",
  "vaultls",
  "pocket-id",
  "watchyourlan",
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

function buildUpdatePayload(host, updatedFields) {
  const basePayload = pick(host, UPDATABLE_PROXY_HOST_FIELDS);

  return {
    ...basePayload,
    ...updatedFields,
    access_list_id: host.access_list_id ?? 0,
    certificate_id: host.certificate_id ?? 0,
    advanced_config: host.advanced_config || "",
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

async function run(rawOptions = program.opts(), environment = env) {
  if (argv.length <= 2 && !environment.NPM_HOST && !environment.NPM_EMAIL && !environment.NPM_PASSWORD) {
    program.help();
  }

  const options = resolveOptions(rawOptions, environment);
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
  diffSecurityState,
  getDesiredSecurityState,
  listDomains,
  normalizeHostUrl,
  parsePositiveInteger,
  requestJson,
  resolveOptions,
  run,
  sanitizeLocation,
  shouldSkipBlockExploits,
};
