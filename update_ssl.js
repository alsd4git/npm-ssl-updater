#!/usr/bin/env node
require('dotenv').config();
const axios = require("axios");
const { program } = require("commander");
const inquirer = require("inquirer");
const packageJson = require("./package.json");

program
  .name("npm-ssl-updater")
  .description("Enables Force SSL, HTTP/2, HSTS, and other options on Nginx Proxy Manager")
  .version(packageJson.version)
  .option('-H, --host <url>', 'NPM address (e.g., http://localhost:81)')
  .option('-e, --email <email>', 'NPM admin email')
  .option('-p, --password <password>', 'NPM admin password')
  .option('--hsts-subdomains, --hsd', 'Enable HSTS for subdomains as well', false)
  .option('--cache-assets, --ca', 'Enable static asset caching')
  .option('--block-exploits, --bce', 'Block common exploits')
  .option('--enable-websockets, --ws', 'Enable WebSocket support')
  .option('--dry-run', 'Show what would change without applying modifications', false)
  .option('--print-advanced', 'Show the advanced_config section for each host', false)
  .option('-l, --list-domains', 'Show a list of configured domains and their targets', false)
  .parse(process.argv);

const opts = program.opts();

// Environment variable handling
const envHost = process.env.NPM_HOST;
const envEmail = process.env.NPM_EMAIL;
const envPassword = process.env.NPM_PASSWORD;

if (opts.host && envHost && opts.host !== envHost) {
  console.warn("⚠️ The --host parameter differs from NPM_HOST in the .env file.");
}
if (opts.email && envEmail && opts.email !== envEmail) {
  console.warn("⚠️ The --email parameter differs from NPM_EMAIL in the .env file.");
}
if (opts.password && envPassword && opts.password !== envPassword) {
  console.warn("⚠️ The --password parameter differs from NPM_PASSWORD in the .env file.");
}

opts.host = opts.host || envHost;
opts.email = opts.email || envEmail;
opts.password = opts.password || envPassword;

if (!opts.host || !opts.email || !opts.password) {
  console.error("❌ Error: Host, email, and password are required. Provide them via command line or .env file.");
  program.help();
  process.exit(1);
}

if (process.argv.length <= 2 && !envHost && !envEmail && !envPassword) {
  program.help();
}

//const opts = program.opts();

const blockExploitsExceptions = [
  'tinyauth',
  'vaultls',
  'pocket-id',
  'watchyourlan'
];

function shouldSkipBlockExploits(domain) {
  return blockExploitsExceptions.some(skip => domain.includes(skip));
}

function printDiff(before, after) {
  const keys = [
    'ssl_forced',
    'http2_support',
    'hsts_enabled',
    'hsts_subdomains',
    'block_exploits',
    'caching_enabled',
    'allow_websocket_upgrade'
  ];

  const emoji = (v) => v === true ? '✅' : '❌';

  for (const key of keys) {
    const oldVal = before[key] ?? false;
    const newVal = after[key] ?? false;
    const changed = oldVal !== newVal;
    const prefix = changed ? '🔁' : '   ';
    console.log(`${prefix} ${key.padEnd(24)}: ${emoji(oldVal)} → ${emoji(newVal)}`);
  }
}

function listDomains(proxyHosts) {
  console.log("📄 List of configured domains:");
  console.log("--------------------------------------------------");
  for (const host of proxyHosts) {
    const domains = host.domain_names.join(", ");
    const forward = `${host.forward_host}:${host.forward_port}`;
    console.log(`  • ${domains} → ${forward}`);
  }
  console.log("--------------------------------------------------");
}

async function main() {
  try {
    const loginRes = await axios.post(`${opts.host}/api/tokens`, {
      identity: opts.email,
      secret: opts.password
    });
    const token = loginRes.data.token;
    const headers = { Authorization: `Bearer ${token}` };

    const proxyRes = await axios.get(`${opts.host}/api/nginx/proxy-hosts`, { headers });
    const proxyHosts = proxyRes.data;

    if (!proxyHosts.length) {
      console.log("❗ No proxy hosts found.");
      return;
    }

    if (opts.listDomains || process.argv.length <= 2) {
      listDomains(proxyHosts);
      return;
    }

    let applyToAll = false;

    for (const host of proxyHosts) {
      const { id, domain_names } = host;

      if (opts.printAdvanced) {
        console.log(`\n📄 Advanced config for: ${domain_names.join(", ")}`);
        console.log("--------------------------------------------------");
        console.log(host.advanced_config || "<empty>");
        console.log("--------------------------------------------------");
        continue;
      }

      const updated = {
        ...host,
        ssl_forced: true,
        http2_support: true,
        hsts_enabled: true,
        hsts_subdomains: opts.hstsSubdomains,
        block_exploits: (
          opts.blockExploits === true && !shouldSkipBlockExploits(domain_names[0])
        ) ? true : host.block_exploits || false,
        caching_enabled: opts.cacheAssets === true ? true : host.caching_enabled || false,
        allow_websocket_upgrade: opts.enableWebsockets === true ? true : host.allow_websocket_upgrade || false
      };

      const willChange = JSON.stringify({
        ssl_forced: host.ssl_forced,
        http2_support: host.http2_support,
        hsts_enabled: host.hsts_enabled,
        hsts_subdomains: host.hsts_subdomains,
        block_exploits: host.block_exploits,
        caching_enabled: host.caching_enabled,
        allow_websocket_upgrade: host.allow_websocket_upgrade
      }) !== JSON.stringify({
        ssl_forced: updated.ssl_forced,
        http2_support: updated.http2_support,
        hsts_enabled: updated.hsts_enabled,
        hsts_subdomains: updated.hsts_subdomains,
        block_exploits: updated.block_exploits,
        caching_enabled: updated.caching_enabled,
        allow_websocket_upgrade: updated.allow_websocket_upgrade
      });

      if (!willChange) {
        console.log(`✅ ${domain_names.join(", ")} is already correctly configured.`);
        continue;
      }

      console.log(`\n🔧 Proxy: ${domain_names.join(", ")}`);
      printDiff(host, updated);

      if (opts.dryRun) {
        console.log("   → Dry-run mode: no changes applied.");
        continue;
      }

      if (!applyToAll) {
        const answer = await inquirer.prompt([{
          type: 'input',
          name: 'confirm',
          message: 'Apply changes? ([y]es / [n]o / [a]ll)',
          validate: input => ['y', 'n', 'a'].includes(input.toLowerCase()) || 'Respond with y / n / a'
        }]);

        const input = answer.confirm.toLowerCase();
        if (input === 'n') {
          console.log("   → ❌ Skipped.");
          continue;
        } else if (input === 'a') {
          applyToAll = true;
        }
      }

      const updatePayload = {
        domain_names: host.domain_names,
        forward_scheme: host.forward_scheme,
        forward_host: host.forward_host,
        forward_port: host.forward_port,
        access_list_id: host.access_list_id || 0,
        certificate_id: host.certificate_id,
        ssl_forced: updated.ssl_forced,
        http2_support: updated.http2_support,
        hsts_enabled: updated.hsts_enabled,
        hsts_subdomains: updated.hsts_subdomains,
        block_exploits: updated.block_exploits,
        caching_enabled: updated.caching_enabled,
        allow_websocket_upgrade: updated.allow_websocket_upgrade,
        locations: host.locations || [],
        advanced_config: host.advanced_config || '',
        meta: {
          letsencrypt_agree: true,
          dns_challenge: host.meta?.dns_challenge || false
        }
      };

      try {
        await axios.put(`${opts.host}/api/nginx/proxy-hosts/${id}`, updatePayload, { headers });
        console.log("   → ✅ Change applied");
      } catch (err) {
        console.warn("   → ⚠️ Error during update:", err.message);
      }
    }

    console.log("\n✅ Script completed.");
  } catch (err) {
    console.error("❌ General error:", err.response?.data || err.message);
    process.exit(1);
  }
}

main();
