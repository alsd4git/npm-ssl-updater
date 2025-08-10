#!/usr/bin/env node
require('dotenv').config();
const axios = require("axios");
const { program } = require("commander");
const inquirer = require("inquirer");
const packageJson = require("./package.json");

program
  .name("npm-ssl-updater")
  .description("Abilita Force SSL, HTTP/2, HSTS e altre opzioni su Nginx Proxy Manager")
  .version(packageJson.version)
  .option('-H, --host <url>', 'Indirizzo di NPM (es: http://localhost:81)')
  .option('-e, --email <email>', 'Email admin NPM')
  .option('-p, --password <password>', 'Password admin NPM')
  .option('--hsts-subdomains, --hsd', 'Abilita HSTS anche per i sottodomini', false)
  .option('--cache-assets, --ca', 'Abilita cache degli asset statici')
  .option('--block-exploits, --bce', 'Blocca exploit comuni')
  .option('--enable-websockets, --ws', 'Abilita supporto WebSocket')
  .option('--dry-run', 'Mostra cosa cambierebbe senza applicare modifiche', false)
  .option('--print-advanced', 'Mostra la sezione advanced_config per ciascun host', false)
  .parse(process.argv);

const opts = program.opts();

// Environment variable handling
const envHost = process.env.NPM_HOST;
const envEmail = process.env.NPM_EMAIL;
const envPassword = process.env.NPM_PASSWORD;

if (opts.host && envHost && opts.host !== envHost) {
  console.warn("⚠️ Il parametro --host è diverso da NPM_HOST nel file .env.");
}
if (opts.email && envEmail && opts.email !== envEmail) {
  console.warn("⚠️ Il parametro --email è diverso da NPM_EMAIL nel file .env.");
}
if (opts.password && envPassword && opts.password !== envPassword) {
  console.warn("⚠️ Il parametro --password è diverso da NPM_PASSWORD nel file .env.");
}

opts.host = opts.host || envHost;
opts.email = opts.email || envEmail;
opts.password = opts.password || envPassword;

if (!opts.host || !opts.email || !opts.password) {
  console.error("❌ Errore: Host, email e password sono obbligatori. Forniscili tramite linea di comando o file .env.");
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
      console.log("❗ Nessun proxy host trovato.");
      return;
    }

    let applyToAll = false;

    for (const host of proxyHosts) {
      const { id, domain_names } = host;

      if (opts.printAdvanced) {
        console.log(`\n📄 Advanced config for: ${domain_names.join(", ")}`);
        console.log("--------------------------------------------------");
        console.log(host.advanced_config || "<vuoto>");
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
        console.log(`✅ ${domain_names.join(", ")} è già configurato correttamente.`);
        continue;
      }

      console.log(`\n🔧 Proxy: ${domain_names.join(", ")}`);
      printDiff(host, updated);

      if (opts.dryRun) {
        console.log("   → Modalità dry-run: nessuna modifica applicata.");
        continue;
      }

      if (!applyToAll) {
        const answer = await inquirer.prompt([{
          type: 'input',
          name: 'confirm',
          message: 'Applico modifiche? ([s]ì / [n]o / [t]utti)',
          validate: input => ['s', 'n', 't'].includes(input.toLowerCase()) || 'Rispondi con s / n / t'
        }]);

        const input = answer.confirm.toLowerCase();
        if (input === 'n') {
          console.log("   → ❌ Saltato.");
          continue;
        } else if (input === 't') {
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
        console.log("   → ✅ Modifica applicata");
      } catch (err) {
        console.warn("   → ⚠️ Errore durante update:", err.message);
      }
    }

    console.log("\n✅ Script completato.");
  } catch (err) {
    console.error("❌ Errore generale:", err.response?.data || err.message);
    process.exit(1);
  }
}

main();
