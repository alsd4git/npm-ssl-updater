# 🔐 npm-ssl-updater

[Versione italiana](README.md)

> Automatically updates security settings for all configured proxy hosts in [Nginx Proxy Manager](https://github.com/NginxProxyManager/nginx-proxy-manager).

## 📦 Installation

```bash
git clone https://github.com/alsd4git/npm-ssl-updater.git
cd npm-ssl-updater
npm install
```

### (optional) Install globally

```bash
npm install -g .
```

## 🚀 Usage

### Environment Variables

You can create a `.env` file in the project root to store your credentials:

```
NPM_HOST=http://localhost:81
NPM_EMAIL=admin@example.com
NPM_PASSWORD=changeme
```

If the `.env` file is present, you don't need to pass the `--host`, `--email`, and `--password` flags.

**Note:** Command-line flags take precedence over environment variables.

**Important:** If the tool is installed globally, the `.env` file must be located in the directory from which you run the `npm-ssl-updater` command.

### Listing Domains

Running the script without any arguments will display a list of all configured domains and their forward destinations.

```bash
npm-ssl-updater
```

This is the default behavior. You can also use the `--list-domains` or `-l` flags to achieve the same result.

### Interactive Mode (all available flags)

```bash
npm-ssl-updater \
  --host http://localhost:81 \
  --email admin@example.com \
  --password changeme \
  --hsts-subdomains \
  --cache-assets \
  --block-exploits \
  --enable-websockets \
  --print-advanced # (optional) shows advanced configuration
```

Available aliases for flags:
- `-l`, `--list-domains`: shows the list of configured domains
- `--hsts-subdomains`: `--hsd`
- `--cache-assets`: `--ca`
- `--block-exploits`: `--bce`
- `--enable-websockets`: `--ws`

### View Only (dry-run)

```bash
npm-ssl-updater \
  --host http://localhost:81 \
  --email admin@example.com \
  --password changeme \
  --dry-run
```

## ✨ What it does

- Shows the current status of security options
- Compares with proposed changes
- Supports interactive mode with confirmation (`yes`, `no`, `all`)
- Supports `--dry-run` for viewing without modifying
- Supports extra options:
  - `--cache-assets`: enables caching for static assets
  - `--block-exploits`: activates protection against common exploits (with integrated intelligence)
  - `--enable-websockets`: activates WebSocket support
- Automatically disables `--block-exploits` for known incompatible hosts:
  - `tinyauth`, `vaultls`, `pocket-id`, `watchyourlan`

## 🔧 Automatic exclusion from `--block-exploits`

Some services (e.g., authentication or admin panels) may break if "Block Common Exploits" is enabled.

The script includes an array of keywords that, if present in the domain, prevent `block_exploits` from being forced.

You can modify it in the `update_ssl.js` file:

```js
const blockExploitsExceptions = [
  'tinyauth',
  'vaultls',
  'pocket-id',
  'watchyourlan'
];
```

## ✅ Example output

```
🔧 Proxy: example.duckdns.org
🔁 ssl_forced              : ❌ → ✅
🔁 http2_support           : ❌ → ✅
   hsts_enabled            : ✅ → ✅
   hsts_subdomains         : ❌ → ❌
   block_exploits          : ✅ → ✅
   caching_enabled         : ❌ → ❌
🔁 allow_websocket_upgrade : ❌ → ✅
Apply changes? ([y]es / [n]o / [a]ll): y
   → ✅ Change applied
```

## 🛡 Requirements

- Nginx Proxy Manager active and reachable
- Valid admin credentials
- Node.js 18+ (`nvm use` recommended)

---

## 📃 License

MIT License - Do what you want, but link the author :)
© [Alessandro Digilio](https://github.com/alsd4git)
