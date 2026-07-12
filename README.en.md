# 🔐 Nginx Proxy Manager SSL CLI

[Versione italiana](README.it.md)

> Automatically updates security settings for all configured proxy hosts in [Nginx Proxy Manager](https://github.com/NginxProxyManager/nginx-proxy-manager).

> Formerly **npm-ssl-updater**. The published package and command retain that
> name for backward compatibility.

## 📦 Installation

```bash
git clone https://github.com/alsd4git/nginx-proxy-manager-ssl-cli.git
cd nginx-proxy-manager-ssl-cli
npm install
```

### (optional) Install globally

```bash
npm install -g .
```

## 🚀 Usage

### Environment Variables

You can create a `.env` file in the project root to store your credentials:

```env
NPM_HOST=http://localhost:81
NPM_EMAIL=admin@example.com
NPM_PASSWORD=changeme
```

If the `.env` file is present, you don't need to pass the `--host`, `--email`, and `--password` flags.

**Note:** Command-line flags take precedence over environment variables.

**Important:** If the tool is installed globally, the `.env` file must be located in the directory from which you run the `npm-ssl-updater` command.

### Credential safety

Prefer `.env` (which is ignored by Git) or `--password-stdin` instead of
`--password`: command-line arguments can be retained in shell history and be
visible to other local processes. `--password` remains available for backwards
compatibility.

```bash
printf '%s\n' "$NPM_PASSWORD" | npm-ssl-updater \
  --host http://localhost:81 \
  --email admin@example.com \
  --password-stdin \
  --dry-run
```

`--password-stdin` accepts exactly one newline-terminated password from a pipe
or redirected file; it does not prompt on a terminal.

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
  --hsts-subdomains \
  --cache-assets \
  --block-exploits \
  --enable-websockets \
  --request-timeout 15000 \
  --print-advanced # (optional) shows advanced configuration
```

Available aliases for flags:

- `-l`, `--list-domains`: shows the list of configured domains
- `--hsts-subdomains`: `--hsd`
- `--cache-assets`: `--ca`
- `--block-exploits`: `--bce`
- `--enable-websockets`: `--ws`
- `--yes`: `-y`

### Non-interactive apply

Use `--yes` to apply every pending change without prompts. This is the safest mode for automation and cron jobs.

```bash
npm-ssl-updater \
  --host http://localhost:81 \
  --email admin@example.com \
  --block-exploits \
  --yes
```

### View Only (dry-run)

```bash
npm-ssl-updater \
  --host http://localhost:81 \
  --email admin@example.com \
  --dry-run
```

### Update a single host `advanced_config`

When you only need to update one proxy host's `advanced_config`, use the dedicated file-based helper:

```bash
npm-ssl-updater \
  --host http://localhost:81 \
  --email admin@example.com \
  --advanced-config-host-id 36 \
  --advanced-config-file ./media/NPM-extraconf.conf
```

`--advanced-config-dry-run` is available to preview the file without applying changes.

This helper exists because some NPM hosts can ignore `advanced_config` when the update payload is too large or includes fields that are unnecessary for the snippet. The dedicated path sends only the advanced snippet, reducing the chance of regressions.

### List certificates

You can inspect the certificates already stored in Nginx Proxy Manager with:

```bash
npm-ssl-updater \
  --host http://localhost:81 \
  --email admin@example.com \
  --list-certificates
```

This is useful when you want to recover an existing certificate ID or verify which wildcard cert covers a host.

### List access lists

You can inspect the access lists already stored in Nginx Proxy Manager with:

```bash
npm-ssl-updater \
  --host http://localhost:81 \
  --email admin@example.com \
  --list-access-lists
```

This is useful when you want to recover a named access list such as `local-only` and reuse it on a proxy host.

### Proxy host helper

When you want to create or update a proxy host, use the dedicated helper. It automatically looks up a matching certificate in NPM by domain name and wildcard coverage. You can still override the certificate with `--proxy-certificate-id` if needed.

```bash
npm-ssl-updater \
  --host http://localhost:81 \
  --email admin@example.com \
  --upsert-proxy-host \
  --proxy-domain app.example.com \
  --proxy-forward-host app \
  --proxy-forward-port 3000 \
  --proxy-advanced-config-file ./path/to/NPM-extraconf.conf
```

Available proxy-host flags:

- `--proxy-domain`: public hostname for the proxy host
- `--proxy-forward-host`: upstream container host, defaults to `app`
- `--proxy-forward-port`: upstream port, defaults to `3000`
- `--proxy-forward-scheme`: upstream scheme, defaults to `http`
- `--proxy-certificate-id`: force a specific certificate ID
- `--proxy-certificate-domain`: use a different domain hint when auto-selecting a certificate
- `--proxy-access-list-id`: force a specific access list ID
- `--proxy-access-list-name`: use a named access list, for example `local-only`
- `--proxy-advanced-config-file`: apply an `advanced_config` snippet after the host is created or updated
- `--proxy-dry-run`: preview the host operation without applying changes

## ✨ What it does

- Shows the current status of security options
- Compares with proposed changes
- Supports interactive mode with confirmation (`yes`, `no`, `all`)
- Supports safe non-interactive execution with `--yes`
- Supports `--dry-run` for viewing without modifying
- Uses explicit request timeouts to avoid hanging forever on unhealthy NPM instances
- Supports a dedicated helper to update a single host's `advanced_config` with a minimal payload
- Supports extra options:
  - `--cache-assets`: enables caching for static assets
  - `--block-exploits`: activates protection against common exploits (with integrated intelligence)
  - `--enable-websockets`: activates WebSocket support
- Automatically keeps `--block-exploits` disabled only for `tinyauth`, because Tinyauth relies on forwarded host handling and query parameters behind NPM.

## 🔧 Automatic exclusion from `--block-exploits`

Some services (e.g., authentication or admin panels) may break if "Block Common Exploits" is enabled.

The script only skips `block_exploits` for `tinyauth`, because Tinyauth needs forwarded host handling and query parameters to stay intact behind NPM.

You can modify it in the `update_ssl.js` file:

```js
const blockExploitsExceptions = ['tinyauth'];
```

For `advanced_config` snippets, use the dedicated path:

```bash
npm-ssl-updater \
  --host http://localhost:81 \
  --email admin@example.com \
  --advanced-config-host-id 36 \
  --advanced-config-file ./media/NPM-extraconf.conf
```

## ✅ Example output

```bash
🔧 Proxy: example.duckdns.org
🔁 ssl_forced              : ❌ → ✅
🔁 http2_support           : ❌ → ✅
   hsts_enabled            : ✅ → ✅
   hsts_subdomains         : ❌ → ❌
   block_exploits          : ✅ → ✅
   caching_enabled         : ❌ → ❌
🔁 allow_websocket_upgrade : ❌ → ✅
Apply changes? ([y]es / [n]o / [a]ll): y
   Change applied.
```

## 🛡 Requirements

- Nginx Proxy Manager active and reachable
- Valid admin credentials
- Node.js 18+ (`nvm use` recommended)

---

## 📃 License

MIT License - Do what you want, but link the author :)
© [Alessandro Digilio](https://github.com/alsd4git)
