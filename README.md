# 🔐 npm-ssl-updater

> Aggiorna automaticamente le impostazioni di sicurezza per tutti i proxy host configurati in [Nginx Proxy Manager](https://github.com/NginxProxyManager/nginx-proxy-manager).

## 📦 Installazione

```bash
git clone https://github.com/alsd4git/npm-ssl-updater.git
cd npm-ssl-updater
npm install
```

### (opzionale) Installa globalmente

```bash
npm install -g .
```

## 🚀 Uso

### Modalità interattiva (tutti i flag disponibili)

```bash
npm-ssl-updater \
  --host http://localhost:81 \
  --email admin@example.com \
  --password changeme \
  --hsts-subdomains \
  --cache-assets \
  --block-exploits \
  --enable-websockets
```

### Solo visualizzazione (dry-run)

```bash
npm-ssl-updater \
  --host http://localhost:81 \
  --email admin@example.com \
  --password changeme \
  --dry-run
```

## ✨ Cosa fa

- Mostra lo stato attuale delle opzioni di sicurezza
- Confronta con le modifiche proposte
- Supporta modalità interattiva con conferma (`sì`, `no`, `tutti`)
- Supporta `--dry-run` per visualizzare senza modificare
- Supporta opzioni extra:
  - `--cache-assets`: abilita cache per asset statici
  - `--block-exploits`: attiva protezione contro exploit comuni (con intelligenza integrata)
  - `--enable-websockets`: attiva il supporto WebSocket
- Disattiva automaticamente `--block-exploits` per host noti incompatibili:
  - `tinyauth`, `vaultls`, `pocket-id`, `watchyourlan`

## 🔧 Esclusione automatica da `--block-exploits`

Alcuni servizi (es. autenticazione o admin panel) possono rompersi se "Block Common Exploits" è abilitato.

Lo script include un array di parole chiave che, se presenti nel dominio, evitano di forzare `block_exploits`.

Puoi modificarlo nel file `update_ssl.js`:

```js
const blockExploitsExceptions = [
  'tinyauth',
  'vaultls',
  'pocket-id',
  'watchyourlan'
];
```

## ✅ Esempio output

```
🔧 Proxy: example.duckdns.org
🔁 ssl_forced              : ❌ → ✅
🔁 http2_support           : ❌ → ✅
   hsts_enabled            : ✅ → ✅
   hsts_subdomains         : ❌ → ❌
   block_exploits          : ✅ → ✅
   caching_enabled         : ❌ → ❌
🔁 allow_websocket_upgrade : ❌ → ✅
Applico modifiche? ([s]ì / [n]o / [t]utti): s
   → ✅ Modifica applicata
```

## 🛡 Requisiti

- Nginx Proxy Manager attivo e raggiungibile
- Credenziali admin valide
- Node.js 18+ (`nvm use` consigliato)

---

## 🛡️ Licenza

MIT License - Fai quello che vuoi, ma linka l'autore :)
© [Alessandro Digilio](https://github.com/alsd4git)
