# 🔐 npm-ssl-updater

[English version](README.en.md)

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

### Variabili d'ambiente

È possibile creare un file `.env` nella root del progetto per memorizzare le credenziali:

```env
NPM_HOST=http://localhost:81
NPM_EMAIL=admin@example.com
NPM_PASSWORD=changeme
```

Se il file `.env` è presente, non è necessario passare i flag `--host`, `--email` e `--password`.

**Nota:** I flag passati da linea di comando hanno la precedenza sulle variabili d'ambiente.

**Importante:** Se lo strumento è installato globalmente, il file `.env` deve trovarsi nella directory da cui si esegue il comando `npm-ssl-updater`.

### Elenco dei domini

Eseguendo lo script senza alcun argomento, verrà mostrata la lista di tutti i domini configurati e la loro destinazione (forward).

```bash
npm-ssl-updater
```

Questo è il comportamento predefinito. È anche possibile usare i flag `--list-domains` o `-l` per ottenere lo stesso risultato.

### Modalità interattiva (tutti i flag disponibili)

```bash
npm-ssl-updater \
  --host http://localhost:81 \
  --email admin@example.com \
  --password changeme \
  --hsts-subdomains \
  --cache-assets \
  --block-exploits \
  --enable-websockets \
  --request-timeout 15000 \
  --print-advanced # (opzionale) mostra la configurazione avanzata
```

Alias disponibili per i flag:

- `-l`, `--list-domains`: mostra la lista dei domini configurati
- `--hsts-subdomains`: `--hsd`
- `--cache-assets`: `--ca`
- `--block-exploits`: `--bce`
- `--enable-websockets`: `--ws`
- `--yes`: `-y`

### Applicazione non interattiva

Usa `--yes` per applicare tutte le modifiche pendenti senza prompt. È la modalità consigliata per automazioni e cron job.

```bash
npm-ssl-updater \
  --host http://localhost:81 \
  --email admin@example.com \
  --password changeme \
  --block-exploits \
  --yes
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
- Supporta modalità interattiva con conferma (`yes`, `no`, `all`)
- Supporta esecuzione non interattiva sicura con `--yes`
- Supporta `--dry-run` per visualizzare senza modificare
- Usa timeout espliciti sulle richieste per evitare blocchi indefiniti verso istanze NPM non sane
- Supporta opzioni extra:
  - `--cache-assets`: abilita cache per asset statici
  - `--block-exploits`: attiva protezione contro exploit comuni (con intelligenza integrata)
  - `--enable-websockets`: attiva il supporto WebSocket
- Disattiva automaticamente `--block-exploits` per host noti incompatibili:
  - `tinyauth`, `vaultls`, `pocket-id`, `watchyourlan`

## 🔧 Esclusione automatica da `--block-exploits`

Alcuni servizi (es. autenticazione o admin panel) possono rompersi se "Block Common Exploits" è abilitato.

Lo script include un array di parole chiave che, se presenti in qualunque dominio configurato, evitano di forzare `block_exploits`.

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

## 🛡 Requisiti

- Nginx Proxy Manager attivo e raggiungibile
- Credenziali admin valide
- Node.js 18+ (`nvm use` consigliato)

---

## 📃 Licenza

MIT License - Fai quello che vuoi, ma linka l'autore :)
© [Alessandro Digilio](https://github.com/alsd4git)
