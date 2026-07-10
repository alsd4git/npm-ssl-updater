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

### Sicurezza delle credenziali

Preferisci `.env` (ignorato da Git) oppure `--password-stdin` a
`--password`: gli argomenti della riga di comando possono restare nella cronologia
della shell ed essere visibili ad altri processi locali. `--password` resta
disponibile per compatibilità con le versioni precedenti.

```bash
printf '%s\n' "$NPM_PASSWORD" | npm-ssl-updater \
  --host http://localhost:81 \
  --email admin@example.com \
  --password-stdin \
  --dry-run
```

`--password-stdin` accetta esattamente una password terminata da newline tramite
pipe o redirezione di file; non richiede input da un terminale.

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
  --block-exploits \
  --yes
```

### Solo visualizzazione (dry-run)

```bash
npm-ssl-updater \
  --host http://localhost:81 \
  --email admin@example.com \
  --dry-run
```

### Aggiornare `advanced_config` di un host specifico

Quando devi aggiornare solo lo snippet `advanced_config` di un proxy host, usa il percorso dedicato con payload minimale:

```bash
npm-ssl-updater \
  --host http://localhost:81 \
  --email admin@example.com \
  --advanced-config-host-id 36 \
  --advanced-config-file ./media/NPM-extraconf.conf
```

È disponibile anche `--advanced-config-dry-run` per verificare il file senza applicare modifiche.

Questo helper esiste perché alcuni host NPM possono ignorare `advanced_config` quando il payload di update è troppo grande o include campi non necessari. Il percorso dedicato manda solo lo snippet avanzato, riducendo il rischio di regressioni.

### Elencare i certificati

Puoi vedere i certificati già presenti in Nginx Proxy Manager con:

```bash
npm-ssl-updater \
  --host http://localhost:81 \
  --email admin@example.com \
  --list-certificates
```

È utile quando vuoi recuperare l'ID di un certificato esistente o verificare quale wildcard copre un host.

### Elencare le access list

Puoi vedere le access list già presenti in Nginx Proxy Manager con:

```bash
npm-ssl-updater \
  --host http://localhost:81 \
  --email admin@example.com \
  --list-access-lists
```

È utile quando vuoi recuperare una access list con nome, ad esempio `local-only`, e riusarla su un proxy host.

### Helper proxy host

Quando vuoi creare o aggiornare un proxy host, usa l'helper dedicato. Cerca automaticamente un certificato compatibile in NPM tramite dominio e wildcard. Se serve, puoi forzare il certificato con `--proxy-certificate-id`.

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

Flag proxy host disponibili:

- `--proxy-domain`: hostname pubblico del proxy host
- `--proxy-forward-host`: host upstream del container, default `app`
- `--proxy-forward-port`: porta upstream, default `3000`
- `--proxy-forward-scheme`: schema upstream, default `http`
- `--proxy-certificate-id`: forza un ID certificato specifico
- `--proxy-certificate-domain`: usa un dominio diverso come hint per la selezione automatica del certificato
- `--proxy-access-list-id`: forza un ID access list specifico
- `--proxy-access-list-name`: usa una access list nominata, ad esempio `local-only`
- `--proxy-advanced-config-file`: applica uno snippet `advanced_config` dopo la creazione o l'aggiornamento dell'host
- `--proxy-dry-run`: mostra l'operazione senza applicare modifiche

## ✨ Cosa fa

- Mostra lo stato attuale delle opzioni di sicurezza
- Confronta con le modifiche proposte
- Supporta modalità interattiva con conferma (`yes`, `no`, `all`)
- Supporta esecuzione non interattiva sicura con `--yes`
- Supporta `--dry-run` per visualizzare senza modificare
- Usa timeout espliciti sulle richieste per evitare blocchi indefiniti verso istanze NPM non sane
- Supporta un helper dedicato per aggiornare `advanced_config` di un singolo host con payload minimale
- Supporta opzioni extra:
  - `--cache-assets`: abilita cache per asset statici
  - `--block-exploits`: attiva protezione contro exploit comuni (con intelligenza integrata)
  - `--enable-websockets`: attiva il supporto WebSocket
- Mantiene `--block-exploits` disattivato solo per `tinyauth`, perché Tinyauth si basa su forwarded host e query parameters dietro NPM.

## 🔧 Esclusione automatica da `--block-exploits`

Alcuni servizi (es. autenticazione o admin panel) possono rompersi se "Block Common Exploits" è abilitato.

Lo script salta `block_exploits` solo per `tinyauth`, perché Tinyauth ha bisogno di forwarded host e query parameters integri dietro NPM.

Puoi modificarlo nel file `update_ssl.js`:

```js
const blockExploitsExceptions = ['tinyauth'];
```

Per gli snippet `advanced_config`, usa il percorso dedicato:

```bash
npm-ssl-updater \
  --host http://localhost:81 \
  --email admin@example.com \
  --advanced-config-host-id 36 \
  --advanced-config-file ./media/NPM-extraconf.conf
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
