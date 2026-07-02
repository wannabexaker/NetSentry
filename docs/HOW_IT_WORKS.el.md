# NetSentry — πώς δουλεύει η κάθε λειτουργία (τεχνικά)

Αυτό είναι το αναλυτικό «τι κάνει και πώς ακριβώς» reference. Για καθημερινή
λειτουργία δες [OPERATIONS.md](OPERATIONS.md)· για τη σκοπιά του επιτιθέμενου δες
[THREAT_MODEL.md](THREAT_MODEL.md). (Αγγλική έκδοση: [HOW_IT_WORKS.md](HOW_IT_WORKS.md).)

---

## 1. Runtime & αρχιτεκτονική

- **Process model.** Το `netsentry start` φτιάχνει ένα `Runtime` (`core/runtime.py`)
  που φορτώνει το config, ανοίγει το vault, κατασκευάζει τα router / notifier / AI
  clients, ξεκινά τον APScheduler, ανακαλύπτει τα plugins και μετά δίνει τον έλεγχο
  στο `telegram_bot` που μπλοκάρει σε ένα long-poll loop. Ένα process, πολλά threads.
- **Threads.** (α) το Telegram poll loop· (β) ένα bounded `ThreadPoolExecutor`
  (default 4) που τρέχει κάθε command handler ώστε μια αργή εντολή να μην παγώνει το
  bot· (γ) το pool του APScheduler για cron/interval jobs· (δ) τα HTTP + poll threads
  του `lan_dashboard`. Οι **εγγραφές** (writes) στο router σειριοποιούνται με
  re-entrant lock.
- **Plugins.** Ό,τι βλέπει ο χρήστης είναι plugin (`plugins/`). Ο `loader.py` κάνει
  import το `netsentry.plugins.<name>` για κάθε ενεργό entry του config, βρίσκει την
  `Plugin` subclass, φτιάχνει ένα `PluginContext` (router, notifier, vault, logger,
  per-plugin `state_dir`, scheduler, event bus), καλεί `on_load()` και μαζεύει τα
  `scheduled_tasks()`. Ένα plugin που σκάει είναι απομονωμένο — δεν ρίχνει τα υπόλοιπα.
- **Config & secrets.** Το `config.py` φορτώνει YAML και επεκτείνει τα
  `${vault:KEY}` / `${env:KEY}`· το `vault.py` είναι ένα Fernet-encrypted key/value
  store (key file `0400`, ciphertext `0600`). Το startup **validation** αποτυγχάνει
  αμέσως αν λείπουν keys ή αν το Telegram whitelist είναι άδειο.

## 2. Router layer (`core/router.py`) — πώς μιλάει στο MikroTik

- **Transport.** SSH με ControlMaster socket (ένα login ξαναχρησιμοποιείται για
  πολλές εντολές, ώστε να μη γεμίζει το auth log του router). Κάθε κλήση είναι
  `self._ssh("<RouterOS command>")`.
- **Parsing.** Το `as-value` της v7 είναι αναξιόπιστο σε αυτό το firmware, οπότε το
  NetSentry τρέχει κανονικά `print` και κάνει parse το **pretty-print** output
  (ομαδοποιεί continuation lines σε records, μετά σπάει τα `key=value`).
- **Reads** (`stats`, `wifi_clients`, `dhcp_leases`, `arp_table`, …) γυρίζουν typed
  dataclasses· σε SSH αποτυχία γυρίζουν `None`/`[]` ώστε ο caller να ξεχωρίζει το
  «unreachable» από το «άδειο» (ποτέ δεν επινοούν μηδενικά).
- **Writes** (`set_wifi_passphrase`, `block_mac`, `export_config`, …) παίρνουν το
  write-lock. Όλα τα inputs validated/quoted: τα MAC πρέπει να ταιριάζουν αυστηρό
  pattern και τα filenames / passphrases τυλίγονται με `_routeros_quote`, ώστε καμία
  τιμή να μην μπορεί να κάνει inject δεύτερη RouterOS εντολή.
- **Guest passphrase (το P0 fix).** Το `set_wifi_passphrase` γράφει το security
  **profile** *και* κάθε `/interface wifi` που το αναφέρει (το inline
  `security.passphrase` υπερισχύει του profile), μετά τα **ξαναδιαβάζει** όλα και
  γυρίζει `True` μόνο αν ταιριάζουν.

## 3. Plugins — τι κάνει το καθένα & πώς

- **`telegram_bot`** — κατέχει το loop. Καταχωρεί τα `COMMANDS` κάθε plugin στο
  Telegram, κάνει long-poll στο `getUpdates` και dispatch κάθε update στο worker
  pool. **Fail-closed authz**: μια εντολή/callback απορρίπτεται εκτός αν το chat
  *και* αυτός που πατάει το κουμπί είναι στο `allowed_chats`. Per-chat token-bucket
  **rate limit**· οι destructive εντολές (`confirm_commands`) θέλουν inline
  **Confirm**. Οι αποτυχίες poll κάνουν exponential backoff και λογάρονται μία φορά
  (όχι σε κάθε retry).
- **`guest_wifi_rotator`** (`/rotate`, `/guest`) — φτιάχνει diceware passphrase με
  τον `secrets` RNG, καλεί `set_wifi_passphrase`, και μόνο σε verified επιτυχία
  στέλνει το Wi-Fi QR. Σε αποτυχία ειδοποιεί αντί να στείλει QR.
- **`router_info`** (`/status /clients /wan /services /log`) — μορφοποιεί router
  reads για το Telegram.
- **`security_actions`** (`/kick /security`) — inline keyboard για disconnect ή
  block ενός client MAC (μέσω των validated writes).
- **`pihole_stats`** (`/pi`) — διαβάζει το Pi-hole **FTL SQLite** DB. Στο Pi-hole v6
  το `queries` είναι *view* που ήδη επιλύει domain/client σε strings, οπότε τα
  διαβάζει απευθείας (χωρίς legacy `domain_by_id` join).
- **`health_monitor`** — κάθε 5 λεπτά: internet ping, router uptime, disk, failed
  logins, νέοι clients. Το πρώτο run θέτει **σιωπηλό baseline**· ειδοποιεί μόνο σε
  πραγματική αλλαγή. Γράφει append-only `alerts.jsonl`.
- **`threat_detector`** — active detection (δες §4).
- **`lan_scanner`** (`/lan …`) — συγχωνεύει router ARP + DHCP + Wi-Fi σε per-MAC
  inventory με friendly-name tags (κοινό `tag_store`).
- **`lan_dashboard`** (`/dashboard`) — Flask app (δες §5).
- **`speedtest`**, **`channel_scan`**, **`config_backup`**, **`traffic_report`**,
  **`morning_briefing`**, **`youtube_bookmarks`** (`/yt`), **`github_explorer`**
  (`/gh`) — periodic/utility plugins· τα `/yt` και `/gh` κάνουν validate το URL
  argument με allowlist και το περνούν μετά από `--` ώστε να μη διαβαστεί ως flag.

## 4. threat_detector — εσωτερικά της ανίχνευσης

**Πηγές δεδομένων (read-only):** το Pi-hole FTL DB (`SELECT DISTINCT domain, client
FROM queries WHERE timestamp > now-window`) και ο ARP table του router. Τα
reverse-DNS (`*.arpa`) και τα Pi-hole pseudo-entries πετιούνται ως θόρυβος.

**Detectors** (pure functions στο `detectors.py`, το καθένα unit-tested):

| Detector | Πώς αποφασίζει |
|---|---|
| `dns_tunnel` | Ομαδοποιεί high-entropy sub-domains ανά registrable parent· φλαγκάρει parent με ≥ N (default 5) διαφορετικά τυχαία sub-domains, ή ένα εξωφρενικά μακρύ FQDN. Aggregation, οπότε ένα τυχαίο CDN όνομα δεν το ενεργοποιεί. |
| `suspicious_tld` | Το TLD του domain είναι σε high-abuse λίστα (`.tk .top .zip .mov` …). |
| `new_domain` | Domain που δεν υπάρχει στο baseline set. **Off by default** (θόρυβος browsing). |
| `arp_conflict` | Ένα IP εμφανίζεται με δύο διαφορετικά MAC → spoofing/impersonation. |
| `arp_change` | Το MAC ενός IP άλλαξε σε σχέση με το baseline → πιθανό MITM. |
| `rogue_dhcp` | DHCP server στο LAN εκτός allow-list (θέλει router alert). |
| `port_scan` | Πηγή που τα `psd` firewall rules του router σημείωσαν (tag σε `port-scanners` address-list — χωρίς log flood). |

Μια built-in **CDN allow-list** (`fbcdn.net`, `whatsapp.net`, akamai, …) καταπνίγει
τον καλόβουλο θόρυβο (π.χ. τα `netseer` UUID sub-domains της Meta) από false positive.

**Μοντέλο παράδοσης (report mode — το default):**
- Το scan τρέχει κάθε `interval_minutes` (default 10) αλλά είναι **σιωπηλό**:
  καταγράφει κάθε νέο finding στο `alerts.jsonl` και ενημερώνει το **domain journal**
  (`domains.json`: `first_seen`, `last_seen`, `clients`, `count`, το `note` σου).
- Το **report** παραδίδεται στο `report_cron` (default καθημερινά 09:00) *και*
  on-demand με `/report`· συνοψίζει την περίοδο από log + journal, ομαδοποιημένο κατά
  severity με per-device attribution.
- Το `immediate_attacks: true` (opt-in) στέλνει επιπλέον attack-severity findings τη
  στιγμή που εμφανίζονται.

**Έλεγχος operator (όλα από Telegram, ζωντανά, persisted — χωρίς restart):**

| Εντολή | Τι κάνει |
|---|---|
| `/report` | Αναλυτικό report από το τελευταίο report. |
| `/threats` | Live scan του τρέχοντος window τώρα. |
| `/threatlog [n]` | Τα τελευταία *n* καταγεγραμμένα findings. |
| `/domains [text]` | Περιήγηση/αναζήτηση στο domain journal (ιστορικό + σημειώσεις σου). |
| `/note <domain> <text>` | Βάζεις ετικέτα σε domain για να θυμάσαι τι είναι. |
| `/scans` / `/scans <key> on\|off` | Λίστα detectors (με επεξήγηση) / on·off. |
| `/audit <hours>\|off` | Audit mode: ανάβει το `new_domain` για ένα διάστημα για να δεις τι τραβάει κάθε συσκευή· επαναφέρεται μόνο του. |

## 5. lan_dashboard — πώς είναι ασφαλισμένο το web UI

Flask σε background thread στο configured bind (loopback συνιστάται). Το auth είναι
ένα one-time `/auth?token=…` link που ανταλλάσσει το token με **HttpOnly, Secure,
SameSite=Strict** session cookie και κάνει redirect σε token-less URL — έτσι το
token δεν μένει ποτέ σε URL, history ή request lines. Το φτάνεις μέσω Tailscale
(WireGuard-encrypted)· το `tailscale serve` προσθέτει πραγματικό HTTPS.

## 6. Παράρτημα — τι κάνει το `/ip dhcp-server alert` (για rogue-DHCP)

Το RouterOS μπορεί να παρακολουθεί ένα interface για DHCP servers. Βάζεις ένα alert
δεμένο στο LAN bridge και δηλώνεις τον *νόμιμο* server (το MAC του router σου) ως
valid:

```
/ip dhcp-server alert
add interface=<lan-bridge> alert-timeout=1h valid-server=<router-dhcp-server-mac>
```

Από κει και πέρα, αν οποιοσδήποτε **άλλος** host απαντήσει DHCP σε αυτό το
interface, το RouterOS καταγράφει event «unknown dhcp server» (στο πεδίο
`unknown-server` και στο log topic `dhcp`). Ο `rogue_dhcp` detector του NetSentry
διαβάζει αυτά και — για κάθε server MAC που δεν είναι valid — βγάζει attack-severity
finding. Χωρίς αυτό δεν υπάρχει DHCP traffic να δει, γι' αυτό ο detector είναι off by
default. Είναι ασφαλές, read-only monitoring (δεν μπλοκάρει τίποτα)· η μόνη προσοχή
είναι να διαλέξεις σωστό interface και valid-server MAC. Αναίρεση:
`/ip dhcp-server alert remove [find]`.

**Στην τρέχουσα εγκατάσταση** στήθηκε alert σε 3 bridges (`bridge`, `bridge-guest`,
`bridge-iot`), το καθένα με valid-server το MAC εκείνου του bridge, και ο
`rogue_dhcp` detector είναι ενεργός.
