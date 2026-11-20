# Telegram UI conventions

How every NetSentry message and button should look. The helpers live in
`src/netsentry/core/ui.py` (pure) and `src/netsentry/core/notify.py` (how loud).
Use them in anything you touch.

## Messages

- **Line 1 = `<state emoji> <subject> — <verdict>`**, about 40 characters. It is
  what the phone notification shows. `ui.header(ui.ATTENTION, "Router storage", "almost full")`.
- Most important first; names before MAC/IP (`📱 Kitchen plug` then `IP 192.0.2.20 · AA:BB:…`).
- A `━`×17 rule (`ui.RULE`) only on screens and reports, never in one-line replies.
- End in buttons, never in typed syntax ("type /status"). Use
  `ui.command_row(ctx, ("🩺 Full check", "/health"))`: it only adds buttons for
  commands that exist, and none when the menu plugin isn't loaded.
- Long text is split by the notifier (`ui.split_message`, 4096 limit, at line
  breaks); buttons go under the last part. A photo caption over 1024 characters
  keeps only its first line; the rest follows as text.
- **No pictures in alerts.** The only photo is the guest WiFi QR code (and maps),
  where the picture is the content.

- Screens and reports start with `ui.title(icon, subject, verdict)` (header +
  rule). Reports lead with the verdict: `🛡 Daily report — ⚠️ 2 to review` /
  `— ✅ nothing to review`, then one line per kind of thing with at most three
  subjects (`ui.first_few(...)` → `a, b, c +2 more`).
- **Lists lead with the name**, one line per item, no column alignment
  (Telegram's font is proportional): `ui.item("🏷 Kitchen plug", "IoT",
  "192.0.2.8", "-32 dBm")` → `🏷 Kitchen plug — IoT · 192.0.2.8 · -32 dBm`.
  Show a MAC only for a device without a name of its own (and in search
  results, where it may be what was searched for).
- **Links are URL buttons** (`ui.url_button` / `ui.url_row`, which drops empty
  URLs), never text — a dashboard link carries its access token.
- Markdown is not rendered in plain messages: no `*`, `` ` `` or `#` in text
  (strip them from README excerpts and the like).

## Commands

- `COMMANDS` descriptions are what Telegram's "/" list and the /menu buttons
  show: one emoji of its own (never a state emoji), then what it shows (noun
  phrase: `📺 Saved YouTube videos`) or does (imperative: `💾 Back up the router
  config now`), ≤ ~35 characters, no colon, no argument syntax.
- Typed forms go in an optional `"usage"` key; only `/help` shows them. A bare
  command always opens buttons; a typed form that misses its argument says in
  one sentence what to tap or type, never `Usage: …`.

## State emoji — one meaning each

| | meaning | | meaning |
|---|---|---|---|
| 🚨 | attack or outage | ❌ | an action failed |
| ⚠️ | needs you | ⏳ | working on it |
| ℹ️ | FYI | ✖ | cancelled / nothing changed |
| ✅ | OK / done / back to normal | 🆕 | a new device |

## Buttons

- Verb first, emoji prefix, about 20 characters: `🔁 Try again`, `🚫 Block Kitchen plug`.
- Primary action in the first row. Refresh is always `🔄 Refresh` (`ui.refresh_button`).
- Last row of a screen: `[⬅ Back] [🏠 Menu]` (`ui.nav_row(back_data)`).
- `callback_data` ≤ 64 bytes (`ui.button` refuses longer). A MAC has five colons:
  put it last and take it with `partition`, never an unbounded `split(":")`.
- **Destructive = two taps.** First a sentence with the consequence, then
  `ui.confirm_rows("🚫", "block", yes_data, cancel_data)` →
  `[🚫 Yes, block] [✖ Cancel]`. Example:
  `🚫 Block Lenovo-Idea-Tab? It can't join any WiFi until you unblock it.`
- Results and cancels **edit the same message** (no live buttons left behind):
  `🚫 Blocked Lenovo-Idea-Tab.` or `✖ Nothing changed.` (`ui.NOTHING_CHANGED`).
- A one-shot button under a message that must stay readable (e.g. `✅ Trust
  x.com` under a report) turns into a record of itself — `✔ Trusted x.com` —
  while the other buttons stay: `ui.mark_tapped(...)` (the bot hands the
  plugin the tapped keyboard during `on_callback`; `notifier.edit_buttons`).
  Tapping the record only answers "Already done".
- A screen button under a report or alert opens its screen as a **new**
  message (the report stays); buttons inside a screen redraw it in place.
- `🔄 Refresh` redraws; `🔁 Try again` repeats a failed action. Top-level
  screens end in `[🏠 Menu]`; screens with a parent in `[⬅ Back] [🏠 Menu]`.
  A screen opened from another plugin's screen gets its Back from the caller
  (Settings → Guest WiFi schedule).
- A plugin whose command asks its own question lists it in
  `Plugin.CONFIRMS_ITSELF`; the bot's generic confirmation then skips it.

## Wording

- Sentence case. Results in past tense with the device name (`Blocked Kitchen plug.`).
- Failures say what did **not** happen and what is still true:
  `❌ The router was NOT restarted — it didn't take the command. Everything keeps running.`
- Never raw exception text, stderr or internal identifiers — log them
  (`self.log.exception(...)`) and say "details are in the log".
- Vocabulary: name / unnamed (not tag), block vs disconnect, trust / stop
  trusting (not allow/deny), finding, check, "Guest WiFi".
- Device label: owner's name → DHCP hostname → MAC (`ui.device_label`,
  `ui.device_names(ctx, router, macs)`).

## Dates and numbers

- `Mon 23 Nov 09:00` — 24-hour, year only when not the current year
  (`ui.fmt_when`; English names whatever the host locale). A day alone:
  `ui.fmt_day` → `Mon 23 Nov`.
- A past moment as the owner reads it: `ui.when_text(value)` — `14 min ago`
  under a day, else the date; takes a datetime, an ISO string or epoch seconds.
  Lengths: `14 min`, `2 h 5 min` (`ui.duration`).
- A space before units: `-51 dBm`, `12 MB` (`ui.size(bytes)`).
  `ui.plural(3, "device")` → `3 devices`.

## How loud (unprompted messages only)

`notifier.notify(kind, text, buttons=…)` — replies use `send_to` and are always
delivered with sound.

| kind | Relaxed | Normal (default) | Everything |
|---|---|---|---|
| `urgent` 🚨 attack/outage | sound | sound | sound |
| `attention` ⚠️ needs you | silent | sound | sound |
| `recovery` ✅ back to normal | silent | silent | sound |
| `report` scheduled reports | silent | silent | sound |
| `info` ℹ️ FYI, 🆕 new device | not sent | silent | sound |
| `success` a scheduled job worked | not sent | not sent | silent |

A message that arrives by itself some time after a tap is unprompted too: "the
Pi is back" after a restart is `recovery`; a DNS-trace hit (the answer to a
question the owner set up) is `attention`; "the trace expired, nobody asked" is
`info`. The immediate answer to a tap stays a plain reply.

The mode is the notifier's `notify_mode` config key, changed live in
`/settings → 🔔 Notifications` (stored, wins over the config).

One problem → one alert → one recovery: a plugin that alerts about its own
failure returns that check with `HealthCheck(..., notified=True)` and calls
`notify.report_problem(ctx, check_name)`; the self-check watchdog then only
sends the recovery, with how long it lasted.

## HTML (opt-in)

Plain text stays the default. `notify()` escapes the text and makes line 1 bold
by itself. For your own formatting pass `html=True` (also `edit_message(...,
html=True)`) and build the text with `ui.lines(...)`, `ui.b()`, `ui.code()`,
`ui.esc()` — every inserted value is escaped (names, domains and log lines can
contain `<` and `&`). Keep each tag on one line. If Telegram refuses the
formatting, the notifier resends it once as plain text with the tags stripped.
Use `ui.code(password)` for anything the owner will want to copy.
