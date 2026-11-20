(function () {
  "use strict";

  const SORT_STORAGE_KEY = "netsentry.lan_dashboard.sortMode";
  const DEFAULT_SORT_MODE = "unnamed-first";
  // Older choices that still have a close match; anything else falls back
  // to the default (the list used to have nine options).
  const LEGACY_SORT = { "unknown-first": "unnamed-first", "tag-asc": "name-asc", "hostname-asc": "name-asc" };
  const BUSIEST_RESORT_MS = 10000;   // "Busiest now" reorders at most this often
  const ARM_MS = 4000;               // how long a "Tap again" stays armed
  const RESULT_MS = 6000;            // how long "✓ Saved" stays next to the row
  const STALE_STREAM_MS = 15000;     // no data for this long = offline
  // Auth is carried by the HttpOnly session cookie (set by /auth); the token
  // is never placed in a URL or request body.
  const listEl = document.getElementById("deviceList");
  const searchEl = document.getElementById("deviceSearch");
  const sortEl = document.getElementById("sortMode");
  const netEl = document.getElementById("netFilter");
  const WIRED = "__wired__";
  const emptyEl = document.getElementById("emptyState");
  const template = document.getElementById("deviceRowTemplate");
  const statDevicesEl = document.getElementById("statDevices");
  const statActiveEl = document.getElementById("statActive");
  const statUntaggedEl = document.getElementById("statUntagged");
  const statUntaggedCardEl = document.getElementById("statUntaggedCard");
  const statTrafficEl = document.getElementById("statTraffic");

  const devices = new Map();
  const rows = new Map();
  const openRows = new Set();
  const focusedRows = new Set();
  const editingMacs = new Set();
  const armed = new Map();     // mac -> {action, timer}: first tap of a two-tap action
  const results = new Map();   // mac -> {ok, text, timer}: outcome of the last action
  let busyRank = new Map();
  let busyAt = 0;
  let eventSource = null;
  let renderQueued = false;
  let reconnectTimer = null;
  let staleTimer = null;

  const ARM_TEXT = {
    block: "Tap again to block",
    retire: "Tap again — no longer used",
    keep: "Tap again to keep password",
    unkeep: "Tap again — normal guest",
  };

  function connect() {
    clearTimeout(reconnectTimer);
    if (eventSource) {
      eventSource.close();
    }
    eventSource = new EventSource("/events");
    eventSource.onopen = function () {
      NS.status.live();
      watchStream();
    };
    eventSource.onmessage = function (event) {
      NS.status.live();
      watchStream();
      applyPayload(JSON.parse(event.data));
      scheduleRender();
    };
    eventSource.onerror = function () {
      offline();
    };
  }

  function offline() {
    clearTimeout(staleTimer);
    NS.status.offline();
    if (eventSource) {
      eventSource.close();
      eventSource = null;
    }
    clearTimeout(reconnectTimer);
    reconnectTimer = setTimeout(connect, 3000);
  }

  // The server sends a snapshot every second; a silent stream is a dead one.
  function watchStream() {
    clearTimeout(staleTimer);
    staleTimer = setTimeout(offline, STALE_STREAM_MS);
  }

  function applyPayload(payload) {
    const ts = Number(payload.ts || Date.now() / 1000);
    for (const device of payload.devices || []) {
      const current = devices.get(device.mac) || { samples: [] };
      current.mac = device.mac;
      current.ip = device.ip || "";
      current.hostname = device.hostname || "";
      current.name = device.name || "";
      current.retired = Boolean(device.retired);
      current.tx_bps = Number(device.tx_bps || 0);
      current.rx_bps = Number(device.rx_bps || 0);
      current.last_activity_ms = Number(device.last_activity_ms || 999999999);
      current.active = Boolean(device.active);
      current.can_tag = Boolean(device.can_tag);
      current.blocked = Boolean(device.blocked);
      current.ssid = device.ssid || "";
      current.band = device.band || "";
      current.signal = typeof device.signal === "number" ? device.signal : null;
      current.guest = Boolean(device.guest);
      current.kept = Boolean(device.kept);
      current.samples.push({
        ts: ts,
        tx: current.tx_bps,
        rx: current.rx_bps,
      });
      if (current.samples.length > 60) {
        current.samples.splice(0, current.samples.length - 60);
      }
      devices.set(device.mac, current);
    }
  }

  function scheduleRender() {
    if (renderQueued) {
      return;
    }
    renderQueued = true;
    requestAnimationFrame(function () {
      renderQueued = false;
      render();
    });
  }

  function render() {
    refreshEditingMacs();
    const query = (searchEl.value || "").trim().toLowerCase();
    const network = updateNetworkFilter();
    const mode = sortEl.value || DEFAULT_SORT_MODE;
    if (mode === "busiest") {
      refreshBusyRank();
    }
    const sortedItems = Array.from(devices.values())
      .filter(function (device) {
        if (network && (network === WIRED ? device.ssid : device.ssid !== network)) {
          return false;
        }
        if (!query) {
          return true;
        }
        return [device.mac, device.ip, device.hostname, device.name, device.ssid]
          .join(" ")
          .toLowerCase()
          .includes(query);
      })
      .sort(comparatorFor(mode));

    const items = stabilizeEditingRows(sortedItems);
    const visible = new Set();
    const orderedRows = [];
    for (const device of items) {
      const row = rowFor(device.mac);
      updateRow(row, device);
      visible.add(device.mac);
      orderedRows.push(row);
    }
    for (const [mac, row] of rows) {
      if (!visible.has(mac)) {
        row.remove();
      }
    }
    let cursor = listEl.firstElementChild;
    for (const row of orderedRows) {
      if (row === cursor) {
        cursor = cursor.nextElementSibling;
        continue;
      }
      listEl.insertBefore(row, cursor);
    }
    emptyEl.classList.toggle("is-visible", items.length === 0);
    updateStats();
  }

  // The network list follows what is actually connected; the choice survives
  // a network that is empty for a moment.
  function updateNetworkFilter() {
    if (!netEl) {
      return "";
    }
    const names = new Set();
    let wired = false;
    for (const device of devices.values()) {
      if (device.ssid) {
        names.add(device.ssid);
      } else {
        wired = true;
      }
    }
    const chosen = netEl.value;
    if (chosen && chosen !== WIRED) {
      names.add(chosen);
    }
    const wanted = [""].concat(Array.from(names).sort(), wired || chosen === WIRED ? [WIRED] : []);
    const have = Array.from(netEl.options).map(function (o) { return o.value; });
    if (wanted.join("\n") !== have.join("\n")) {
      netEl.replaceChildren();
      for (const value of wanted) {
        const option = document.createElement("option");
        option.value = value;
        option.textContent = value === "" ? "All networks" : value === WIRED ? "Wired / not on WiFi" : value;
        netEl.appendChild(option);
      }
      netEl.value = chosen;
    }
    return netEl.value;
  }

  // The router reports "2ghz-n", "5ghz-ax"…; NetSentry also uses "2.4ghz".
  function bandLabel(band) {
    if (band.indexOf("5") === 0) { return "5 GHz"; }
    if (band.indexOf("2") === 0) { return "2.4 GHz"; }
    if (band.indexOf("6") === 0) { return "6 GHz"; }
    return "";
  }

  function updateStats() {
    if (!statDevicesEl) {
      return;
    }
    const all = Array.from(devices.values());
    let active = 0;
    let unnamed = 0;
    let total = 0;
    for (const device of all) {
      if (device.active) {
        active += 1;
      }
      if (!device.name && device.can_tag) {
        unnamed += 1;
      }
      total += Number(device.tx_bps || 0) + Number(device.rx_bps || 0);
    }
    statDevicesEl.textContent = String(all.length);
    statActiveEl.textContent = String(active);
    statUntaggedEl.textContent = String(unnamed);
    if (statUntaggedCardEl) {
      statUntaggedCardEl.classList.toggle("is-warn", unnamed > 0);
    }
    const rate = formatRate(total).split(" ");
    const unit = document.createElement("small");
    unit.textContent = " " + (rate[1] || "B/s");
    statTrafficEl.replaceChildren(document.createTextNode(rate[0]), unit);
  }

  function rowFor(mac) {
    if (rows.has(mac)) {
      return rows.get(mac);
    }
    const row = template.content.firstElementChild.cloneNode(true);
    row.dataset.mac = mac;
    const formId = "edit-" + mac.replace(/[^0-9A-Za-z]/g, "");
    row.querySelector(".tag-form").id = formId;
    row.querySelector(".tag-toggle").setAttribute("aria-controls", formId);
    rows.set(mac, row);
    return row;
  }

  // What a person recognises first: the name, else the hostname.
  function displayName(device) {
    return device.name || device.hostname || "";
  }

  function armedText(mac, action, normal) {
    const a = armed.get(mac);
    return a && a.action === action ? ARM_TEXT[action] : normal;
  }

  function updateRow(row, device) {
    const open = openRows.has(device.mac);
    row.classList.toggle("is-editing", open);
    row.classList.toggle("is-retired", device.retired);
    row.classList.toggle("is-unnamed", !device.name && device.can_tag);

    const toggle = row.querySelector(".tag-toggle");
    toggle.disabled = !device.can_tag;
    toggle.setAttribute("aria-expanded", open ? "true" : "false");
    const label = displayName(device);
    const primary = row.querySelector(".id-primary");
    primary.textContent = label || (device.can_tag ? "Unnamed device" : "Unknown devices");
    primary.classList.toggle("is-placeholder", !label);
    row.querySelector(".edit-hint").textContent = open ? "Close" : (device.name ? "Edit" : "Name it");
    toggle.setAttribute("aria-label", (label || "Unnamed device") + " " + device.mac +
      (open ? " — close" : device.name ? " — edit" : " — name it"));
    row.querySelector(".mac").textContent = device.mac;

    row.querySelector(".ip").textContent = device.ip || "-";
    // The hostname is the main line when there is no name; do not repeat it.
    row.querySelector(".hostname").textContent = device.name ? device.hostname : "";
    row.querySelector(".tx strong").textContent = formatRate(device.tx_bps);
    row.querySelector(".rx strong").textContent = formatRate(device.rx_bps);

    const badge = row.querySelector(".activity-badge");
    badge.textContent = device.active ? "active" : "idle";
    badge.classList.toggle("is-active", device.active);

    const input = row.querySelector("input[name='name']");
    if (document.activeElement !== input) {
      input.value = device.name || "";
    }
    const net = row.querySelector(".net-chip");
    net.hidden = !device.ssid;
    if (device.ssid) {
      const parts = [device.ssid, bandLabel(device.band)];
      if (device.signal !== null) {
        parts.push(device.signal + " dBm");
      }
      net.textContent = parts.filter(Boolean).join(" · ");
      net.classList.toggle("is-guest", device.guest);
      net.classList.toggle("is-weak", device.signal !== null && device.signal <= -75);
    }
    row.classList.toggle("is-kept", device.kept);
    row.classList.toggle("is-blocked", device.blocked);

    const save = row.querySelector(".save-tag");
    save.disabled = !device.can_tag;
    const retire = row.querySelector(".retire-tag");
    retire.disabled = !device.can_tag;
    retire.hidden = device.retired;
    setArmed(retire, device.mac, "retire", "Mark as no longer used");

    const keepBtn = row.querySelector(".keep-toggle");
    keepBtn.hidden = !(device.guest || device.kept);
    setArmed(keepBtn, device.mac, device.kept ? "unkeep" : "keep",
      device.kept ? "Normal guest again" : "Keep password");

    const blockBtn = row.querySelector(".block-toggle");
    blockBtn.disabled = !device.can_tag;
    if (device.blocked) {
      blockBtn.textContent = "Unblock";
      blockBtn.classList.remove("is-armed");
    } else {
      setArmed(blockBtn, device.mac, "block", "Block");
    }

    const res = results.get(device.mac);
    const out = row.querySelector(".action-result");
    const text = res ? res.text : "";
    if (out.textContent !== text) {
      out.textContent = text;
    }
    out.classList.toggle("is-ok", Boolean(res && res.ok));
    out.classList.toggle("is-error", Boolean(res && !res.ok));
    drawSparkline(row.querySelector("canvas"), device.samples);
  }

  function setArmed(button, mac, action, normal) {
    const text = armedText(mac, action, normal);
    if (button.textContent !== text) {
      button.textContent = text;
    }
    button.classList.toggle("is-armed", text !== normal);
  }

  // A second tap confirms, like the Telegram buttons; the first one arms the
  // button for ARM_MS. Returns true when this tap should act.
  function secondTap(mac, action) {
    const current = armed.get(mac);
    if (current && current.action === action) {
      clearTimeout(current.timer);
      armed.delete(mac);
      return true;
    }
    if (current) {
      clearTimeout(current.timer);
    }
    armed.set(mac, {
      action: action,
      timer: setTimeout(function () {
        armed.delete(mac);
        scheduleRender();
      }, ARM_MS),
    });
    scheduleRender();
    return false;
  }

  function showResult(mac, ok, text) {
    const old = results.get(mac);
    if (old) {
      clearTimeout(old.timer);
    }
    results.set(mac, {
      ok: ok,
      text: (ok ? "✓ " : "✗ ") + text,
      timer: setTimeout(function () {
        results.delete(mac);
        scheduleRender();
      }, RESULT_MS),
    });
    scheduleRender();
  }

  function compareLabel(a, b) {
    return compareTextEmptyLast(displayName(a), displayName(b)) || a.mac.localeCompare(b.mac);
  }

  function refreshBusyRank() {
    const now = Date.now();
    if (now - busyAt < BUSIEST_RESORT_MS && busyRank.size) {
      return;
    }
    busyAt = now;
    busyRank = new Map(Array.from(devices.values())
      .sort(compareTrafficDesc)
      .map(function (device, index) { return [device.mac, index]; }));
  }

  function comparatorFor(mode) {
    const comparators = {
      "unnamed-first": function (a, b) {
        return Number(Boolean(a.name)) - Number(Boolean(b.name)) || compareLabel(a, b);
      },
      "name-asc": compareLabel,
      "network": function (a, b) {
        return compareTextEmptyLast(a.ssid, b.ssid) || compareLabel(a, b);
      },
      // Ranks are refreshed every BUSIEST_RESORT_MS so rows do not jump while
      // being read; a device that appeared since goes to the end.
      "busiest": function (a, b) {
        const ra = busyRank.has(a.mac) ? busyRank.get(a.mac) : Infinity;
        const rb = busyRank.has(b.mac) ? busyRank.get(b.mac) : Infinity;
        return (ra - rb) || compareLabel(a, b);
      },
    };
    return comparators[mode] || comparators[DEFAULT_SORT_MODE];
  }

  function compareTrafficDesc(a, b) {
    const totalA = a.tx_bps + a.rx_bps;
    const totalB = b.tx_bps + b.rx_bps;
    if (totalA !== totalB) {
      return totalB - totalA;
    }
    return a.last_activity_ms - b.last_activity_ms;
  }

  function compareTextEmptyLast(a, b) {
    const textA = (a || "").trim().toLowerCase();
    const textB = (b || "").trim().toLowerCase();
    if (!textA && textB) {
      return 1;
    }
    if (textA && !textB) {
      return -1;
    }
    return textA.localeCompare(textB);
  }

  function stabilizeEditingRows(sortedItems) {
    if (editingMacs.size === 0) {
      return sortedItems;
    }

    const sortedByMac = new Map(sortedItems.map(function (device) {
      return [device.mac, device];
    }));
    const nonEditingItems = sortedItems.filter(function (device) {
      return !editingMacs.has(device.mac);
    });
    const currentMacs = Array.from(listEl.children)
      .map(function (row) {
        return row.dataset.mac || "";
      })
      .filter(function (mac) {
        return sortedByMac.has(mac);
      });

    const stabilized = [];
    const pinned = new Set();
    let nonEditingIndex = 0;
    for (const mac of currentMacs) {
      if (editingMacs.has(mac)) {
        stabilized.push(sortedByMac.get(mac));
        pinned.add(mac);
        continue;
      }
      if (nonEditingIndex < nonEditingItems.length) {
        stabilized.push(nonEditingItems[nonEditingIndex]);
        nonEditingIndex += 1;
      }
    }
    while (nonEditingIndex < nonEditingItems.length) {
      stabilized.push(nonEditingItems[nonEditingIndex]);
      nonEditingIndex += 1;
    }
    for (const device of sortedItems) {
      if (editingMacs.has(device.mac) && !pinned.has(device.mac)) {
        stabilized.push(device);
      }
    }
    return stabilized;
  }

  function refreshEditingMacs() {
    editingMacs.clear();
    for (const mac of openRows) {
      editingMacs.add(mac);
    }
    for (const mac of focusedRows) {
      editingMacs.add(mac);
    }
    const row = document.activeElement
      ? document.activeElement.closest(".device-row")
      : null;
    if (row && row.dataset.mac) {
      editingMacs.add(row.dataset.mac);
    }
  }

  function closeEditing(mac, blurActive) {
    openRows.delete(mac);
    focusedRows.delete(mac);
    editingMacs.delete(mac);
    const pending = armed.get(mac);
    if (pending) {
      clearTimeout(pending.timer);
      armed.delete(mac);
    }
    if (blurActive) {
      const row = rows.get(mac);
      if (row && row.contains(document.activeElement)) {
        document.activeElement.blur();
      }
    }
    scheduleRender();
  }

  // Leave the "✓ Saved" readable for a moment, then fold the panel away —
  // unless the owner has gone back to editing.
  function closeSoon(mac) {
    setTimeout(function () {
      const row = rows.get(mac);
      const input = row ? row.querySelector("input[name='name']") : null;
      if (input && document.activeElement === input) {
        return;
      }
      closeEditing(mac, true);
    }, 1500);
  }

  function formatScan(res) {
    if (!res || res.ok === false) {
      return "⚠ " + ((res && res.error) || "scan unavailable");
    }
    if (!res.services || !res.services.length) {
      return "✔ No open TCP ports found (top 200).";
    }
    return res.services.map(function (s) {
      return s.port + "/" + s.proto + "  " + (s.service || "?") +
        (s.version ? "  " + s.version : "");
    }).join("\n");
  }

  function formatRate(value) {
    const units = ["B/s", "KB/s", "MB/s", "GB/s", "TB/s"];
    let amount = Math.max(0, Number(value || 0));
    let unit = 0;
    while (amount >= 1024 && unit < units.length - 1) {
      amount = amount / 1024;
      unit += 1;
    }
    if (unit === 0) {
      return Math.round(amount) + " " + units[unit];
    }
    return amount.toFixed(amount >= 10 ? 1 : 2) + " " + units[unit];
  }

  function drawSparkline(canvas, samples) {
    const ctx = canvas.getContext("2d");
    const width = canvas.width;
    const height = canvas.height;
    const accent = cssVar("--accent", "#80fff9");
    const border = cssVar("--border", "#2a3450");
    ctx.clearRect(0, 0, width, height);
    ctx.lineWidth = 1;
    ctx.strokeStyle = border;
    ctx.beginPath();
    ctx.moveTo(0, height - 1);
    ctx.lineTo(width, height - 1);
    ctx.stroke();

    if (!samples || samples.length < 2) {
      return;
    }

    const values = samples.map(function (sample) {
      return Math.max(0, Number(sample.tx || 0) + Number(sample.rx || 0));
    });
    const max = Math.max.apply(null, values);
    if (max <= 0) {
      return;
    }

    const points = values.map(function (value, index) {
      return {
        x: (index / (values.length - 1)) * (width - 1),
        y: height - 2 - (value / max) * (height - 4),
      };
    });

    ctx.fillStyle = hexToRgba(accent, 0.12);
    ctx.beginPath();
    ctx.moveTo(points[0].x, height - 1);
    points.forEach(function (point) {
      ctx.lineTo(point.x, point.y);
    });
    ctx.lineTo(points[points.length - 1].x, height - 1);
    ctx.closePath();
    ctx.fill();

    ctx.strokeStyle = accent;
    ctx.beginPath();
    points.forEach(function (point, index) {
      if (index === 0) {
        ctx.moveTo(point.x, point.y);
      } else {
        ctx.lineTo(point.x, point.y);
      }
    });
    ctx.stroke();
  }

  function cssVar(name, fallback) {
    const value = getComputedStyle(document.documentElement)
      .getPropertyValue(name)
      .trim();
    return value || fallback;
  }

  function hexToRgba(hex, alpha) {
    const clean = hex.replace("#", "").trim();
    if (!/^[0-9a-f]{6}$/i.test(clean)) {
      return "rgba(128, 255, 249, " + alpha + ")";
    }
    const r = parseInt(clean.slice(0, 2), 16);
    const g = parseInt(clean.slice(2, 4), 16);
    const b = parseInt(clean.slice(4, 6), 16);
    return "rgba(" + r + ", " + g + ", " + b + ", " + alpha + ")";
  }

  function loadSortMode() {
    let stored = "";
    try {
      stored = window.localStorage.getItem(SORT_STORAGE_KEY) || "";
    } catch (error) {
      stored = "";
    }
    let mode = LEGACY_SORT[stored] || stored;
    if (!mode || !sortEl.querySelector("option[value='" + mode + "']")) {
      mode = DEFAULT_SORT_MODE;
    }
    sortEl.value = mode;
    if (stored && stored !== mode) {
      saveSortMode();          // a choice from the old list: remember the new one
    }
  }

  function saveSortMode() {
    try {
      window.localStorage.setItem(SORT_STORAGE_KEY, sortEl.value);
    } catch (error) {
      return;
    }
  }

  const NO_ANSWER = "NetSentry did not answer — nothing changed";
  const KEEP_REFUSED = {
    "not-connected": "The device is not connected right now — nothing changed",
    unavailable: "Guest WiFi is not set up on this install — nothing changed",
    failed: "The router did not answer — nothing changed",
  };

  listEl.addEventListener("click", function (event) {
    const row = event.target.closest(".device-row");
    if (!row) {
      return;
    }
    const mac = row.dataset.mac;
    const device = devices.get(mac);
    if (!device) {
      return;
    }
    if (event.target.closest(".tag-toggle") && device.can_tag) {
      if (openRows.has(mac)) {
        closeEditing(mac, false);
      } else {
        openRows.add(mac);
        editingMacs.add(mac);
        scheduleRender();
      }
      return;
    }
    if (event.target.closest(".retire-tag") && device.can_tag) {
      if (!secondTap(mac, "retire")) {
        return;
      }
      NS.postJSON("/retire", { mac: mac })
        .then(function (result) {
          device.name = result.name || device.name;
          device.retired = true;
          showResult(mac, true, "Marked as no longer used");
          closeSoon(mac);
        })
        .catch(function () {
          showResult(mac, false, NO_ANSWER);
        });
      return;
    }
    if (event.target.closest(".scan-btn")) {
      const btn = event.target.closest(".scan-btn");
      const out = row.querySelector(".scan-out");
      out.hidden = false;
      if (!device.ip || device.ip === "-") {
        out.textContent = "No IP known for this device yet.";
        return;
      }
      btn.disabled = true;
      out.textContent = "🔍 Scanning " + device.ip + " … (up to ~30s)";
      NS.postJSON("/api/tools/nmap", { ip: device.ip })
        .then(function (res) { out.textContent = formatScan(res); })
        .catch(function () { out.textContent = "Scan failed."; })
        .then(function () { btn.disabled = false; });
      return;
    }
    if (event.target.closest(".keep-toggle") && device.can_tag) {
      const turnOn = !device.kept;
      if (!secondTap(mac, turnOn ? "keep" : "unkeep")) {
        return;
      }
      NS.postJSON("/keep", { mac: mac, on: turnOn })
        .then(function (result) {
          device.kept = Boolean(result.kept);
          if (result.ok) {
            showResult(mac, true, device.kept
              ? "Keeps its password — it reconnects for a moment"
              : "Normal guest again — it needs the shared password next time");
          } else {
            showResult(mac, false, KEEP_REFUSED[result.state] || "Not changed");
          }
        })
        .catch(function () {
          showResult(mac, false, NO_ANSWER);
        });
      return;
    }
    if (event.target.closest(".block-toggle") && device.can_tag) {
      const unblock = device.blocked;          // unblocking is one tap
      if (!unblock && !secondTap(mac, "block")) {
        return;
      }
      NS.postJSON(unblock ? "/unblock" : "/block", { mac: mac })
        .then(function (result) {
          device.blocked = Boolean(result.blocked);
          if (result.ok) {
            showResult(mac, true, device.blocked ? "Blocked on the router" : "Unblocked");
          } else {
            showResult(mac, false, "The router did not answer — nothing changed");
          }
        })
        .catch(function () {
          showResult(mac, false, NO_ANSWER);
        });
    }
  });

  listEl.addEventListener("focusin", function (event) {
    const row = event.target.closest(".device-row");
    if (!row || !row.dataset.mac) {
      return;
    }
    focusedRows.add(row.dataset.mac);
    editingMacs.add(row.dataset.mac);
  });

  listEl.addEventListener("focusout", function (event) {
    const row = event.target.closest(".device-row");
    if (!row || !row.dataset.mac) {
      return;
    }
    const mac = row.dataset.mac;
    window.setTimeout(function () {
      if (row.contains(document.activeElement)) {
        return;
      }
      focusedRows.delete(mac);
      editingMacs.delete(mac);
      // Keep the panel open while a two-tap is armed or a result is showing.
      if (!armed.has(mac) && !results.has(mac)) {
        openRows.delete(mac);
      }
      scheduleRender();
    }, 0);
  });

  listEl.addEventListener("keydown", function (event) {
    if (event.key !== "Escape") {
      return;
    }
    const row = event.target.closest(".device-row");
    if (!row || !row.dataset.mac) {
      return;
    }
    event.preventDefault();
    const toggle = row.querySelector(".tag-toggle");
    closeEditing(row.dataset.mac, true);
    if (toggle) {
      toggle.focus();
    }
  });

  listEl.addEventListener("submit", function (event) {
    const form = event.target.closest(".tag-form");
    if (!form) {
      return;
    }
    event.preventDefault();
    const row = form.closest(".device-row");
    const mac = row.dataset.mac;
    const device = devices.get(mac);
    const name = new FormData(form).get("name").toString().trim();
    if (!device || !device.can_tag) {
      return;
    }
    if (!name) {
      showResult(mac, false, "Type a name first");
      return;
    }
    NS.postJSON("/tag", { mac: mac, name: name })
      .then(function (result) {
        device.name = result.name || name;
        device.retired = false;
        const input = form.querySelector("input[name='name']");
        if (input && document.activeElement === input) {
          input.blur();
        }
        showResult(mac, true, "Saved");
        closeSoon(mac);
      })
      .catch(function () {
        showResult(mac, false, "Not saved — " + NO_ANSWER.split(" — ")[0]);
      });
  });

  searchEl.addEventListener("input", scheduleRender);
  if (netEl) {
    // "#net=<name>" (the network chips on the home page) preselects a network.
    const applyHash = function () {
      const fromHash = /^#net=(.+)$/.exec(window.location.hash || "");
      if (!fromHash) {
        return;
      }
      const option = document.createElement("option");
      option.value = decodeURIComponent(fromHash[1]);
      option.textContent = option.value;
      netEl.appendChild(option);
      netEl.value = option.value;
      scheduleRender();
    };
    applyHash();
    window.addEventListener("hashchange", applyHash);
    netEl.addEventListener("change", scheduleRender);
  }
  sortEl.addEventListener("change", function () {
    busyAt = 0;                // a fresh "Busiest now" order when picked
    saveSortMode();
    scheduleRender();
  });

  loadSortMode();
  connect();
})();
