(function () {
  "use strict";

  const SORT_STORAGE_KEY = "netsentry.lan_dashboard.sortMode";
  const DEFAULT_SORT_MODE = "traffic-desc";
  // Auth is carried by the HttpOnly session cookie (set by /auth); the token
  // is never placed in a URL or request body.
  const listEl = document.getElementById("deviceList");
  const searchEl = document.getElementById("deviceSearch");
  const sortEl = document.getElementById("sortMode");
  const statusEl = document.getElementById("connectionStatus");
  const emptyEl = document.getElementById("emptyState");
  const template = document.getElementById("deviceRowTemplate");
  const statDevicesEl = document.getElementById("statDevices");
  const statActiveEl = document.getElementById("statActive");
  const statUntaggedEl = document.getElementById("statUntagged");
  const statUntaggedCardEl = document.getElementById("statUntaggedCard");
  const statTrafficEl = document.getElementById("statTraffic");
  const tabDevicesEl = document.getElementById("tabDevices");

  const devices = new Map();
  const rows = new Map();
  const openRows = new Set();
  const focusedRows = new Set();
  const editingMacs = new Set();
  let eventSource = null;
  let renderQueued = false;
  let reconnectTimer = null;

  function setStatus(text, className) {
    statusEl.textContent = text;
    statusEl.className = "status-pill " + (className || "");
  }

  function connect() {
    clearTimeout(reconnectTimer);
    if (eventSource) {
      eventSource.close();
    }
    setStatus("connecting", "");
    eventSource = new EventSource("/events");
    eventSource.onopen = function () {
      setStatus("live", "is-live");
    };
    eventSource.onmessage = function (event) {
      const payload = JSON.parse(event.data);
      applyPayload(payload);
      scheduleRender();
    };
    eventSource.onerror = function () {
      setStatus("reconnecting", "is-error");
      eventSource.close();
      reconnectTimer = setTimeout(connect, 3000);
    };
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
    const sortedItems = Array.from(devices.values())
      .filter(function (device) {
        if (!query) {
          return true;
        }
        return [device.mac, device.ip, device.hostname, device.name]
          .join(" ")
          .toLowerCase()
          .includes(query);
      })
      .sort(comparatorFor(sortEl.value || DEFAULT_SORT_MODE));

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

  function updateStats() {
    if (!statDevicesEl) {
      return;
    }
    const all = Array.from(devices.values());
    let active = 0;
    let untagged = 0;
    let total = 0;
    for (const device of all) {
      if (device.active) {
        active += 1;
      }
      if (!device.name) {
        untagged += 1;
      }
      total += Number(device.tx_bps || 0) + Number(device.rx_bps || 0);
    }
    statDevicesEl.textContent = String(all.length);
    statActiveEl.textContent = String(active);
    statUntaggedEl.textContent = String(untagged);
    if (statUntaggedCardEl) {
      statUntaggedCardEl.classList.toggle("is-warn", untagged > 0);
    }
    const rate = formatRate(total).split(" ");
    statTrafficEl.innerHTML = rate[0] + "<small> " + (rate[1] || "B/s") + "</small>";
    if (tabDevicesEl) {
      tabDevicesEl.textContent = String(all.length);
    }
  }

  function rowFor(mac) {
    if (rows.has(mac)) {
      return rows.get(mac);
    }
    const row = template.content.firstElementChild.cloneNode(true);
    row.dataset.mac = mac;
    rows.set(mac, row);
    return row;
  }

  function updateRow(row, device) {
    row.classList.toggle("is-editing", openRows.has(device.mac));
    row.classList.toggle("is-retired", device.retired);
    row.querySelector(".mac").textContent = device.mac;
    row.querySelector(".ip").textContent = device.ip || "-";
    row.querySelector(".hostname").textContent = device.hostname || "";
    row.querySelector(".tx strong").textContent = formatRate(device.tx_bps);
    row.querySelector(".rx strong").textContent = formatRate(device.rx_bps);

    const chip = row.querySelector(".tag-chip");
    chip.textContent = device.name || "?";
    chip.title = device.name ? "Rename" : "Name this";
    chip.disabled = !device.can_tag;
    chip.classList.toggle("is-empty", !device.name);

    const badge = row.querySelector(".activity-badge");
    badge.textContent = device.active ? "active" : "idle";
    badge.classList.toggle("is-active", device.active);

    const input = row.querySelector("input[name='name']");
    if (document.activeElement !== input) {
      input.value = device.name || "";
    }
    row.querySelector(".retire-tag").disabled = !device.can_tag;
    row.querySelector(".save-tag").disabled = !device.can_tag;
    row.classList.toggle("is-blocked", device.blocked);
    const blockBtn = row.querySelector(".block-toggle");
    blockBtn.textContent = device.blocked ? "Unblock" : "Block";
    blockBtn.disabled = !device.can_tag;
    drawSparkline(row.querySelector("canvas"), device.samples);
  }

  function comparatorFor(mode) {
    const traffic = compareTrafficDesc;
    const comparators = {
      "activity-desc": function (a, b) {
        return compareActivityDesc(a, b) || traffic(a, b);
      },
      "traffic-desc": traffic,
      "tx-desc": function (a, b) {
        return (b.tx_bps - a.tx_bps) || traffic(a, b);
      },
      "rx-desc": function (a, b) {
        return (b.rx_bps - a.rx_bps) || traffic(a, b);
      },
      "mac-asc": function (a, b) {
        return a.mac.localeCompare(b.mac);
      },
      "hostname-asc": function (a, b) {
        return compareTextEmptyLast(a.hostname, b.hostname) || traffic(a, b);
      },
      "tag-asc": function (a, b) {
        return compareTextEmptyLast(a.name, b.name) || traffic(a, b);
      },
      "unknown-first": function (a, b) {
        return Number(Boolean(a.name)) - Number(Boolean(b.name)) || traffic(a, b);
      },
      "known-first": function (a, b) {
        return Number(!a.name) - Number(!b.name) || traffic(a, b);
      },
    };
    return comparators[mode] || traffic;
  }

  function compareTrafficDesc(a, b) {
    const totalA = a.tx_bps + a.rx_bps;
    const totalB = b.tx_bps + b.rx_bps;
    if (totalA !== totalB) {
      return totalB - totalA;
    }
    return compareActivityDesc(a, b);
  }

  function compareActivityDesc(a, b) {
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
    if (blurActive) {
      const row = rows.get(mac);
      if (row && row.contains(document.activeElement)) {
        document.activeElement.blur();
      }
    }
    scheduleRender();
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

  async function postJson(path, body) {
    const response = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      throw new Error(await response.text());
    }
    return response.json();
  }

  function loadSortMode() {
    let stored = "";
    try {
      stored = window.localStorage.getItem(SORT_STORAGE_KEY) || "";
    } catch (error) {
      stored = "";
    }
    if (stored && sortEl.querySelector("option[value='" + stored + "']")) {
      sortEl.value = stored;
      return;
    }
    sortEl.value = DEFAULT_SORT_MODE;
  }

  function saveSortMode() {
    try {
      window.localStorage.setItem(SORT_STORAGE_KEY, sortEl.value);
    } catch (error) {
      return;
    }
  }

  listEl.addEventListener("click", function (event) {
    const row = event.target.closest(".device-row");
    if (!row) {
      return;
    }
    const mac = row.dataset.mac;
    const device = devices.get(mac);
    if (event.target.closest(".tag-toggle") && device && device.can_tag) {
      if (openRows.has(mac)) {
        closeEditing(mac, false);
      } else {
        openRows.add(mac);
        editingMacs.add(mac);
        scheduleRender();
      }
    }
    if (event.target.closest(".retire-tag") && device && device.can_tag) {
      postJson("/retire", { mac: mac })
        .then(function (result) {
          device.name = result.name || device.name;
          device.retired = true;
          closeEditing(mac, true);
        })
        .catch(function () {
          setStatus("write failed", "is-error");
        });
    }
    if (event.target.closest(".scan-btn") && device) {
      const btn = event.target.closest(".scan-btn");
      const out = row.querySelector(".scan-out");
      out.hidden = false;
      if (!device.ip || device.ip === "-") {
        out.textContent = "No IP known for this device yet.";
        return;
      }
      btn.disabled = true;
      out.textContent = "🔍 Scanning " + device.ip + " … (up to ~30s)";
      postJson("/api/tools/nmap", { ip: device.ip })
        .then(function (res) { out.textContent = formatScan(res); })
        .catch(function () { out.textContent = "Scan failed."; })
        .then(function () { btn.disabled = false; });
    }
    if (event.target.closest(".block-toggle") && device && device.can_tag) {
      const verb = device.blocked ? "Unblock" : "Block";
      if (!window.confirm(verb + " this device on the router?\n" + mac)) {
        return;
      }
      postJson(device.blocked ? "/unblock" : "/block", { mac: mac })
        .then(function (result) {
          device.blocked = Boolean(result.blocked);
          scheduleRender();
        })
        .catch(function () {
          setStatus("write failed", "is-error");
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
      openRows.delete(mac);
      focusedRows.delete(mac);
      editingMacs.delete(mac);
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
    closeEditing(row.dataset.mac, true);
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
    if (!device || !device.can_tag || !name) {
      return;
    }
    postJson("/tag", { mac: mac, name: name })
      .then(function (result) {
        device.name = result.name || name;
        device.retired = false;
        closeEditing(mac, true);
      })
      .catch(function () {
        setStatus("write failed", "is-error");
      });
  });

  searchEl.addEventListener("input", scheduleRender);
  sortEl.addEventListener("change", function () {
    saveSortMode();
    scheduleRender();
  });

  loadSortMode();
  connect();
})();
