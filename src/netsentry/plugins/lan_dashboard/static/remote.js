/* NetSentry dashboard — Remote: keyboard and mouse on the PC.
   Rules: nothing is sent while disarmed; everything goes as a JSON POST (no
   key ever appears in a URL); typed text is never stored (no localStorage,
   no cookies) and never shown in a message; the page disarms itself when it
   is hidden or closed. The server enforces the same rules on its side. */
(function () {
  "use strict";

  const $ = function (s) { return document.querySelector(s); };
  const live = $("#live"), armBtn = $("#armBtn"), box = $("#typeBox");
  const optShow = $("#optShow"), optLive = $("#optLive"), optEnter = $("#optEnter");
  const pad = $("#pad"), speed = $("#speed");
  const latched = new Set();
  let armed = false, deadline = 0, relayProblem = "", sentValue = "";
  let chain = Promise.resolve();

  // ─── talking to the server ────────────────────────────────────

  async function post(path, body) {
    let r;
    try {
      r = await fetch(path, {
        method: "POST", credentials: "same-origin", cache: "no-store",
        headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}),
      });
    } catch (e) {
      showError("Cannot reach NetSentry. Nothing was sent.");
      return false;
    }
    let data = null;
    try { data = await r.json(); } catch (e) { data = null; }
    if (!data) {
      showError(r.status === 403 ? "Signed out — open the dashboard link from Telegram again."
        : "NetSentry answered " + r.status + ".");
      return false;
    }
    if (data.state) { render(data.state); }
    if (data.ok) { clearError(); } else { showError(data.message || "Refused."); }
    return !!data.ok;
  }

  // Keyboard input keeps its order: one request after the other.
  function enqueue(fn) {
    chain = chain.then(fn, fn);
    return chain;
  }

  function showError(text) { const e = $("#rError"); e.textContent = text; e.hidden = false; }
  function clearError() { const e = $("#rError"); e.textContent = ""; e.hidden = true; }

  // ─── state on screen ──────────────────────────────────────────

  const CONTROL = {
    you: ["You have control", "pill--warn"],
    other: ["HIDway client in control", "pill--info"],
    none: ["Nobody in control", ""],
  };

  function render(st) {
    armed = !!st.armed;
    deadline = Date.now() + (st.armed_left_s || 0) * 1000;
    relayProblem = st.problem || "";
    armBtn.textContent = armed ? "Disarm" : "Arm";
    armBtn.className = "btn " + (armed ? "btn--danger" : "btn--primary");
    live.classList.toggle("remote-off", !armed);
    const c = CONTROL[st.control] || CONTROL.none;
    const pill = $("#rControl"); pill.textContent = c[0]; pill.className = "pill " + c[1];
    const bits = ["Relay " + (st.relay || "unknown")];
    if (st.relay === "running") {
      bits.push("Pico " + st.pico);
      bits.push("PC " + st.pc);
      if (st.encrypted != null) { bits.push(st.encrypted ? "encrypted" : "not encrypted"); }
    }
    if (st.transport) { bits.push(st.transport === "local" ? "via local socket" : "via UDP"); }
    $("#rLine").textContent = bits.join(" · ");
    if (relayProblem) { showError(relayProblem); }
    if (!armed) { forget(); }
    tick();
  }

  function mmss(s) { s = Math.max(0, Math.ceil(s)); return Math.floor(s / 60) + ":" + (s % 60 < 10 ? "0" : "") + (s % 60); }

  function tick() {
    const left = (deadline - Date.now()) / 1000;
    if (armed && left <= 0) { armed = false; refresh(); }
    if (relayProblem) {
      NS.status.show("⚠ relay unavailable", "error");
      $("#armText").textContent = "Cannot be used right now.";
    } else if (armed) {
      NS.status.show("armed " + mmss(left), "armed");
      $("#armText").textContent = "Armed — disarms after " + mmss(left) + " without input, or when you leave this page.";
    } else {
      NS.status.show("disarmed", "");
      $("#armText").textContent = "Disarmed — nothing reaches the PC until you tap Arm.";
    }
  }

  async function refresh() {
    try {
      const d = await NS.getJSON("/api/remote/status");
      if (d && d.state) { render(d.state); }
    } catch (e) {
      NS.status.offline();
    }
  }

  // Leaving the page: the text box is emptied, latches drop, the server disarms.
  function forget() {
    box.value = ""; sentValue = "";
    latched.clear();
    document.querySelectorAll("[data-mod]").forEach(function (b) { b.setAttribute("aria-pressed", "false"); b.classList.remove("btn--on"); });
  }

  function disarmNow() {
    forget();
    if (!armed) { return; }
    armed = false;
    try { navigator.sendBeacon("/api/remote/disarm", ""); } catch (e) { /* the idle timeout still applies */ }
  }

  // ─── keys ─────────────────────────────────────────────────────

  function takeMods() {
    const mods = Array.from(latched);
    latched.clear();
    document.querySelectorAll("[data-mod]").forEach(function (b) { b.setAttribute("aria-pressed", "false"); b.classList.remove("btn--on"); });
    return mods;
  }

  function pressKey(key, extra) {
    const mods = Array.from(new Set(takeMods().concat(extra || [])));
    return enqueue(function () { return post("/api/remote/key", { key: key, mods: mods }); });
  }

  document.querySelectorAll("[data-mod]").forEach(function (b) {
    b.addEventListener("click", function () {
      const m = b.dataset.mod;
      if (latched.has(m)) { latched.delete(m); } else { latched.add(m); }
      const on = latched.has(m);
      b.setAttribute("aria-pressed", on ? "true" : "false");
      b.classList.toggle("btn--on", on);
    });
  });

  document.querySelectorAll("[data-key]").forEach(function (b) {
    b.addEventListener("click", function () {
      if (!armed) { return; }
      pressKey(b.dataset.key, b.dataset.mods ? b.dataset.mods.split(",") : []);
    });
  });

  // ─── text ─────────────────────────────────────────────────────

  // One letter or digit with a latched modifier is a shortcut (Ctrl+C), not text.
  function sendText(text, enter) {
    if (latched.size && text.length === 1 && /^[A-Za-z0-9]$/.test(text)) {
      return pressKey(text.toLowerCase(), []);
    }
    return enqueue(function () { return post("/api/remote/text", { text: text, enter: !!enter }); });
  }

  optShow.addEventListener("change", function () { box.type = optShow.checked ? "text" : "password"; });
  optLive.addEventListener("change", function () { box.value = ""; sentValue = ""; box.focus(); });

  $("#typeForm").addEventListener("submit", function (e) {
    e.preventDefault();
    if (!armed) { return; }
    if (optLive.checked) {             // the text is already on the PC: Enter is a key
      box.value = ""; sentValue = "";
      pressKey("enter", []);
      return;
    }
    const text = box.value;
    if (!text) { return; }
    sendText(text, optEnter.checked).then(function (ok) { if (ok) { box.value = ""; } });
  });

  // "Send as I type": send what changed since the last send — characters
  // added at the end, or Backspaces for what was deleted.
  box.addEventListener("input", function () {
    if (!optLive.checked || !armed) { return; }
    const now = box.value;
    let same = 0;
    while (same < now.length && same < sentValue.length && now[same] === sentValue[same]) { same++; }
    const erase = sentValue.length - same, add = now.slice(same);
    sentValue = now;
    for (let i = 0; i < erase; i++) { pressKey("backspace", []); }
    if (add) { sendText(add, false); }
    if (now.length > 64) { box.value = ""; sentValue = ""; }   // keep the diff short
  });

  // ─── mouse ────────────────────────────────────────────────────

  const MAX_STEP = 400, FLUSH_MS = 60;
  const pointers = new Map();
  let accX = 0, accY = 0, accScroll = 0, moved = 0, downAt = 0, most = 0;
  let inFlight = false, timer = null;

  function take(v) { const n = Math.max(-MAX_STEP, Math.min(MAX_STEP, Math.trunc(v))); return n; }

  async function flush() {
    timer = null;
    if (inFlight || !armed) { return; }
    const dx = take(accX), dy = take(accY);
    const wheel = Math.max(-10, Math.min(10, Math.trunc(accScroll / 24)));
    if (!dx && !dy && !wheel) { return; }
    accX -= dx; accY -= dy; accScroll -= wheel * 24;
    inFlight = true;
    await post("/api/remote/mouse", { dx: dx, dy: dy, wheel: wheel });
    inFlight = false;
    if (accX || accY || Math.abs(accScroll) >= 24) { schedule(); }
  }

  function schedule() { if (!timer) { timer = setTimeout(flush, FLUSH_MS); } }

  function click(button, double) {
    return post("/api/remote/mouse", { click: button, double: !!double });
  }

  pad.addEventListener("pointerdown", function (e) {
    if (!armed) { return; }
    e.preventDefault();
    pad.setPointerCapture(e.pointerId);
    if (!pointers.size) { downAt = Date.now(); moved = 0; most = 0; }
    pointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
    most = Math.max(most, pointers.size);
    pad.classList.add("is-active");
  });

  pad.addEventListener("pointermove", function (e) {
    const p = pointers.get(e.pointerId);
    if (!p || !armed) { return; }
    const dx = e.clientX - p.x, dy = e.clientY - p.y;
    p.x = e.clientX; p.y = e.clientY;
    moved += Math.abs(dx) + Math.abs(dy);
    if (pointers.size >= 2) {
      if (e.pointerId === pointers.keys().next().value) { accScroll -= dy; }   // drag up = scroll down, like a phone
    } else {
      const k = Number(speed.value) || 2;
      accX += dx * k; accY += dy * k;
    }
    schedule();
  });

  function pointerEnd(e) {
    if (!pointers.delete(e.pointerId)) { return; }
    if (pointers.size) { return; }
    pad.classList.remove("is-active");
    if (armed && Date.now() - downAt < 250 && moved < 10) {
      click(most >= 2 ? "right" : "left", false);
    }
  }
  pad.addEventListener("pointerup", pointerEnd);
  pad.addEventListener("pointercancel", pointerEnd);

  document.querySelectorAll("[data-click]").forEach(function (b) {
    b.addEventListener("click", function () { if (armed) { click(b.dataset.click, b.dataset.double === "1"); } });
  });
  document.querySelectorAll("[data-wheel]").forEach(function (b) {
    b.addEventListener("click", function () { if (armed) { post("/api/remote/mouse", { wheel: Number(b.dataset.wheel) }); } });
  });

  // ─── arm / disarm ─────────────────────────────────────────────

  armBtn.addEventListener("click", function () {
    if (armed) {
      forget();
      post("/api/remote/disarm", {});
    } else {
      post("/api/remote/arm", {});
    }
  });

  document.addEventListener("visibilitychange", function () {
    if (document.visibilityState === "hidden") { disarmNow(); } else { refresh(); }
  });
  window.addEventListener("pagehide", disarmNow);

  refresh();
  setInterval(tick, 1000);
  setInterval(function () { if (document.visibilityState === "visible") { refresh(); } }, 3000);
})();
