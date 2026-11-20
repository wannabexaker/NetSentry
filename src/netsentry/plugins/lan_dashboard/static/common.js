/* NetSentry dashboard — helpers shared by every page (loaded by base.html).
   One status pill, one date format, one source for the tab badges. */
(function () {
  "use strict";

  const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

  function pad(n) { return (n < 10 ? "0" : "") + n; }

  function el(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) { node.className = cls; }
    if (text != null) { node.textContent = String(text); }
    return node;
  }

  function plural(n, one, many) {
    return n + " " + (n === 1 ? one : many);
  }

  function hhmm(date) { return pad(date.getHours()) + ":" + pad(date.getMinutes()); }

  // "Mon 23 Nov 09:00" (24-hour); the year only when it is not this year.
  function absolute(ts) {
    if (!ts) { return ""; }
    const d = new Date(ts * 1000);
    const year = d.getFullYear() !== new Date().getFullYear() ? " " + d.getFullYear() : "";
    return DAYS[d.getDay()] + " " + d.getDate() + " " + MONTHS[d.getMonth()] + year + " " + hhmm(d);
  }

  // Anything in the last 24 h reads "14 min ago"; older or future moments
  // use the absolute format. ts is epoch seconds.
  function when(ts) {
    if (!ts) { return ""; }
    const s = Date.now() / 1000 - ts;
    if (s >= 0 && s < 86400) {
      if (s < 60) { return "just now"; }
      if (s < 3600) { return Math.floor(s / 60) + " min ago"; }
      return Math.floor(s / 3600) + " h ago";
    }
    return absolute(ts);
  }

  // The header pill: "● live" / "updated 14:02" / "⚠ offline — retrying".
  function pill() { return document.getElementById("pageStatus"); }
  const status = {
    live: function () {
      const p = pill(); if (!p) { return; }
      p.textContent = "live"; p.className = "status-pill is-live";
    },
    updated: function (ts) {
      const p = pill(); if (!p) { return; }
      p.textContent = "updated " + hhmm(ts ? new Date(ts * 1000) : new Date());
      p.className = "status-pill";
    },
    offline: function () {
      const p = pill(); if (!p) { return; }
      p.textContent = "⚠ offline — retrying"; p.className = "status-pill is-error";
    },
    // A page-specific state (Remote: "armed 2:41", "disarmed"). kind: "live",
    // "error", "armed" or "" (neutral).
    show: function (text, kind) {
      const p = pill(); if (!p) { return; }
      p.textContent = text; p.className = "status-pill" + (kind ? " is-" + kind : "");
    },
  };

  async function getJSON(url) {
    const r = await fetch(url, { credentials: "same-origin" });
    if (!r.ok) { throw new Error(url + " answered " + r.status); }
    return r.json();
  }

  async function postJSON(url, body) {
    const r = await fetch(url, {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}),
    });
    if (!r.ok) { throw new Error(url + " answered " + r.status); }
    return r.json();
  }

  // Tab badges count only what needs the owner, from /api/overview `badges`.
  function setBadges(b) {
    if (!b) { return; }
    const set = function (id, n) {
      const node = document.getElementById(id);
      if (node) { node.textContent = n > 0 ? String(n) : ""; }
    };
    set("tabThreats", b.threats || 0);
    set("tabSystem", b.system || 0);
    set("tabDevices", b.devices || 0);
  }

  async function refreshBadges() {
    try { setBadges((await getJSON("/api/overview")).badges); } catch (e) { /* keep the last numbers */ }
  }

  window.NS = { el: el, plural: plural, when: when, absolute: absolute, status: status,
                getJSON: getJSON, postJSON: postJSON, setBadges: setBadges };

  // Home reads /api/overview itself and calls NS.setBadges; every other page
  // fetches the badges here so the numbers match on every page.
  document.addEventListener("DOMContentLoaded", function () {
    if (document.body.dataset.page !== "home") {
      refreshBadges();
      setInterval(refreshBadges, 60000);
    }
  });
})();
