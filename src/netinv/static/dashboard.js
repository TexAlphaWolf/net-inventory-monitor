// Everything that comes from the network (names, vendors) is written with textContent, never as
// HTML: a device can choose its own host name.
"use strict";

const $ = (id) => document.getElementById(id);
// Colour of each kind of change in the history table (not the notification severity).
const KIND_STYLE = {
  new_device: "medium", ip_takeover: "high", ip_changed: "info",
  device_offline: "medium", device_online: "low", baseline: "info",
};

class AuthError extends Error {}

function token() {
  try { return sessionStorage.getItem("netinv-token") || ""; } catch { return ""; }
}
function saveToken(value) {
  try { sessionStorage.setItem("netinv-token", value); } catch { /* storage unavailable */ }
}

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (token()) headers.Authorization = "Bearer " + token();
  if (options.body) headers["Content-Type"] = "application/json";
  const response = await fetch(path, { ...options, headers });
  if (response.status === 401) throw new AuthError("unauthorised");
  if (!response.ok && response.status !== 204) throw new Error("HTTP " + response.status);
  return response.status === 204 ? null : response.json();
}

function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function ago(iso) {
  const seconds = Math.max(0, (Date.now() - Date.parse(iso)) / 1000);
  if (seconds < 90) return "just now";
  if (seconds < 5400) return Math.round(seconds / 60) + " min ago";
  if (seconds < 129600) return Math.round(seconds / 3600) + " h ago";
  return Math.round(seconds / 86400) + " d ago";
}

function renderCards(stats) {
  const box = $("cards");
  box.replaceChildren();
  const items = [
    ["Devices", stats.devices, ""],
    ["Online", stats.online, "good"],
    ["Unknown", stats.unknown, stats.unknown ? "alert" : "good"],
    ["Changes 24h", stats.events_24h, ""],
  ];
  for (const [label, value, cls] of items) {
    const card = el("div", null, "card " + cls);
    card.append(el("div", value, "value"), el("div", label, "label"));
    box.append(card);
  }
  const scan = stats.scan;
  let text = stats.subnets.join(", ") + " - every " + Math.round(stats.interval_seconds / 60) + " min";
  if (scan.last_finished) text += " - last scan " + ago(scan.last_finished);
  if (scan.last_error) text += " - scan error: " + scan.last_error;
  $("status").textContent = text;
  $("scan").disabled = scan.running;
}

async function changeDevice(device, patch) {
  await api("/api/devices/" + encodeURIComponent(device.id), {
    method: "PATCH", body: JSON.stringify(patch),
  });
  await refresh();
}

function actionButton(text, handler) {
  const button = el("button", text);
  button.type = "button";
  button.addEventListener("click", () => handler().catch(showError));
  return button;
}

async function toggleHistory(device, row) {
  const next = row.nextElementSibling;
  if (next && next.dataset.history === device.id) { next.remove(); return; }
  const rows = await api("/api/devices/" + encodeURIComponent(device.id) + "/history?limit=96");
  const cell = el("td");
  cell.colSpan = 5;
  const strip = el("div", null, "strip");
  for (const probe of rows) {
    const bar = el("i", null, probe.up ? "" : "down");
    bar.title = probe.ts + (probe.up ? " up" : " down");
    strip.append(bar);
  }
  const facts = [
    "First seen " + device.first_seen, "ID " + device.id,
    device.details.other_ips ? "Also answers on " + device.details.other_ips.join(", ") : "",
    device.latency_ms !== null ? "Latency " + device.latency_ms + " ms" : "",
  ].filter(Boolean).join(" - ");
  cell.append(el("div", facts, "muted"), strip);
  const detail = el("tr");
  detail.dataset.history = device.id;
  detail.append(cell);
  row.after(detail);
}

function renderDevices(devices) {
  const body = $("devices").tBodies[0];
  body.replaceChildren();
  for (const device of devices) {
    const row = el("tr");
    const name = el("td");
    name.append(el("span", null, "dot " + (device.online ? "up" : "down")), el("strong", device.name));
    if (device.vendor && device.vendor !== device.name) name.append(el("div", device.vendor, "muted"));
    const tags = el("div", null, "muted");
    if (!device.trusted) tags.append(el("span", "unknown", "tag unknown"));
    if (device.watched) tags.append(el("span", "watched", "tag"));
    if (device.randomized) tags.append(el("span", "random MAC", "tag"));
    if (device.details.self) tags.append(el("span", "this machine", "tag"));
    name.append(tags);

    const address = el("td");
    address.append(el("div", device.ip, "mono"), el("div", device.mac || "no MAC (routed)", "muted mono"));

    const uptime = device.uptime_24h === null || device.uptime_24h === undefined ? "-" : device.uptime_24h + "%";
    const actions = el("td", null, "actions");
    actions.append(
      actionButton(device.trusted ? "Untrust" : "Trust", () => changeDevice(device, { trusted: !device.trusted })),
      actionButton(device.watched ? "Unwatch" : "Watch", () => changeDevice(device, { watched: !device.watched })),
      actionButton("Rename", async () => {
        const label = window.prompt("Name for this device (empty removes it)", device.label || "");
        if (label !== null) await changeDevice(device, { label });
      }),
      actionButton("History", () => toggleHistory(device, row)),
      actionButton("Forget", async () => {
        if (!window.confirm("Forget " + device.name + "?")) return;
        await api("/api/devices/" + encodeURIComponent(device.id), { method: "DELETE" });
        await refresh();
      }),
    );
    row.append(
      name, address, el("td", uptime, "hide-small"),
      el("td", ago(device.last_seen), "hide-small"), actions,
    );
    body.append(row);
  }
  if (!devices.length) {
    const row = el("tr");
    const cell = el("td", "No devices yet: the first scan is running.", "muted");
    cell.colSpan = 5;
    row.append(cell);
    body.append(row);
  }
}

function renderEvents(events) {
  const body = $("events").tBodies[0];
  body.replaceChildren();
  for (const event of events) {
    const row = el("tr");
    const kind = el("td");
    kind.append(el("span", event.kind.replace("_", " "), "sev " + (KIND_STYLE[event.kind] || "info")));
    row.append(el("td", new Date(event.ts).toLocaleString()), kind, el("td", event.message));
    body.append(row);
  }
}

function showError(error) {
  if (error instanceof AuthError) { $("login").hidden = false; return; }
  $("status").textContent = "error: " + error.message;
}

async function refresh() {
  try {
    const only = $("only-unknown").checked ? "?unknown=true" : "";
    const [stats, devices, events] = await Promise.all([
      api("/api/stats"), api("/api/devices" + only), api("/api/events?limit=30"),
    ]);
    $("login").hidden = true;
    renderCards(stats);
    renderDevices(devices);
    renderEvents(events);
  } catch (error) {
    showError(error);
  }
}

$("login").addEventListener("submit", (event) => {
  event.preventDefault();
  saveToken($("token").value);
  refresh();
});
$("only-unknown").addEventListener("change", refresh);
$("scan").addEventListener("click", async () => {
  $("scan").disabled = true;
  $("status").textContent = "scanning…";
  try { await api("/api/scan", { method: "POST" }); } catch (error) { showError(error); }
  await refresh();
});
$("export").addEventListener("click", async (event) => {
  if (!token()) return;  // no token needed: let the browser download the link
  event.preventDefault();
  const response = await fetch("/api/export?format=csv", { headers: { Authorization: "Bearer " + token() } });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(await response.blob());
  link.download = "devices.csv";
  link.click();
  URL.revokeObjectURL(link.href);
});

refresh();
setInterval(refresh, 30000);
