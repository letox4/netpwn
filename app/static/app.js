// NetPwn - logica de la interfaz web

const state = {
  interfaces: [],
  gateway: null,
};

const $ = (sel) => document.querySelector(sel);
const el = (tag, props = {}, ...children) => {
  const node = document.createElement(tag);
  Object.assign(node, props);
  children.forEach((c) => node.append(c));
  return node;
};

function currentIface() {
  const name = $("#iface").value;
  return state.interfaces.find((i) => i.name === name) || null;
}

async function api(path, body) {
  const opts = { method: body ? "POST" : "GET" };
  if (body) {
    opts.headers = { "Content-Type": "application/json" };
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  if (!res.ok) {
    const txt = await res.text();
    throw new Error(txt || res.statusText);
  }
  return res.json();
}

// ------------------------------------------------------------------ Consola
const MAX_LOG_LINES = 400;
function log(type, text) {
  const line = el("div", { className: "line" });
  const ts = new Date().toLocaleTimeString();
  line.append(el("span", { className: "t", textContent: `[${ts}] ` }));
  line.append(el("span", { className: type, textContent: text }));
  const box = $("#log");
  box.append(line);
  // Tope: no dejamos que la consola crezca sin limite (pestaña abierta horas)
  while (box.children.length > MAX_LOG_LINES) box.removeChild(box.firstChild);
  box.scrollTop = box.scrollHeight;
}

// ------------------------------------------------------------------ WebSocket
function connectWS() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws`);
  ws.onopen = () => $("#ws-state").classList.add("on");
  ws.onclose = () => {
    $("#ws-state").classList.remove("on");
    setTimeout(connectWS, 2000);
  };
  ws.onmessage = (ev) => handleEvent(JSON.parse(ev.data));
}

function handleEvent(e) {
  switch (e.type) {
    case "packet": {
      const ports = e.sport ? `${e.sport} → ${e.dport}` : "";
      addRow("#sniff-body", [e.proto, e.src, e.dst, ports, e.info || ""], 200);
      break;
    }
    case "cred":
      if (e.proto === "info") { log("info", e.data); break; }
      addRow("#creds-body", [e.proto, e.data, `${e.src} → ${e.dst}`]);
      log("cred", `[${e.proto}] ${e.data}`);
      break;
    case "port":
      addRow("#ports-body", [e.port, e.service || "-", e.banner || ""]);
      break;
    case "portscan": log("info", e.msg); break;
    case "fingerprint": {
      const row = document.querySelector(`#hosts-body tr[data-ip="${e.ip}"] .os-cell`);
      if (row) row.textContent = e.os || "?";
      log("info", t("log.os", { ip: e.ip, os: e.os || "", ttl: e.ttl ? ` (TTL ${e.ttl})` : "" }));
      break;
    }
    case "inject": log("inject", e.msg); break;
    case "httpreq":
      addRow("#http-body", [e.host || "-", e.path || "/", e.dst || ""], 200);
      break;
    case "wifi_ap":
      addWifiAp(e);
      break;
    case "wifi_client":
      addWifiClient(e);
      break;
    case "wifi_eapol":
      updateHandshake(e.bssid, e.client, { msg: e.msg });
      log("wifi", `EAPOL M${e.msg}  ${e.client} @ ${e.bssid}`);
      break;
    case "handshake":
      updateHandshake(e.bssid, e.client, { captured: true, ssid: e.essid, file: e.file });
      log("cred", t("log.hs", { name: e.essid || e.bssid, file: e.file }));
      loadCaptures();
      break;
    case "hashcat":
      if (e.ok) log("cred", t("log.hashOk", { file: e.file, hashes: e.hashes }));
      else log("error", t("log.hashFail", { file: e.file, log: e.log || "" }));
      loadCaptures();
      break;
    case "wifi": log("wifi", e.msg); refreshWifiMode(); break;
    case "poison":
      if (e.proto === "info") { log("poison", e.msg); break; }
      addRow("#poison-body", [e.proto, e.name, e.src], 200);
      log("poison", t("poison.hit", { proto: e.proto, name: e.name, src: e.src }));
      break;
    case "wpad": log("wpad", e.msg); break;
    case "dns6":
      addRow("#mitm6-body", [e.qtype, e.name, e.src], 200);
      log("dns6", `[${e.qtype}] ${e.name} desde ${e.src}`);
      break;
    case "mitm6": log("dns6", e.msg); break;
    case "pmkid":
      log("cred", t("log.pmkid", { name: e.essid || e.bssid, file: e.file }));
      loadCaptures();
      break;
    case "cleanup": log("opsec", e.msg); break;
    case "opsec":
      log("opsec", e.msg);
      loadOpsec();
      break;
    case "arp": log("arp", e.msg); break;
    case "dns": log("dns", e.msg); break;
    case "sniff": log("sniff", e.msg); break;
    case "topology": log("info", `[topo] ${e.msg}`); break;
    case "camera":
      if (e.msg) log("camera", e.msg);
      if (e.found) {
        const c = e.found;
        addRow("#cam-body", ["info", "discovery", `${c.ip}:${c.port}`, c.vendor || c.service || "camera"]);
        $("#cam-discovered").dataset.dirty = "1";
      }
      if (e.module_done) log("camera", `← modulo ${e.module_done}: ${e.n} hallazgos`);
      if (e.finding) addCameraFinding(e.finding);
      if (e.audit_done) log("camera", `Audit completa: ${e.audit_done.findings.length} hallazgos`);
      break;
    case "error": log("error", e.msg); break;
    default: log("info", JSON.stringify(e));
  }
}

const wifiSeen = new Set();
const wifiApByBssid = new Map();
const wifiClientSeen = new Map();
function addWifiAp(ap) {
  if (wifiSeen.has(ap.bssid)) return;
  wifiSeen.add(ap.bssid);
  wifiApByBssid.set(ap.bssid.toLowerCase(), ap);
  const tbody = $("#wifi-body");
  const row = el("tr");
  [ap.ssid, ap.bssid, ap.channel ?? "?", ap.signal ?? "?", ap.enc].forEach(
    (c) => row.append(el("td", { textContent: String(c ?? "") }))
  );
  const td = el("td");
  td.append(el("button", {
    className: "mini danger", textContent: "Deauth",
    onclick: () => {
      $("#deauth-bssid").value = ap.bssid;
      if (ap.channel) $("#deauth-channel").value = ap.channel;
      renderDeauthClients();
      document.querySelector('.nav[data-panel="wifi"]').click();
    },
  }));
  td.append(document.createTextNode(" "));
  td.append(el("button", {
    className: "mini", textContent: "PMKID",
    onclick: () => {
      $("#pmkid-bssid").value = ap.bssid;
      if (ap.channel) $("#pmkid-channel").value = ap.channel;
      document.querySelector('.nav[data-panel="wifi"]').click();
      log("info", t("wifi.pmkidReady", { ssid: ap.ssid, bssid: ap.bssid }));
    },
  }));
  row.append(td);
  tbody.append(row);
}

function addWifiClient(client) {
  const bssid = String(client.bssid || "").toLowerCase();
  const mac = String(client.client || "").toLowerCase();
  if (!bssid || !mac) return;
  const key = `${bssid}|${mac}`;
  if (wifiClientSeen.has(key)) return;
  wifiClientSeen.set(key, client);
  const ap = wifiApByBssid.get(bssid);
  const row = el("tr");
  row.dataset.clientKey = key;
  const apLabel = ap?.ssid && ap.ssid !== "<oculto>" ? `${ap.ssid} — ${bssid}` : bssid;
  row.append(el("td", { textContent: apLabel }));
  row.append(el("td", { textContent: mac }));
  row.append(el("td", { textContent: client.signal == null ? "—" : `${client.signal} dBm` }));
  row.append(el("td", { textContent: client.channel || ap?.channel || "—" }));
  const action = el("td");
  action.append(el("button", {
    className: "mini", textContent: t("wifi.selectClientAction"),
    onclick: () => {
      $("#deauth-bssid").value = bssid;
      const channel = client.channel || ap?.channel;
      if (channel) $("#deauth-channel").value = channel;
      renderDeauthClients();
      $("#deauth-client").value = mac;
      document.querySelector('.nav[data-panel="wifi"]').click();
    },
  }));
  row.append(action);
  $("#wifi-clients-body").append(row);
  renderDeauthClients();
}

function renderDeauthClients() {
  const select = $("#deauth-client");
  if (!select) return;
  const selected = select.value;
  const bssid = $("#deauth-bssid").value.trim().toLowerCase();
  select.innerHTML = "";
  select.append(el("option", { value: "", textContent: t("wifi.selectClient") }));
  for (const client of wifiClientSeen.values()) {
    if (client.bssid.toLowerCase() !== bssid) continue;
    const label = `${client.client}${client.signal == null ? "" : ` (${client.signal} dBm)`}`;
    select.append(el("option", { value: client.client.toLowerCase(), textContent: label }));
  }
  if ([...select.options].some((o) => o.value === selected)) select.value = selected;
}

async function loadWifiClients() {
  try {
    const { clients } = await api("/api/wifi/clients");
    (clients || []).forEach(addWifiClient);
  } catch (e) {
    // Puede no haber un escaneo anterior; no es un error de arranque.
  }
}

// ---- Handshakes (tabla indexada por bssid+cliente) ----
const hsRows = {};
function updateHandshake(bssid, client, data) {
  const key = `${bssid}|${client}`;
  let st = hsRows[key];
  if (!st) {
    st = { msgs: new Set(), captured: false, ssid: "", file: "" };
    const row = el("tr");
    row.append(el("td", { className: "c-state" }));
    row.append(el("td", { className: "c-ssid" }));
    row.append(el("td", { textContent: bssid }));
    row.append(el("td", { textContent: client }));
    row.append(el("td", { className: "c-file" }));
    $("#hs-body").append(row);
    st.row = row;
    hsRows[key] = st;
  }
  if (data.msg) st.msgs.add(data.msg);
  if (data.captured) st.captured = true;
  if (data.ssid) st.ssid = data.ssid;
  if (data.file) st.file = data.file;
  const msgList = [...st.msgs].sort().map((m) => `M${m}`).join(" ");
  st.row.querySelector(".c-state").textContent = st.captured ? `✓ ${msgList}` : msgList;
  st.row.querySelector(".c-state").style.color = st.captured ? "var(--accent)" : "var(--muted)";
  st.row.querySelector(".c-ssid").textContent = st.ssid || "-";
  st.row.querySelector(".c-file").textContent = st.file || "-";
}

// ---- Lista de capturas guardadas ----
async function loadCaptures() {
  try {
    const { captures } = await api("/api/wifi/captures");
    const body = $("#captures-body");
    body.innerHTML = "";
    captures.forEach((f) => {
      const row = el("tr");
      row.append(el("td", { textContent: f.name }));
      row.append(el("td", { textContent: f.kind }));
      row.append(el("td", { textContent: `${(f.size / 1024).toFixed(1)} KB` }));
      const actions = el("td");
      if (f.kind === "pcap") {
        actions.append(el("button", {
          className: "mini primary", textContent: "→ hashcat (.22000)",
          onclick: () => convertCapture(f.name),
        }));
        actions.append(document.createTextNode(" "));
      }
      const dl = el("button", { className: "mini" });
      dl.dataset.i18n = "wifi.download";
      dl.textContent = t("wifi.download");
      dl.onclick = () => window.open(`/api/wifi/download?file=${encodeURIComponent(f.name)}`, "_blank");
      actions.append(dl);
      row.append(actions);
      body.append(row);
    });
  } catch (e) {
    log("error", e.message);
  }
}

async function convertCapture(name) {
  log("info", t("wifi.converting", { name }));
  try {
    const res = await api("/api/wifi/convert", { file: name });
    if (res.ok) log("cred", t("wifi.converted", { file: res.file, hashes: res.hashes }));
    else log("error", t("wifi.noHs", { name, log: res.log || "" }));
    loadCaptures();
  } catch (e) {
    log("error", e.message);
  }
}

function addRow(tbodySel, cells, maxRows) {
  const tbody = $(tbodySel);
  const row = el("tr");
  cells.forEach((c) => row.append(el("td", { textContent: String(c ?? "") })));
  tbody.prepend(row);
  if (maxRows && tbody.children.length > maxRows) {
    tbody.removeChild(tbody.lastChild);
  }
}

// ------------------------------------------------------------------ Camaras
function camSeverityColor(sev) {
  return { critical: "var(--danger)", high: "var(--amber)",
           medium: "var(--blue)", low: "var(--accent)", info: "var(--muted)" }[sev] || "var(--muted)";
}

function addCameraFinding(f) {
  const row = el("tr");
  const sev = el("td", { textContent: (f.severity || "info").toUpperCase(), className: "c-sev" });
  sev.style.color = camSeverityColor(f.severity);
  sev.style.fontWeight = "700";
  row.append(sev);
  row.append(el("td", { textContent: f.module || f.category || "-" }));
  row.append(el("td", { textContent: f.description || f.title || "-" }));
  row.append(el("td", { textContent: f.detail || f.evidence || f.url || "" }));
  $("#cam-body").prepend(row);
}

function camSelectedModules() {
  const sel = [];
  const map = { "cam-creds": "creds", "cam-rtsp": "rtsp", "cam-onvif": "onvif",
                "cam-http": "http", "cam-wifi": "wifi", "cam-modern": "modern",
                "cam-cloud": "cloud", "cam-vuln": "vuln" };
  for (const [id, mod] of Object.entries(map)) {
    if ($("#" + id).checked) sel.push(mod);
  }
  return sel;
}

async function runCameraAudit() {
  const target = $("#cam-target").value.trim();
  if (!target || !target.includes(".")) return log("error", "Target de camara invalido");
  const mods = camSelectedModules();
  if (!mods.length) return log("error", "Selecciona al menos un modulo");
  $("#cam-body").innerHTML = "";
  log("camera", `Audit de camara ${target}: ${mods.join(", ")}...`);
  try {
    const res = await api("/api/camera/audit", {
      target, modules: mods, timeout: 5, depth: 2,
      interface: ifaceName() || undefined,
    });
    log("camera", `Resultado: ${res.findings.length} hallazgos` +
      (res.errors.length ? `, errores: ${res.errors.join("; ")}` : ""));
  } catch (e) {
    log("error", e.message);
  }
}

async function runCameraDiscover() {
  const target = $("#cam-target").value.trim();
  if (!target || !target.includes("/")) return log("error", "Discovery necesita CIDR (ej. 192.168.1.0/24)");
  $("#cam-body").innerHTML = "";
  $("#cam-discovered").innerHTML = "";
  log("camera", `Descubriendo camaras en ${target}...`);
  try {
    const cams = await api("/api/camera/discover", { target, timeout: 3 });
    const box = $("#cam-discovered");
    if (!cams.length) {
      box.innerHTML = "";
      log("camera", "No se encontraron camaras");
      return;
    }
    log("camera", `Camaras encontradas: ${cams.length}`);
    cams.forEach((c) => {
      const row = el("tr");
      row.append(el("td", { textContent: c.ip }));
      row.append(el("td", { textContent: c.port }));
      row.append(el("td", { textContent: c.vendor || c.service || "-" }));
      const td = el("td");
      td.append(el("button", {
        className: "mini primary", textContent: "Auditar",
        onclick: () => { $("#cam-target").value = c.ip; runCameraAudit(); },
      }));
      row.append(td);
      box.append(row);
    });
  } catch (e) {
    log("error", e.message);
  }
}

$("#btn-cam-audit").addEventListener("click", runCameraAudit);
$("#btn-cam-discover").addEventListener("click", runCameraDiscover);
$("#btn-cam-clear").addEventListener("click", () => {
  $("#cam-body").innerHTML = "";
  $("#cam-discovered").innerHTML = "";
});

// ------------------------------------------------------------------ Navegacion
document.querySelectorAll(".nav").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".nav").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    $(`#panel-${btn.dataset.panel}`).classList.add("active");
  });
});

// ------------------------------------------------------------------ Interfaces
async function loadInterfaces() {
  const data = await api("/api/interfaces");
  state.interfaces = data.interfaces;
  state.gateway = data.gateway;
  const sel = $("#iface");
  sel.innerHTML = "";
  data.interfaces.forEach((i) => {
    const tag = i.ip || (i.wireless ? "wifi" : t("iface.noIp"));
    sel.append(el("option", { value: i.name, textContent: `${i.name} (${tag})` }));
  });
  if (data.gateway) {
    $("#gateway").textContent = `gateway: ${data.gateway.ip}`;
    $("#arp-gateway").value = data.gateway.ip;
  }
  refreshWifiMode();
}

// ------------------------------------------------------------------ Hosts
$("#btn-scan").addEventListener("click", async () => {
  const iface = currentIface();
  if (!iface || !iface.cidr) return log("error", t("hosts.noCidr"));
  log("info", t("hosts.scanning", { cidr: iface.cidr, name: iface.name }));
  $("#btn-scan").disabled = true;
  try {
    const { hosts } = await api("/api/discovery", { interface: iface.name, cidr: iface.cidr });
    const body = $("#hosts-body");
    body.innerHTML = "";
    hosts.forEach((h) => {
      const row = el("tr");
      row.dataset.ip = h.ip;
      row.append(el("td", { textContent: h.ip }));
      row.append(el("td", { textContent: h.mac }));
      row.append(el("td", { textContent: h.vendor || "-" }));
      row.append(el("td", { className: "os-cell", textContent: "-" }));
      const actions = el("td");
      const targetBtn = el("button", {
        className: "mini primary",
        onclick: () => { $("#arp-target").value = h.ip; $("#port-ip").value = h.ip; log("info", t("hosts.targetSet", { ip: h.ip })); },
      });
      targetBtn.dataset.i18n = "hosts.target";
      targetBtn.textContent = t("hosts.target");
      actions.append(targetBtn);
      actions.append(document.createTextNode(" "));
      const portsBtn = el("button", {
        className: "mini",
        onclick: () => scanPorts(h.ip),
      });
      portsBtn.dataset.i18n = "hosts.ports";
      portsBtn.textContent = t("hosts.ports");
      actions.append(portsBtn);
      actions.append(document.createTextNode(" "));
      const osBtn = el("button", {
        className: "mini",
        onclick: () => api("/api/fingerprint", { ip: h.ip, mac: h.mac }).catch((e) => log("error", e.message)),
      });
      osBtn.dataset.i18n = "hosts.osBtn";
      osBtn.textContent = t("hosts.osBtn");
      actions.append(osBtn);
      actions.append(document.createTextNode(" "));
      const expBtn = el("button", {
        className: "mini",
        textContent: "Exploits",
        onclick: () => checkExploitsForHost(h.ip),
      });
      actions.append(expBtn);
      row.append(actions);
      body.append(row);
    });
    log("info", t("hosts.found", { n: hosts.length }));
  } catch (e) {
    log("error", e.message);
  } finally {
    $("#btn-scan").disabled = false;
  }
});

let lastPortScanResults = [];
let lastPortScanIp = null;

// ------------------------------------------------------------------ Exploits
function renderExploitsResults(container, results) {
  container.innerHTML = "";
  if (!results || !results.length) {
    container.append(el("div", { className: "muted", textContent: "Sin exploits encontrados con ese producto/versión" }));
    return;
  }
  results.forEach((r) => {
    const group = el("div", { className: "exp-group" });
    const head = el("div", { className: "exp-head" });
    const svc = r.product || r.service || "unknown";
    const ver = r.version ? ` ${r.version}` : "";
    head.append(el("span", { textContent: `[${r.port}/${r.proto || "tcp"}] ${svc}${ver}` }));
    if (r.query) {
      head.append(el("span", { className: "muted", textContent: `  query: ${r.query}` }));
    }
    group.append(head);
    const ul = el("ul", { className: "exp-list" });
    (r.exploits || []).forEach((ex) => {
      const li = el("li");
      if (ex.url) {
        const a = el("a", { href: ex.url, target: "_blank", rel: "noopener", textContent: `${ex.edb_id || ""} - ${ex.title}` });
        li.append(a);
      } else {
        li.append(el("span", { textContent: ex.title }));
      }
      ul.append(li);
    });
    group.append(ul);
    container.append(group);
  });
}

async function checkExploitsForServices(ip, services) {
  try {
    const res = await api("/api/exploits/check", { ip, services });
    return res.results || [];
  } catch (e) {
    log("error", e.message);
    return [];
  }
}

async function checkExploitsForHost(ip) {
  const ports = lastPortScanIp === ip ? lastPortScanResults : [];
  if (!ports.length) {
    log("info", `Sin puertos guardados para ${ip}. Haz un portscan primero.`);
    document.querySelector('.nav[data-panel="ports"]').click();
    $("#port-ip").value = ip;
    return;
  }
  log("info", `Buscando exploits para ${ip} con ${ports.length} puertos...`);
  const results = await checkExploitsForServices(ip, ports);
  const section = $("#exploits-global");
  const box = $("#exploits-results");
  section.style.display = "block";
  renderExploitsResults(box, results);
  if (results.length) {
    log("info", `Exploits encontrados: ${results.length} servicio(s) con coincidencias`);
  } else {
    log("info", "Sin exploits encontrados con service+version/banners");
  }
}

$("#btn-exploits-clear").addEventListener("click", () => {
  $("#exploits-global").style.display = "none";
  $("#exploits-results").innerHTML = "";
});

$("#btn-exploits-ports").addEventListener("click", async () => {
  const ip = $("#port-ip").value.trim();
  if (!ip) return log("error", "Falta IP objetivo");
  const services = lastPortScanIp === ip ? lastPortScanResults : [];
  if (!services.length) {
    log("info", "No hay puertos escaneados aún. Ejecuta el portscan primero.");
    return;
  }
  const status = $("#exploits-ports-status");
  status.textContent = "Buscando...";
  try {
    const results = await checkExploitsForServices(ip, services);
    const panel = $("#exploits-ports-panel");
    const box = $("#exploits-ports-results");
    panel.style.display = "block";
    renderExploitsResults(box, results);
    if (results.length) {
      status.textContent = `${results.length} grupo(s) con resultados`;
      log("info", `Exploits: ${results.length} servicio(s) con coincidencias`);
    } else {
      status.textContent = "Sin resultados";
      log("info", "Sin exploits encontrados");
    }
  } catch (e) {
    status.textContent = "Error";
    log("error", e.message);
  }
});

// ------------------------------------------------------------------ Puertos
async function scanPorts(ip) {
  document.querySelector('.nav[data-panel="ports"]').click();
  $("#port-ip").value = ip;
  const ports = $("#port-range").value.trim() || null;
  const mode = $("#port-mode").value;
  const low = $("#port-lownoise").checked;
  log("info", t("ports.scanning", { ip, mode: `${mode}${low ? "/low-noise" : ""}` }));
  $("#ports-body").innerHTML = "";
  $("#exploits-ports-panel").style.display = "none";
  $("#exploits-ports-results").innerHTML = "";
  $("#exploits-ports-status").textContent = "";
  try {
    const { open } = await api("/api/portscan", { ip, ports, mode, low_noise: low });
    lastPortScanResults = Array.isArray(open) ? open.map((o) => ({ ...o, ip })) : [];
    lastPortScanIp = ip;
    // Las filas ya se fueron añadiendo en vivo por el evento "port";
    // este log final solo resume.
    log("info", t("ports.open", { n: open.length, ip }));
  } catch (e) {
    log("error", e.message);
  }
}
$("#btn-portscan").addEventListener("click", () => {
  const ip = $("#port-ip").value.trim();
  if (ip) scanPorts(ip);
});

// ------------------------------------------------------------------ Helper start/stop
function wire(startBtn, stopBtn, startPath, buildBody) {
  $(startBtn).addEventListener("click", async () => {
    try { await api(startPath + "/start", buildBody()); pollStatus(); }
    catch (e) { log("error", e.message); }
  });
  $(stopBtn).addEventListener("click", async () => {
    try { await api(startPath + "/stop", {}); pollStatus(); }
    catch (e) { log("error", e.message); }
  });
}

// ---- Estado en vivo de los modulos (polling /api/status) ----
// clave de /api/status -> [boton arrancar, boton parar]
const MODULE_BUTTONS = {
  arp: ["#btn-arp-start", "#btn-arp-stop"],
  sniffer: ["#btn-sniff-start", "#btn-sniff-stop"],
  dns: ["#btn-dns-start", "#btn-dns-stop"],
  creds: ["#btn-creds-start", "#btn-creds-stop"],
  httpinject: ["#btn-http-start", "#btn-http-stop"],
  wifi_scan: ["#btn-wifi-scan-start", "#btn-wifi-scan-stop"],
  handshake: ["#btn-hs-start", "#btn-hs-stop"],
  pmkid: ["#btn-pmkid-start", "#btn-pmkid-stop"],
  poison: ["#btn-poison-start", "#btn-poison-stop"],
  wpad: ["#btn-wpad-start", "#btn-wpad-stop"],
  mitm6: ["#btn-mitm6-start", "#btn-mitm6-stop"],
};

let lastModuleStatus = {};
async function pollStatus() {
  try {
    const st = await api("/api/status");
    lastModuleStatus = st;
    const active = [];
    for (const [key, [startSel, stopSel]] of Object.entries(MODULE_BUTTONS)) {
      const on = !!st[key];
      const startBtn = $(startSel);
      const stopBtn = $(stopSel);
      if (!startBtn || !stopBtn) continue;
      startBtn.classList.toggle("running", on);
      startBtn.disabled = on;
      stopBtn.disabled = !on;
      if (on) active.push(t(`module.${key}`) || key);
    }
    const pill = $("#active-modules");
    if (pill) {
      pill.hidden = active.length === 0;
      pill.textContent = `▲ ${active.length} ${active.length === 1 ? "activo" : "activos"}`;
      pill.title = active.join("\n");
    }
  } catch (e) {
    // backend caido: la pill del WS ya lo indica
  }
}

const ifaceName = () => (currentIface() ? currentIface().name : "");

wire("#btn-arp-start", "#btn-arp-stop", "/api/arp", () => ({
  interface: ifaceName(),
  target_ip: $("#arp-target").value.trim(),
  gateway_ip: $("#arp-gateway").value.trim(),
}));

wire("#btn-sniff-start", "#btn-sniff-stop", "/api/sniff", () => ({
  interface: ifaceName(),
  bpf: $("#sniff-bpf").value.trim() || null,
}));

wire("#btn-dns-start", "#btn-dns-stop", "/api/dns", () => {
  const mapping = {};
  $("#dns-map").value.split("\n").forEach((line) => {
    const [d, ip] = line.split("=").map((s) => s && s.trim());
    if (d && ip) mapping[d] = ip;
  });
  return { interface: ifaceName(), mapping, spoof_all_to: $("#dns-all").value.trim() || null };
});

wire("#btn-creds-start", "#btn-creds-stop", "/api/creds", () => ({ interface: ifaceName() }));

$("#btn-creds-export").addEventListener("click", () => {
  window.open("/api/creds/export", "_blank");
});

$("#btn-creds-clear").addEventListener("click", async () => {
  try {
    await api("/api/creds/clear", {});
    $("#creds-body").innerHTML = "";
    log("info", t("creds.cleared"));
  } catch (e) {
    log("error", e.message);
  }
});

wire("#btn-http-start", "#btn-http-stop", "/api/httpinject", () => ({
  inject: $("#http-inject").value,
  sslstrip: $("#http-sslstrip").checked,
  port: parseInt($("#http-port").value, 10) || 8080,
}));

// ------------------------------------------------------------------ Poisoners + WPAD
$("#btn-poison-start").addEventListener("click", async () => {
  const iface = ifaceName();
  if (!iface) return log("error", t("poison.needIface"));
  try {
    await api("/api/poison/start", {
      interface: iface,
      spoof_ip: $("#poison-ip").value.trim() || null,
      llmnr: $("#poison-llmnr").checked,
      nbtns: $("#poison-nbtns").checked,
      mdns: $("#poison-mdns").checked,
    });
    if ($("#poison-wpad").checked) {
      await api("/api/wpad/start", {
        interface: iface,
        proxy_port: parseInt($("#poison-proxyport").value, 10) || 3128,
      });
    }
    log("poison", t("poison.started"));
  } catch (e) {
    log("error", e.message);
  }
});

$("#btn-poison-stop").addEventListener("click", async () => {
  for (const path of ["/api/poison/stop", "/api/wpad/stop"]) {
    try { await api(path, {}); } catch (e) { log("error", e.message); }
  }
  log("poison", t("poison.stopped"));
});

// ------------------------------------------------------------------ mitm6
wire("#btn-mitm6-start", "#btn-mitm6-stop", "/api/mitm6", () => {
  const mapping = {};
  $("#mitm6-map").value.split("\n").forEach((line) => {
    const [d, ip] = line.split("=").map((s) => s && s.trim());
    if (d && ip) mapping[d] = ip;
  });
  return {
    interface: ifaceName(),
    mapping,
    redirect_http_port: $("#mitm6-redirect").checked
      ? (parseInt($("#http-port").value, 10) || 8080)
      : null,
  };
});

// ------------------------------------------------------------------ PANICO + entorno
$("#btn-panic").addEventListener("click", async () => {
  if (!confirm(t("panic.confirm"))) return;
  log("opsec", t("panic.running"));
  try {
    const res = await api("/api/panic", {});
    (res.actions || []).forEach((a) => log("opsec", a));
    loadOpsec().catch(() => {});
    loadInterfaces().catch(() => {});
  } catch (e) {
    log("error", e.message);
  }
});

async function loadEnvcheck() {
  try {
    const { warnings } = await api("/api/envcheck");
    const box = $("#envcheck");
    box.innerHTML = "";
    warnings.forEach((w) => {
      box.append(el("div", { className: `env-${w.level}`, textContent: w.msg }));
    });
    if (!warnings.length) {
      const ok = el("div", { className: "env-ok" });
      ok.dataset.i18n = "env.ok";
      ok.textContent = t("env.ok");
      box.append(ok);
    }
  } catch (e) {
    $("#envcheck").innerHTML = "";
  }
}

function wifiPrepare() {
  return $("#wifi-prepare").checked;
}

async function refreshWifiMode() {
  try {
    const data = await api("/api/wifi/ifaces");
    const name = ifaceName();
    const info = (data.interfaces || []).find((i) => i.name === name);
    $("#wifi-iface-name").textContent = name || "—";
    $("#wifi-mode").textContent = info ? info.mode : (name ? "?" : "—");
  } catch (e) {
    $("#wifi-iface-name").textContent = ifaceName() || "—";
  }
}

wire("#btn-wifi-scan-start", "#btn-wifi-scan-stop", "/api/wifi/scan", () => {
  wifiSeen.clear();
  wifiApByBssid.clear();
  wifiClientSeen.clear();
  $("#wifi-body").innerHTML = "";
  $("#wifi-clients-body").innerHTML = "";
  $("#deauth-client").innerHTML = "";
  $("#deauth-client").append(el("option", { value: "", textContent: t("wifi.selectClient") }));
  return { interface: ifaceName(), prepare: wifiPrepare() };
});

$("#deauth-bssid").addEventListener("input", renderDeauthClients);
$("#deauth-broadcast").addEventListener("change", () => {
  const on = $("#deauth-broadcast").checked;
  $("#deauth-client").disabled = on;
  $("#deauth-lownoise").disabled = on;
  if (on) log("wifi", t("wifi.broadcastArmed"));
});
$("#btn-deauth-start").addEventListener("click", async () => {
  const broadcast = $("#deauth-broadcast").checked;
  let client = $("#deauth-client").value;
  if (broadcast) {
    if (!confirm(t("wifi.broadcastConfirm"))) return;
    client = "ff:ff:ff:ff:ff:ff";
  } else if (!client) {
    return log("error", t("wifi.chooseDetectedClient"));
  }
  try {
    await api("/api/wifi/deauth/start", {
      interface: ifaceName(),
      bssid: $("#deauth-bssid").value.trim(),
      client,
      channel: parseInt($("#deauth-channel").value, 10) || null,
      prepare: wifiPrepare(),
      low_noise: $("#deauth-lownoise").checked,
      broadcast,
    });
  } catch (e) {
    log("error", e.message);
  }
});
$("#btn-deauth-stop").addEventListener("click", async () => {
  try { await api("/api/wifi/deauth/stop", {}); }
  catch (e) { log("error", e.message); }
});

wire("#btn-pmkid-start", "#btn-pmkid-stop", "/api/wifi/pmkid", () => ({
  interface: ifaceName(),
  bssid: $("#pmkid-bssid").value.trim(),
  channel: parseInt($("#pmkid-channel").value, 10) || null,
  auto_convert: $("#pmkid-auto").checked,
  prepare: wifiPrepare(),
}));

wire("#btn-hs-start", "#btn-hs-stop", "/api/wifi/handshake", () => ({
  interface: ifaceName(),
  channel: parseInt($("#hs-channel").value, 10) || null,
  auto_convert: $("#hs-auto").checked,
  prepare: wifiPrepare(),
}));

$("#btn-mon-start").addEventListener("click", async () => {
  try {
    const res = await api("/api/wifi/monitor/start", { interface: ifaceName(), prepare: true });
    log("wifi", t("wifi.monitorOn", { iface: res.interface || ifaceName() }));
    await loadInterfaces();
    if (res.interface) $("#iface").value = res.interface;
    refreshWifiMode();
  } catch (e) {
    log("error", e.message);
  }
});

$("#btn-mon-stop").addEventListener("click", async () => {
  try {
    const res = await api("/api/wifi/monitor/stop", { interface: ifaceName(), prepare: true });
    log("wifi", t("wifi.managedOn", { iface: res.interface || ifaceName() }));
    await loadInterfaces();
    if (res.interface) $("#iface").value = res.interface;
    refreshWifiMode();
  } catch (e) {
    log("error", e.message);
  }
});

$("#btn-wifi-kill").addEventListener("click", async () => {
  try {
    const res = await api("/api/wifi/kill", {});
    log("wifi", t("wifi.stoppedSvcs", { list: (res.stopped || []).join(", ") }));
  } catch (e) {
    log("error", e.message);
  }
});

$("#btn-wifi-restore").addEventListener("click", async () => {
  try {
    const res = await api("/api/wifi/restore-services", {});
    log("wifi", t("wifi.restoredSvcs", { list: (res.started || []).join(", ") }));
  } catch (e) {
    log("error", e.message);
  }
});

$("#btn-captures-refresh").addEventListener("click", loadCaptures);

$("#btn-clear").addEventListener("click", () => ($("#log").innerHTML = ""));

// ------------------------------------------------------------------ OPSEC
let opsecState = null;

function selectedOpsecIface() {
  return ifaceName() || (opsecState && opsecState.interfaces[0] && opsecState.interfaces[0].name) || "";
}

function ifaceOpsec(name) {
  if (!opsecState) return null;
  return opsecState.interfaces.find((i) => i.name === name) || null;
}

function renderOpsec() {
  if (!opsecState) return;
  const name = selectedOpsecIface();
  const link = ifaceOpsec(name);
  const host = opsecState.hostname || "—";
  const mac = (link && link.mac) || "—";
  const perm = (link && link.permanent) || "—";
  const spoofed = opsecState.spoofed || (link && link.spoofed);
  $("#opsec-host").textContent = host;
  $("#opsec-mac").textContent = mac;
  $("#opsec-perm").textContent = perm;
  $("#opsec-state").textContent = spoofed ? t("opsec.covered") : t("opsec.real");
  const pill = $("#opsec-id");
  pill.textContent = `${host} · ${mac}`;
  pill.classList.toggle("hot", !!spoofed);
  const vendorSel = $("#opsec-vendor");
  if (vendorSel && !vendorSel.options.length) {
    (opsecState.vendors || []).forEach((v) => {
      vendorSel.append(el("option", { value: v, textContent: v }));
    });
  }
  const box = $("#opsec-profiles");
  if (box && !box.dataset.ready) {
    box.dataset.ready = "1";
    (opsecState.profiles || []).forEach((p) => {
      const btn = el("button", { className: "profile", type: "button" });
      btn.append(document.createTextNode(p.label));
      btn.append(el("small", { textContent: p.blurb }));
      btn.addEventListener("click", () => applyOpsecProfile(p.id));
      box.append(btn);
    });
  }
}

async function loadOpsec() {
  try {
    opsecState = await api("/api/opsec");
    renderOpsec();
  } catch (e) {
    log("error", e.message);
  }
}

function opsecDhcp() {
  return $("#opsec-dhcp").checked;
}

async function applyOpsecProfile(id) {
  const iface = selectedOpsecIface();
  if (!iface) return log("error", t("opsec.needIface"));
  log("opsec", t("opsec.applying", { id, iface }));
  try {
    opsecState = await api("/api/opsec/profile", { interface: iface, profile: id, dhcp: opsecDhcp() });
    renderOpsec();
    loadInterfaces().catch(() => {});
  } catch (e) {
    log("error", e.message);
  }
}

$("#btn-opsec-genmac").addEventListener("click", async () => {
  try {
    const res = await api("/api/opsec/generate", { vendor: $("#opsec-vendor").value || null });
    $("#opsec-mac-in").value = res.mac;
    log("opsec", t("opsec.macGen", { vendor: res.vendor, mac: res.mac }));
  } catch (e) {
    log("error", e.message);
  }
});

$("#btn-opsec-genhost").addEventListener("click", async () => {
  try {
    const res = await api("/api/opsec/generate", { kind: "windows" });
    $("#opsec-hostname").value = res.hostname;
    $("#opsec-pretty").value = "DESKTOP";
  } catch (e) {
    log("error", e.message);
  }
});

$("#btn-opsec-apply").addEventListener("click", async () => {
  const hostname = $("#opsec-hostname").value.trim();
  if (!hostname) return log("error", t("opsec.needHostGen"));
  try {
    opsecState = await api("/api/opsec/apply", {
      interface: selectedOpsecIface(),
      hostname,
      pretty: $("#opsec-pretty").value.trim() || null,
      mac: $("#opsec-mac-in").value.trim() || null,
      vendor: $("#opsec-vendor").value || null,
      dhcp: opsecDhcp(),
    });
    renderOpsec();
    loadInterfaces().catch(() => {});
  } catch (e) {
    log("error", e.message);
  }
});

$("#btn-opsec-host-only").addEventListener("click", async () => {
  const hostname = $("#opsec-hostname").value.trim();
  if (!hostname) return log("error", t("opsec.needHost"));
  try {
    opsecState = await api("/api/opsec/hostname", {
      hostname,
      pretty: $("#opsec-pretty").value.trim() || null,
    });
    renderOpsec();
  } catch (e) {
    log("error", e.message);
  }
});

$("#btn-opsec-mac-only").addEventListener("click", async () => {
  try {
    opsecState = await api("/api/opsec/mac", {
      interface: selectedOpsecIface(),
      mac: $("#opsec-mac-in").value.trim() || null,
      vendor: $("#opsec-vendor").value || null,
      dhcp: opsecDhcp(),
    });
    renderOpsec();
    loadInterfaces().catch(() => {});
  } catch (e) {
    log("error", e.message);
  }
});

$("#btn-opsec-restore").addEventListener("click", async () => {
  try {
    opsecState = await api("/api/opsec/restore", {});
    renderOpsec();
    loadInterfaces().catch(() => {});
  } catch (e) {
    log("error", e.message);
  }
});

$("#iface").addEventListener("change", () => {
  renderOpsec();
  refreshWifiMode();
});

// ------------------------------------------------------------------ Topologia
const TOPO_TYPES = {
  self:     { label: "topo.t.self",     color: "#39ff88" },
  router:   { label: "topo.t.router",   color: "#4dd8ff" },
  internet: { label: "topo.t.internet", color: "#c8e6d3" },
  pc:       { label: "topo.t.pc",       color: "#4dd8ff" },
  phone:    { label: "topo.t.phone",    color: "#c77dff" },
  tv:       { label: "topo.t.tv",       color: "#ffc857" },
  printer:  { label: "topo.t.printer",  color: "#ff9ecb" },
  iot:      { label: "topo.t.iot",      color: "#ffa657" },
  camera:   { label: "topo.t.camera",   color: "#ff4d5e" },
  console:  { label: "topo.t.console",  color: "#79c0ff" },
  nas:      { label: "topo.t.nas",      color: "#39d3a0" },
  speaker:  { label: "topo.t.speaker",  color: "#d2a8ff" },
  plc:      { label: "topo.t.plc",      color: "#ffb020" },
  hmi:      { label: "topo.t.hmi",      color: "#3ddc97" },
  rtu:      { label: "topo.t.rtu",      color: "#e08a3c" },
  scada:    { label: "topo.t.scada",    color: "#7ec8ff" },
  drive:    { label: "topo.t.drive",    color: "#ff6b3d" },
  relay:    { label: "topo.t.relay",    color: "#f0d56a" },
  robot:    { label: "topo.t.robot",    color: "#b6e354" },
  switch:   { label: "topo.t.switch",   color: "#4dd8ff" },
  gateway:  { label: "topo.t.gateway",  color: "#c9a6ff" },
  sensor:   { label: "topo.t.sensor",   color: "#5ee0d0" },
  unknown:  { label: "topo.t.unknown",  color: "#5f8371" },
};

const TOPO_GROUPS = [
  ["topo.group.plant", ["plc", "hmi", "rtu", "scada", "drive", "relay", "robot", "switch", "gateway", "sensor"]],
  ["topo.group.net", ["self", "router", "pc", "phone", "tv", "printer", "iot", "camera", "console", "nas", "speaker", "unknown"]],
];

// Iconos vectoriales (viewport 24x24, trazo redondeado) por tipo de aparato.
const TOPO_ICONS = {
  router: {
    paths: ["M4.5 11.2h15v8.2h-15z", "M8 11.2V6.4", "M16 11.2V6.4"],
    dots: [[8, 5.1], [16, 5.1], [8, 15], [12, 15], [16, 15]],
  },
  pc: {
    paths: ["M6 4.2h12v9H6z", "M3.2 15.2h17.6", "M5.2 15.2h13.6l-1.1 3.4H6.3z"],
  },
  phone: {
    paths: [
      "M9 2.4h6a2 2 0 0 1 2 2v15.2a2 2 0 0 1-2 2H9a2 2 0 0 1-2-2V4.4a2 2 0 0 1 2-2z",
      "M10.6 18.7h2.8",
    ],
  },
  tv: {
    paths: ["M3 4.2h18v11.2H3z", "M8.2 15.4l-1.4 3.4", "M15.8 15.4l1.4 3.4"],
  },
  printer: {
    paths: ["M7.2 8V3.4h9.6V8", "M4 8.4h16v6.4H4z", "M7.4 13.2h9.2V20.4H7.4z"],
    dots: [[16.6, 11]],
  },
  iot: {
    paths: [
      "M12 2.6a5.4 5.4 0 0 0-3.4 9.6c.7.6 1.1 1.3 1.2 2.1h4.4c.1-.8.5-1.5 1.2-2.1A5.4 5.4 0 0 0 12 2.6z",
      "M9.5 16.4h5",
      "M10.2 18.6h3.6",
      "M10.7 20.7h2.6",
    ],
  },
  camera: {
    paths: ["M12 14.4v3.8", "M8 20.8h8"],
    circles: [[12, 9, 5], [12, 9, 1.8]],
  },
  console: {
    paths: [
      "M8 9.6h8a3.6 3.6 0 0 1 3.6 3.6v.6a2.7 2.7 0 0 1-4.6 1.9l-.9-1.1H9.9l-.9 1.1A2.7 2.7 0 0 1 4.4 13.8v-.6A3.6 3.6 0 0 1 8 9.6z",
      "M8.1 12v2.5",
      "M6.85 13.25h2.5",
    ],
    dots: [[15.5, 12.2], [17.5, 14.2]],
  },
  nas: {
    paths: ["M4 4.4h16v6.2H4z", "M4 13.4h16v6.2H4z"],
    dots: [[7.1, 7.5], [7.1, 16.5]],
  },
  speaker: {
    paths: ["M9 2.8h6a1.6 1.6 0 0 1 1.6 1.6v15.2a1.6 1.6 0 0 1-1.6 1.6H9a1.6 1.6 0 0 1-1.6-1.6V4.4A1.6 1.6 0 0 1 9 2.8z"],
    circles: [[12, 15.2, 2.5]],
    dots: [[12, 7]],
  },
  self: {
    paths: ["M3.2 4.4h17.6v14.2H3.2z", "M7 9l2.7 2.4L7 13.8", "M11.6 14.2h4.6"],
  },
  internet: {
    paths: ["M7 18.2a4.6 4.6 0 0 1-.5-9.1A6.1 6.1 0 0 1 18.2 8.2 3.9 3.9 0 0 1 17.6 18.2H7z"],
  },
  unknown: { circles: [[12, 12, 8.4]], text: "?" },
  plc: {
    paths: ["M3.2 6.2h17.6v11.6H3.2z", "M7.6 6.2v11.6", "M12 6.2v11.6", "M16.4 6.2v11.6"],
    dots: [[5.4, 9.6], [5.4, 14.4], [9.8, 12], [14.2, 12]],
  },
  hmi: {
    paths: ["M2.6 3.6h18.8v16.8H2.6z", "M4.6 5.8h11.4v9.4H4.6z", "M17.2 7h1.6", "M17.2 10.6h1.6", "M17.2 14.2h1.6"],
  },
  rtu: {
    paths: ["M7 8.2h10v12H7z", "M12 8.2V3.8"],
    dots: [[12, 2.8], [9.4, 12.6], [12, 12.6], [14.6, 12.6]],
  },
  scada: {
    paths: ["M1.6 5.2h9.4v7.4H1.6z", "M13 7h9.4v7.4H13z", "M6.3 12.6v2.8", "M17.7 14.4v1.8", "M3.8 17.8h16.4"],
  },
  drive: {
    paths: ["M4 3.6h16v16.8H4z", "M7.2 7h9.6", "M7.2 10h9.6", "M7.2 13h9.6", "M8 16.6h8"],
  },
  relay: {
    paths: ["M6.2 2.8h11.6v18.4H6.2z", "M8.2 5.8h7.6v3.8H8.2z"],
    dots: [[9, 12.8], [12, 12.8], [15, 12.8], [9, 16.6], [15, 16.6]],
  },
  robot: {
    paths: ["M4.8 19.6h7.2", "M8.4 19.6V14", "M8.4 14h6.4", "M14.8 14V8", "M14.8 8h4"],
    circles: [[18.8, 8, 1.7], [8.4, 19.6, 2.1]],
  },
  switch: {
    paths: ["M3 8h18v8.4H3z", "M6 10.2v4", "M9.4 10.2v4", "M12.8 10.2v4", "M16.2 10.2v4"],
    dots: [[5, 9.2]],
  },
  gateway: {
    paths: ["M2.4 7h6.4v10H2.4z", "M15.2 7h6.4v10h-6.4z", "M8.8 12h4.4", "M11.8 9.6 L14.8 12 L11.8 14.4"],
  },
  sensor: {
    paths: ["M12 11.2v6.6", "M8 20.4h8"],
    circles: [[12, 7.2, 3.8]],
  },
};

function drawTopoIcon(ctx, type, x, y, size, color) {
  const icon = TOPO_ICONS[type] || TOPO_ICONS.unknown;
  const s = size / 24;
  ctx.save();
  ctx.translate(x - 12 * s, y - 12 * s);
  ctx.scale(s, s);
  ctx.strokeStyle = color;
  ctx.fillStyle = color;
  ctx.lineWidth = 1.9 / s;
  ctx.lineJoin = "round";
  ctx.lineCap = "round";
  for (const d of icon.paths || []) {
    ctx.stroke(new Path2D(d));
  }
  for (const [cx, cy, r] of icon.circles || []) {
    ctx.beginPath();
    ctx.arc(cx, cy, r, 0, Math.PI * 2);
    ctx.stroke();
  }
  for (const [dx, dy] of icon.dots || []) {
    ctx.beginPath();
    ctx.arc(dx, dy, 1.1, 0, Math.PI * 2);
    ctx.fill();
  }
  if (icon.text) {
    ctx.font = "700 11px monospace";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText(icon.text, 12, 12.5);
  }
  ctx.restore();
  ctx.textBaseline = "alphabetic";
}

const topo = { nodes: [], edges: [], running: false, raf: null, drag: null, pan: { x: 0, y: 0 }, zoom: 1, selected: null };

function topoCanvas() { return $("#topo-canvas"); }

function resizeTopo() {
  const canvas = topoCanvas();
  const dpr = window.devicePixelRatio || 1;
  const r = canvas.getBoundingClientRect();
  if (r.width === 0) return false;  // panel oculto
  const w = Math.round(r.width * dpr), h = Math.round(r.height * dpr);
  if (canvas.width !== w || canvas.height !== h) {
    canvas.width = w;
    canvas.height = h;
    canvas.getContext("2d").setTransform(dpr, 0, 0, dpr, 0, 0);
  }
  return true;
}

function initTopo() {
  const canvas = topoCanvas();
  resizeTopo();
  window.addEventListener("resize", resizeTopo);
  renderTopoLegend();

  // Pan / zoom / drag de nodos
  let panning = false, last = { x: 0, y: 0 };
  canvas.addEventListener("mousedown", (ev) => {
    const n = pickNode(ev.offsetX, ev.offsetY);
    if (n) { topo.drag = n; n.fixed = true; }
    else { panning = true; last = { x: ev.offsetX, y: ev.offsetY }; canvas.classList.add("dragging"); }
  });
  canvas.addEventListener("mousemove", (ev) => {
    if (topo.drag) {
      const c = toWorld(ev.offsetX, ev.offsetY);
      topo.drag.x = c.x; topo.drag.y = c.y;
      topo.drag.vx = topo.drag.vy = 0;
    } else if (panning) {
      topo.pan.x += ev.offsetX - last.x;
      topo.pan.y += ev.offsetY - last.y;
      last = { x: ev.offsetX, y: ev.offsetY };
    }
  });
  window.addEventListener("mouseup", () => { panning = false; if (topo.drag) topo.drag.fixed = false; topo.drag = null; canvas.classList.remove("dragging"); });
  canvas.addEventListener("click", (ev) => {
    const n = pickNode(ev.offsetX, ev.offsetY);
    if (n) showTopoDetails(n); else hideTopoDetails();
  });
  canvas.addEventListener("wheel", (ev) => {
    ev.preventDefault();
    const f = ev.deltaY < 0 ? 1.12 : 0.89;
    topo.zoom = Math.min(3, Math.max(0.25, topo.zoom * f));
  }, { passive: false });
}

function toWorld(sx, sy) { return { x: (sx - topo.pan.x) / topo.zoom, y: (sy - topo.pan.y) / topo.zoom }; }
function toScreen(wx, wy) { return { x: wx * topo.zoom + topo.pan.x, y: wy * topo.zoom + topo.pan.y }; }

function pickNode(sx, sy) {
  for (const n of topo.nodes) {
    const p = toScreen(n.x, n.y);
    if (Math.hypot(p.x - sx, p.y - sy) < 24 * topo.zoom) return n;
  }
  return null;
}

function paintTypeIcon(canvas, type, color, cssSize) {
  const dpr = window.devicePixelRatio || 1;
  canvas.width = Math.round(cssSize * dpr);
  canvas.height = Math.round(cssSize * dpr);
  canvas.className = "lg-icon";
  canvas.style.width = `${cssSize}px`;
  canvas.style.height = `${cssSize}px`;
  const ictx = canvas.getContext("2d");
  ictx.setTransform(dpr, 0, 0, dpr, 0, 0);
  drawTopoIcon(ictx, type, cssSize / 2, cssSize / 2, cssSize - 1, color);
}

function renderTopoLegend() {
  const box = $("#topo-legend");
  box.innerHTML = "";
  for (const [title, types] of TOPO_GROUPS) {
    const col = el("div", { className: "lg-col" });
    col.append(el("div", { className: "lg-title", textContent: t(title) }));
    for (const type of types) {
      const cfg = TOPO_TYPES[type];
      if (!cfg) continue;
      const icon = document.createElement("canvas");
      paintTypeIcon(icon, type, cfg.color, 15);
      col.append(el("div", { className: "lg-item" },
        icon,
        el("span", { textContent: t(cfg.label) })));
    }
    box.append(col);
  }
}

function seedTopo(data) {
  const W = topoCanvas().parentElement.getBoundingClientRect();
  const cx = W.width / 2, cy = W.height / 2;
  const byId = new Map();
  topo.nodes = data.nodes.map((n, i) => {
    const angle = (i / Math.max(1, data.nodes.length - 1)) * Math.PI * 2;
    const radius = n.type === "internet" ? 0 : n.type === "router" ? 110 : 240 + (i % 3) * 50;
    const node = {
      ...n, x: cx + Math.cos(angle) * radius + (Math.random() - 0.5) * 30,
      y: cy + Math.sin(angle) * radius + (Math.random() - 0.5) * 30,
      vx: 0, vy: 0, fixed: false,
    };
    byId.set(node.id, node);
    return node;
  });
  topo.edges = data.edges
    .map((e) => ({ a: byId.get(e.source), b: byId.get(e.target) }))
    .filter((e) => e.a && e.b);
}

function stepTopo() {
  const nodes = topo.nodes;
  // Repulsion entre todos (O(n^2), suficiente para redes domesticas)
  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
      const a = nodes[i], b = nodes[j];
      let dx = a.x - b.x, dy = a.y - b.y;
      let d2 = dx * dx + dy * dy || 1;
      if (d2 > 260 * 260) continue;
      const d = Math.sqrt(d2);
      const f = 2600 / d2;
      dx /= d; dy /= d;
      a.vx += dx * f; a.vy += dy * f;
      b.vx -= dx * f; b.vy -= dy * f;
    }
  }
  // Muelles en las aristas
  for (const e of topo.edges) {
    const dx = e.b.x - e.a.x, dy = e.b.y - e.a.y;
    const d = Math.hypot(dx, dy) || 1;
    const target = 150;
    const f = (d - target) * 0.015;
    const ux = dx / d, uy = dy / d;
    e.a.vx += ux * f; e.a.vy += uy * f;
    e.b.vx -= ux * f; e.b.vy -= uy * f;
  }
  // Gravedad suave hacia el centro + integracion
  const W = topoCanvas().parentElement.getBoundingClientRect();
  const cx = W.width / 2, cy = W.height / 2;
  for (const n of nodes) {
    if (n.fixed) continue;
    if (n.type === "internet") { n.x = cx; n.y = cy - 210; n.vx = n.vy = 0; continue; }
    n.vx += (cx - n.x) * 0.0018;
    n.vy += (cy - n.y) * 0.0018;
    n.vx *= 0.85; n.vy *= 0.85;
    n.x += Math.max(-14, Math.min(14, n.vx));
    n.y += Math.max(-14, Math.min(14, n.vy));
  }
}

function drawTopo() {
  const canvas = topoCanvas();
  const ctx = canvas.getContext("2d");
  const W = canvas.width / (window.devicePixelRatio || 1);
  const H = canvas.height / (window.devicePixelRatio || 1);
  ctx.clearRect(0, 0, W, H);

  // Aristas
  for (const e of topo.edges) {
    const p1 = toScreen(e.a.x, e.a.y), p2 = toScreen(e.b.x, e.b.y);
    if (e.kind === "traffic") {
      // Relacion inferida del trafico: ambar, grosor segun volumen
      ctx.strokeStyle = "rgba(255, 200, 87, 0.55)";
      ctx.lineWidth = 1 + Math.min(2.5, Math.log2((e.count || 1) + 1) / 2);
      ctx.setLineDash([]);
    } else {
      const isUp = e.a.type === "internet" || e.b.type === "internet";
      ctx.strokeStyle = isUp ? "rgba(200, 230, 211, 0.18)" : "rgba(57, 255, 136, 0.25)";
      ctx.lineWidth = 1.2;
      ctx.setLineDash(isUp ? [4, 6] : []);
    }
    ctx.beginPath();
    ctx.moveTo(p1.x, p1.y);
    ctx.lineTo(p2.x, p2.y);
    ctx.stroke();
  }
  ctx.setLineDash([]);

  // Nodos
  ctx.textAlign = "center";
  for (const n of topo.nodes) {
    const cfg = TOPO_TYPES[n.type] || TOPO_TYPES.unknown;
    const p = toScreen(n.x, n.y);
    const base = (n.type === "router" || n.type === "self") ? 22
      : (n.type === "internet" ? 19 : 16);
    const rad = Math.max(14, base * topo.zoom);
    const glow = n === topo.selected ? 16 : (n.type === "self" || n.type === "router") ? 10 : 0;

    if (glow) {
      ctx.shadowColor = cfg.color;
      ctx.shadowBlur = glow;
    }
    ctx.fillStyle = "rgba(6, 10, 8, 0.95)";
    ctx.beginPath();
    ctx.arc(p.x, p.y, rad, 0, Math.PI * 2);
    ctx.fill();
    ctx.shadowBlur = 0;

    ctx.strokeStyle = n === topo.selected ? "#fff" : cfg.color;
    ctx.lineWidth = n === topo.selected ? 2.5 : 1.6;
    ctx.stroke();

    const ink = n === topo.selected ? "#f4fff8" : cfg.color;
    drawTopoIcon(ctx, n.type, p.x, p.y, rad * 1.32, ink);

    ctx.textAlign = "center";
    ctx.textBaseline = "alphabetic";
    ctx.font = `${Math.max(10, 12 * topo.zoom)}px "Bebas Neue", monospace`;
    ctx.fillStyle = "#c8e6d3";
    const label = n.type === "self" ? t("topo.t.self") : (n.label || n.ip || n.id);
    ctx.fillText(label.length > 18 ? label.slice(0, 17) + "…" : label, p.x, p.y + rad + 16);
    if (n.ip) {
      ctx.fillStyle = "#5f8371";
      ctx.fillText(n.ip, p.x, p.y + rad + 29);
    }
  }
}

function topoLoop() {
  if (!topo.running) return;
  if (document.getElementById("panel-topo").classList.contains("active") && resizeTopo()) {
    stepTopo();
    drawTopo();
  }
  topo.raf = requestAnimationFrame(topoLoop);
}

function showTopoDetails(n) {
  topo.selected = n;
  const cfg = TOPO_TYPES[n.type] || TOPO_TYPES.unknown;
  const box = $("#topo-details");
  box.style.display = "";
  box.innerHTML = "";
  const tipo = el("div", {});
  tipo.append(el("span", { className: "muted", textContent: t("topo.f.type") }));
  const tipoVal = el("div", { className: "topo-type-val" });
  const tipoIcon = document.createElement("canvas");
  paintTypeIcon(tipoIcon, n.type, cfg.color, 18);
  tipoVal.append(tipoIcon, el("strong", { textContent: t(cfg.label) }));
  tipo.append(tipoVal);
  box.append(tipo);
  const fields = [
    ["IP", n.ip || "—"],
    ["Hostname", n.hostname || "—"],
    ["MAC", n.mac || "—"],
    [t("topo.f.vendor"), n.vendor || "—"],
    [t("topo.f.os"), n.os ? `${n.os}${n.ttl ? ` (TTL ${n.ttl})` : ""}` : "—"],
    [t("topo.f.ports"), (n.open_ports && n.open_ports.length) ? n.open_ports.join(", ") : "—"],
    [t("topo.f.conf"), n.confidence ? `${n.confidence}%` : "—"],
    [t("topo.f.evidence"), (n.evidence || []).join(" · ") || "—"],
  ];
  for (const [k, v] of fields) {
    box.append(el("div", {}, el("span", { className: "muted", textContent: k }), el("strong", { textContent: String(v) })));
  }
}

function hideTopoDetails() { topo.selected = null; $("#topo-details").style.display = "none"; }

async function runTopology(aggressive) {
  const iface = currentIface();
  if (!iface || !iface.cidr) return log("error", t("hosts.noCidr"));
  const btn = aggressive ? $("#btn-topo-aggressive") : $("#btn-topo-passive");
  btn.disabled = true;
  btn.textContent = aggressive ? t("topo.scanning") : t("topo.mapping");
  log("info", t("topo.running", {
    mode: aggressive ? t("topo.modeAgg") : t("topo.modeQuiet"),
    cidr: iface.cidr,
  }));
  try {
    const data = await api("/api/topology", { interface: iface.name, cidr: iface.cidr, aggressive });
    seedTopo(data);
    topo.pan = { x: 0, y: 0 };
    topo.zoom = 1;
    if (!topo.running) { topo.running = true; topoLoop(); }
    log("info", t("topo.ready", { nodes: data.nodes.length, edges: data.edges.length }));
  } catch (e) {
    log("error", t("topo.fail", { msg: e.message }));
  } finally {
    btn.disabled = false;
    btn.textContent = aggressive ? t("topo.aggressive") : t("topo.passive");
  }
}

$("#btn-topo-passive").addEventListener("click", () => runTopology(false));
$("#btn-topo-aggressive").addEventListener("click", () => runTopology(true));

// ------------------------------------------------------------------ Demo (?demo=1)
const TOPO_DEMO = {
  nodes: [
    { id: "self", ip: "10.10.20.50", type: "self", label: "Tu maquina", confidence: 100, evidence: ["interfaz eth0"] },
    { id: "gw-10.10.20.1", ip: "10.10.20.1", type: "router", label: "FW-PLANTA", mac: "00:1a:2b:10:00:01", vendor: "Cisco", confidence: 96, hostname: "fw-planta", os: "Router (TTL 255)", ttl: 255, open_ports: [22, 443], evidence: ["OUI: Cisco", "gateway por defecto"] },
    { id: "internet", type: "internet", label: "Internet / WAN", confidence: 100 },
    { id: "host-10.10.20.2", ip: "10.10.20.2", type: "switch", label: "CELDA-SW", mac: "00:90:e8:11:22:33", vendor: "Moxa", hostname: "celda-sw", os: "Switch (TTL 255)", ttl: 255, open_ports: [22, 80, 161], confidence: 90, evidence: ["OUI: Moxa", "hostname: switch"] },
    { id: "host-10.10.20.10", ip: "10.10.20.10", type: "plc", label: "S7-1500-LINEA1", mac: "00:1b:1b:aa:10:10", vendor: "Siemens", hostname: "s7-1500-linea1", os: "PLC (TTL 64)", ttl: 64, open_ports: [102, 443], confidence: 96, evidence: ["puertos [102]", "OUI: Siemens", "hostname: s7-1500"] },
    { id: "host-10.10.20.11", ip: "10.10.20.11", type: "plc", label: "CompactLogix", mac: "00:00:bc:bb:11:11", vendor: "Rockwell", hostname: "compactlogix-prensa", os: "PLC (TTL 64)", ttl: 64, open_ports: [44818], confidence: 96, evidence: ["puertos [44818]", "OUI: Rockwell"] },
    { id: "host-10.10.20.12", ip: "10.10.20.12", type: "hmi", label: "HMI-PRENSA", mac: "00:0e:8c:12:12:12", vendor: "Siemens", hostname: "hmi-prensa", os: "Linux (TTL 64)", ttl: 64, open_ports: [80, 443], confidence: 84, evidence: ["hostname: hmi"] },
    { id: "host-10.10.20.20", ip: "10.10.20.20", type: "scada", label: "SCADA-SALA", mac: "00:0c:29:20:20:20", vendor: "VMware", hostname: "scada-sala", os: "Windows (TTL 128)", ttl: 128, open_ports: [443, 4840], confidence: 92, evidence: ["puertos [4840]", "hostname: scada"] },
    { id: "host-10.10.20.15", ip: "10.10.20.15", type: "gateway", label: "ANYBUS-GW", mac: "00:30:11:15:15:15", vendor: "HMS Industrial", hostname: "anybus-gw", os: "Linux (TTL 64)", ttl: 64, open_ports: [80, 502], confidence: 88, evidence: ["OUI: HMS Industrial", "hostname: anybus"] },
    { id: "host-10.10.20.30", ip: "10.10.20.30", type: "drive", label: "VFD-BOMBA", mac: "00:1b:1b:30:30:30", vendor: "Danfoss", hostname: "vfd-bomba2", os: "Variador", ttl: 64, open_ports: [80], confidence: 80, evidence: ["OUI: Danfoss", "hostname: vfd"] },
    { id: "host-10.10.20.31", ip: "10.10.20.31", type: "robot", label: "FANUC-R30", mac: "00:e0:e4:31:31:31", vendor: "FANUC", hostname: "fanuc-r30", os: "Linux (TTL 64)", ttl: 64, open_ports: [80], confidence: 90, evidence: ["OUI: FANUC", "hostname: fanuc"] },
    { id: "host-10.10.20.40", ip: "10.10.20.40", type: "rtu", label: "RTU-SUBEST", mac: "00:a0:f8:40:40:40", vendor: "GE", hostname: "rtu-subest", os: "RTU", ttl: 64, open_ports: [2404, 20000], confidence: 94, evidence: ["puertos [2404, 20000]", "hostname: rtu"] },
    { id: "host-10.10.20.41", ip: "10.10.20.41", type: "relay", label: "SEL-751", mac: "00:30:a7:41:41:41", vendor: "Schweitzer Engineering", hostname: "rele-751", os: "Rele", ttl: 64, open_ports: [23, 80], confidence: 86, evidence: ["OUI: Schweitzer", "hostname: rele-"] },
    { id: "host-10.10.20.60", ip: "10.10.20.60", type: "sensor", label: "TT-TANQUE", mac: "00:0e:8c:60:60:60", vendor: "Endress+Hauser", hostname: "transmisor-tanque", os: "Instrumento", ttl: 64, open_ports: [], confidence: 78, evidence: ["OUI: Endress+Hauser", "hostname: transmisor"] },
    { id: "host-10.10.20.25", ip: "10.10.20.25", type: "pc", label: "ENG-01", mac: "3c:07:54:25:25:25", vendor: "Dell", hostname: "eng-01", os: "Windows (TTL 128)", ttl: 128, open_ports: [445, 3389], confidence: 70, evidence: ["puertos [445, 3389]", "OUI: Dell"] },
    { id: "host-10.10.20.99", ip: "10.10.20.99", type: "unknown", label: "10.10.20.99", mac: "5c:cf:7f:99:99:99", vendor: "", os: "", open_ports: [], confidence: 0, evidence: ["sin respuesta ICMP"] },
  ],
  edges: [
    { source: "self", target: "gw-10.10.20.1" },
    { source: "gw-10.10.20.1", target: "internet" },
    { source: "gw-10.10.20.1", target: "host-10.10.20.2" },
    { source: "host-10.10.20.2", target: "host-10.10.20.10" },
    { source: "host-10.10.20.2", target: "host-10.10.20.11" },
    { source: "host-10.10.20.2", target: "host-10.10.20.12" },
    { source: "host-10.10.20.2", target: "host-10.10.20.20" },
    { source: "host-10.10.20.2", target: "host-10.10.20.15" },
    { source: "host-10.10.20.2", target: "host-10.10.20.30" },
    { source: "host-10.10.20.2", target: "host-10.10.20.31" },
    { source: "host-10.10.20.2", target: "host-10.10.20.40" },
    { source: "host-10.10.20.2", target: "host-10.10.20.41" },
    { source: "host-10.10.20.2", target: "host-10.10.20.60" },
    { source: "host-10.10.20.2", target: "host-10.10.20.25" },
    { source: "host-10.10.20.2", target: "host-10.10.20.99" },
  ],
};

// ------------------------------------------------------------------ Init
loadInterfaces().catch((e) => log("error", e.message));
loadWifiClients();
loadCaptures();
loadOpsec();
loadEnvcheck();
connectWS();
initTopo();
pollStatus();
setInterval(pollStatus, 3000);

// Modo demo: grafo inventado para previsualizar sin backend (?demo=1)
if (new URLSearchParams(location.search).has("demo")) {
  seedTopo(TOPO_DEMO);
  topo.running = true;
  topoLoop();
  document.querySelector('.nav[data-panel="topo"]').click();
  log("info", t("log.demo"));
}

$("#lang").addEventListener("change", () => setLang($("#lang").value));
window.addEventListener("netpwn-lang", () => {
  renderTopoLegend();
  if (topo.selected) showTopoDetails(topo.selected);
  renderOpsec();
  const sel = $("#iface");
  const current = sel.value;
  sel.innerHTML = "";
  state.interfaces.forEach((i) => {
    const tag = i.ip || (i.wireless ? "wifi" : t("iface.noIp"));
    sel.append(el("option", { value: i.name, textContent: `${i.name} (${tag})` }));
  });
  if (current) sel.value = current;
});
applyI18n();
