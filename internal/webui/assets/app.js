"use strict";

const $ = (id) => document.getElementById(id);
const tokenKey = "onesocks.apiToken";
const state = { config: null, nodes: [], subscriptions: [], status: null, generation: 0, detailID: "", format: "link", loading: false, busy: false, page: "nodes", nodePage: 1 };
const extraFilterIDs = ["protocol-filter", "country-filter", "latency-status-filter", "ip-status-filter", "latency-max-filter", "score-max-filter"];
const filterIDs = ["node-search", "subscription-filter", ...extraFilterIDs, "node-sort"];
const probes = new Map();
let batch = null;
let detailPage = "connection";
let detailTrigger = null;
let token = "";
let session = 0;
let pollTimer;
let noticeTimer;
let editing = null;
let deleting = null;

function savedToken(value) {
  try {
    if (value === undefined) return sessionStorage.getItem(tokenKey) || "";
    if (value) sessionStorage.setItem(tokenKey, value);
    else sessionStorage.removeItem(tokenKey);
  } catch { /* The current session also works without browser storage. */ }
  return "";
}

function notify(message, error = false, persistent = false) {
  clearTimeout(noticeTimer);
  $("notice-message").textContent = message;
  $("notice").classList.toggle("error", error);
  $("notice").hidden = !message;
  if (message && !error && !persistent) noticeTimer = setTimeout(() => { $("notice").hidden = true; }, 2600);
}

function formError(id, message) {
  $(id).textContent = message;
  $(id).hidden = !message;
}

function showLogin(message = "") {
  session++;
  stopProbes();
  probes.clear();
  batch = null;
  $("probe-progress").textContent = "";
  token = "";
  savedToken("");
  clearTimeout(pollTimer);
  document.querySelectorAll("dialog[open]").forEach((dialog) => dialog.close());
  state.nodes = [];
  state.subscriptions = [];
  state.config = null;
  state.detailID = "";
  state.loading = false;
  state.busy = false;
  for (const id of filterIDs) $(id).value = "";
  state.nodePage = 1;
  setExportOpen(false);
  renderFilter();
  $("boot-panel").hidden = true;
  $("app").hidden = true;
  $("login-panel").hidden = false;
  $("api-token").value = "";
  $("socks-password").value = "";
  formError("login-error", message);
  notify("");
  renderNodes();
  renderSubscriptions();
  $("api-token").focus();
}

async function api(path, options = {}, onResult) {
  const currentSession = session;
  const headers = { Accept: "application/json", ...options.headers };
  if (token) headers.Authorization = "Bearer " + token;
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  const response = await fetch(path, { ...options, headers, cache: "no-store", credentials: "same-origin" });
  if (response.status === 401) {
    if (currentSession === session) showLogin(token ? "API token 无效" : "");
    const error = new Error("需要登录");
    error.unauthorized = true;
    throw error;
  }
  if (response.status === 204) return null;
  if (response.ok && onResult) {
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    try {
      while (true) {
        const { value, done } = await reader.read();
        buffer += decoder.decode(value, { stream: !done });
        const lines = buffer.split("\n");
        buffer = lines.pop();
        for (const line of lines) if (line.trim()) onResult(JSON.parse(line));
        if (done) break;
      }
      if (buffer.trim()) onResult(JSON.parse(buffer));
    } finally { reader.releaseLock(); }
    return;
  }
  let result;
  try { result = await response.json(); } catch {}
  if (!response.ok) throw new Error(result?.error?.message || `请求失败（HTTP ${response.status}）`);
  if (result === undefined) throw new Error("服务返回了无效的 JSON。");
  return result;
}

function updateBusy() {
  $("reload-button").disabled = state.loading || state.busy;
  $("reload-button").textContent = state.loading ? "加载中…" : "刷新列表";
  $("add-button").disabled = state.busy;
  for (const id of ["nodes-content", "subscriptions-content"]) $(id).setAttribute("aria-busy", String(state.loading));
  document.querySelectorAll("[data-mutation], #subscription-form button, #subscription-form input, #subscription-form textarea, #delete-form button").forEach((element) => { element.disabled = state.busy; });
}

async function loadData() {
  const currentSession = session;
  state.loading = true;
  updateBusy();
  try {
    const [config, status, nodes, subscriptions] = await Promise.all([api("/api/config"), api("/api/status"), api("/api/nodes"), api("/api/subscriptions")]);
    if (currentSession !== session) return false;
    if (!state.config) {
      $("socks-address").value = defaultAddress(config.socks_listen);
      $("socks-password").value = config.socks_password || "anything";
    }
    state.config = config;
    state.status = status;
    const previous = new Map(state.nodes.map((node) => [node.id, node]));
    state.nodes = (nodes.items || []).map((node) => {
      const old = previous.get(node.id);
      if (old && sameOutbound(old.outbound, node.outbound)) {
        for (const key of ["latency", "ip_check"]) {
          if (old[key] && (!node[key] || Date.parse(old[key].checked_at) > Date.parse(node[key].checked_at))) node[key] = old[key];
        }
      }
      return node;
    });
    state.subscriptions = subscriptions.items || [];
    state.generation = nodes.generation;
    renderStatus();
    renderSubscriptions();
    renderFilter();
    renderNodes();
    $("nodes-count").textContent = state.nodes.length;
    $("subscriptions-count").textContent = state.subscriptions.length;
    $("last-sync").textContent = "更新于 " + new Date().toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit" });
    return true;
  } finally {
    if (currentSession === session) { state.loading = false; updateBusy(); }
  }
}

function renderStatus(disconnected = false) {
  const status = state.status;
  $("status-dot").className = "status-dot" + (!disconnected && status?.ready ? " ready" : "") + (!disconnected && status?.updating ? " updating" : "");
  $("service-state").textContent = disconnected ? "连接中断" : status?.updating ? "订阅更新中" : status?.ready ? "服务运行中" : "正在准备";
  $("runtime-info").textContent = status ? "已运行 " + duration(status.uptime_seconds) : "";
  $("version-value").textContent = status?.version ? "v" + status.version.replace(/^v/, "") : "onesocks";
  $("update-hint").textContent = !disconnected && status?.generation !== state.generation ? "节点已更新" : "";
}

function duration(seconds) {
  const minutes = Math.floor(Math.max(0, seconds) / 60);
  if (minutes < 1) return "不到 1 分钟";
  if (minutes < 60) return minutes + " 分钟";
  if (minutes < 1440) return Math.floor(minutes / 60) + " 小时 " + minutes % 60 + " 分钟";
  return Math.floor(minutes / 1440) + " 天 " + Math.floor(minutes % 1440 / 60) + " 小时";
}

function pollStatus() {
  clearTimeout(pollTimer);
  if ($("app").hidden) return;
  pollTimer = setTimeout(async () => {
    if (!document.hidden && !state.loading && !state.busy) {
      const currentSession = session;
      try {
        const status = await api("/api/status");
        if (currentSession === session) { state.status = status; renderStatus(); }
      } catch (error) { if (!error.unauthorized && currentSession === session) renderStatus(true); }
    }
    pollStatus();
  }, 15000);
}

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function action(label, callback, className = "", mutation = false) {
  const button = element("button", "text-button " + className, label);
  button.type = "button";
  if (mutation) { button.dataset.mutation = ""; button.disabled = state.busy; }
  button.addEventListener("click", callback);
  return button;
}

function sourceName(id) { return state.subscriptions.find((item) => item.id === id)?.name || id; }
function nodeName(node) {
  const prefix = sourceName(node.subscription_id) + "-";
  return node.name.startsWith(prefix) ? node.name.slice(prefix.length) : node.name;
}

function filterOptions(id, label, entries) {
  const filter = $(id);
  const selected = filter.value;
  if (selected && !entries.some(([value]) => value === selected)) entries.push([selected, filter.selectedOptions[0].textContent]);
  const options = [["", label], ...entries];
  if (options.length === filter.options.length && options.every(([value, text], index) => filter.options[index].value === value && filter.options[index].textContent === text)) return;
  filter.replaceChildren(...options.map(([value, text]) => new Option(text, value)));
  filter.value = selected;
}

function ipReport(node) { return node.ip_check?.error ? null : node.ip_check?.data; }
function countryKey(info) { return String(info?.country_code || info?.country || "").toUpperCase(); }
function probeState(result) { return !result ? "untested" : result.error ? "failed" : "success"; }
function nodeLatency(node) { return !node.latency?.error && typeof node.latency?.milliseconds === "number" ? node.latency.milliseconds : null; }
function nodeScore(node) { const score = ipReport(node)?.score; return typeof score === "number" ? score : null; }

function renderFilter() {
  filterOptions("subscription-filter", "全部订阅", state.subscriptions.map((sub) => [sub.id, sub.name]));
  const protocols = [...new Set(state.nodes.map((node) => node.protocol))].sort();
  filterOptions("protocol-filter", "全部协议", protocols.map((protocol) => [protocol, protocol]));
  const countries = new Map();
  for (const node of state.nodes) {
    const info = ipReport(node)?.ip_info;
    const key = countryKey(info);
    if (key) countries.set(key, countryName(info));
  }
  filterOptions("country-filter", "全部地区", [...countries].sort((a, b) => a[1].localeCompare(b[1], "zh-CN")));
}

function filteredNodes() {
  const query = $("node-search").value.trim().toLocaleLowerCase();
  const subscriptionID = $("subscription-filter").value;
  const protocol = $("protocol-filter").value;
  const country = $("country-filter").value;
  const latencyState = $("latency-status-filter").value;
  const ipState = $("ip-status-filter").value;
  const maxLatency = $("latency-max-filter").value;
  const maxScore = $("score-max-filter").value;
  const nodes = state.nodes.filter((node) => {
    if (subscriptionID && node.subscription_id !== subscriptionID) return false;
    if (protocol && node.protocol !== protocol) return false;
    const info = ipReport(node)?.ip_info;
    if (country && countryKey(info) !== country) return false;
    if (latencyState && probeState(node.latency) !== latencyState) return false;
    if (ipState && probeState(node.ip_check) !== ipState) return false;
    if (maxLatency !== "" && (nodeLatency(node) === null || nodeLatency(node) > Number(maxLatency))) return false;
    if (maxScore !== "" && (nodeScore(node) === null || nodeScore(node) > Number(maxScore))) return false;
    const searchable = [node.name, node.username, node.protocol, sourceName(node.subscription_id), info?.ip, info?.country, info?.country_code, info?.city, countryName(info)].join(" ");
    return !query || searchable.toLocaleLowerCase().includes(query);
  });
  const sort = $("node-sort").value;
  const byName = (a, b) => a.name.localeCompare(b.name, "zh-CN", { numeric: true }) || a.id.localeCompare(b.id);
  if (sort === "name") nodes.sort(byName);
  if (sort.startsWith("latency-") || sort.startsWith("score-")) {
    const metric = sort.startsWith("latency-") ? nodeLatency : nodeScore;
    const direction = sort.endsWith("desc") ? -1 : 1;
    nodes.sort((a, b) => {
      const left = metric(a), right = metric(b);
      if (left === null || right === null) return left === right ? byName(a, b) : left === null ? 1 : -1;
      return (left - right) * direction || byName(a, b);
    });
  }
  return nodes;
}

function applyFilters() { state.nodePage = 1; renderNodes(); }

function countryName(info) {
  if (!info) return "—";
  try { return new Intl.DisplayNames(["zh-CN"], { type: "region" }).of(info.country_code) || info.country || "—"; }
  catch { return info.country || info.country_code || "—"; }
}

function scoreText(data) { return typeof data?.score === "number" ? String(data.score) : "—"; }

function sameOutbound(a, b) {
  const serialize = (value) => JSON.stringify(value, (_, item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) return item;
    return Object.fromEntries(Object.keys(item).sort().map((key) => [key, item[key]]));
  });
  return serialize(a) === serialize(b);
}

function probeStatus(id, kind) {
  return probes.has(id + ":" + kind) ? "检测中…" : "";
}

function renderNodeMetrics(row, node) {
  const report = ipReport(node);
  const info = report?.ip_info;
  const latency = nodeLatency(node);
  row.querySelector(".ip-address").textContent = info?.ip || "—";
  row.querySelector(".ip-location").textContent = info ? [countryName(info), info.city].filter(Boolean).join(" · ") : "";
  for (const [kind, selector, result, value] of [
    ["latency", ".latency-cell", node.latency, latency === null ? "—" : latency + " ms"],
    ["ip-check", ".score-cell", node.ip_check, scoreText(report)],
  ]) {
    const cell = row.querySelector(selector);
    const pending = probeStatus(node.id, kind);
    cell.textContent = pending || (result?.error ? "失败" : !result ? "未检测" : value);
    cell.classList.toggle("metric-error", !pending && !!result?.error);
    cell.classList.toggle("metric-muted", !!pending || (!result?.error && value === "—"));
    cell.dataset.verdict = kind === "ip-check" && !pending ? report?.verdict || "" : "";
    cell.title = pending ? "" : result?.error || "";
  }
}

function updateProbeNode(id) {
  renderFilter();
  renderNodes(false);
  const node = state.nodes.find((item) => item.id === id);
  if (node && state.detailID === id) renderDiagnostics(node);
}

function renderNodes(updateDetails = true) {
  const nodes = filteredNodes();
  if (!state.nodes.some((node) => node.id === state.detailID)) state.detailID = "";
  const pageSize = Number($("page-size").value);
  const pages = Math.max(1, Math.ceil(nodes.length / pageSize));
  state.nodePage = Math.max(1, Math.min(state.nodePage, pages));
  const offset = (state.nodePage - 1) * pageSize;
  const visible = nodes.slice(offset, offset + pageSize);
  const body = $("nodes-body");
  const focused = document.activeElement;
  const existing = new Map(Array.from(body.rows, (row) => [row.dataset.nodeId, row]));
  const visibleIDs = new Set(visible.map((node) => node.id));
  let focusRemoved = false;
  for (const [id, row] of existing) {
    if (visibleIDs.has(id)) continue;
    focusRemoved ||= row.contains(document.activeElement);
    row.remove();
  }
  visible.forEach((node, index) => {
    const row = existing.get(node.id) || createNodeRow(node.id);
    row.querySelector(".cell-title").textContent = nodeName(node);
    row.querySelector(".protocol-name").textContent = node.protocol.toUpperCase();
    row.querySelector(".source-label").textContent = sourceName(node.subscription_id);
    const choose = row.querySelector(".connect-action");
    choose.setAttribute("aria-label", "连接 " + node.name);
    row.querySelector(".inspect-action").setAttribute("aria-label", "检测详情 " + node.name);
    renderNodeMetrics(row, node);
    if (body.rows[index] !== row) body.insertBefore(row, body.rows[index] || null);
  });
  if (focusRemoved) $("node-search").focus({ preventScroll: true });
  else if (body.contains(focused) && document.activeElement !== focused) focused.focus({ preventScroll: true });
  body.closest("table").hidden = nodes.length === 0;
  $("nodes-empty").hidden = nodes.length !== 0;
  $("nodes-empty-title").textContent = state.nodes.length ? "没有匹配的节点" : "还没有节点";
  $("empty-add-button").hidden = state.nodes.length > 0;
  $("node-results").textContent = nodes.length === state.nodes.length ? `共 ${nodes.length} 个节点` : `${nodes.length} / ${state.nodes.length} 个节点`;
  renderPagination(nodes.length, pageSize, pages, offset);
  const activeFilters = extraFilterIDs.filter((id) => $(id).value !== "").length;
  $("filters-toggle").textContent = activeFilters ? `筛选 · ${activeFilters}` : "筛选";
  $("filters-reset").disabled = !filterIDs.some((id) => $(id).value !== "");
  $("export-toggle").disabled = nodes.length === 0;
  $("export-toggle").textContent = `导出（${nodes.length}）`;
  if (!nodes.length) setExportOpen(false);
  if (updateDetails) renderConnection();
  renderProbeControls(nodes);
}

function createNodeRow(id) {
  const row = element("tr");
  row.dataset.nodeId = id;
  const name = element("td");
  const meta = element("div", "node-meta");
  meta.append(element("span", "protocol-name"), element("span", "source-label"));
  name.append(element("div", "cell-title"), meta);
  const exit = element("td", "exit-cell");
  exit.dataset.label = "出口 IP / 地区";
  exit.append(element("span", "ip-address"), element("span", "ip-location"));
  const latency = element("td", "node-metric latency-cell");
  latency.dataset.label = "延迟";
  const score = element("td", "node-metric score-cell");
  score.dataset.label = "风险评分";
  const controls = element("td");
  const buttons = element("div", "row-actions");
  buttons.append(action("连接", (event) => openNode(id, "connection", event.currentTarget), "connect-action"), action("详情", (event) => openNode(id, "diagnostics", event.currentTarget), "inspect-action"));
  for (const button of buttons.children) {
    button.setAttribute("aria-haspopup", "dialog");
    button.setAttribute("aria-controls", "connection-dialog");
  }
  controls.append(buttons);
  row.append(name, exit, latency, score, controls);
  return row;
}

function renderPagination(total, pageSize, pages, offset) {
  $("node-pagination").hidden = total === 0;
  $("page-range").textContent = total ? `显示 ${offset + 1}–${Math.min(offset + pageSize, total)}，共 ${total} 个` : "";
  $("page-number").max = pages;
  $("page-total").textContent = pages;
  $("page-jump").hidden = pages <= 5;
  $("page-prev").disabled = state.nodePage === 1;
  $("page-next").disabled = state.nodePage === pages;
  const list = $("page-list");
  const key = `${state.nodePage}/${pages}`;
  if (list.dataset.pages === key) return;
  const focused = list.contains(document.activeElement);
  const current = state.nodePage;
  const numbers = pages <= 5 ? Array.from({ length: pages }, (_, i) => i + 1)
    : current <= 3 ? [1, 2, 3, null, pages]
    : current >= pages - 2 ? [1, null, pages - 2, pages - 1, pages]
    : [1, null, current, null, pages];
  list.replaceChildren(...numbers.map((page) => {
    if (page === null) {
      const gap = element("span", "page-gap", "…");
      gap.setAttribute("aria-hidden", "true");
      return gap;
    }
    const button = element("button", "page-button", page);
    button.type = "button";
    button.dataset.page = page;
    button.setAttribute("aria-label", `第 ${page} 页`);
    if (page === current) button.setAttribute("aria-current", "page");
    return button;
  }));
  list.dataset.pages = key;
  if (focused) list.querySelector('[aria-current="page"]').focus({ preventScroll: true });
}

function changePage(page) {
  state.nodePage = Math.trunc(Number(page)) || 1;
  renderNodes();
  $("page-list").querySelector('[aria-current="page"]').focus({ preventScroll: true });
  $("nodes-panel").scrollIntoView({ block: "start" });
}

function setExportOpen(open) {
  $("export-options").hidden = !open;
  $("export-toggle").setAttribute("aria-expanded", String(open));
}

function exportNodes(format) {
  const nodes = filteredNodes();
  if (!nodes.length) return;
  try {
    const rows = nodes.map((node) => {
      const subscription = state.subscriptions.find((item) => item.id === node.subscription_id);
      return { ...node, subscription_name: sourceName(node.subscription_id), subscription_url: subscription?.url || "", socks5: connectionValues(node).link };
    });
    let content, mime;
    if (format === "txt") {
      content = rows.map((row) => row.socks5).join("\n") + "\n";
      mime = "text/plain";
    } else if (format === "json") {
      content = JSON.stringify(rows, null, 2) + "\n";
      mime = "application/json";
    } else {
      const fields = [
        ["节点名称", (node) => node.name], ["用户名", (node) => node.username],
        ["订阅", (node) => node.subscription_name], ["订阅链接", (node) => node.subscription_url],
        ["协议", (node) => node.protocol], ["SOCKS5 链接", (node) => node.socks5],
        ["出口 IP", (node) => ipReport(node)?.ip_info?.ip],
        ["国家/地区", (node) => countryName(ipReport(node)?.ip_info)],
        ["城市", (node) => ipReport(node)?.ip_info?.city],
        ["延迟(ms)", nodeLatency], ["评分", nodeScore],
        ["风险结论", (node) => ipReport(node)?.verdict], ["信誉", (node) => ipReport(node)?.reputation],
        ["延迟检测时间", (node) => node.latency?.checked_at], ["延迟错误", (node) => node.latency?.error],
        ["IP 检测时间", (node) => node.ip_check?.checked_at], ["IP 检测错误", (node) => node.ip_check?.error],
      ];
      const csv = (value) => '"' + String(value ?? "").replace(/"/g, '""') + '"';
      content = "\uFEFF" + [fields.map(([label]) => csv(label)).join(","), ...rows.map((node) => fields.map(([, value]) => csv(value(node))).join(","))].join("\r\n") + "\r\n";
      mime = "text/csv";
    }
    const url = URL.createObjectURL(new Blob([content], { type: mime + ";charset=utf-8" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = `onesocks-${new Date().toISOString().slice(0, 10)}.${format}`;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
    notify(`已导出 ${rows.length} 个节点`);
  } catch (error) { notify("导出失败：" + error.message, true); }
  setExportOpen(false);
  $("export-toggle").focus();
}

function openNode(id, page, trigger) {
  state.detailID = id;
  detailPage = page;
  detailTrigger = trigger;
  renderConnection();
  renderProbeControls(filteredNodes());
  if (!$("connection-dialog").open) $("connection-dialog").showModal();
  const invalid = $("connection-panel").querySelector('[aria-invalid="true"]');
  (page === "diagnostics" ? $("diagnostics-tab") : invalid || $("connection-copy")).focus({ preventScroll: true });
}

function renderDetailPage() {
  for (const page of ["connection", "diagnostics"]) {
    $(page + "-tab").setAttribute("aria-pressed", String(page === detailPage));
  }
  $("connection-settings").hidden = detailPage !== "connection";
  $("diagnostics-panel").hidden = detailPage !== "diagnostics";
}

function connectionValues(node) {
  let address;
  try { address = new URL("socks5://" + $("socks-address").value.trim()); } catch {}
  if (!address?.hostname || !address.port || address.username || address.password || address.search || address.hash || (address.pathname && address.pathname !== "/")) {
    $("socks-address").setAttribute("aria-invalid", "true");
    throw new Error("代理地址无效");
  }
  const password = $("socks-password").value || state.config.socks_password || "anything";
  const link = `socks5://${encodeURIComponent(node.username)}:${encodeURIComponent(password)}@${address.host}`;
  const command = "curl --proxy " + shellQuote("socks5h://" + address.host) + " \\\n  --proxy-user " + shellQuote(node.username + ":" + password) + " \\\n  https://ipinfo.io/json";
  return { link, curl: command };
}

function shellQuote(value) { return "'" + value.replace(/'/g, "'\"'\"'") + "'"; }

function renderConnection() {
  const node = state.nodes.find((item) => item.id === state.detailID);
  $("connection-details").hidden = !node;
  $("connection-preview").value = "";
  $("selected-username").value = node?.username || "";
  $("connection-copy").disabled = true;
  $("copy-hint").hidden = true;
  for (const id of ["socks-address", "socks-password"]) $(id).removeAttribute("aria-invalid");
  formError("connection-error", "");
  if (!node) {
    if ($("connection-dialog").open) $("connection-dialog").close();
    return;
  }
  $("selected-name").textContent = nodeName(node);
  $("selected-protocol").textContent = node.protocol.toUpperCase();
  $("selected-source").textContent = sourceName(node.subscription_id);
  renderDetailPage();
  renderDiagnostics(node);
  $("link-tab").setAttribute("aria-pressed", String(state.format === "link"));
  $("curl-tab").setAttribute("aria-pressed", String(state.format === "curl"));
  $("connection-preview-label").textContent = state.format === "link" ? "连接链接" : "测试命令";
  $("connection-preview").classList.toggle("command", state.format === "curl");
  $("connection-copy").textContent = state.format === "link" ? "复制 SOCKS5 链接" : "复制 curl 命令";
  try {
    $("connection-preview").value = connectionValues(node)[state.format];
    $("connection-copy").disabled = false;
  } catch (error) { formError("connection-error", error.message); }
}

async function copyInput(input, label) {
  if (!input.value) return;
  formError("copy-hint", "");
  let copied = false;
  try {
    await navigator.clipboard.writeText(input.value);
    copied = true;
  } catch {
    const focused = document.activeElement;
    const { selectionStart, selectionEnd } = input;
    try {
      input.focus({ preventScroll: true });
      input.select();
      copied = document.execCommand("copy");
    } catch {}
    finally {
      input.setSelectionRange(selectionStart, selectionEnd);
      focused?.focus({ preventScroll: true });
    }
  }
  $("copy-hint").classList.toggle("form-error", !copied);
  formError("copy-hint", copied ? label + "已复制。" : "复制失败");
}

function renderProbeControls(nodes) {
  for (const [kind, prefix, label] of [["latency", "latency", "延迟探测"], ["ip-check", "ip", "IP 检测"]]) {
    const status = probeStatus(state.detailID, kind);
    $(prefix + "-test").disabled = !!status;
    $(prefix + "-test").textContent = status || label;
    $(prefix + "-all").disabled = !!batch || probes.size > 0 || !nodes.length;
    $(prefix + "-all").textContent = batch?.kind === kind && !batch.incompleteOnly ? "检测中…" : kind === "latency" ? "批量延迟探测" : "批量 IP 检测";
  }
  const missing = nodes.filter((node) => probeState(node.ip_check) !== "success").length;
  $("ip-missing").disabled = !!batch || probes.size > 0 || missing === 0;
  $("ip-missing").textContent = batch?.incompleteOnly ? "补测中…" : `补测 IP（${missing}）`;
  $("probe-stop").hidden = !batch;
}

function applyProbeResult(id, kind, result) {
  const node = state.nodes.find((item) => item.id === id);
  if (!node) return false;
  const field = kind === "latency" ? "latency" : "ip_check";
  if (result?.id !== id || !result[field]?.checked_at) throw new Error("检测接口未返回结果");
  if (!sameOutbound(node.outbound, result.outbound)) throw new Error("节点配置已更新");
  const detail = result[field];
  if (!detail.error && (kind === "ip-check" ? !detail.data?.ip_info?.ip : detail.milliseconds == null)) throw new Error("检测接口未返回结果");
  node[field] = detail;
  return !detail.error;
}

async function probeNode(id, kind) {
  const key = id + ":" + kind;
  const field = kind === "latency" ? "latency" : "ip_check";
  if (probes.has(key)) return false;
  const currentSession = session;
  const controller = new AbortController();
  probes.set(key, controller);
  updateProbeNode(id);
  try {
    const result = await api("/api/nodes/" + encodeURIComponent(id) + "/" + kind, { method: "POST", signal: controller.signal });
    if (currentSession !== session) return false;
    return applyProbeResult(id, kind, result);
  } catch (error) {
    if (currentSession === session && error.name !== "AbortError" && !error.unauthorized) {
      const node = state.nodes.find((item) => item.id === id);
      if (node) node[field] = { checked_at: new Date().toISOString(), error: error.message };
      if (!batch && state.detailID !== id) notify("检测失败：" + error.message, true);
    }
    return false;
  } finally {
    if (currentSession === session) {
      probes.delete(key);
      updateProbeNode(id);
    }
  }
}

async function probeFiltered(kind, incompleteOnly = false) {
  if (batch || probes.size) return;
  const field = kind === "latency" ? "latency" : "ip_check";
  const ids = filteredNodes().filter((node) => !incompleteOnly || probeState(node[field]) !== "success").map((node) => node.id);
  if (!ids.length) return;
  const currentSession = session;
  const controller = new AbortController();
  const job = { kind, incompleteOnly, done: 0, failed: 0, stopped: false };
  batch = job;
  for (const id of ids) probes.set(id + ":" + kind, controller);
  $("probe-progress").textContent = `正在检测 0 / ${ids.length}`;
  renderNodes();
  const finish = (id, result, message) => {
    if (batch !== job || probes.get(id + ":" + kind) !== controller) return;
    try {
      if (message) throw new Error(message);
      if (!applyProbeResult(id, kind, result)) job.failed++;
    } catch (error) {
      const node = state.nodes.find((item) => item.id === id);
      if (node) node[kind === "latency" ? "latency" : "ip_check"] = { checked_at: new Date().toISOString(), error: error.message };
      job.failed++;
    }
    probes.delete(id + ":" + kind);
    job.done++;
    updateProbeNode(id);
    $("probe-progress").textContent = `正在检测 ${job.done} / ${ids.length}`;
  };
  try {
    await api("/api/nodes/probe", { method: "POST", body: JSON.stringify({ ids, kind }), signal: controller.signal }, (item) => finish(item.id, item.node, item.error?.message));
    for (const id of ids) finish(id, null, "检测接口未返回结果");
  } catch (error) {
    if (currentSession === session && error.name !== "AbortError" && !error.unauthorized) {
      for (const id of ids) finish(id, null, error.message);
    }
  } finally {
    controller.abort();
    if (batch === job) {
      batch = null;
      for (const id of ids) if (probes.get(id + ":" + kind) === controller) probes.delete(id + ":" + kind);
      $("probe-progress").textContent = job.stopped ? `已停止 · ${job.done} / ${ids.length}` : `检测完成 · ${job.done - job.failed} 成功${job.failed ? " / " + job.failed + " 失败" : ""}`;
      updateProbeNode(state.detailID);
    }
  }
}

function stopProbes() {
  if (batch) batch.stopped = true;
  for (const controller of probes.values()) controller.abort();
}

function detailField(list, label, value) {
  const row = element("div");
  const term = element("dt", "", label);
  row.append(term, element("dd", "", value === undefined || value === null || value === "" ? "—" : String(value)));
  list.append(row);
}

function renderDiagnostics(node) {
  const latency = node.latency;
  $("latency-checked").textContent = latency ? dateTime(latency.checked_at) : "";
  $("latency-result").textContent = probeStatus(node.id, "latency") || latency?.error || (latency?.milliseconds != null ? latency.milliseconds + " ms" : "未检测");
  $("latency-result").classList.toggle("metric-error", !!latency?.error);
  const check = node.ip_check;
  const data = check?.error ? null : check?.data;
  $("ip-checked").textContent = check ? dateTime(check.checked_at) : "";
  $("ip-report").hidden = !data;
  const status = probeStatus(node.id, "ip-check");
  $("ip-empty").hidden = !!data && !status;
  $("ip-empty").textContent = status || check?.error || "未检测";
  $("ip-empty").classList.toggle("metric-error", !!check?.error);
  if (!data) return;
  const info = data.ip_info || {};
  $("ip-address").textContent = info.ip || "—";
  $("ip-location").textContent = [countryName(info), info.city].filter(Boolean).join(" · ");
  const verdicts = { clean: "未发现明显代理特征", suspicious: "存在可疑特征", vpn_likely: "较明显的代理特征", vpn_detected: "检测到代理 / VPN 特征" };
  const reputations = { allowlist: "白名单", greylist: "灰名单", blocklist: "黑名单" };
  const summary = $("risk-summary");
  summary.dataset.verdict = data.verdict || "";
  summary.replaceChildren(element("strong", "risk-score", scoreText(data)), element("div", "", "风险评分"));
  const fields = $("ip-fields");
  fields.replaceChildren();
  for (const field of [
    ["检测结论", verdicts[data.verdict] ? verdicts[data.verdict] + "（" + data.verdict + "）" : data.verdict],
    ["信誉状态", reputations[data.reputation] ? reputations[data.reputation] + "（" + data.reputation + "）" : data.reputation],
    ["置信值", data.confidence],
    ["国家 / 地区", [info.country, info.country_code].filter(Boolean).join(" / ")],
    ["城市", info.city],
    ["经纬度", info.lat != null && info.lon != null ? info.lat + ", " + info.lon : null],
    ["自治系统", info.asn],
    ["所属组织", info.org],
    ["网络运营商", info.isp],
    ["网络类型", info.type],
    ["VPN 信息源", info.vpn_provider_sources?.join("、")],
    ["基础 VPN 标记", info.is_vpn == null ? null : info.is_vpn ? "是" : "否"],
    ["基础代理标记", info.is_proxy == null ? null : info.is_proxy ? "是" : "否"],
    ["滥用联系邮箱", info.abuse_contact],
    ["所属网段", info.prefix],
    ["网段持有者", info.prefix_holder],
    ["检测模式", data.mode || "full"],
    ["请求编号", data.request_id],
  ]) detailField(fields, ...field);
  const flags = $("ip-flags");
  flags.replaceChildren();
  for (const [key, label] of [
    ["is_vpn", "VPN"], ["is_proxy", "代理"],
    ["is_tor", "Tor"], ["is_relay", "中继"],
    ["is_hosting", "托管 / 机房"], ["is_crawler", "爬虫"],
    ["is_satellite", "卫星网络"],
  ]) detailField(flags, label, data[key] == null ? null : data[key] ? "是" : "否");
  const signals = $("ip-signals");
  signals.replaceChildren();
  for (const signal of data.signals || []) {
    const entry = element("div", "signal-entry");
    entry.append(element("strong", "", signal.type), element("span", "cell-detail", (signal.matched ? "已命中" : "未命中") + " · 权重 " + (signal.weight ?? "未提供")), element("p", "", signal.detail || "—"));
    signals.append(entry);
  }
  if (!signals.childElementCount) signals.append(element("p", "field-help", "—"));
  $("ip-raw").textContent = JSON.stringify(data, null, 2);
}

function dateTime(value) {
  if (!value) return "尚未更新";
  return new Date(value).toLocaleString("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

function formatBytes(value) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
  const index = value > 0 ? Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1) : 0;
  return new Intl.NumberFormat("zh-CN", { maximumFractionDigits: 2 }).format(value / 1024 ** index) + "\u00a0" + units[index];
}

function subscriptionTrafficCell(subscription) {
  const cell = element("td", "subscription-traffic");
  const traffic = subscription.traffic;
  if (!traffic) {
    cell.append(element("span", "muted", "流量未提供"));
    return cell;
  }
  const used = traffic.upload_bytes != null && traffic.download_bytes != null ? traffic.upload_bytes + traffic.download_bytes : null;
  const total = traffic.total_bytes > 0 ? traffic.total_bytes : null;
  const remaining = used != null && total != null ? Math.max(0, total - used) : null;
  cell.append(element("div", "cell-title", remaining != null ? "剩余 " + formatBytes(remaining) : used != null ? "已用 " + formatBytes(used) : "用量未提供"));
  const detail = [used != null && remaining != null ? "已用 " + formatBytes(used) : "", total != null ? "总计 " + formatBytes(total) : "总额未提供"].filter(Boolean).join(" / ");
  cell.append(element("span", "cell-detail", detail));
  const expiry = traffic.expires_at ? new Date(traffic.expires_at) : null;
  const expires = element("span", "cell-detail", expiry ? (expiry <= new Date() ? "已到期 · " : "到期 ") + expiry.toLocaleString("zh-CN", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" }) : "到期时间未提供");
  expires.classList.toggle("metric-error", !!expiry && expiry <= new Date());
  cell.append(expires);
  cell.title = [
    "服务商统计，更新于 " + dateTime(subscription.last_success_at),
    traffic.upload_bytes != null ? "上传 " + formatBytes(traffic.upload_bytes) : "上传量未提供",
    traffic.download_bytes != null ? "下载 " + formatBytes(traffic.download_bytes) : "下载量未提供",
  ].join("\n");
  return cell;
}

function renderSubscriptions() {
  const rows = document.createDocumentFragment();
  for (const subscription of state.subscriptions) {
    const row = document.createElement("tr");
    const name = element("td");
    const url = element("code", "cell-detail subscription-url", subscription.url);
    url.title = subscription.url;
    name.append(element("div", "cell-title", subscription.name), url, element("span", "cell-detail", "每 " + subscription.refresh_interval + " 自动更新"));
    const count = element("td");
    count.textContent = subscription.node_count;
    const sync = element("td");
    sync.append(element("span", "sync-state" + (subscription.last_error ? " failed" : ""), subscription.last_error ? "更新失败" : subscription.last_success_at ? "已同步" : "尚未同步"), element("span", "cell-detail", "最近成功 " + dateTime(subscription.last_success_at)));
    if (subscription.last_error) sync.append(element("span", "cell-detail error-detail", subscription.last_error));
    const controls = element("td");
    const buttons = element("div", "row-actions");
    buttons.append(action("刷新", (event) => refreshSubscription(subscription, event.currentTarget), "", true), action("编辑", () => openSubscription(subscription), "", true), action("删除", () => openDelete(subscription), "delete-action", true));
    controls.append(buttons);
    row.append(name, count, subscriptionTrafficCell(subscription), sync, controls);
    rows.append(row);
  }
  $("subscriptions-body").replaceChildren(rows);
  $("subscriptions-body").closest("table").hidden = state.subscriptions.length === 0;
  $("subscriptions-empty").hidden = state.subscriptions.length !== 0;
  $("subscription-results").textContent = `共 ${state.subscriptions.length} 个订阅`;
}

function switchPage(page) {
  state.page = page;
  for (const id of ["nodes", "subscriptions"]) {
    $(id + "-panel").hidden = id !== page;
    $(id + "-tab").classList.toggle("active", id === page);
    if (id === page) $(id + "-tab").setAttribute("aria-current", "page");
    else $(id + "-tab").removeAttribute("aria-current");
  }
  $("page-title").textContent = page === "nodes" ? "节点池" : "订阅管理";
}

function openSubscription(subscription = null) {
  if (state.busy) return;
  editing = subscription;
  $("subscription-dialog-title").textContent = subscription ? "编辑订阅" : "添加订阅";
  $("subscription-submit").textContent = subscription ? "保存修改" : "添加并拉取";
  $("subscription-name").value = subscription?.name || "";
  $("subscription-name").placeholder = subscription ? "订阅名称" : "自动命名";
  $("subscription-url").value = subscription?.url || "";
  $("subscription-url").required = !subscription;
  $("subscription-url").placeholder = "https://…";
  $("subscription-interval").value = subscription?.refresh_interval || "";
  $("subscription-advanced").open = false;
  formError("subscription-error", "");
  $("subscription-dialog").showModal();
  $(subscription ? "subscription-name" : "subscription-url").focus();
}

function openDelete(subscription) {
  if (state.busy) return;
  deleting = subscription;
  $("delete-description").textContent = "确定删除「" + subscription.name + "」？";
  formError("delete-error", "");
  $("delete-dialog").showModal();
}

async function mutate(path, options, success, button, dialogID = "", errorID = "") {
  if (state.busy) return;
  const currentSession = session;
  const buttonText = button.textContent;
  state.busy = true;
  updateBusy();
  const pendingText = { DELETE: "删除中…", PATCH: "保存中…", POST: "拉取中…" };
  button.textContent = dialogID ? pendingText[options.method] : "刷新中…";
  button.setAttribute("aria-busy", "true");
  notify("");
  try {
    const result = await api(path, options);
    if (currentSession !== session) return;
    if (dialogID) $(dialogID).close();
    const warnings = result?.warnings || [];
    const message = typeof success === "function" ? success(result) : success;
    notify(message + (warnings.length ? "\n" + warnings.join("\n") : ""), false, warnings.length > 0);
    try {
      await loadData();
      if (options.method === "POST" && path === "/api/subscriptions" && state.page === "nodes") {
        $("subscription-filter").value = result.subscription.id;
        renderNodes();
      }
    } catch (error) { if (!error.unauthorized) notify(message + " 列表加载失败：" + error.message, true); }
  } catch (error) {
    if (!error.unauthorized && currentSession === session) {
      if (errorID) formError(errorID, error.message);
      else {
        notify(error.message, true);
        try { await loadData(); } catch { /* Keep the original operation error visible. */ }
      }
    }
  } finally {
    button.textContent = buttonText;
    button.removeAttribute("aria-busy");
    if (currentSession === session) { state.busy = false; updateBusy(); }
  }
}

function refreshSubscription(subscription, button) {
  return mutate("/api/subscriptions/" + encodeURIComponent(subscription.id) + "/refresh", { method: "POST" }, (result) => `订阅已刷新，共 ${result.subscription.node_count} 个节点。`, button);
}

function defaultAddress(address) {
  try {
    const url = new URL("socks5://" + address);
    if (["0.0.0.0", "[::]"].includes(url.hostname)) url.hostname = location.hostname;
    return url.host;
  } catch { return address; }
}

function revealApp() {
  $("boot-panel").hidden = true;
  $("login-panel").hidden = true;
  $("app").hidden = false;
  $("logout-button").hidden = !state.config.api_token;
  pollStatus();
}

async function start() {
  $("boot-panel").hidden = false;
  $("boot-retry").hidden = true;
  $("boot-title").textContent = "正在连接服务";
  $("boot-message").textContent = "加载节点与订阅…";
  try {
    token = savedToken();
    if (await loadData()) revealApp();
  } catch (error) {
    if (error.unauthorized) return;
    $("boot-title").textContent = "暂时无法连接服务";
    $("boot-message").textContent = error.message;
    $("boot-retry").hidden = false;
  }
}

$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const attempt = ++session;
  token = $("api-token").value.trim();
  $("login-submit").disabled = true;
  $("login-submit").textContent = "正在验证…";
  formError("login-error", "");
  try {
    if (await loadData()) {
      savedToken(token);
      $("api-token").value = "";
      notify("");
      revealApp();
    }
  } catch (error) { if (!error.unauthorized && attempt === session) formError("login-error", error.message); }
  finally { $("login-submit").disabled = false; $("login-submit").textContent = "登录后台"; }
});

$("subscription-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const input = {};
  const name = $("subscription-name").value.trim();
  const url = $("subscription-url").value.trim();
  const interval = $("subscription-interval").value.trim();
  if (name) input.name = name;
  if (url) input.url = url;
  if (interval || $("subscription-advanced").open) input.refresh_interval = interval;
  formError("subscription-error", "");
  mutate(editing ? "/api/subscriptions/" + encodeURIComponent(editing.id) : "/api/subscriptions", { method: editing ? "PATCH" : "POST", body: JSON.stringify(input) }, editing ? "订阅已保存。" : (result) => `已添加订阅，导入 ${result.subscription.node_count} 个节点。`, $("subscription-submit"), "subscription-dialog", "subscription-error");
});

$("delete-form").addEventListener("submit", (event) => {
  event.preventDefault();
  formError("delete-error", "");
  mutate("/api/subscriptions/" + encodeURIComponent(deleting.id), { method: "DELETE" }, "订阅已删除。", $("delete-submit"), "delete-dialog", "delete-error");
});

$("reload-button").addEventListener("click", async () => {
  try { await loadData(); notify("列表已更新。"); } catch (error) { if (!error.unauthorized) { renderStatus(true); notify("加载失败：" + error.message, true); } }
});
$("nodes-tab").addEventListener("click", () => switchPage("nodes"));
$("subscriptions-tab").addEventListener("click", () => switchPage("subscriptions"));
for (const id of filterIDs) $(id).addEventListener($(id).tagName === "SELECT" ? "change" : "input", applyFilters);
$("filters-toggle").addEventListener("click", () => {
  $("node-filters").hidden = !$("node-filters").hidden;
  $("filters-toggle").setAttribute("aria-expanded", String(!$("node-filters").hidden));
});
$("filters-reset").addEventListener("click", () => {
  for (const id of filterIDs) $(id).value = "";
  renderFilter();
  applyFilters();
});
$("page-size").addEventListener("change", applyFilters);
$("page-prev").addEventListener("click", () => changePage(state.nodePage - 1));
$("page-next").addEventListener("click", () => changePage(state.nodePage + 1));
$("page-list").addEventListener("click", (event) => {
  const button = event.target.closest("[data-page]");
  if (button) changePage(button.dataset.page);
});
$("page-jump").addEventListener("submit", (event) => {
  event.preventDefault();
  changePage($("page-number").value);
  $("page-number").value = "";
});
$("export-toggle").addEventListener("click", () => setExportOpen($("export-options").hidden));
document.querySelectorAll("[data-export]").forEach((button) => button.addEventListener("click", () => exportNodes(button.dataset.export)));
document.addEventListener("click", (event) => { if (!event.target.closest(".export-control")) setExportOpen(false); });
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !$("export-options").hidden) {
    setExportOpen(false);
    $("export-toggle").focus();
  }
});
for (const id of ["add-button", "empty-add-button", "subscriptions-empty-add"]) $(id).addEventListener("click", () => openSubscription());
for (const id of ["socks-address", "socks-password"]) $(id).addEventListener("input", renderConnection);
for (const format of ["link", "curl"]) $(format + "-tab").addEventListener("click", () => { state.format = format; renderConnection(); });
$("connection-copy").addEventListener("click", () => copyInput($("connection-preview"), state.format === "link" ? "SOCKS5 链接" : "curl 命令"));
$("username-copy").addEventListener("click", () => copyInput($("selected-username"), "用户名"));
$("connection-close").addEventListener("click", () => $("connection-dialog").close());
$("connection-dialog").addEventListener("close", () => {
  if (!$("app").hidden) (detailTrigger?.isConnected ? detailTrigger : $("node-search")).focus({ preventScroll: true });
  detailTrigger = null;
  state.detailID = "";
});
for (const page of ["connection", "diagnostics"]) $(page + "-tab").addEventListener("click", () => { detailPage = page; renderDetailPage(); });
$("latency-test").addEventListener("click", () => probeNode(state.detailID, "latency"));
$("ip-test").addEventListener("click", () => probeNode(state.detailID, "ip-check"));
$("latency-all").addEventListener("click", () => probeFiltered("latency"));
$("ip-all").addEventListener("click", () => probeFiltered("ip-check"));
$("ip-missing").addEventListener("click", () => probeFiltered("ip-check", true));
$("probe-stop").addEventListener("click", stopProbes);
$("logout-button").addEventListener("click", () => showLogin());
$("boot-retry").addEventListener("click", start);
$("notice-dismiss").addEventListener("click", () => notify(""));
document.querySelectorAll(".close-dialog").forEach((button) => button.addEventListener("click", () => button.closest("dialog").close()));
for (const id of ["subscription-dialog", "delete-dialog"]) $(id).addEventListener("cancel", (event) => { if (state.busy) event.preventDefault(); });
start();
