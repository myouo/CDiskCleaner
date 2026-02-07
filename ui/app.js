const tauriGlobal = window.__TAURI__ || {};
const invoke =
  tauriGlobal?.core?.invoke ??
  tauriGlobal?.invoke ??
  null;
const windowApi = tauriGlobal?.window ?? tauriGlobal?.appWindow ?? null;
const appWindow =
  typeof windowApi?.getCurrentWindow === "function"
    ? windowApi.getCurrentWindow()
    : windowApi?.appWindow ?? windowApi ?? null;

const rulesList = document.getElementById("rulesList");
const ruleCount = document.getElementById("ruleCount");
const selectedCount = document.getElementById("selectedCount");
const estSize = document.getElementById("estSize");
const riskChips = document.querySelectorAll(".chip");
const scanBtn = document.getElementById("scanBtn");
const cleanBtn = document.getElementById("cleanBtn");
const analysisModal = document.getElementById("analysisModal");
const analysisClose = document.getElementById("analysisClose");
const analysisTotal = document.getElementById("analysisTotal");
const analysisFiles = document.getElementById("analysisFiles");
const analysisByCategory = document.getElementById("analysisByCategory");
const analysisByDrive = document.getElementById("analysisByDrive");
const analysisItems = document.getElementById("analysisItems");
const analysisToggle = document.getElementById("analysisToggle");
const titlebarMin = document.getElementById("titlebar-minimize");
const titlebarMax = document.getElementById("titlebar-maximize");
const titlebarClose = document.getElementById("titlebar-close");

let rules = [];
let riskFilter = "all";
let scanResults = new Map();
let showAnalysis = true;

const RULE_I18N = {
  sys_temp: { title: "系统临时文件", description: "Windows 系统临时目录", category: "临时文件" },
  user_temp: { title: "用户临时文件", description: "当前用户临时目录", category: "临时文件" },
  thumb_cache: { title: "缩略图缓存", description: "资源管理器缩略图缓存数据库", category: "缓存" },
  icon_cache: { title: "图标缓存", description: "资源管理器图标缓存数据库", category: "缓存" },
  font_cache: { title: "字体缓存", description: "Windows 字体缓存文件", category: "缓存" },
  wer_logs: { title: "错误报告日志", description: "WER 报告与日志", category: "日志" },
  diag_etl: { title: "诊断 ETL 日志", description: "Windows 诊断 ETL 日志", category: "日志" },
  windows_logs: { title: "Windows 旧日志", description: "Windows\\Logs 下的旧日志", category: "日志" },
  recent_file_cache: { title: "最近文件列表", description: "Windows 最近文件缓存", category: "隐私" },
  prefetch: { title: "预取文件", description: "应用启动预取缓存", category: "缓存" },
  recycle_bin: { title: "回收站", description: "清空回收站内容", category: "临时文件" },
  chrome_cache: { title: "Chrome 缓存", description: "Chrome 所有配置文件缓存目录", category: "浏览器" },
  chrome_code_cache: { title: "Chrome 代码缓存", description: "Chrome 代码缓存目录", category: "浏览器" },
  chrome_gpu_cache: { title: "Chrome GPU 缓存", description: "Chrome GPU 缓存目录", category: "浏览器" },
  edge_cache: { title: "Edge 缓存", description: "Edge 所有配置文件缓存目录", category: "浏览器" },
  edge_code_cache: { title: "Edge 代码缓存", description: "Edge 代码缓存目录", category: "浏览器" },
  edge_gpu_cache: { title: "Edge GPU 缓存", description: "Edge GPU 缓存目录", category: "浏览器" },
  brave_cache: { title: "Brave 缓存", description: "Brave 所有配置文件缓存目录", category: "浏览器" },
  firefox_cache: { title: "Firefox 缓存", description: "Firefox cache2 缓存目录", category: "浏览器" },
  win_update_cache: { title: "Windows 更新缓存", description: "已下载的更新包", category: "更新" },
  delivery_opt_cache: { title: "传递优化缓存", description: "更新传递优化缓存", category: "更新" },
  windows_update_logs: { title: "Windows 更新日志", description: "Windows Update 日志", category: "日志" },
  wer_archive: { title: "错误报告归档", description: "WER 报告归档", category: "日志" },
  crash_dumps: { title: "崩溃转储文件", description: "系统崩溃转储文件", category: "崩溃" },
  minidumps: { title: "小型转储文件", description: "系统 Minidump 文件", category: "崩溃" },
  driver_logs: { title: "驱动安装日志", description: "驱动安装的 SetupAPI 日志", category: "日志" },
  user_cache: { title: "用户缓存", description: "Windows 用户缓存目录", category: "缓存" },
  onedrive_cache: { title: "OneDrive 缓存", description: "OneDrive 日志与缓存", category: "应用" },
  onedrive_temp: { title: "OneDrive 临时文件", description: "OneDrive 临时目录", category: "应用" },
  teams_cache: { title: "Teams 缓存", description: "Microsoft Teams 缓存", category: "应用" },
  teams_gpu_cache: { title: "Teams GPU 缓存", description: "Microsoft Teams GPU 缓存", category: "应用" },
  office_cache: { title: "Office 缓存", description: "Office 文件缓存", category: "应用" },
  wechat_cache: { title: "微信缓存", description: "微信缓存文件", category: "应用" },
  qq_cache: { title: "QQ 缓存", description: "QQ 缓存文件", category: "应用" },
  discord_cache: { title: "Discord 缓存", description: "Discord 缓存文件", category: "应用" },
  telegram_cache: { title: "Telegram 缓存", description: "Telegram 缓存文件", category: "应用" },
  steam_cache: { title: "Steam 下载缓存", description: "Steam 下载缓存", category: "应用" },
  epic_cache: { title: "Epic 下载缓存", description: "Epic Games 下载缓存", category: "应用" },
  battle_net_cache: { title: "Battle.net 缓存", description: "Battle.net 缓存目录", category: "应用" },
  adobe_cache: { title: "Adobe 缓存", description: "Adobe 通用缓存", category: "应用" },
  autodesk_cache: { title: "Autodesk 缓存", description: "Autodesk 缓存目录", category: "应用" },
  winsxs_cleanup: { title: "WinSxS 清理", description: "使用 DISM 清理组件存储", category: "系统" },
  restore_points: { title: "系统还原点", description: "删除系统还原点", category: "系统" },
  registry_orphans: { title: "注册表孤项", description: "检测孤立卸载项与无效路径", category: "注册表" },
  app_residue: { title: "卸载残留", description: "检测已卸载应用的残留文件", category: "应用" }
};

const CATEGORY_I18N = {
  temp: "临时文件",
  cache: "缓存",
  logs: "日志",
  privacy: "隐私",
  browser: "浏览器",
  update: "更新",
  crash: "崩溃",
  apps: "应用",
  system: "系统",
  registry: "注册表"
};

const RISK_LABELS = {
  low: "低",
  medium: "中",
  high: "高"
};

function getRuleDisplay(rule) {
  const i18n = RULE_I18N[rule.id];
  return {
    title: i18n?.title ?? rule.title,
    description: i18n?.description ?? rule.description,
    category: i18n?.category ?? CATEGORY_I18N[rule.category] ?? rule.category,
    riskLabel: RISK_LABELS[rule.risk] ?? rule.risk
  };
}

async function toggleMaximize() {
  if (!appWindow) return;
  if (typeof appWindow.isMaximized !== "function") {
    if (typeof appWindow.maximize === "function") appWindow.maximize();
    return;
  }
  const isMax = await appWindow.isMaximized();
  if (isMax && typeof appWindow.unmaximize === "function") {
    await appWindow.unmaximize();
  } else if (typeof appWindow.maximize === "function") {
    await appWindow.maximize();
  }
}

if (titlebarMin && appWindow?.minimize) {
  titlebarMin.addEventListener("click", () => appWindow.minimize());
}
if (titlebarMax) {
  titlebarMax.addEventListener("click", toggleMaximize);
}
if (titlebarClose && appWindow?.close) {
  titlebarClose.addEventListener("click", () => appWindow.close());
}

function renderRules() {
  const filtered = rules.filter((rule) => riskFilter === "all" || rule.risk === riskFilter);
  rulesList.innerHTML = "";
  filtered.forEach((rule) => {
    const display = getRuleDisplay(rule);
    const item = document.createElement("div");
    item.className = `rule-item ${rule.blocked ? "blocked" : ""}`;
    item.dataset.ruleId = rule.id;

    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.checked = rule.default_checked && !rule.blocked;
    checkbox.disabled = rule.blocked;
    checkbox.addEventListener("change", updateSelectionCount);

    const details = document.createElement("div");
    const title = document.createElement("div");
    title.className = "rule-title";
    title.textContent = display.title;
    const desc = document.createElement("div");
    desc.className = "rule-desc";
    desc.textContent = rule.blocked
      ? `${display.description} · ${rule.blocked_reason}`
      : display.description;
    details.appendChild(title);
    details.appendChild(desc);

    const size = document.createElement("div");
    size.className = "rule-size";
    size.textContent = "--";

    const badge = document.createElement("div");
    badge.className = `badge ${rule.risk}`;
    badge.textContent = display.riskLabel;

    item.appendChild(checkbox);
    item.appendChild(details);
    item.appendChild(size);
    item.appendChild(badge);
    rulesList.appendChild(item);
  });

  ruleCount.textContent = `${filtered.length} 条规则`;
  updateSelectionCount();
}

function updateSelectionCount() {
  const checked = rulesList.querySelectorAll("input[type='checkbox']:checked").length;
  selectedCount.textContent = checked.toString();
  updateEstimatedSize();
}

function setRiskFilter(value) {
  riskFilter = value;
  riskChips.forEach((chip) => chip.classList.toggle("active", chip.dataset.risk === value));
  renderRules();
}

riskChips.forEach((chip) => {
  chip.addEventListener("click", () => setRiskFilter(chip.dataset.risk));
});

async function loadRules() {
  if (!invoke) {
    rules = [];
    renderRules();
    return;
  }
  try {
    rules = await invoke("list_rules_cmd");
  } catch (err) {
    console.error(err);
    rules = [];
  }
  renderRules();
}

function updateEstimatedSize() {
  let total = 0;
  const items = rulesList.querySelectorAll(".rule-item");
  items.forEach((item) => {
    const checkbox = item.querySelector("input[type='checkbox']");
    if (!checkbox || !checkbox.checked) return;
    const id = item.dataset.ruleId;
    const scan = scanResults.get(id);
    if (scan) total += scan.total_bytes;
  });
  estSize.textContent = formatBytes(total);
}

function formatBytes(bytes) {
  if (!bytes) return "0 GB";
  const gb = bytes / (1024 * 1024 * 1024);
  if (gb >= 1) return `${gb.toFixed(2)} GB`;
  const mb = bytes / (1024 * 1024);
  return `${mb.toFixed(1)} MB`;
}

async function scanRules() {
  if (!invoke) return;
  scanBtn.disabled = true;
  scanBtn.textContent = "扫描中...";
  try {
    const results = await invoke("scan_rules_cmd");
    scanResults = new Map(results.map((r) => [r.id, r]));
    results.forEach((result) => {
      const item = rulesList.querySelector(`[data-rule-id='${result.id}']`);
      if (!item) return;
      const sizeEl = item.querySelector(".rule-size");
      if (!sizeEl) return;
      sizeEl.textContent =
        result.status === "ok" ? formatBytes(result.total_bytes) : result.status;
    });
    updateSpaceChart();
  } catch (err) {
    console.error(err);
  } finally {
    scanBtn.disabled = false;
    scanBtn.textContent = "扫描";
    updateEstimatedSize();
  }
}

scanBtn.addEventListener("click", scanRules);

function updateSpaceChart() {
  const categories = {};
  scanResults.forEach((result, id) => {
    if (result.status !== "ok") return;
    const rule = rules.find((r) => r.id === id);
    if (!rule) return;
    const display = getRuleDisplay(rule);
    categories[display.category] = (categories[display.category] || 0) + result.total_bytes;
  });
  const entries = Object.entries(categories).sort((a, b) => b[1] - a[1]).slice(0, 5);
  const chart = document.getElementById("spaceChart");
  chart.innerHTML = "";
  const total = entries.reduce((sum, [, bytes]) => sum + bytes, 0);
  entries.forEach(([key, bytes]) => {
    const bar = document.createElement("div");
    bar.className = "bar";
    const percent = total ? Math.round((bytes / total) * 100) : 0;
    bar.style.setProperty("--w", `${percent}%`);
    bar.textContent = `${key} ${percent}%`;
    chart.appendChild(bar);
  });
}

function getSelectedRuleIds() {
  const selected = [];
  rulesList.querySelectorAll(".rule-item").forEach((item) => {
    const checkbox = item.querySelector("input[type='checkbox']");
    if (checkbox && checkbox.checked) {
      selected.push(item.dataset.ruleId);
    }
  });
  return selected;
}

async function cleanSelected() {
  if (!invoke) return;
  const selectedIds = getSelectedRuleIds();
  if (!selectedIds.length) return;
  const hasHighRisk = selectedIds.some((id) => {
    const rule = rules.find((r) => r.id === id);
    return rule && rule.risk === "high";
  });
  if (
    hasHighRisk &&
    !confirm(
      "已选择高风险项目（含注册表/应用残留）。便携应用可能被误判，是否继续清理？"
    )
  ) {
    return;
  }
  cleanBtn.disabled = true;
  cleanBtn.textContent = "清理中...";
  try {
    const report = await invoke("clean_rules_cmd", { selectedIds });
    if (showAnalysis) {
      renderAnalysis(report);
      analysisModal.classList.remove("hidden");
    }
  } catch (err) {
    console.error(err);
  } finally {
    cleanBtn.disabled = false;
    cleanBtn.textContent = "清理所选";
  }
}

function renderAnalysis(report) {
  analysisTotal.textContent = formatBytes(report.summary.total_bytes);
  analysisFiles.textContent = report.summary.total_files.toString();

  renderBucketList(analysisByCategory, report.summary.by_category);
  renderBucketList(analysisByDrive, report.summary.by_drive);
  renderItems(analysisItems, report.items);
}

function renderBucketList(container, items) {
  container.innerHTML = "";
  if (!items.length) {
    container.textContent = "暂无数据";
    return;
  }
  items.forEach((item) => {
    const row = document.createElement("div");
    row.className = "bucket-item";
    row.innerHTML = `<span>${item.key}</span><span>${formatBytes(item.bytes)} · ${item.percent.toFixed(
      1
    )}%</span>`;
    container.appendChild(row);
  });
}

function renderItems(container, items) {
  container.innerHTML = "";
  items.forEach((item) => {
    if (item.status !== "ok" && item.status !== "partial") return;
    const row = document.createElement("div");
    row.className = "bucket-item";
    row.innerHTML = `<span>${item.title}</span><span>${formatBytes(item.total_bytes)}</span>`;
    container.appendChild(row);
  });
}

analysisClose.addEventListener("click", () => {
  analysisModal.classList.add("hidden");
});

analysisToggle.addEventListener("change", async (event) => {
  showAnalysis = event.target.checked;
  if (invoke) {
    await invoke("set_setting_cmd", {
      key: "show_analysis",
      value: showAnalysis ? "1" : "0",
    });
  }
});

cleanBtn.addEventListener("click", cleanSelected);

async function loadSettings() {
  if (!invoke) return;
  const value = await invoke("get_setting_cmd", { key: "show_analysis" });
  showAnalysis = value !== "0";
  analysisToggle.checked = showAnalysis;
}

loadSettings();
loadRules();
