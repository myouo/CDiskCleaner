const { invoke } = window.__TAURI__ || {};

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

let rules = [];
let riskFilter = "all";
let scanResults = new Map();
let showAnalysis = true;

function renderRules() {
  const filtered = rules.filter((rule) => riskFilter === "all" || rule.risk === riskFilter);
  rulesList.innerHTML = "";
  filtered.forEach((rule) => {
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
    title.textContent = rule.title;
    const desc = document.createElement("div");
    desc.className = "rule-desc";
    desc.textContent = rule.blocked
      ? `${rule.description} · ${rule.blocked_reason}`
      : rule.description;
    details.appendChild(title);
    details.appendChild(desc);

    const size = document.createElement("div");
    size.className = "rule-size";
    size.textContent = "--";

    const badge = document.createElement("div");
    badge.className = `badge ${rule.risk}`;
    badge.textContent = rule.risk.toUpperCase();

    item.appendChild(checkbox);
    item.appendChild(details);
    item.appendChild(size);
    item.appendChild(badge);
    rulesList.appendChild(item);
  });

  ruleCount.textContent = `${filtered.length} rules`;
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
  scanBtn.textContent = "Scanning...";
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
    scanBtn.textContent = "Scan";
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
    categories[rule.category] = (categories[rule.category] || 0) + result.total_bytes;
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
      "High-risk items selected (registry/app residue included). Portable apps may be misdetected. Continue cleanup?"
    )
  ) {
    return;
  }
  cleanBtn.disabled = true;
  cleanBtn.textContent = "Cleaning...";
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
    cleanBtn.textContent = "Clean Selected";
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
    container.textContent = "No data";
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
