const { invoke } = window.__TAURI__ || {};

const rulesList = document.getElementById("rulesList");
const ruleCount = document.getElementById("ruleCount");
const selectedCount = document.getElementById("selectedCount");
const riskChips = document.querySelectorAll(".chip");

let rules = [];
let riskFilter = "all";

function renderRules() {
  const filtered = rules.filter((rule) => riskFilter === "all" || rule.risk === riskFilter);
  rulesList.innerHTML = "";
  filtered.forEach((rule) => {
    const item = document.createElement("div");
    item.className = "rule-item";

    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.checked = rule.default_checked;
    checkbox.addEventListener("change", updateSelectionCount);

    const details = document.createElement("div");
    const title = document.createElement("div");
    title.className = "rule-title";
    title.textContent = rule.title;
    const desc = document.createElement("div");
    desc.className = "rule-desc";
    desc.textContent = rule.description;
    details.appendChild(title);
    details.appendChild(desc);

    const badge = document.createElement("div");
    badge.className = `badge ${rule.risk}`;
    badge.textContent = rule.risk.toUpperCase();

    item.appendChild(checkbox);
    item.appendChild(details);
    item.appendChild(badge);
    rulesList.appendChild(item);
  });

  ruleCount.textContent = `${filtered.length} rules`;
  updateSelectionCount();
}

function updateSelectionCount() {
  const checked = rulesList.querySelectorAll("input[type='checkbox']:checked").length;
  selectedCount.textContent = checked.toString();
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

loadRules();
