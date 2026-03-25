const STORAGE_KEY = "nfec-saved-runs-v1";
const SAMPLE_FILES = {
  pcap: "./sample/pcap_events.csv",
  firewall: "./sample/firewall_logs.csv",
  ids: "./sample/ids_alerts.json",
};

const phaseOrder = ["Reconnaissance", "Exploitation", "Exfiltration", "Unknown"];
const phaseToMitre = {
  Reconnaissance: ["T1046 - Network Service Scanning", "T1595 - Active Scanning"],
  Exploitation: ["T1190 - Exploit Public-Facing Application", "T1059 - Command and Scripting Interpreter"],
  Exfiltration: ["T1041 - Exfiltration Over C2 Channel", "T1048 - Exfiltration Over Alternative Protocol"],
};

const dom = {
  sampleBtn: document.getElementById("load-sample-btn"),
  runBtn: document.getElementById("run-analysis-btn"),
  clearBtn: document.getElementById("clear-inputs-btn"),
  refreshRunsBtn: document.getElementById("refresh-runs-btn"),
  saveNotesBtn: document.getElementById("save-notes-btn"),
  exportJsonBtn: document.getElementById("export-json-btn"),
  exportMarkdownBtn: document.getElementById("export-markdown-btn"),
  exportTimelineBtn: document.getElementById("export-timeline-btn"),
  exportIncidentsBtn: document.getElementById("export-incidents-btn"),
  exportSummaryBtn: document.getElementById("export-summary-btn"),
  pcapInput: document.getElementById("pcap-input"),
  firewallInput: document.getElementById("firewall-input"),
  idsInput: document.getElementById("ids-input"),
  error: document.getElementById("input-error"),
  metricEvents: document.getElementById("metric-events"),
  metricIncidents: document.getElementById("metric-incidents"),
  metricRisk: document.getElementById("metric-risk"),
  metricMitre: document.getElementById("metric-mitre"),
  chainCount: document.getElementById("chain-count"),
  timelineCount: document.getElementById("timeline-count"),
  incidentCount: document.getElementById("incident-count"),
  attackChains: document.getElementById("attack-chains"),
  riskChart: document.getElementById("risk-chart"),
  timelineBody: document.getElementById("timeline-body"),
  incidentsList: document.getElementById("incidents-list"),
  savedRuns: document.getElementById("saved-runs"),
  notes: document.getElementById("case-notes"),
  filterIp: document.getElementById("filter-ip"),
  filterPhase: document.getElementById("filter-phase"),
  filterRisk: document.getElementById("filter-risk"),
};

let currentResult = null;
let currentRunId = null;

function parseCsv(text) {
  const lines = text.trim().split(/\r?\n/).filter(Boolean);
  const headers = lines.shift().split(",").map((cell) => cell.trim());
  return lines.map((line) => {
    const values = line.split(",").map((cell) => cell.trim());
    return headers.reduce((record, header, index) => {
      record[header] = values[index] ?? "";
      return record;
    }, {});
  });
}

function parseTimestamp(value) {
  return new Date(value).toISOString();
}

function safeInt(value) {
  if (value === undefined || value === null || value === "") return null;
  return Number.parseInt(value, 10);
}

function normalizePcap(text) {
  return parseCsv(text).map((row, index) => ({
    event_id: `pcap-${index + 1}`,
    timestamp: parseTimestamp(row.timestamp),
    source: "pcap",
    src_ip: row.src_ip,
    dst_ip: row.dst_ip,
    src_port: safeInt(row.src_port),
    dst_port: safeInt(row.dst_port),
    protocol: (row.protocol || "UNKNOWN").toUpperCase(),
    action: "observed",
    severity: 2,
    summary: row.notes || "PCAP event",
    bytes_transferred: Number.parseInt(row.bytes || "0", 10),
    packet_count: Number.parseInt(row.packet_count || "0", 10),
    signature: null,
    category: null,
  }));
}

function normalizeFirewall(text) {
  return parseCsv(text).map((row, index) => {
    const action = (row.action || "unknown").toLowerCase();
    return {
      event_id: `fw-${index + 1}`,
      timestamp: parseTimestamp(row.timestamp),
      source: "firewall",
      src_ip: row.src_ip,
      dst_ip: row.dst_ip,
      src_port: safeInt(row.src_port),
      dst_port: safeInt(row.dst_port),
      protocol: (row.protocol || "UNKNOWN").toUpperCase(),
      action,
      severity: action === "blocked" ? 4 : 2,
      summary: `Firewall ${action} by rule ${row.rule || "n/a"}`,
      bytes_transferred: 0,
      packet_count: 0,
      signature: null,
      category: null,
    };
  });
}

function normalizeIds(text) {
  const payload = JSON.parse(text);
  return payload.map((row, index) => ({
    event_id: `ids-${index + 1}`,
    timestamp: parseTimestamp(row.timestamp),
    source: "ids",
    src_ip: row.src_ip,
    dst_ip: row.dst_ip,
    src_port: safeInt(row.src_port),
    dst_port: safeInt(row.dst_port),
    protocol: (row.protocol || "UNKNOWN").toUpperCase(),
    action: "alert",
    severity: Number.parseInt(row.severity || "3", 10),
    summary: row.signature || "IDS alert",
    bytes_transferred: 0,
    packet_count: 0,
    signature: row.signature || null,
    category: row.category || null,
  }));
}

function inferPhase(event) {
  const text = [event.summary, event.signature, event.category, event.action].filter(Boolean).join(" ").toLowerCase();
  if (["scan", "sweep", "recon", "probe"].some((token) => text.includes(token))) return "Reconnaissance";
  if (["exploit", "injection", "rce", "shell", "web attack", "sql"].some((token) => text.includes(token))) return "Exploitation";
  if (["exfil", "large transfer", "dns tunnel", "data staging"].some((token) => text.includes(token))) return "Exfiltration";
  if (event.source === "pcap" && event.bytes_transferred > 50000 && [53, 443, 8080].includes(event.dst_port)) return "Exfiltration";
  if (event.source === "firewall" && event.action === "blocked") return "Reconnaissance";
  return "Unknown";
}

function calculateRisk(events, phases) {
  const severityTotal = events.reduce((sum, event) => sum + event.severity, 0);
  const idsEvents = events.filter((event) => event.source === "ids").length;
  const blocked = events.filter((event) => event.action === "blocked").length;
  const bytesSent = events.reduce((sum, event) => sum + (event.bytes_transferred || 0), 0);
  let score = Math.min(severityTotal * 4, 40);
  score += Math.min(idsEvents * 6, 18);
  score += Math.min(blocked * 2, 8);
  if (phases.includes("Exfiltration")) score += 25;
  if (phases.includes("Exploitation")) score += 15;
  if (phases.includes("Reconnaissance")) score += 10;
  if (bytesSent > 100000) score += 10;
  else if (bytesSent > 25000) score += 6;
  return Math.min(score, 100);
}

function inferMitre(phases, events) {
  const techniques = new Set();
  phases.forEach((phase) => (phaseToMitre[phase] || []).forEach((item) => techniques.add(item)));
  events.forEach((event) => {
    const text = [event.summary, event.signature, event.category].filter(Boolean).join(" ").toLowerCase();
    if (text.includes("sql")) techniques.add("T1190 - Exploit Public-Facing Application");
    if (text.includes("scan") || text.includes("sweep")) techniques.add("T1046 - Network Service Scanning");
    if (text.includes("dns") && (event.bytes_transferred || 0) > 0) techniques.add("T1048 - Exfiltration Over Alternative Protocol");
  });
  return [...techniques].sort();
}

function buildNarrative(events, phases, score) {
  const sources = [...new Set(events.map((event) => event.source))].sort().join(", ");
  const phaseText = phases.length ? phases.join(" -> ") : "Unclassified activity";
  return `Correlated ${events.length} events from ${sources}. Observed attack path: ${phaseText}. Assigned risk score: ${score}/100.`;
}

function correlateEvents(events) {
  const ordered = [...events].sort((left, right) => new Date(left.timestamp) - new Date(right.timestamp));
  const clusters = new Map();
  for (const event of ordered) {
    const key = `${event.src_ip}|${event.dst_ip}|${event.protocol}`;
    const list = clusters.get(key) || [];
    if (!list.length) {
      list.push([event]);
      clusters.set(key, list);
      continue;
    }
    const currentCluster = list[list.length - 1];
    const lastEvent = currentCluster[currentCluster.length - 1];
    const delta = new Date(event.timestamp).getTime() - new Date(lastEvent.timestamp).getTime();
    if (delta <= 5 * 60 * 1000) currentCluster.push(event);
    else list.push([event]);
    clusters.set(key, list);
  }

  let counter = 1;
  const incidents = [];
  for (const [key, groups] of clusters.entries()) {
    const [src_ip, dst_ip, protocol] = key.split("|");
    groups.forEach((group) => {
      const phases = [...new Set(group.map(inferPhase).filter((phase) => phase !== "Unknown"))].sort(
        (left, right) => phaseOrder.indexOf(left) - phaseOrder.indexOf(right),
      );
      const risk_score = calculateRisk(group, phases);
      incidents.push({
        incident_id: `INC-${String(counter).padStart(4, "0")}`,
        start_time: group[0].timestamp,
        end_time: group[group.length - 1].timestamp,
        src_ip,
        dst_ip,
        protocol,
        events: group,
        phases,
        risk_score,
        mitre_techniques: inferMitre(phases, group),
        narrative: buildNarrative(group, phases, risk_score),
      });
      counter += 1;
    });
  }
  return incidents.sort((left, right) => new Date(left.start_time) - new Date(right.start_time));
}

function buildTimeline(events, incidents) {
  const incidentMap = new Map();
  incidents.forEach((incident) => {
    incident.events.forEach((event) => {
      incidentMap.set(event.event_id, {
        incident_id: incident.incident_id,
        phases: incident.phases,
        risk_score: incident.risk_score,
      });
    });
  });
  return [...events]
    .sort((left, right) => new Date(left.timestamp) - new Date(right.timestamp))
    .map((event) => ({
      ...event,
      ...(incidentMap.get(event.event_id) || { incident_id: null, phases: [], risk_score: 0 }),
    }));
}

function buildAnalysisResult({ pcapText, firewallText, idsText, scenarioLabel }) {
  const events = [...normalizePcap(pcapText), ...normalizeFirewall(firewallText), ...normalizeIds(idsText)];
  const incidents = correlateEvents(events);
  const timeline = buildTimeline(events, incidents);
  return {
    run_id: createRunId(),
    generated_at: new Date().toISOString(),
    scenario_label: scenarioLabel,
    events: timeline,
    timeline,
    incidents,
    notes: "",
  };
}

function createRunId() {
  const stamp = new Date().toISOString().replace(/[-:TZ.]/g, "").slice(0, 14);
  return `RUN-${stamp}-${Math.random().toString(36).slice(2, 8).toUpperCase()}`;
}

function init() {
  wireDropzones();
  wireActions();
  renderSavedRuns();
  setEmptyState();
}

function wireDropzones() {
  document.querySelectorAll(".dropzone").forEach((zone) => {
    const input = document.getElementById(zone.dataset.input);
    const label = zone.querySelector(".file-label");
    zone.addEventListener("dragover", (event) => {
      event.preventDefault();
      zone.classList.add("active");
    });
    zone.addEventListener("dragleave", () => zone.classList.remove("active"));
    zone.addEventListener("drop", (event) => {
      event.preventDefault();
      zone.classList.remove("active");
      input.files = event.dataTransfer.files;
      label.textContent = input.files[0]?.name || "No file selected";
    });
    input.addEventListener("change", () => {
      label.textContent = input.files[0]?.name || "No file selected";
    });
  });
}

function wireActions() {
  dom.sampleBtn.addEventListener("click", loadSampleScenario);
  dom.runBtn.addEventListener("click", runAnalysisFromInputs);
  dom.clearBtn.addEventListener("click", clearInputs);
  dom.refreshRunsBtn.addEventListener("click", renderSavedRuns);
  dom.saveNotesBtn.addEventListener("click", saveCaseNotes);
  dom.exportJsonBtn.addEventListener("click", () => exportJson(currentResult));
  dom.exportMarkdownBtn.addEventListener("click", () => exportMarkdown(currentResult));
  dom.exportTimelineBtn.addEventListener("click", () => exportCsv("timeline.csv", buildTimelineCsvRows(currentResult)));
  dom.exportIncidentsBtn.addEventListener("click", () => exportCsv("incidents.csv", buildIncidentCsvRows(currentResult)));
  dom.exportSummaryBtn.addEventListener("click", () => exportExecutiveSummary(currentResult));
  [dom.filterIp, dom.filterPhase, dom.filterRisk].forEach((element) => {
    element.addEventListener("input", applyFilters);
    element.addEventListener("change", applyFilters);
  });
}

async function loadSampleScenario() {
  clearError();
  const [pcap, firewall, ids] = await Promise.all([
    fetch(SAMPLE_FILES.pcap).then((response) => response.text()),
    fetch(SAMPLE_FILES.firewall).then((response) => response.text()),
    fetch(SAMPLE_FILES.ids).then((response) => response.text()),
  ]);
  useResult(
    buildAnalysisResult({
      pcapText: pcap,
      firewallText: firewall,
      idsText: ids,
      scenarioLabel: "Bundled sample attack",
    }),
    true,
  );
}

async function runAnalysisFromInputs() {
  clearError();
  try {
    const pcapFile = dom.pcapInput.files[0];
    const firewallFile = dom.firewallInput.files[0];
    const idsFile = dom.idsInput.files[0];
    if (!pcapFile || !firewallFile || !idsFile) {
      throw new Error("Upload PCAP CSV, firewall CSV, and IDS JSON, or use the sample attack.");
    }
    if (!pcapFile.name.endsWith(".csv") || !firewallFile.name.endsWith(".csv") || !idsFile.name.endsWith(".json")) {
      throw new Error("Invalid file types. Use CSV for PCAP/firewall and JSON for IDS.");
    }

    const [pcapText, firewallText, idsText] = await Promise.all([
      pcapFile.text(),
      firewallFile.text(),
      idsFile.text(),
    ]);
    useResult(
      buildAnalysisResult({
        pcapText,
        firewallText,
        idsText,
        scenarioLabel: `${pcapFile.name} / ${firewallFile.name} / ${idsFile.name}`,
      }),
      true,
    );
  } catch (error) {
    showError(error.message || "Unable to analyze inputs.");
  }
}

function clearInputs() {
  [dom.pcapInput, dom.firewallInput, dom.idsInput].forEach((input) => {
    input.value = "";
    const zone = document.querySelector(`[data-input="${input.id}"]`);
    if (zone) zone.querySelector(".file-label").textContent = "No file selected";
  });
  clearError();
}

function useResult(result, persist) {
  currentResult = result;
  currentRunId = result.run_id;
  dom.notes.value = result.notes || "";
  renderResult(result);
  setExportState(true);
  if (persist) persistRun(result);
}

function renderResult(result) {
  const techniques = new Set(result.incidents.flatMap((incident) => incident.mitre_techniques));
  const highestRisk = Math.max(0, ...result.incidents.map((incident) => incident.risk_score));
  dom.metricEvents.textContent = String(result.timeline.length);
  dom.metricIncidents.textContent = String(result.incidents.length);
  dom.metricRisk.textContent = String(highestRisk);
  dom.metricMitre.textContent = String(techniques.size);
  renderAttackChains(result.incidents);
  renderRiskChart(result.incidents);
  renderIncidents(result.incidents);
  renderTimeline(result.timeline);
  renderSavedRuns();
  applyFilters();
}

function renderAttackChains(incidents) {
  dom.chainCount.textContent = `${incidents.length} chains`;
  if (!incidents.length) {
    dom.attackChains.className = "attack-chain-list empty-state";
    dom.attackChains.textContent = "No correlated incidents found.";
    return;
  }
  dom.attackChains.className = "attack-chain-list";
  dom.attackChains.innerHTML = incidents.map((incident) => {
    const phases = (incident.phases.length ? incident.phases : ["Unknown"])
      .map((phase) => `<span class="flow-node">${phase}</span>`)
      .join('<span class="flow-arrow">→</span>');
    return `
      <article class="chain-card" data-phase="${incident.phases.join("|")}" data-risk="${incident.risk_score}" data-ip="${incident.src_ip} ${incident.dst_ip}">
        <div class="incident-card-header">
          <div>
            <strong>${incident.incident_id}</strong>
            <p>${incident.protocol} corridor with ${incident.events.length} evidence events</p>
          </div>
          <span class="risk-badge">Risk ${incident.risk_score}/100</span>
        </div>
        <div class="chain-flow">
          <span class="flow-endpoint attacker">${incident.src_ip}</span>
          <span class="flow-arrow">→</span>
          ${phases}
          <span class="flow-arrow">→</span>
          <span class="flow-endpoint target">${incident.dst_ip}</span>
        </div>
        <p>${incident.narrative}</p>
      </article>
    `;
  }).join("");
}

function renderRiskChart(incidents) {
  if (!incidents.length) {
    dom.riskChart.className = "risk-chart empty-state";
    dom.riskChart.textContent = "Run an analysis to generate the priority chart.";
    return;
  }
  dom.riskChart.className = "risk-chart";
  dom.riskChart.innerHTML = incidents.map((incident) => `
    <article class="saved-run-card">
      <div class="run-card-header">
        <strong>${incident.incident_id}</strong>
        <span>${incident.risk_score}/100</span>
      </div>
      <div class="risk-bar"><span style="width:${incident.risk_score}%"></span></div>
      <p>${incident.src_ip} → ${incident.dst_ip}</p>
    </article>
  `).join("");
}

function renderTimeline(timeline) {
  dom.timelineBody.innerHTML = timeline.map((row) => `
    <tr data-phase="${row.phases.join("|")}" data-risk="${row.risk_score}" data-ip="${row.src_ip} ${row.dst_ip}">
      <td>${formatDate(row.timestamp)}</td>
      <td>${row.incident_id || "-"}</td>
      <td>${row.source}</td>
      <td>${row.src_ip} → ${row.dst_ip}</td>
      <td>${row.protocol}</td>
      <td>${row.action}</td>
      <td>${row.summary}</td>
    </tr>
  `).join("");
  dom.timelineCount.textContent = `${timeline.length} rows`;
}

function renderIncidents(incidents) {
  dom.incidentCount.textContent = `${incidents.length} incidents`;
  if (!incidents.length) {
    dom.incidentsList.className = "incident-list empty-state";
    dom.incidentsList.textContent = "No correlated incidents found.";
    return;
  }
  dom.incidentsList.className = "incident-list";
  dom.incidentsList.innerHTML = incidents.map((incident) => `
    <article class="incident-card" data-phase="${incident.phases.join("|")}" data-risk="${incident.risk_score}" data-ip="${incident.src_ip} ${incident.dst_ip}">
      <div class="incident-card-header">
        <div>
          <h3>${incident.incident_id}</h3>
          <p>${incident.src_ip} → ${incident.dst_ip} over ${incident.protocol}</p>
        </div>
        <span class="risk-badge">Risk ${incident.risk_score}/100</span>
      </div>
      <div class="incident-meta">
        ${(incident.phases.length ? incident.phases : ["Unknown"]).map((phase) => `<span class="phase-chip">${phase}</span>`).join("")}
      </div>
      <p>${incident.narrative}</p>
      <div class="incident-meta">
        ${incident.mitre_techniques.map((item) => `<span class="meta-chip">${item}</span>`).join("")}
      </div>
    </article>
  `).join("");
}

function formatDate(value) {
  return new Date(value).toLocaleString();
}

function applyFilters() {
  const ipValue = dom.filterIp.value.trim().toLowerCase();
  const phaseValue = dom.filterPhase.value;
  const riskValue = Number(dom.filterRisk.value);
  const matches = (element) => {
    const phases = element.dataset.phase || "";
    const risk = Number(element.dataset.risk || "0");
    const ip = (element.dataset.ip || "").toLowerCase();
    return (!ipValue || ip.includes(ipValue)) && (!phaseValue || phases.split("|").includes(phaseValue)) && risk >= riskValue;
  };

  const timelineRows = [...dom.timelineBody.querySelectorAll("tr")];
  timelineRows.forEach((row) => row.classList.toggle("hidden", !matches(row)));
  dom.timelineCount.textContent = `${timelineRows.filter((row) => !row.classList.contains("hidden")).length} rows`;
  document.querySelectorAll(".incident-card").forEach((card) => card.classList.toggle("hidden", !matches(card)));
  document.querySelectorAll(".chain-card").forEach((card) => card.classList.toggle("hidden", !matches(card)));
}

function persistRun(result) {
  const saved = getSavedRuns();
  const next = [result, ...saved.filter((run) => run.run_id !== result.run_id)].slice(0, 8);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
}

function saveCaseNotes() {
  if (!currentResult) return;
  const saved = getSavedRuns();
  const next = saved.map((run) => (run.run_id === currentRunId ? { ...run, notes: dom.notes.value } : run));
  localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
  currentResult.notes = dom.notes.value;
  renderSavedRuns();
}

function getSavedRuns() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
  } catch {
    return [];
  }
}

function renderSavedRuns() {
  const saved = getSavedRuns();
  if (!saved.length) {
    dom.savedRuns.className = "saved-runs empty-state";
    dom.savedRuns.textContent = "Saved local investigations will appear here after analysis.";
    return;
  }
  dom.savedRuns.className = "saved-runs";
  dom.savedRuns.innerHTML = saved.map((run) => `
    <article class="saved-run-card">
      <div class="run-card-header">
        <div><strong>${run.run_id}</strong><p>${run.scenario_label}</p></div>
        <span class="quiet-pill">${run.incidents.length} incidents</span>
      </div>
      <div class="run-meta">
        <span class="meta-chip">${run.timeline.length} events</span>
        <span class="meta-chip">Highest risk ${Math.max(0, ...run.incidents.map((incident) => incident.risk_score))}</span>
      </div>
      <button class="ghost-button" data-open-run="${run.run_id}">Open</button>
      <button class="ghost-button" data-delete-run="${run.run_id}">Delete</button>
    </article>
  `).join("");

  dom.savedRuns.querySelectorAll("[data-open-run]").forEach((button) => {
    button.addEventListener("click", () => {
      const run = saved.find((entry) => entry.run_id === button.dataset.openRun);
      if (run) useResult(run, false);
    });
  });
  dom.savedRuns.querySelectorAll("[data-delete-run]").forEach((button) => {
    button.addEventListener("click", () => {
      const next = saved.filter((entry) => entry.run_id !== button.dataset.deleteRun);
      localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
      if (currentRunId === button.dataset.deleteRun) {
        currentResult = null;
        currentRunId = null;
        dom.notes.value = "";
        setEmptyState();
      }
      renderSavedRuns();
    });
  });
}

function setEmptyState() {
  dom.metricEvents.textContent = "0";
  dom.metricIncidents.textContent = "0";
  dom.metricRisk.textContent = "0";
  dom.metricMitre.textContent = "0";
  dom.chainCount.textContent = "0 chains";
  dom.timelineCount.textContent = "0 rows";
  dom.incidentCount.textContent = "0 incidents";
  dom.attackChains.className = "attack-chain-list empty-state";
  dom.attackChains.textContent = "Run an analysis to visualize the attack progression.";
  dom.riskChart.className = "risk-chart empty-state";
  dom.riskChart.textContent = "Run an analysis to generate the priority chart.";
  dom.timelineBody.innerHTML = "";
  dom.incidentsList.className = "incident-list empty-state";
  dom.incidentsList.textContent = "Upload evidence or load the sample attack to generate incidents.";
  setExportState(false);
}

function setExportState(enabled) {
  [dom.exportJsonBtn, dom.exportMarkdownBtn, dom.exportTimelineBtn, dom.exportIncidentsBtn, dom.exportSummaryBtn]
    .forEach((button) => { button.disabled = !enabled; });
}

function buildTimelineCsvRows(result) {
  return result.timeline.map((row) => ({
    timestamp: row.timestamp,
    incident_id: row.incident_id || "",
    source: row.source,
    src_ip: row.src_ip,
    dst_ip: row.dst_ip,
    protocol: row.protocol,
    action: row.action,
    summary: row.summary,
    severity: row.severity,
    phases: row.phases.join(" | "),
    risk_score: row.risk_score,
  }));
}

function buildIncidentCsvRows(result) {
  return result.incidents.map((incident) => ({
    incident_id: incident.incident_id,
    start_time: incident.start_time,
    end_time: incident.end_time,
    src_ip: incident.src_ip,
    dst_ip: incident.dst_ip,
    protocol: incident.protocol,
    risk_score: incident.risk_score,
    phases: incident.phases.join(" | "),
    mitre_techniques: incident.mitre_techniques.join(" | "),
    event_count: incident.events.length,
    narrative: incident.narrative,
  }));
}

function toCsv(rows) {
  if (!rows.length) return "";
  const headers = Object.keys(rows[0]);
  return [headers.join(","), ...rows.map((row) => headers.map((header) => `"${String(row[header] ?? "").replaceAll('"', '""')}"`).join(","))].join("\n");
}

function download(filename, content, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function exportJson(result) {
  download(`${result.run_id}.json`, JSON.stringify(result, null, 2), "application/json");
}

function exportCsv(filename, rows) {
  download(filename, toCsv(rows), "text/csv;charset=utf-8");
}

function exportMarkdown(result) {
  const lines = [
    "# Network Forensics Evidence Correlator Report",
    "",
    `Run ID: ${result.run_id}`,
    `Generated: ${result.generated_at}`,
    `Scenario: ${result.scenario_label}`,
    "",
    `Total incidents: ${result.incidents.length}`,
    "",
  ];
  result.incidents.forEach((incident) => {
    lines.push(`## ${incident.incident_id}`);
    lines.push(`- Flow: ${incident.src_ip} -> ${incident.dst_ip} (${incident.protocol})`);
    lines.push(`- Time Window: ${incident.start_time} to ${incident.end_time}`);
    lines.push(`- Risk: ${incident.risk_score}/100`);
    lines.push(`- Phases: ${incident.phases.join(", ") || "Unknown"}`);
    lines.push(`- MITRE: ${incident.mitre_techniques.join(", ") || "None"}`);
    lines.push(`- Narrative: ${incident.narrative}`);
    lines.push("");
  });
  if (dom.notes.value.trim()) lines.push("## Case Notes", "", dom.notes.value.trim(), "");
  download(`${result.run_id}.md`, lines.join("\n"), "text/markdown;charset=utf-8");
}

function exportExecutiveSummary(result) {
  const highestRisk = Math.max(0, ...result.incidents.map((incident) => incident.risk_score));
  const techniques = [...new Set(result.incidents.flatMap((incident) => incident.mitre_techniques))];
  const topTarget = result.incidents[0]?.dst_ip || "N/A";
  const notes = dom.notes.value.trim();
  const html = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8" /><title>Executive Summary</title><style>body{font-family:Segoe UI,sans-serif;margin:0;padding:28px;color:#102332;background:#eef4f6}.sheet{max-width:960px;margin:0 auto;background:white;border-radius:20px;padding:28px;box-shadow:0 22px 48px rgba(16,35,50,.08)}h1,h2{margin-top:0}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:18px 0 24px}.card{border:1px solid #d7e4ea;border-radius:16px;padding:14px}.card strong{display:block;font-size:1.8rem;color:#f46b16}.chain{border:1px solid #d7e4ea;border-radius:16px;padding:14px;margin-top:14px}@media print{body{background:white;padding:0}.sheet{box-shadow:none;border-radius:0}}</style></head><body><div class="sheet"><h1>Executive Attack Summary</h1><p>Run ID: ${result.run_id}</p><div class="grid"><div class="card"><span>Total Events</span><strong>${result.timeline.length}</strong></div><div class="card"><span>Incidents</span><strong>${result.incidents.length}</strong></div><div class="card"><span>Highest Risk</span><strong>${highestRisk}</strong></div><div class="card"><span>Top Target</span><strong>${topTarget}</strong></div></div><h2>Executive Narrative</h2><p>The correlator reconstructed ${result.incidents.length} incidents from ${result.timeline.length} evidence events. The highest assessed risk reached ${highestRisk}/100 and the primary focus target was ${topTarget}.</p><h2>Top MITRE Techniques</h2><p>${techniques.join(", ") || "None"}</p><h2>Attack Chains</h2>${result.incidents.map((incident) => `<div class="chain"><strong>${incident.incident_id}</strong><p>${incident.src_ip} -> ${incident.dst_ip} over ${incident.protocol}</p><p>${incident.narrative}</p></div>`).join("")}${notes ? `<h2>Case Notes</h2><p>${notes.replaceAll("\n", "<br>")}</p>` : ""}</div></body></html>`;
  download(`${result.run_id}-executive-summary.html`, html, "text/html;charset=utf-8");
}

function showError(message) {
  dom.error.textContent = message;
  dom.error.classList.remove("hidden");
}

function clearError() {
  dom.error.textContent = "";
  dom.error.classList.add("hidden");
}

init();
