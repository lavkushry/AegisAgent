// ── AegisAgent SOC Console JS Application Logic ──

(function () {
  "use strict";

  // ── State Management ──
  var state = {
    activeView: "overview",
    gatewayUrl: localStorage.getItem("aegis_gateway_url") || window.location.origin,
    token: localStorage.getItem("aegis_token") || "tenant_123",
    tenantId: "tenant_123",
    tenants: ["tenant_123"],
    autoRefresh: true,
    refreshInterval: null,
    
    // Cached Data
    alerts: [],
    incidents: [],
    approvals: [],
    agents: [],
    mcpServers: [],
    receipts: [],
    riskScoreboard: [],
    selectedIncident: null,
    selectedMcpServerKey: null,
    selectedAgent: null,
    graphNetworks: {}, // #1273: live vis.Network instances, keyed by container id
    
    // Explore View Filters
    searchQuery: "",
    activeFilters: {}
  };

  // If local dev or served from binary, ensure url is relative by default if appropriate
  if (state.gatewayUrl === "null" || !state.gatewayUrl) {
    state.gatewayUrl = window.location.origin;
  }

  // ── DOM References ──
  var refs = {
    menuItems: document.querySelectorAll(".menu-item"),
    views: document.querySelectorAll(".view-panel"),
    tenantSelect: document.getElementById("tenant-select"),
    configToggle: document.getElementById("config-toggle"),
    configPanel: document.getElementById("connection-config-panel"),
    gatewayUrlInput: document.getElementById("gateway-url-input"),
    authTokenInput: document.getElementById("auth-token-input"),
    saveConfigBtn: document.getElementById("save-config-btn"),
    globalRefreshBtn: document.getElementById("global-refresh-btn"),
    globalAutoRefresh: document.getElementById("global-auto-refresh"),
    globalStatusDot: document.getElementById("global-status-dot"),
    globalStatusText: document.getElementById("global-status-text"),
    errorBanner: document.getElementById("error-banner"),
    
    // Menu badges
    menuAlertsCount: document.getElementById("menu-alerts-count"),
    menuIncidentsCount: document.getElementById("menu-incidents-count"),
    menuApprovalsCount: document.getElementById("menu-approvals-count"),
    
    // Stat Cards
    statProtected: document.getElementById("stat-protected"),
    statDenied: document.getElementById("stat-denied"),
    statApprovals: document.getElementById("stat-approvals"),
    statIncidents: document.getElementById("stat-incidents"),
    statAlerts: document.getElementById("stat-alerts"),
    statChainStatus: document.getElementById("stat-chain-status"),
    statUntrustedPct: document.getElementById("stat-untrusted-pct"),
    statAgentsTotal: document.getElementById("stat-agents-total"),
    statDenyRate: document.getElementById("stat-deny-rate"),
    statRiskPosture: document.getElementById("stat-risk-posture"),
    sparklineDecisions: document.getElementById("sparkline-decisions"),

    // Overview elements
    liveFeed: document.getElementById("live-feed-events"),
    topIncidentContainer: document.getElementById("top-incident-container"),
    svgDecisionChart: document.getElementById("svg-decision-chart"),
    trustLevelDistribution: document.getElementById("trust-level-distribution"),
    
    // Explore Elements
    exploreQueryInput: document.getElementById("explore-query-input"),
    executeSearchBtn: document.getElementById("execute-search-btn"),
    activeFiltersContainer: document.getElementById("active-filters-container"),
    searchResultsCount: document.getElementById("search-results-count"),
    exploreTbody: document.getElementById("explore-tbody"),
    facetDecision: document.getElementById("facet-decision"),
    facetTrust: document.getElementById("facet-trust"),
    facetTool: document.getElementById("facet-tool"),
    
    // Alerts Elements
    alertsViewCount: document.getElementById("alerts-view-count"),
    alertsViewTbody: document.getElementById("alerts-view-tbody"),
    
    // Incidents List & Detail
    incidentsListContainer: document.getElementById("incidents-list-container"),
    incidentsViewCount: document.getElementById("incidents-view-count"),
    incidentsViewTbody: document.getElementById("incidents-view-tbody"),
    incidentDetailContainer: document.getElementById("incident-detail-container"),
    backToIncidentsBtn: document.getElementById("back-to-incidents-btn"),
    incDetailId: document.getElementById("inc-detail-id"),
    incDetailSeverity: document.getElementById("inc-detail-severity"),
    incDetailStatus: document.getElementById("inc-detail-status"),
    incDetailTimelineFlow: document.getElementById("incident-timeline-flow"),
    incDetailRcaContent: document.getElementById("incident-rca-content"),
    incDetailAgentStatus: document.getElementById("inc-detail-agent-status"),
    incMetaAgentId: document.getElementById("inc-meta-agent-id"),
    incMetaKind: document.getElementById("inc-meta-kind"),
    incMetaRule: document.getElementById("inc-meta-rule"),
    incMetaOpened: document.getElementById("inc-meta-opened"),
    incMetaClosed: document.getElementById("inc-meta-closed"),
    verifyIncidentChainBtn: document.getElementById("verify-incident-chain-btn"),
    timelineVerificationStatus: document.getElementById("timeline-verification-status"),
    narrateIncidentBtn: document.getElementById("narrate-incident-btn"),
    incContainFreezeBtn: document.getElementById("inc-contain-freeze-btn"),
    incContainUnfreezeBtn: document.getElementById("inc-contain-unfreeze-btn"),
    incContainRevokeBtn: document.getElementById("inc-contain-revoke-btn"),
    incCloseIncidentBtn: document.getElementById("inc-close-incident-btn"),

    // Incident Evidence Graph (#1273)
    incidentGraphContainer: document.getElementById("incident-graph-container"),
    incidentGraphLoading: document.getElementById("incident-graph-loading"),
    incidentGraphLegend: document.getElementById("incident-graph-legend"),
    incidentGraphNodeDetail: document.getElementById("incident-graph-node-detail"),
    incidentGraphNodeType: document.getElementById("incident-graph-node-type"),
    incidentGraphNodeLabel: document.getElementById("incident-graph-node-label"),
    incidentGraphNodeTimestamp: document.getElementById("incident-graph-node-timestamp"),
    incidentGraphNodeMetadata: document.getElementById("incident-graph-node-metadata"),

    // Approvals Queue
    approvalsViewCount: document.getElementById("approvals-view-count"),
    approvalsCardsContainer: document.getElementById("approvals-cards-container"),

    // Fleet / Agents List & Detail (#1273)
    agentListContainer: document.getElementById("agent-list-container"),
    agentsTbody: document.getElementById("agents-tbody"),
    agentDetailContainer: document.getElementById("agent-detail-container"),
    backToAgentsBtn: document.getElementById("back-to-agents-btn"),
    agentDetailId: document.getElementById("agent-detail-id"),
    agentDetailStatus: document.getElementById("agent-detail-status"),
    agentDetailOwner: document.getElementById("agent-detail-owner"),
    agentDetailEnv: document.getElementById("agent-detail-env"),
    agentDetailRiskTier: document.getElementById("agent-detail-risk-tier"),
    agentDetailCreated: document.getElementById("agent-detail-created"),
    agentGraphContainer: document.getElementById("agent-graph-container"),
    agentGraphLoading: document.getElementById("agent-graph-loading"),
    agentGraphLegend: document.getElementById("agent-graph-legend"),
    agentGraphNodeDetail: document.getElementById("agent-graph-node-detail"),
    agentGraphNodeType: document.getElementById("agent-graph-node-type"),
    agentGraphNodeLabel: document.getElementById("agent-graph-node-label"),
    agentGraphNodeTimestamp: document.getElementById("agent-graph-node-timestamp"),
    agentGraphNodeMetadata: document.getElementById("agent-graph-node-metadata"),

    // Agent Risk Scoreboard (#1290)
    riskScoreboardTbody: document.getElementById("risk-scoreboard-tbody"),
    exportRiskScoreboardCsvBtn: document.getElementById("export-risk-scoreboard-csv-btn"),
    topRiskAgentsContainer: document.getElementById("top-risk-agents-container"),

    // MCP Server List & Detail (#1334)
    mcpListContainer: document.getElementById("mcp-list-container"),
    mcpServersTbody: document.getElementById("mcp-servers-tbody"),
    mcpDetailContainer: document.getElementById("mcp-detail-container"),
    backToMcpBtn: document.getElementById("back-to-mcp-btn"),
    mcpDetailServerKey: document.getElementById("mcp-detail-server-key"),
    mcpDetailStatus: document.getElementById("mcp-detail-status"),
    mcpDetailToolsTbody: document.getElementById("mcp-detail-tools-tbody"),
    mcpDetailHistoryTbody: document.getElementById("mcp-detail-history-tbody"),
    mcpDetailQuarantineStatus: document.getElementById("mcp-detail-quarantine-status"),
    mcpQuarantineBtn: document.getElementById("mcp-quarantine-btn"),
    mcpRestoreBtn: document.getElementById("mcp-restore-btn"),
    mcpDetailManifestHash: document.getElementById("mcp-detail-manifest-hash"),
    mcpDetailLastDiscovery: document.getElementById("mcp-detail-last-discovery"),
    mcpDetailTrustLevel: document.getElementById("mcp-detail-trust-level"),
    mcpDetailTransport: document.getElementById("mcp-detail-transport"),

    // Integrity receipts
    receiptsTbody: document.getElementById("receipts-tbody"),
    verifyWholeChainBtn: document.getElementById("verify-whole-chain-btn"),
    chainVerifyBanner: document.getElementById("chain-verify-banner")
  };

  // Initialize Connection inputs
  refs.gatewayUrlInput.value = state.gatewayUrl;
  refs.authTokenInput.value = state.token;

  // ── Network Client ──
  function apiFetch(endpoint, method, body) {
    var url = state.gatewayUrl.replace(/\/+$/, "") + endpoint;
    var headers = {
      "Accept": "application/json",
      "X-Aegis-Tenant-ID": state.tenantId,
      "X-Tenant-ID": state.tenantId
    };
    if (state.token) {
      headers["Authorization"] = "Bearer " + state.token;
    }
    
    // Add CSRF token to headers if present in HTML
    var csrfMeta = document.querySelector('meta[name="csrf-token"]');
    if (csrfMeta) {
      headers["X-CSRF-Token"] = csrfMeta.getAttribute("content");
    }
    
    var options = { method: method || "GET", headers: headers };
    if (body) {
      options.headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(body);
    }
    
    return fetch(url, options).then(function (resp) {
      if (!resp.ok) {
        if (resp.status === 401) {
          throw new Error("Unauthorized access. Check Bearer token.");
        }
        return resp.json().then(function (json) {
          throw new Error(json.error || json.reason || "HTTP error " + resp.status);
        }).catch(function() {
          throw new Error("HTTP error " + resp.status + ": " + resp.statusText);
        });
      }
      if (resp.status === 204) {
        return null;
      }
      return resp.json();
    });
  }

  // ── UI Error Display ──
  function showError(msg) {
    if (msg) {
      refs.errorBanner.querySelector(".banner-text").textContent = msg;
      refs.errorBanner.style.display = "flex";
    } else {
      refs.errorBanner.style.display = "none";
    }
  }

  // Close banner
  refs.errorBanner.querySelector(".banner-close").addEventListener("click", function() {
    showError(null);
  });

  // ── View Router ──
  function switchView(viewName) {
    state.activeView = viewName;
    
    // Update Menu selection UI
    refs.menuItems.forEach(function (item) {
      if (item.getAttribute("data-view") === viewName) {
        item.classList.add("active");
      } else {
        item.classList.remove("active");
      }
    });

    // Hide/show views
    refs.views.forEach(function (view) {
      if (view.id === "view-" + viewName) {
        view.style.display = "block";
      } else {
        view.style.display = "none";
      }
    });

    // Proactively close incident detail if moving away
    if (viewName !== "incidents") {
      refs.incidentDetailContainer.style.display = "none";
      refs.incidentsListContainer.style.display = "block";
      destroyGraphNetwork(refs.incidentGraphContainer);
    }

    // Proactively close MCP server detail if moving away (#1334)
    if (viewName !== "mcp") {
      refs.mcpDetailContainer.style.display = "none";
      refs.mcpListContainer.style.display = "block";
    }

    // Proactively close agent detail if moving away (#1273)
    if (viewName !== "agents") {
      refs.agentDetailContainer.style.display = "none";
      refs.agentListContainer.style.display = "block";
      destroyGraphNetwork(refs.agentGraphContainer);
    }

    // Load initial data for selected view
    loadViewData(viewName);
  }

  // Attach nav event listeners
  refs.menuItems.forEach(function (item) {
    item.addEventListener("click", function (e) {
      e.preventDefault();
      var view = item.getAttribute("data-view");
      switchView(view);
    });
  });

  // Attach card navigation
  document.querySelectorAll("[data-target-view]").forEach(function(card) {
    card.addEventListener("click", function() {
      var view = card.getAttribute("data-target-view");
      if (view) switchView(view);
    });
  });

  // Collapsible Connection panel
  refs.configToggle.addEventListener("click", function() {
    if (refs.configPanel.style.display === "none") {
      refs.configPanel.style.display = "block";
    } else {
      refs.configPanel.style.display = "none";
    }
  });

  // Save config
  refs.saveConfigBtn.addEventListener("click", function() {
    state.gatewayUrl = refs.gatewayUrlInput.value || window.location.origin;
    state.token = refs.authTokenInput.value;
    localStorage.setItem("aegis_gateway_url", state.gatewayUrl);
    localStorage.setItem("aegis_token", state.token);
    refs.configPanel.style.display = "none";
    
    showError(null);
    refs.globalStatusDot.className = "status-dot yellow";
    refs.globalStatusText.textContent = "Connecting...";
    
    refreshAllData();
  });

  // ── Load & Refresh Data ──
  function refreshAllData() {
    showError(null);
    loadViewData(state.activeView);
    // Always update menu badges & overview counters
    fetchOverviewCounters();
  }

  refs.globalRefreshBtn.addEventListener("click", refreshAllData);

  function toggleAutoRefresh(enabled) {
    state.autoRefresh = enabled;
    if (state.refreshInterval) {
      clearInterval(state.refreshInterval);
      state.refreshInterval = null;
    }
    if (enabled) {
      state.refreshInterval = setInterval(refreshAllData, 10000);
    }
  }

  refs.globalAutoRefresh.addEventListener("change", function(e) {
    toggleAutoRefresh(e.target.checked);
  });

  // ── Load specific views ──
  function loadViewData(view) {
    switch (view) {
      case "overview":
        fetchOverviewData();
        break;
      case "explore":
        executeExploreSearch();
        break;
      case "alerts":
        fetchAlertsView();
        break;
      case "incidents":
        if (refs.incidentDetailContainer.style.display === "block" && state.selectedIncident) {
          fetchIncidentDetail(state.selectedIncident.id);
        } else {
          fetchIncidentsView();
        }
        break;
      case "approvals":
        fetchApprovalsView();
        break;
      case "agents":
        fetchAgentsView();
        break;
      case "risk-scoreboard":
        fetchRiskScoreboardView();
        break;
      case "mcp":
        if (refs.mcpDetailContainer.style.display === "block" && state.selectedMcpServerKey) {
          fetchMcpServerDetail(state.selectedMcpServerKey);
        } else {
          fetchMcpView();
        }
        break;
      case "receipts":
        fetchReceiptsView();
        break;
    }
  }

  // ── Fetch Operations ──

  // Fetch Overview Counters & Badges
  function fetchOverviewCounters() {
    // Stat 1, 2, 3, 5, 6, 8: Get metrics from /v1/soc/summary
    apiFetch("/v1/soc/summary").then(function (data) {
      // Menu badges
      refs.menuIncidentsCount.textContent = data.incidents_open;
      refs.menuIncidentsCount.style.display = data.incidents_open > 0 ? "inline-block" : "none";
      refs.menuAlertsCount.textContent = data.alerts_total;
      refs.menuAlertsCount.style.display = data.alerts_total > 0 ? "inline-block" : "none";
      refs.menuApprovalsCount.textContent = data.approvals_pending;
      refs.menuApprovalsCount.style.display = data.approvals_pending > 0 ? "inline-block" : "none";

      // Overview stat cards
      refs.statAgentsTotal.textContent = data.agents_total || 0;
      refs.statIncidents.textContent = data.incidents_open || 0;
      refs.statApprovals.textContent = data.approvals_pending || 0;
      refs.statProtected.textContent = data.decisions_today || 0;
      refs.statDenyRate.textContent = Math.round(data.deny_rate_today || 0) + "%";
      refs.statAlerts.textContent = data.alerts_total || 0;

      // Risk Posture
      var posture = data.risk_posture || "healthy";
      refs.statRiskPosture.textContent = posture.charAt(0).toUpperCase() + posture.slice(1);
      if (posture === "critical") {
        refs.statRiskPosture.className = "stat-value text-critical";
      } else if (posture === "degraded") {
        refs.statRiskPosture.className = "stat-value text-warning";
      } else {
        refs.statRiskPosture.className = "stat-value text-success";
      }

      // Sparklines & Charts
      renderSparkline(data.hourly_decisions_24h || []);
      renderDecisionChart(data.hourly_decisions_24h || []);
    }).catch(console.error);

    // Stat 4 & 7: Get overall stats and trust distribution from /v1/stats
    apiFetch("/v1/stats").then(function (data) {
      renderTrustLevelDistribution(data.trust_level_breakdown || [], data.total_decisions || 0);
      refs.globalStatusDot.className = "status-dot green";
      refs.globalStatusText.textContent = "Connected";
    }).catch(function(err) {
      refs.globalStatusDot.className = "status-dot red";
      refs.globalStatusText.textContent = "Offline / Error";
      showError("Connection failed to " + state.gatewayUrl + ": " + err.message);
    });
  }

  // Fetch Overview Panel
  function fetchOverviewData() {
    fetchOverviewCounters();
    
    // Fetch live decisions for feed
    apiFetch("/v1/decisions?limit=25&offset=0").then(function(data) {
      var rows = Array.isArray(data) ? data : (data.decisions ? data.decisions : []);
      renderLiveFeed(rows);
    }).catch(console.error);

    // Fetch top incident
    apiFetch("/v1/incidents?limit=1&offset=0").then(function (data) {
      var rows = Array.isArray(data) ? data : (data.incidents ? data.incidents : []);
      renderTopIncident(rows[0]);
    }).catch(console.error);

    // Fetch top 5 riskiest agents (#1290)
    apiFetch("/v1/agents/risk-scoreboard").then(function (data) {
      renderTopRiskAgents(data.slice(0, 5));
    }).catch(console.error);
  }

  function renderLiveFeed(decisions) {
    refs.liveFeed.innerHTML = "";
    if (decisions.length === 0) {
      refs.liveFeed.innerHTML = "<div class='empty-row'>No recent events.</div>";
      return;
    }
    decisions.forEach(function (d) {
      var item = document.createElement("div");
      item.className = "feed-item";
      
      var isDeny = d.decision === "deny";
      var isApproval = d.decision === "require_approval";
      var decSpan = isDeny ? "<strong class='text-error'>Blocked</strong>" : (isApproval ? "<strong class='text-warning'>Approval Required</strong>" : "<strong class='text-success'>Allowed</strong>");
      
      var timeStr = new Date(d.created_at).toLocaleTimeString();
      
      item.innerHTML = `
        <div class="feed-item-header">
          <span>${timeStr}</span>
          <span class="mono">${d.agent_id}</span>
        </div>
        <div class="feed-item-desc">
          ${decSpan} <code>${d.skill}.${d.action}</code> &mdash; ${escapeHtml(d.reason || "Policy authorized")}
        </div>
      `;
      refs.liveFeed.appendChild(item);
    });
  }

  // Render SVG Chart using decisions
  function renderDecisionChart(hourlySeries) {
    var series = Array.isArray(hourlySeries) ? hourlySeries : [];
    if (series.length === 0) {
      series = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    }
    
    // Generate labels for the last 24h
    var labelsList = [];
    var now = new Date();
    for (var i = 0; i < series.length; i++) {
      var h = new Date(now.getTime() - (23 - i) * 60 * 60 * 1000);
      var label = h.getHours() + ":00";
      labelsList.push(label);
    }

    var maxVal = Math.max.apply(null, series) || 10;
    
    // Draw SVG Chart
    var width = 600;
    var height = 180;
    var padding = 20;
    var step = (width - padding * 2) / (series.length - 1);
    
    var points = [];
    for (var i = 0; i < series.length; i++) {
      var x = padding + i * step;
      var y = height - padding - ((series[i] / maxVal) * (height - padding * 2));
      points.push({ x: x, y: y, label: labelsList[i], val: series[i], showLabel: i % 4 === 0 || i === series.length - 1 });
    }

    var linePath = "M " + points[0].x + " " + points[0].y;
    var areaPath = "M " + points[0].x + " " + (height - padding) + " L " + points[0].x + " " + points[0].y;
    
    for (var i = 1; i < points.length; i++) {
      linePath += " L " + points[i].x + " " + points[i].y;
      areaPath += " L " + points[i].x + " " + points[i].y;
    }
    areaPath += " L " + points[points.length - 1].x + " " + (height - padding) + " Z";

    // Draw grid lines
    var grid = "";
    for (var j = 1; j <= 3; j++) {
      var yGrid = padding + (j * (height - padding * 2) / 4);
      grid += `<line x1="${padding}" y1="${yGrid}" x2="${width - padding}" y2="${yGrid}" class="grid-line" />`;
    }

    // Draw grid labels
    var labels = "";
    points.forEach(function(pt) {
      labels += `<circle cx="${pt.x}" cy="${pt.y}" r="2" fill="#6366f1" />`;
      if (pt.showLabel) {
        labels += `
          <text x="${pt.x}" y="${height - 2}" font-size="8" fill="#64748b" text-anchor="middle">${pt.label}</text>
        `;
        if (pt.val > 0) {
          labels += `
            <text x="${pt.x}" y="${pt.y - 6}" font-size="8" font-weight="bold" fill="#fff" text-anchor="middle">${pt.val}</text>
          `;
        }
      }
    });

    refs.svgDecisionChart.innerHTML = `
      <defs>
        <linearGradient id="area-grad" x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" stop-color="#6366f1" stop-opacity="0.4" />
          <stop offset="100%" stop-color="#6366f1" stop-opacity="0.0" />
        </linearGradient>
      </defs>
      ${grid}
      <path d="${areaPath}" fill="url(#area-grad)" />
      <path d="${linePath}" fill="none" stroke="#6366f1" stroke-width="2" />
      ${labels}
    `;
  }

  // Draw small vector sparkline inside Overview cards
  function renderSparkline(series) {
    if (!refs.sparklineDecisions) return;
    if (series.length === 0) {
      refs.sparklineDecisions.innerHTML = "";
      return;
    }
    var width = 80;
    var height = 30;
    var maxVal = Math.max.apply(null, series) || 10;
    
    var points = [];
    var step = width / (series.length - 1);
    for (var i = 0; i < series.length; i++) {
      var x = i * step;
      var y = height - ((series[i] / maxVal) * (height - 4)) - 2;
      points.push(x + "," + y);
    }
    
    var pathData = "M " + points.join(" L ");
    refs.sparklineDecisions.innerHTML = `<path d="${pathData}" />`;
  }

  // #1294: renders the per-trust-level decision breakdown as a bar list and
  // updates the "Untrusted Sources" overview stat. "Untrusted" is defined as
  // untrusted_external + malicious_suspected — the two levels the Cedar
  // policy pack denies mutating actions for outright (see CLAUDE.md's
  // "Critical invariants" on trust-provenance).
  function renderTrustLevelDistribution(breakdown, totalDecisions) {
    var untrustedCount = 0;
    breakdown.forEach(function (entry) {
      if (entry.trust_level === "untrusted_external" || entry.trust_level === "malicious_suspected") {
        untrustedCount += entry.count;
      }
    });
    var pct = totalDecisions > 0 ? Math.round((untrustedCount / totalDecisions) * 100) : 0;
    refs.statUntrustedPct.textContent = pct + "%";

    if (breakdown.length === 0) {
      refs.trustLevelDistribution.innerHTML = "<div class='empty-row'>No decisions recorded yet.</div>";
      return;
    }

    var maxCount = Math.max.apply(null, breakdown.map(function (e) { return e.count; }));
    var sorted = breakdown.slice().sort(function (a, b) { return b.count - a.count; });

    refs.trustLevelDistribution.innerHTML = sorted.map(function (entry) {
      var widthPct = maxCount > 0 ? (entry.count / maxCount) * 100 : 0;
      var badgeClass = trustBadgeClass(entry.trust_level);
      return `
        <div class="trust-bar-row">
          <span class="trust-bar-label">${escapeHtml(entry.trust_level)}</span>
          <span class="trust-bar-track"><span class="trust-bar-fill ${badgeClass}" style="width:${widthPct}%;"></span></span>
          <span class="trust-bar-count">${entry.count}</span>
        </div>
      `;
    }).join("");
  }

  function renderTopIncident(incident) {
    if (!incident) {
      refs.topIncidentContainer.innerHTML = "<div class='empty-row'>No open incidents. All systems safe.</div>";
      return;
    }
    
    var timeStr = new Date(incident.opened_at || incident.created_at).toLocaleString();
    refs.topIncidentContainer.innerHTML = `
      <div class="incident hoverable-incident" style="cursor:pointer; border-left: 3px solid #f43f5e;">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <div>
            <strong class="text-critical">${incident.id} &mdash; ${escapeHtml(incident.kind)}</strong>
            <div style="margin-top:4px;"><small>Agent ID: <code>${incident.agent_id}</code> &middot; Opened ${timeStr}</small></div>
          </div>
          <span class="badge badge-critical">${incident.severity}</span>
        </div>
        <p style="margin-top:10px; font-size:13px; color:var(--text-muted); line-height:1.4;">
          ${escapeHtml(incident.summary)}
        </p>
      </div>
    `;

    refs.topIncidentContainer.querySelector(".hoverable-incident").addEventListener("click", function() {
      switchView("incidents");
      openIncidentDetail(incident);
    });
  }

  // ── Explore View Search Logic ──
  function executeExploreSearch() {
    var rawQuery = refs.exploreQueryInput.value.trim();
    state.searchQuery = rawQuery;
    
    // Simple filter parsing e.g. decision:deny agent_id:xxx
    var queryParams = { limit: 100, offset: 0 };
    var filters = {};
    
    var parts = rawQuery.split(/\s+/);
    parts.forEach(function (part) {
      var kv = part.split(":");
      if (kv.length === 2 && kv[0]) {
        filters[kv[0].toLowerCase()] = kv[1];
      }
    });

    state.activeFilters = filters;
    renderFilterPills();

    // Call API for decisions matching search criteria
    apiFetch("/v1/decisions?limit=100&offset=0").then(function (data) {
      var rows = Array.isArray(data) ? data : (data.decisions ? data.decisions : []);
      
      // Perform client-side filter mock (since SQLite doesn't support complex KQL, but has full REST filter)
      var filtered = rows.filter(function (d) {
        for (var key in filters) {
          var val = filters[key].toLowerCase();
          if (key === "decision" && d.decision.toLowerCase() !== val) return false;
          if (key === "agent_id" && d.agent_id.toLowerCase().indexOf(val) === -1) return false;
          if (key === "tool" && d.skill.toLowerCase().indexOf(val) === -1) return false;
          if (key === "trust" && d.root_trust_level.toLowerCase() !== val) return false;
        }
        return true;
      });

      renderExploreTable(filtered);
      populateFacets(rows);
    }).catch(function(err) {
      showError("Search failed: " + err.message);
    });
  }

  refs.executeSearchBtn.addEventListener("click", executeExploreSearch);
  refs.exploreQueryInput.addEventListener("keypress", function(e) {
    if (e.key === "Enter") executeExploreSearch();
  });

  function renderFilterPills() {
    refs.activeFiltersContainer.innerHTML = "";
    var count = 0;
    for (var key in state.activeFilters) {
      count++;
      var pill = document.createElement("div");
      pill.className = "filter-pill";
      pill.innerHTML = `
        <span>${key}: <strong>${state.activeFilters[key]}</strong></span>
        <span class="filter-pill-remove" data-key="${key}">&times;</span>
      `;
      refs.activeFiltersContainer.appendChild(pill);
      
      pill.querySelector(".filter-pill-remove").addEventListener("click", function(e) {
        var k = e.target.getAttribute("data-key");
        delete state.activeFilters[k];
        rebuildQueryInputFromFilters();
        executeExploreSearch();
      });
    }
  }

  function rebuildQueryInputFromFilters() {
    var parts = [];
    for (var key in state.activeFilters) {
      parts.push(key + ":" + state.activeFilters[key]);
    }
    refs.exploreQueryInput.value = parts.join(" ");
  }

  function addFilter(key, value) {
    state.activeFilters[key] = value;
    rebuildQueryInputFromFilters();
    executeExploreSearch();
  }

  function renderExploreTable(rows) {
    refs.searchResultsCount.textContent = `Showing ${rows.length} decision(s)`;
    refs.exploreTbody.innerHTML = "";
    if (rows.length === 0) {
      refs.exploreTbody.innerHTML = "<tr class='empty-row'><td colspan='7'>No matching results. Try adjusting filters.</td></tr>";
      return;
    }

    rows.forEach(function (d) {
      var tr = document.createElement("tr");
      var isDeny = d.decision === "deny";
      var isApproval = d.decision === "require_approval";
      var decClass = isDeny ? "badge badge-error" : (isApproval ? "badge badge-warning" : "badge badge-success");
      
      tr.innerHTML = `
        <td class="mono">${new Date(d.created_at).toLocaleString()}</td>
        <td class="mono">${d.agent_id}</td>
        <td><code>${d.skill}.${d.action}</code></td>
        <td><span class="${decClass}">${d.decision}</span></td>
        <td><span class="badge ${trustBadgeClass(d.root_trust_level)}">${d.root_trust_level}</span></td>
        <td class="mono">${d.risk_score || 0}</td>
        <td class="mono hash">${d.id.slice(0, 8)}...</td>
      `;
      refs.exploreTbody.appendChild(tr);
    });
  }

  function populateFacets(allRows) {
    // Decsion counts
    var decisions = { allow: 0, deny: 0, require_approval: 0 };
    var trusts = {};
    var tools = {};

    allRows.forEach(function (d) {
      if (decisions[d.decision] !== undefined) decisions[d.decision]++;
      trusts[d.root_trust_level] = (trusts[d.root_trust_level] || 0) + 1;
      tools[d.skill] = (tools[d.skill] || 0) + 1;
    });

    // Populate Decision Facet
    refs.facetDecision.innerHTML = "";
    for (var key in decisions) {
      var li = document.createElement("li");
      li.className = "facet-item";
      li.innerHTML = `<span>${key}</span> <strong>${decisions[key]}</strong>`;
      li.addEventListener("click", function(k) { return function() { addFilter("decision", k); } }(key));
      refs.facetDecision.appendChild(li);
    }

    // Populate Trust Facet
    refs.facetTrust.innerHTML = "";
    var trustKeys = Object.keys(trusts).sort();
    trustKeys.forEach(function (key) {
      var li = document.createElement("li");
      li.className = "facet-item";
      li.innerHTML = `<span><span class="badge ${trustBadgeClass(key)}" style="margin-right:6px;">&nbsp;</span>${key}</span> <strong>${trusts[key]}</strong>`;
      li.addEventListener("click", function(k) { return function() { addFilter("trust", k); } }(key));
      refs.facetTrust.appendChild(li);
    });

    // Populate Tool Facet
    refs.facetTool.innerHTML = "";
    var toolKeys = Object.keys(tools).sort().slice(0, 10); // show top 10
    toolKeys.forEach(function (key) {
      var li = document.createElement("li");
      li.className = "facet-item";
      li.innerHTML = `<span>${key}</span> <strong>${tools[key]}</strong>`;
      li.addEventListener("click", function(k) { return function() { addFilter("tool", k); } }(key));
      refs.facetTool.appendChild(li);
    });
  }

  // ── Alerts View ──
  function fetchAlertsView() {
    apiFetch("/v1/alerts?limit=50&offset=0").then(function (data) {
      var rows = Array.isArray(data) ? data : (data.alerts ? data.alerts : []);
      state.alerts = rows;
      refs.alertsViewCount.textContent = rows.length;
      
      refs.alertsViewTbody.innerHTML = "";
      if (rows.length === 0) {
        refs.alertsViewTbody.innerHTML = "<tr class='empty-row'><td colspan='6'>No detections found.</td></tr>";
        return;
      }
      
      rows.forEach(function (a) {
        var tr = document.createElement("tr");
        var isCrit = a.severity === "critical" || a.severity === "high";
        var sevClass = isCrit ? "badge badge-critical" : "badge badge-warning";
        
        tr.innerHTML = `
          <td><span class="${sevClass}">${a.severity}</span></td>
          <td><strong>${a.rule}</strong></td>
          <td class="mono">${a.agent_id}</td>
          <td>${escapeHtml(a.summary)}</td>
          <td class="mono">${new Date(a.created_at).toLocaleString()}</td>
          <td class="mono hash">${a.id.slice(0, 8)}...</td>
        `;
        refs.alertsViewTbody.appendChild(tr);
      });
    }).catch(function(err) {
      showError("Failed to fetch alerts: " + err.message);
    });
  }

  // ── Incidents View ──
  function fetchIncidentsView() {
    apiFetch("/v1/incidents?limit=50&offset=0").then(function (data) {
      var rows = Array.isArray(data) ? data : (data.incidents ? data.incidents : []);
      state.incidents = rows;
      refs.incidentsViewCount.textContent = rows.length;
      
      refs.incidentsViewTbody.innerHTML = "";
      if (rows.length === 0) {
        refs.incidentsViewTbody.innerHTML = "<tr class='empty-row'><td colspan='7'>No active incidents found.</td></tr>";
        return;
      }
      
      rows.forEach(function (inc) {
        var tr = document.createElement("tr");
        tr.className = "incident-row";
        
        var isCrit = inc.severity === "critical" || inc.severity === "high";
        var sevClass = isCrit ? "badge badge-critical" : "badge badge-warning";
        
        tr.innerHTML = `
          <td><span class="${sevClass}">${inc.severity}</span></td>
          <td><strong>${inc.kind}</strong></td>
          <td class="mono">${inc.agent_id}</td>
          <td>${escapeHtml(inc.summary)}</td>
          <td class="mono">${new Date(inc.opened_at || inc.created_at).toLocaleString()}</td>
          <td><span class="badge badge-dark">${inc.status}</span></td>
          <td><button class="btn btn-secondary btn-sm open-inc-btn" data-id="${inc.id}">Investigate</button></td>
        `;
        
        tr.querySelector(".open-inc-btn").addEventListener("click", function(e) {
          e.stopPropagation();
          openIncidentDetail(inc);
        });
        
        tr.addEventListener("click", function() {
          openIncidentDetail(inc);
        });
        
        refs.incidentsViewTbody.appendChild(tr);
      });
    }).catch(function(err) {
      showError("Failed to fetch incidents: " + err.message);
    });
  }

  // Incident Details & Verification Chain
  function openIncidentDetail(incident) {
    state.selectedIncident = incident;
    refs.incidentsListContainer.style.display = "none";
    refs.incidentDetailContainer.style.display = "block";
    
    refs.incDetailId.textContent = "Incident: " + incident.id;
    refs.incDetailSeverity.textContent = incident.severity;
    refs.incDetailSeverity.className = "badge " + (incident.severity === "critical" ? "badge-critical" : "badge-warning");
    refs.incDetailStatus.textContent = incident.status;
    
    refs.incMetaAgentId.textContent = incident.agent_id;
    refs.incMetaKind.textContent = incident.kind;
    refs.incMetaRule.textContent = incident.rule || "N/A";
    refs.incMetaOpened.textContent = new Date(incident.opened_at).toLocaleString();
    refs.incMetaClosed.textContent = incident.closed_at ? new Date(incident.closed_at).toLocaleString() : "Active / Open";
    
    refs.timelineVerificationStatus.style.display = "none";
    refs.incDetailRcaContent.textContent = "Loading root cause analysis...";
    
    fetchIncidentDetail(incident.id);
  }

  function fetchIncidentDetail(incidentId) {
    // 1. Fetch RCA narrative
    apiFetch("/v1/incidents/" + incidentId + "/narrate").then(function (data) {
      refs.incDetailRcaContent.textContent = data.narrative || "No narrative available.";
    }).catch(function(err) {
      refs.incDetailRcaContent.textContent = "Failed to load narrative: " + err.message;
    });

    // 2. Fetch agent operational status
    apiFetch("/v1/agents/" + state.selectedIncident.agent_id).then(function (data) {
      refs.incDetailAgentStatus.textContent = data.status;
      refs.incDetailAgentStatus.className = data.status === "active" ? "text-success" : "text-critical";
    }).catch(console.error);

    // 3. Fetch Incident timeline/events
    apiFetch("/v1/incidents/" + incidentId).then(function (data) {
      // Build dynamic timeline flow
      renderIncidentTimeline(data.timeline || []);
    }).catch(function(err) {
      refs.incDetailTimelineFlow.innerHTML = "<div class='empty-row'>Failed to load timeline: " + err.message + "</div>";
    });

    // 4. Fetch + render the evidence graph (#1273)
    fetchAndRenderEvidenceGraph("/v1/graph/incident/" + incidentId, {
      container: refs.incidentGraphContainer,
      loading: refs.incidentGraphLoading,
      legend: refs.incidentGraphLegend,
      nodeDetail: refs.incidentGraphNodeDetail,
      nodeType: refs.incidentGraphNodeType,
      nodeLabel: refs.incidentGraphNodeLabel,
      nodeTimestamp: refs.incidentGraphNodeTimestamp,
      nodeMetadata: refs.incidentGraphNodeMetadata
    });
  }

  function renderIncidentTimeline(timeline) {
    refs.incDetailTimelineFlow.innerHTML = "";
    if (timeline.length === 0) {
      refs.incDetailTimelineFlow.innerHTML = "<div class='empty-row'>No timeline events.</div>";
      return;
    }

    timeline.forEach(function (step) {
      var item = document.createElement("div");
      
      var isDeny = step.decision === "deny";
      var isAllow = step.decision === "allow";
      var isCrit = step.event_type === "alert" || step.severity === "critical";
      
      var stepClass = isDeny ? "timeline-step deny" : (isAllow ? "timeline-step allow" : (isCrit ? "timeline-step detection" : "timeline-step action"));
      item.className = stepClass;
      
      var timeStr = new Date(step.created_at || step.ts).toLocaleTimeString();
      var decSpan = isDeny ? "<strong class='text-error'>Blocked</strong>" : (isAllow ? "<strong class='text-success'>Allowed</strong>" : `<strong>${step.decision || step.event_type}</strong>`);
      
      item.innerHTML = `
        <div class="timeline-step-meta">${timeStr}</div>
        <div class="timeline-step-body">
          <div class="timeline-step-desc">
            ${decSpan} <code>${step.skill || step.tool || "system"}.${step.action || "audit"}</code> &mdash; ${escapeHtml(step.reason || step.summary || "Action event")}
          </div>
          ${step.receipt_hash ? `<div class="timeline-step-hash">rcpt &hellip;${step.receipt_hash.slice(-8)}</div>` : ""}
        </div>
      `;
      refs.incDetailTimelineFlow.appendChild(item);
    });
  }

  // ── Evidence Graph Visualization (#1273) ──
  // Shared by the incident detail page and the agent detail page. Renders a
  // GET /v1/graph/{incident,agent,run}/:id response (vis.js-compatible
  // {nodes, edges} shape, see lib/api/src/graph.rs) with vis-network.
  var GRAPH_LEGEND_ITEMS = [
    { label: "Agent", color: "#3b82f6" },
    { label: "Run", color: "#6366f1" },
    { label: "Tool Call", color: "#06b6d4" },
    { label: "Decision: Allow", color: "#22c55e" },
    { label: "Decision: Deny", color: "#ef4444" },
    { label: "Approval", color: "#f59e0b" },
    { label: "Receipt", color: "#94a3b8" },
    { label: "Incident", color: "#f43f5e" },
    { label: "MCP Server", color: "#14b8a6" },
    { label: "Policy", color: "#8b5cf6" }
  ];

  function colorForGraphNode(node) {
    switch (node.group) {
      case "agent": return "#3b82f6";
      case "run": return "#6366f1";
      case "tool_call": return "#06b6d4";
      case "decision":
        if (node.label === "allow") return "#22c55e";
        if (node.label === "deny") return "#ef4444";
        return "#f59e0b"; // require_approval or other
      case "approval":
        if (node.label === "approved") return "#22c55e";
        if (node.label === "denied" || node.label === "rejected") return "#ef4444";
        return "#f59e0b";
      case "receipt": return "#94a3b8";
      case "incident": return "#f43f5e";
      case "mcp_server": return "#14b8a6";
      case "policy": return "#8b5cf6";
      default: return "#64748b";
    }
  }

  function truncateGraphLabel(label) {
    if (!label) return "";
    return label.length > 28 ? label.slice(0, 25) + "..." : label;
  }

  function renderGraphLegend(legendEl) {
    if (legendEl.childElementCount > 0) return; // static legend, render once
    legendEl.innerHTML = GRAPH_LEGEND_ITEMS.map(function (item) {
      return `<span class="graph-legend-item"><span class="graph-legend-dot" style="background:${item.color};"></span>${item.label}</span>`;
    }).join("");
  }

  function showGraphNodeDetail(refsObj, node) {
    refsObj.nodeDetail.style.display = "block";
    refsObj.nodeType.textContent = node.group;
    refsObj.nodeLabel.textContent = node.label;
    refsObj.nodeTimestamp.textContent = node.timestamp ? new Date(node.timestamp).toLocaleString() : "N/A";
    refsObj.nodeMetadata.textContent = (node.metadata !== undefined && node.metadata !== null)
      ? JSON.stringify(node.metadata, null, 2)
      : "No metadata.";
  }

  function renderEvidenceGraph(refsObj, graph) {
    var containerEl = refsObj.container;
    var containerId = containerEl.id;
    var nodesById = {};
    (graph.nodes || []).forEach(function (n) { nodesById[n.id] = n; });

    var visNodes = (graph.nodes || []).map(function (n) {
      return {
        id: n.id,
        label: truncateGraphLabel(n.label),
        title: n.group + ": " + n.label,
        color: { background: colorForGraphNode(n), border: "rgba(255,255,255,0.25)" },
        font: { color: "#e5e7eb", size: 11 }
      };
    });

    var visEdges = (graph.edges || []).map(function (e, idx) {
      return {
        id: idx,
        from: e.from,
        to: e.to,
        label: (e.label || "").replace(/_/g, " "),
        arrows: "to",
        color: { color: "rgba(148,163,184,0.5)" },
        font: { color: "#94a3b8", size: 9, strokeWidth: 0, align: "middle" }
      };
    });

    if (state.graphNetworks[containerId]) {
      state.graphNetworks[containerId].destroy();
      delete state.graphNetworks[containerId];
    }

    var network = new vis.Network(containerEl, {
      nodes: new vis.DataSet(visNodes),
      edges: new vis.DataSet(visEdges)
    }, {
      physics: { stabilization: { iterations: 200 } },
      interaction: { hover: true, zoomView: true, dragView: true, dragNodes: true },
      layout: { improvedLayout: true },
      edges: { smooth: { type: "continuous" } }
    });

    // Freeze physics once the layout settles so dragging stays interactive
    // without the whole graph continuously re-simulating in the background.
    network.once("stabilizationIterationsDone", function () {
      network.setOptions({ physics: false });
    });

    network.on("click", function (params) {
      if (params.nodes && params.nodes.length > 0) {
        var node = nodesById[params.nodes[0]];
        if (node) showGraphNodeDetail(refsObj, node);
      } else {
        refsObj.nodeDetail.style.display = "none";
      }
    });

    state.graphNetworks[containerId] = network;
    // Exposed on the container element (not globally) so E2E tests can drive
    // real node clicks via vis-network's own canvasToDOM() coordinate
    // mapping instead of guessing pixel positions.
    containerEl.visNetwork = network;
    renderGraphLegend(refsObj.legend);
  }

  function fetchAndRenderEvidenceGraph(endpoint, refsObj) {
    refsObj.nodeDetail.style.display = "none";
    refsObj.loading.hidden = false;
    refsObj.loading.textContent = "Loading evidence graph…";
    apiFetch(endpoint).then(function (graph) {
      renderEvidenceGraph(refsObj, graph);
      refsObj.loading.hidden = true;
    }).catch(function (err) {
      refsObj.loading.textContent = "Failed to load evidence graph: " + err.message;
    });
  }

  function destroyGraphNetwork(containerEl) {
    var containerId = containerEl.id;
    if (state.graphNetworks[containerId]) {
      state.graphNetworks[containerId].destroy();
      delete state.graphNetworks[containerId];
      delete containerEl.visNetwork;
    }
  }

  // Go back to list
  refs.backToIncidentsBtn.addEventListener("click", function() {
    refs.incidentDetailContainer.style.display = "none";
    refs.incidentsListContainer.style.display = "block";
    state.selectedIncident = null;
    destroyGraphNetwork(refs.incidentGraphContainer);
    fetchIncidentsView();
  });

  // Verify timeline receipt chain
  refs.verifyIncidentChainBtn.addEventListener("click", function() {
    refs.timelineVerificationStatus.className = "timeline-verify-alert";
    refs.timelineVerificationStatus.textContent = "Verifying cryptographic proof chain...";
    refs.timelineVerificationStatus.style.display = "block";
    
    // Walk through chain verification API
    apiFetch("/v1/receipts/verify-chain", "POST", {}).then(function(data) {
      if (data.status === "verified" || data.verified === true) {
        refs.timelineVerificationStatus.className = "timeline-verify-alert success";
        refs.timelineVerificationStatus.textContent = "✓ Tamper-free: Evidence receipt chain verified successfully. Hash signature holds zero alterations.";
      } else {
        refs.timelineVerificationStatus.className = "timeline-verify-alert error";
        refs.timelineVerificationStatus.textContent = "✗ Integrity break detected: Cryptographic hash signature verification failed.";
      }
    }).catch(function(err) {
      refs.timelineVerificationStatus.className = "timeline-verify-alert error";
      refs.timelineVerificationStatus.textContent = "Verification error: " + err.message;
    });
  });

  // Containment Buttons
  refs.incContainFreezeBtn.addEventListener("click", function() {
    if (confirm("Are you sure you want to FREEZE agent " + state.selectedIncident.agent_id + "? This will immediately block all tool invocations.")) {
      apiFetch("/v1/agents/" + state.selectedIncident.agent_id + "/freeze", "POST").then(function() {
        alert("Agent frozen successfully!");
        fetchIncidentDetail(state.selectedIncident.id);
      }).catch(function(err) {
        alert("Containment failed: " + err.message);
      });
    }
  });

  refs.incContainUnfreezeBtn.addEventListener("click", function() {
    if (confirm("Are you sure you want to UNFREEZE agent " + state.selectedIncident.agent_id + "?")) {
      apiFetch("/v1/agents/" + state.selectedIncident.agent_id + "/unfreeze", "POST").then(function() {
        alert("Agent unfrozen successfully!");
        fetchIncidentDetail(state.selectedIncident.id);
      }).catch(function(err) {
        alert("Unfreeze failed: " + err.message);
      });
    }
  });

  refs.incContainRevokeBtn.addEventListener("click", function() {
    if (confirm("CRITICAL ACTION: Are you sure you want to REVOKE agent token? The agent will lose all connection privileges and require manual registration.")) {
      apiFetch("/v1/agents/" + state.selectedIncident.agent_id + "/revoke", "POST").then(function() {
        alert("Agent credentials revoked!");
        fetchIncidentDetail(state.selectedIncident.id);
      }).catch(function(err) {
        alert("Revoke failed: " + err.message);
      });
    }
  });

  // Close Incident
  refs.incCloseIncidentBtn.addEventListener("click", function() {
    if (confirm("Confirm closing incident " + state.selectedIncident.id + "?")) {
      apiFetch("/v1/incidents/" + state.selectedIncident.id + "/close", "POST").then(function() {
        alert("Incident closed successfully!");
        switchView("incidents");
      }).catch(function(err) {
        alert("Failed to close incident: " + err.message);
      });
    }
  });

  // Regenerate RCA
  refs.narrateIncidentBtn.addEventListener("click", function() {
    refs.incDetailRcaContent.textContent = "Analyzing incident parameters and regenerating narrative...";
    apiFetch("/v1/incidents/" + state.selectedIncident.id + "/narrate").then(function(data) {
      refs.incDetailRcaContent.textContent = data.narrative || "No narrative returned.";
    }).catch(function(err) {
      refs.incDetailRcaContent.textContent = "Narrator failed: " + err.message;
    });
  });

  // ── Approvals View ──
  function fetchApprovalsView() {
    apiFetch("/v1/approvals").then(function (data) {
      // GET /v1/approvals already server-side filters to non-expired,
      // undecided ("created") rows — every row here is pending by construction.
      state.approvals = data;
      refs.approvalsViewCount.textContent = data.length;

      refs.approvalsCardsContainer.innerHTML = "";
      if (data.length === 0) {
        refs.approvalsCardsContainer.innerHTML = "<div class='empty-row' style='grid-column: 1/-1;'>No pending approvals in queue. System operational.</div>";
        return;
      }

      data.forEach(function (app) {
        var card = document.createElement("div");
        card.className = "approval-card";

        var date = new Date(app.expires_at);
        var timeText = isNaN(date.getTime()) ? "N/A" : date.toLocaleTimeString();

        var toolCall = app.tool_call || {};
        var paramsStr = "{}";
        try {
          paramsStr = JSON.stringify(toolCall.parameters || {}, null, 2);
        } catch (_) {
          paramsStr = "{}";
        }

        card.innerHTML = `
          <div class="approval-card-header">
            <span class="badge badge-warning">Require Approval</span>
            <span class="approval-expiry">Expires: ${timeText}</span>
          </div>
          <div class="approval-card-body">
            <div>Agent: <strong class="mono">${app.agent_id || "N/A"}</strong></div>
            <div>Action: <code>${toolCall.tool || "?"}.${toolCall.action || "?"}</code></div>
            <div>Resource: <code>${toolCall.resource || "N/A"}</code></div>
            <div class="mono hash" style="font-size:10px;">action_hash: ${app.action_hash.slice(0, 16)}...</div>
            <div class="approval-code-box">
              <pre>params: ${escapeHtml(paramsStr)}</pre>
            </div>
          </div>
          <div class="approval-card-footer">
            <button class="btn btn-success btn-sm approve-btn" data-id="${app.approval_id}">Approve</button>
            <button class="btn btn-danger btn-sm reject-btn" data-id="${app.approval_id}">Reject</button>
          </div>
        `;

        card.querySelector(".approve-btn").addEventListener("click", function() {
          handleApprovalAction(app.approval_id, "approve");
        });

        card.querySelector(".reject-btn").addEventListener("click", function() {
          handleApprovalAction(app.approval_id, "reject");
        });

        refs.approvalsCardsContainer.appendChild(card);
      });
    }).catch(function(err) {
      showError("Failed to fetch approvals: " + err.message);
    });
  }

  function handleApprovalAction(id, action) {
    if (confirm("Confirm " + action + " for approval " + id + "?")) {
      // approver_user_id is a required field on the gateway's ApproveRequest —
      // this console has no per-operator login, so it records "dashboard-operator".
      apiFetch("/v1/approvals/" + id + "/" + action, "POST", {
        approver_user_id: "dashboard-operator"
      }).then(function() {
        alert("Approval " + action + "d successfully!");
        fetchApprovalsView();
        fetchOverviewCounters();
      }).catch(function(err) {
        alert("Action failed: " + err.message);
      });
    }
  }

  // ── Agent Risk Scoreboard (#1290) ──
  // AC: "rising (up red), falling (down green), stable (right grey)" — rising
  // risk is the bad direction (red), falling risk is good (green).
  var TREND_ARROW = {
    rising: { symbol: "↑", className: "text-error" },
    falling: { symbol: "↓", className: "text-success" },
    stable: { symbol: "→", className: "text-muted" }
  };

  function trendArrowHtml(trend) {
    var arrow = TREND_ARROW[trend] || TREND_ARROW.stable;
    return `<span class="${arrow.className}">${arrow.symbol} ${escapeHtml(trend)}</span>`;
  }

  function renderTopRiskAgents(top5) {
    if (top5.length === 0) {
      refs.topRiskAgentsContainer.innerHTML = "<div class='empty-row'>No agent activity recorded yet.</div>";
      return;
    }
    refs.topRiskAgentsContainer.innerHTML = top5.map(function (entry) {
      return `
        <div class="feed-item">
          <div class="feed-item-header">
            <span class="mono">${escapeHtml(entry.agent_key)}</span>
            <span>${trendArrowHtml(entry.trend)}</span>
          </div>
          <div class="feed-item-desc">
            Rolling 24h avg risk: <strong>${entry.current_avg_risk_score.toFixed(1)}</strong>
            &mdash; ${entry.decision_count_24h} decision(s)
          </div>
        </div>
      `;
    }).join("");
  }

  function fetchRiskScoreboardView() {
    apiFetch("/v1/agents/risk-scoreboard").then(function (data) {
      state.riskScoreboard = data;
      refs.riskScoreboardTbody.innerHTML = "";
      if (data.length === 0) {
        refs.riskScoreboardTbody.innerHTML = "<tr class='empty-row'><td colspan='5'>No agents registered yet.</td></tr>";
        return;
      }
      data.forEach(function (entry) {
        var tr = document.createElement("tr");
        tr.innerHTML = `
          <td class="mono">${escapeHtml(entry.agent_key)}</td>
          <td><strong>${entry.current_avg_risk_score.toFixed(1)}</strong></td>
          <td class="mono">${entry.decision_count_24h}</td>
          <td>${trendArrowHtml(entry.trend)}</td>
          <td><button class="btn btn-secondary btn-sm view-agent-explore-btn" data-agent-id="${entry.agent_id}">View in Explore</button></td>
        `;
        tr.querySelector(".view-agent-explore-btn").addEventListener("click", function() {
          addFilterAndSwitchToExplore("agent_id", entry.agent_id);
        });
        refs.riskScoreboardTbody.appendChild(tr);
      });
    }).catch(function(err) {
      showError("Failed to load risk scoreboard: " + err.message);
    });
  }

  function addFilterAndSwitchToExplore(key, value) {
    switchView("explore");
    addFilter(key, value);
  }

  refs.exportRiskScoreboardCsvBtn.addEventListener("click", function() {
    var url = state.gatewayUrl.replace(/\/+$/, "") + "/v1/agents/risk-scoreboard?format=csv";
    var headers = { "X-Aegis-Tenant-ID": state.tenantId };
    if (state.token) headers["Authorization"] = "Bearer " + state.token;

    fetch(url, { headers: headers }).then(function (resp) {
      if (!resp.ok) throw new Error("HTTP error " + resp.status);
      return resp.blob();
    }).then(function (blob) {
      var downloadUrl = URL.createObjectURL(blob);
      var a = document.createElement("a");
      a.href = downloadUrl;
      a.download = "agent-risk-scoreboard.csv";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(downloadUrl);
    }).catch(function(err) {
      alert("CSV export failed: " + err.message);
    });
  });

  // ── Agents Fleet View ──
  function fetchAgentsView() {
    apiFetch("/v1/agents").then(function (data) {
      state.agents = data;
      refs.agentsTbody.innerHTML = "";
      
      if (data.length === 0) {
        refs.agentsTbody.innerHTML = "<tr class='empty-row'><td colspan='8'>No agents registered.</td></tr>";
        return;
      }

      data.forEach(function (ag) {
        var tr = document.createElement("tr");

        var isFrozen = ag.status === "frozen";
        var isRevoked = ag.status === "revoked";

        var statusBadgeClass = isFrozen ? "badge badge-warning" : (isRevoked ? "badge badge-critical" : "badge badge-success");

        tr.innerHTML = `
          <td class="mono"><strong>${ag.agent_key || ag.id}</strong></td>
          <td>${ag.owner_team || "N/A"}</td>
          <td>${ag.environment || "dev"}</td>
          <td><span class="${statusBadgeClass}">${ag.status}</span></td>
          <td><code>${ag.allowed_environments || "All"}</code></td>
          <td class="mono">${new Date(ag.created_at).toLocaleDateString()}</td>
          <td class="mono">${ag.last_seen_at ? new Date(ag.last_seen_at).toLocaleTimeString() : "Never"}</td>
          <td>
            <div style="display:flex; gap:6px;">
              ${!isFrozen && !isRevoked ? `<button class="btn btn-danger btn-sm freeze-btn" data-id="${ag.id}">Freeze</button>` : ""}
              ${isFrozen ? `<button class="btn btn-success btn-sm unfreeze-btn" data-id="${ag.id}">Unfreeze</button>` : ""}
              ${!isRevoked ? `<button class="btn btn-secondary btn-sm revoke-btn" data-id="${ag.id}">Revoke</button>` : ""}
            </div>
          </td>
        `;

        var freeze = tr.querySelector(".freeze-btn");
        if (freeze) freeze.addEventListener("click", function(e) {
          e.stopPropagation();
          if (confirm("Freeze agent " + ag.id + "?")) {
            apiFetch("/v1/agents/" + ag.id + "/freeze", "POST").then(function() {
              fetchAgentsView();
            }).catch(console.error);
          }
        });

        var unfreeze = tr.querySelector(".unfreeze-btn");
        if (unfreeze) unfreeze.addEventListener("click", function(e) {
          e.stopPropagation();
          if (confirm("Unfreeze agent " + ag.id + "?")) {
            apiFetch("/v1/agents/" + ag.id + "/unfreeze", "POST").then(function() {
              fetchAgentsView();
            }).catch(console.error);
          }
        });

        var revoke = tr.querySelector(".revoke-btn");
        if (revoke) revoke.addEventListener("click", function(e) {
          e.stopPropagation();
          if (confirm("Revoke agent " + ag.id + "?")) {
            apiFetch("/v1/agents/" + ag.id + "/revoke", "POST").then(function() {
              fetchAgentsView();
            }).catch(console.error);
          }
        });

        // #1273: click a row to open the agent's evidence graph detail page.
        tr.style.cursor = "pointer";
        tr.addEventListener("click", function() {
          openAgentDetail(ag);
        });

        refs.agentsTbody.appendChild(tr);
      });
    }).catch(function(err) {
      showError("Failed to load agent fleet: " + err.message);
    });
  }

  // ── Agent Detail: Evidence Graph (#1273) ──
  function openAgentDetail(agent) {
    state.selectedAgent = agent;
    refs.agentListContainer.style.display = "none";
    refs.agentDetailContainer.style.display = "block";

    var isFrozen = agent.status === "frozen";
    var isRevoked = agent.status === "revoked";
    refs.agentDetailId.textContent = "Agent: " + (agent.agent_key || agent.id);
    refs.agentDetailStatus.textContent = agent.status;
    refs.agentDetailStatus.className = "badge " + (isFrozen ? "badge-warning" : (isRevoked ? "badge-critical" : "badge-success"));
    refs.agentDetailOwner.textContent = agent.owner_team || "N/A";
    refs.agentDetailEnv.textContent = agent.environment || "dev";
    refs.agentDetailRiskTier.textContent = agent.risk_tier || "unknown";
    refs.agentDetailCreated.textContent = new Date(agent.created_at).toLocaleString();

    fetchAndRenderEvidenceGraph("/v1/graph/agent/" + agent.id, {
      container: refs.agentGraphContainer,
      loading: refs.agentGraphLoading,
      legend: refs.agentGraphLegend,
      nodeDetail: refs.agentGraphNodeDetail,
      nodeType: refs.agentGraphNodeType,
      nodeLabel: refs.agentGraphNodeLabel,
      nodeTimestamp: refs.agentGraphNodeTimestamp,
      nodeMetadata: refs.agentGraphNodeMetadata
    });
  }

  refs.backToAgentsBtn.addEventListener("click", function() {
    refs.agentDetailContainer.style.display = "none";
    refs.agentListContainer.style.display = "block";
    state.selectedAgent = null;
    destroyGraphNetwork(refs.agentGraphContainer);
    fetchAgentsView();
  });

  // ── MCP Servers View ──
  function fetchMcpView() {
    apiFetch("/v1/mcp/servers").then(function (data) {
      state.mcpServers = data;
      refs.mcpServersTbody.innerHTML = "";
      
      if (data.length === 0) {
        refs.mcpServersTbody.innerHTML = "<tr class='empty-row'><td colspan='8'>No MCP servers registered.</td></tr>";
        return;
      }

      data.forEach(function (m) {
        var tr = document.createElement("tr");
        tr.className = "incident-row";
        // "quarantined" is how the gateway's manifest-drift auto-response
        // (mcp.rs) flags a server whose tool manifest changed since pinning.
        var isDrift = m.status === "quarantined";
        var driftBadgeClass = isDrift ? "badge badge-critical" : "badge badge-success";
        var isInspect = m.inspection_enabled;

        tr.innerHTML = `
          <td class="mono"><strong>${m.server_key}</strong></td>
          <td>${m.name || "N/A"}</td>
          <td><code>${m.transport}</code></td>
          <td><span class="badge badge-dark">${m.trust_level}</span></td>
          <td><span class="badge ${isInspect ? "badge-success" : "badge-dark"}">${isInspect ? "enabled" : "disabled"}</span></td>
          <td><span class="${driftBadgeClass}">${isDrift ? "drifted" : "pinned"}</span></td>
          <td class="mono">${m.last_discovery_at ? new Date(m.last_discovery_at).toLocaleTimeString() : "Never"}</td>
          <td>
            <div style="display:flex; gap:6px;">
              <button class="btn btn-secondary btn-sm open-mcp-server-btn" data-id="${m.server_key}">Manage Tools</button>
            </div>
          </td>
        `;

        tr.querySelector(".open-mcp-server-btn").addEventListener("click", function(e) {
          e.stopPropagation();
          openMcpServerDetail(m.server_key);
        });

        tr.addEventListener("click", function() {
          openMcpServerDetail(m.server_key);
        });

        refs.mcpServersTbody.appendChild(tr);
      });
    }).catch(function(err) {
      showError("Failed to load MCP servers: " + err.message);
    });
  }

  // ── MCP Server Detail: Approved Tool Allowlist (#1334) ──
  function openMcpServerDetail(serverKey) {
    state.selectedMcpServerKey = serverKey;
    refs.mcpListContainer.style.display = "none";
    refs.mcpDetailContainer.style.display = "block";
    refs.mcpDetailServerKey.textContent = "MCP Server: " + serverKey;
    refs.mcpDetailToolsTbody.innerHTML = "<tr class='empty-row'><td colspan='6'>Loading tools...</td></tr>";
    refs.mcpDetailHistoryTbody.innerHTML = "<tr class='empty-row'><td colspan='2'>Loading manifest history...</td></tr>";
    fetchMcpServerDetail(serverKey);
  }

  function fetchMcpServerDetail(serverKey) {
    apiFetch("/v1/mcp/servers/" + serverKey).then(function (server) {
      renderMcpServerMeta(server);
    }).catch(function(err) {
      showError("Failed to load MCP server: " + err.message);
    });

    apiFetch("/v1/mcp/servers/" + serverKey + "/tools").then(function (data) {
      renderMcpDetailTools(serverKey, data.tools || []);
    }).catch(function(err) {
      refs.mcpDetailToolsTbody.innerHTML = "<tr class='empty-row'><td colspan='6'>Failed to load tools: " + escapeHtml(err.message) + "</td></tr>";
    });

    apiFetch("/v1/mcp/servers/" + serverKey + "/manifest-history").then(function (data) {
      renderMcpManifestHistory(data.snapshots || []);
    }).catch(function(err) {
      refs.mcpDetailHistoryTbody.innerHTML = "<tr class='empty-row'><td colspan='2'>Failed to load manifest history: " + escapeHtml(err.message) + "</td></tr>";
    });
  }

  function renderMcpServerMeta(server) {
    var isQuarantined = server.status === "quarantined";
    refs.mcpDetailStatus.textContent = server.status;
    refs.mcpDetailStatus.className = "badge " + (isQuarantined ? "badge-critical" : "badge-success");
    refs.mcpDetailQuarantineStatus.textContent = isQuarantined ? "Quarantined" : "Active";
    refs.mcpDetailQuarantineStatus.className = isQuarantined ? "text-critical" : "text-success";
    refs.mcpDetailManifestHash.textContent = server.manifest_hash || "Not yet pinned";
    refs.mcpDetailLastDiscovery.textContent = server.last_discovery_at ? new Date(server.last_discovery_at).toLocaleString() : "Never";
    refs.mcpDetailTrustLevel.textContent = server.trust_level;
    refs.mcpDetailTransport.textContent = server.transport;
  }

  function renderMcpDetailTools(serverKey, tools) {
    refs.mcpDetailToolsTbody.innerHTML = "";
    if (tools.length === 0) {
      refs.mcpDetailToolsTbody.innerHTML = "<tr class='empty-row'><td colspan='6'>No tools discovered for this server yet.</td></tr>";
      return;
    }

    tools.forEach(function (tool) {
      var tr = document.createElement("tr");
      var statusClass = tool.status === "approved" ? "badge-success" : (tool.status === "disabled" ? "badge-error" : "badge-warning");

      tr.innerHTML = `
        <td class="mono"><strong>${escapeHtml(tool.tool_key)}</strong></td>
        <td>${escapeHtml(tool.name || "N/A")}</td>
        <td><span class="badge badge-dark">${escapeHtml(tool.risk || "unknown")}</span></td>
        <td>${tool.mutates_state ? "Yes" : "No"}</td>
        <td><span class="badge ${statusClass}">${escapeHtml(tool.status)}</span></td>
        <td>
          <div style="display:flex; gap:6px;">
            <button class="btn btn-success btn-sm approve-tool-btn" data-tool="${tool.tool_key}" ${tool.status === "approved" ? "disabled" : ""}>Approve</button>
            <button class="btn btn-danger btn-sm disable-tool-btn" data-tool="${tool.tool_key}" ${tool.status === "disabled" ? "disabled" : ""}>Disable</button>
          </div>
        </td>
      `;

      tr.querySelector(".approve-tool-btn").addEventListener("click", function() {
        handleMcpToolStatusChange(serverKey, tool.tool_key, "approve");
      });
      tr.querySelector(".disable-tool-btn").addEventListener("click", function() {
        handleMcpToolStatusChange(serverKey, tool.tool_key, "disable");
      });

      refs.mcpDetailToolsTbody.appendChild(tr);
    });
  }

  function handleMcpToolStatusChange(serverKey, toolKey, action) {
    if (!confirm("Confirm " + action + " for tool " + toolKey + " on " + serverKey + "?")) {
      return;
    }
    apiFetch("/v1/mcp/servers/" + serverKey + "/tools/" + toolKey + "/" + action, "POST").then(function() {
      fetchMcpServerDetail(serverKey);
    }).catch(function(err) {
      alert("Failed to " + action + " tool: " + err.message);
    });
  }

  function renderMcpManifestHistory(snapshots) {
    refs.mcpDetailHistoryTbody.innerHTML = "";
    if (snapshots.length === 0) {
      refs.mcpDetailHistoryTbody.innerHTML = "<tr class='empty-row'><td colspan='2'>No manifest snapshots recorded yet.</td></tr>";
      return;
    }

    snapshots.forEach(function (snap) {
      var tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="mono">${new Date(snap.created_at).toLocaleString()}</td>
        <td class="mono hash">${escapeHtml(snap.manifest_hash)}</td>
      `;
      refs.mcpDetailHistoryTbody.appendChild(tr);
    });
  }

  // Containment: Quarantine / Restore
  refs.mcpQuarantineBtn.addEventListener("click", function() {
    if (confirm("Are you sure you want to QUARANTINE MCP server " + state.selectedMcpServerKey + "? All tool calls from this server will be denied until restored.")) {
      apiFetch("/v1/mcp/servers/" + state.selectedMcpServerKey + "/quarantine", "POST").then(function() {
        alert("MCP server quarantined.");
        fetchMcpServerDetail(state.selectedMcpServerKey);
      }).catch(function(err) {
        alert("Quarantine failed: " + err.message);
      });
    }
  });

  refs.mcpRestoreBtn.addEventListener("click", function() {
    if (confirm("Restore MCP server " + state.selectedMcpServerKey + " to active status?")) {
      apiFetch("/v1/mcp/servers/" + state.selectedMcpServerKey + "/restore", "POST").then(function() {
        alert("MCP server restored.");
        fetchMcpServerDetail(state.selectedMcpServerKey);
      }).catch(function(err) {
        alert("Restore failed: " + err.message);
      });
    }
  });

  // Go back to MCP registry list
  refs.backToMcpBtn.addEventListener("click", function() {
    refs.mcpDetailContainer.style.display = "none";
    refs.mcpListContainer.style.display = "block";
    state.selectedMcpServerKey = null;
    fetchMcpView();
  });

  // ── Receipts / Integrity logs View ──
  function fetchReceiptsView() {
    apiFetch("/v1/receipts?limit=100&offset=0").then(function (data) {
      var rows = Array.isArray(data) ? data : (data.receipts ? data.receipts : []);
      state.receipts = rows;
      refs.chainVerifyBanner.style.display = "none";
      
      refs.receiptsTbody.innerHTML = "";
      if (rows.length === 0) {
        refs.receiptsTbody.innerHTML = "<tr class='empty-row'><td colspan='7'>No evidence receipts recorded yet.</td></tr>";
        return;
      }

      rows.forEach(function (rec) {
        var tr = document.createElement("tr");
        
        var isDeny = rec.decision === "deny";
        var isTamper = rec.decision === "tamper_attempt";
        var decClass = isTamper ? "badge badge-critical" : (isDeny ? "badge badge-error" : "badge badge-success");
        
        tr.innerHTML = `
          <td class="mono">${new Date(rec.ts || rec.created_at).toLocaleString()}</td>
          <td class="mono hash">${rec.receipt_hash.slice(0, 16)}...</td>
          <td class="mono hash">${rec.prev_receipt_hash ? rec.prev_receipt_hash.slice(0, 16) + "..." : "Genesis (nil)"}</td>
          <td><code>${rec.tool || "system"}.${rec.action || "audit"}</code></td>
          <td><span class="${decClass}">${rec.decision}</span></td>
          <td class="mono">${rec.agent_id || "N/A"}</td>
          <td><button class="btn btn-secondary btn-sm verify-single-receipt" data-id="${rec.id}">Verify Link</button></td>
        `;

        tr.querySelector(".verify-single-receipt").addEventListener("click", function(e) {
          e.stopPropagation();
          verifySingleReceipt(rec.id);
        });

        refs.receiptsTbody.appendChild(tr);
      });
    }).catch(function(err) {
      showError("Failed to load evidence receipts: " + err.message);
    });
  }

  function verifySingleReceipt(id) {
    apiFetch("/v1/receipts/" + id + "/verify").then(function (data) {
      if (data.status === "verified" || data.verified === true) {
        alert("✓ Verifiable: Receipt hash matches canonical body. Cryptographic signature is valid.");
      } else {
        alert("✗ Altered: Receipt hash mismatch or invalid signature!");
      }
    }).catch(function(err) {
      alert("Verification failed: " + err.message);
    });
  }

  refs.verifyWholeChainBtn.addEventListener("click", function() {
    refs.chainVerifyBanner.className = "chain-verification-banner";
    refs.chainVerifyBanner.textContent = "Verifying cryptographic proof chain...";
    refs.chainVerifyBanner.style.display = "block";

    apiFetch("/v1/receipts/verify-chain", "POST", {}).then(function(data) {
      if (data.status === "verified" || data.verified === true) {
        refs.chainVerifyBanner.className = "chain-verification-banner success";
        refs.chainVerifyBanner.textContent = "✓ Verifiable: Evidence chain signature holds zero modifications. Safe state validated.";
      } else {
        refs.chainVerifyBanner.className = "chain-verification-banner error";
        refs.chainVerifyBanner.textContent = "✗ Altered: Evidence chain break detected! Potential unauthorized modification to logs.";
      }
    }).catch(function(err) {
      refs.chainVerifyBanner.className = "chain-verification-banner error";
      refs.chainVerifyBanner.textContent = "Verification failed: " + err.message;
    });
  });

  // ── Helper Utilities ──
  // #1294: maps the 6 context-trust-provenance levels (see CLAUDE.md's
  // "Critical invariants" — tighten-only, never loosened) to badge colors so
  // operators can scan trust at a glance instead of reading raw enum text.
  var TRUST_BADGE_CLASSES = {
    trusted_internal_signed: "badge-success",
    trusted_internal_unsigned: "badge-info",
    semi_trusted_customer: "badge-warning",
    untrusted_external: "badge-error",
    malicious_suspected: "badge-critical",
    unknown: "badge-dark"
  };

  function trustBadgeClass(level) {
    return TRUST_BADGE_CLASSES[level] || "badge-dark";
  }

  function escapeHtml(str) {
    if (!str) return "";
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // ── Initial Start ──
  refreshAllData();
  toggleAutoRefresh(true);
}());
