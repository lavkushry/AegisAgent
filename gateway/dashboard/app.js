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
    selectedIncident: null,
    
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
    
    // Overview elements
    liveFeed: document.getElementById("live-feed-events"),
    topIncidentContainer: document.getElementById("top-incident-container"),
    svgDecisionChart: document.getElementById("svg-decision-chart"),
    
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
    
    // Approvals Queue
    approvalsViewCount: document.getElementById("approvals-view-count"),
    approvalsCardsContainer: document.getElementById("approvals-cards-container"),
    
    // Fleet / Agents List
    agentsTbody: document.getElementById("agents-tbody"),
    
    // MCP Server List
    mcpServersTbody: document.getElementById("mcp-servers-tbody"),
    
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
  document.querySelectorAll(".stat-card.hoverable").forEach(function(card) {
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
      state.refreshInterval = setInterval(refreshAllData, 5000);
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
      case "mcp":
        fetchMcpView();
        break;
      case "receipts":
        fetchReceiptsView();
        break;
    }
  }

  // ── Fetch Operations ──

  // Fetch Overview Counters & Badges
  function fetchOverviewCounters() {
    // Stat 1: Open Incidents
    apiFetch("/v1/incidents?limit=50&offset=0").then(function (data) {
      var count = Array.isArray(data) ? data.length : (data.incidents ? data.incidents.length : 0);
      refs.menuIncidentsCount.textContent = count;
      refs.menuIncidentsCount.style.display = count > 0 ? "inline-block" : "none";
      refs.statIncidents.textContent = count;
      if (refs.tileIncidents) refs.tileIncidents.textContent = count;
    }).catch(console.error);

    // Stat 2: Firing Alerts
    apiFetch("/v1/alerts?limit=50&offset=0").then(function (data) {
      var count = Array.isArray(data) ? data.length : (data.alerts ? data.alerts.length : 0);
      refs.menuAlertsCount.textContent = count;
      refs.menuAlertsCount.style.display = count > 0 ? "inline-block" : "none";
      refs.statAlerts.textContent = count;
      if (refs.tileAlerts) refs.tileAlerts.textContent = count;
    }).catch(console.error);

    // Stat 3: Approvals Queue — GET /v1/approvals already server-side filters
    // to non-expired, undecided ("created") rows, so every row returned here
    // is pending by construction.
    apiFetch("/v1/approvals").then(function (data) {
      refs.menuApprovalsCount.textContent = data.length;
      refs.menuApprovalsCount.style.display = data.length > 0 ? "inline-block" : "none";
      refs.statApprovals.textContent = data.length;
    }).catch(console.error);

    // Stat 4: Tenant statistics (Protected and Denies count)
    apiFetch("/v1/stats").then(function (data) {
      refs.statProtected.textContent = data.total_decisions || 0;
      refs.statDenied.textContent = data.decisions_deny || 0;
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
      renderDecisionChart(rows);
    }).catch(console.error);

    // Fetch top incident
    apiFetch("/v1/incidents?limit=1&offset=0").then(function (data) {
      var rows = Array.isArray(data) ? data : (data.incidents ? data.incidents : []);
      renderTopIncident(rows[0]);
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
  function renderDecisionChart(decisions) {
    // Generate simulated/aggregated points over time
    var countsByMinute = {};
    decisions.forEach(function (d) {
      var time = new Date(d.created_at);
      var min = time.getHours() + ":" + String(time.getMinutes()).padStart(2, '0');
      countsByMinute[min] = (countsByMinute[min] || 0) + 1;
    });

    var keys = Object.keys(countsByMinute).sort();
    if (keys.length < 5) {
      // Add fake/seed timeline points if there are too few live decisions
      keys = ["10:00", "11:00", "12:00", "13:00", "14:00", "15:00"];
      countsByMinute = { "10:00": 10, "11:00": 34, "12:00": 55, "13:00": 12, "14:00": 89, "15:00": 102 };
    }

    var values = keys.map(function(k) { return countsByMinute[k]; });
    var maxVal = Math.max.apply(null, values) || 10;
    
    // Draw SVG Chart
    var width = 600;
    var height = 180;
    var padding = 20;
    var step = (width - padding * 2) / (keys.length - 1);
    
    var points = [];
    for (var i = 0; i < keys.length; i++) {
      var x = padding + i * step;
      var y = height - padding - ((values[i] / maxVal) * (height - padding * 2));
      points.push({ x: x, y: y, label: keys[i], val: values[i] });
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
      labels += `
        <circle cx="${pt.x}" cy="${pt.y}" r="3" fill="#6366f1" />
        <text x="${pt.x}" y="${height - 2}" font-size="9" fill="#64748b" text-anchor="middle">${pt.label}</text>
        <text x="${pt.x}" y="${pt.y - 6}" font-size="9" font-weight="bold" fill="#fff" text-anchor="middle">${pt.val}</text>
      `;
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
      <path d="${linePath}" fill="none" stroke="#6366f1" stroke-width="2.5" />
      ${labels}
    `;
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
        <td><span class="badge badge-dark">${d.root_trust_level}</span></td>
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
      li.innerHTML = `<span>${key}</span> <strong>${trusts[key]}</strong>`;
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

  // Go back to list
  refs.backToIncidentsBtn.addEventListener("click", function() {
    refs.incidentDetailContainer.style.display = "none";
    refs.incidentsListContainer.style.display = "block";
    state.selectedIncident = null;
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
        if (freeze) freeze.addEventListener("click", function() {
          if (confirm("Freeze agent " + ag.id + "?")) {
            apiFetch("/v1/agents/" + ag.id + "/freeze", "POST").then(function() {
              fetchAgentsView();
            }).catch(console.error);
          }
        });

        var unfreeze = tr.querySelector(".unfreeze-btn");
        if (unfreeze) unfreeze.addEventListener("click", function() {
          if (confirm("Unfreeze agent " + ag.id + "?")) {
            apiFetch("/v1/agents/" + ag.id + "/unfreeze", "POST").then(function() {
              fetchAgentsView();
            }).catch(console.error);
          }
        });

        var revoke = tr.querySelector(".revoke-btn");
        if (revoke) revoke.addEventListener("click", function() {
          if (confirm("Revoke agent " + ag.id + "?")) {
            apiFetch("/v1/agents/" + ag.id + "/revoke", "POST").then(function() {
              fetchAgentsView();
            }).catch(console.error);
          }
        });

        refs.agentsTbody.appendChild(tr);
      });
    }).catch(function(err) {
      showError("Failed to load agent fleet: " + err.message);
    });
  }

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
              <button class="btn btn-secondary btn-sm approve-server-btn" data-id="${m.server_key}">Pin Manifest</button>
            </div>
          </td>
        `;
        refs.mcpServersTbody.appendChild(tr);
      });
    }).catch(function(err) {
      showError("Failed to load MCP servers: " + err.message);
    });
  }

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
