#![allow(dead_code)]
use crate::error::{ErrorReason, StatusError};
use crate::models::*;
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(
        health_api,
        livez_api,
        readyz_api,
        startupz_api,
        version_api,
        register_agent_api,
        register_tool_api,
        list_mcp_servers_api,
        create_mcp_server_api,
        get_mcp_server_api,
        update_mcp_server_api,
        get_mcp_server_tools_api,
        discover_mcp_tools_api,
        approve_mcp_tool_api,
        disable_mcp_tool_api,
        inspect_mcp_response_api,
        get_mcp_server_manifest_history_api,
        quarantine_mcp_server_api,
        restore_mcp_server_api,
        list_agents_api,
        get_agent_api,
        patch_agent_api,
        delete_agent_api,
        freeze_agent_api,
        unfreeze_agent_api,
        revoke_agent_api,
        restore_agent_api,
        rotate_agent_token_api,
        report_leaked_agent_token_api,
        list_agent_tool_permissions_api,
        grant_agent_tool_permission_api,
        revoke_agent_tool_permission_api,
        list_approvals_api,
        get_approval_api,
        approve_approval_api,
        reject_approval_api,
        edit_approval_api,
        consume_approval_api,
        list_receipts_api,
        get_receipt_api,
        verify_receipt_api,
        verify_receipt_chain_api,
        list_alerts_api,
        list_incidents_api,
        get_incident_api,
        close_incident_api,
        narrate_incident_api,
        get_incident_evidence_pack_api,
        soc_summary_api,
        soc_stream_api,
        soc_query_api,
        semantic_search_api,
        list_contact_points_api,
        create_contact_point_api,
        update_contact_point_api,
        delete_contact_point_api,
        list_notification_policies_api,
        create_notification_policy_api,
        update_notification_policy_api,
        delete_notification_policy_api,
        list_silences_api,
        create_silence_api,
        delete_silence_api,
        list_soc_dashboards_api,
        get_soc_dashboard_api,
        create_soc_dashboard_api,
        update_soc_dashboard_api,
        delete_soc_dashboard_api,
        create_tenant_api,
        get_tenant_api,
        delete_tenant_api,
        export_tenant_api,
        get_tenant_stats_api,
        get_db_stats_api,
        create_db_backup_api,
        list_webhook_subscriptions_api,
        create_webhook_subscription_api,
        delete_webhook_subscription_api,
        reactivate_webhook_subscription_api,
        list_detection_rules_api,
        upsert_detection_rule_api,
        delete_detection_rule_api,
        get_soc_rules_api,
        create_soc_rule_api,
        reload_soc_rules_api,
        backtest_soc_rule_api,
        get_graph_for_run_api,
        get_graph_for_incident_api,
        get_graph_for_agent_api,
        list_api_keys_api,
        create_api_key_api,
        revoke_api_key_api,
        get_tenant_risk_weights_api,
        put_tenant_risk_weights_api,
        get_tenant_risk_escalation_config_api,
        put_tenant_risk_escalation_config_api,
        get_tenant_slack_approver_group_api,
        put_tenant_slack_approver_group_api,
        authorize_action_api,
        list_decisions_api,
        get_decision_api,
        list_policies_api,
        create_policy_api,
        update_policy_api,
        delete_policy_api,
        rollback_policy_api,
        reload_global_policies_api,
        get_timeline_api,
        get_audit_events_api,
        get_evidence_pack_api,
        ws_events_api,
        list_agent_cage_runs_api,
        get_agent_cage_run_api,
        kill_agent_cage_run_api,
        pause_agent_cage_run_api,
        quarantine_agent_cage_run_api,
        resume_agent_cage_run_api,
        get_agent_risk_scoreboard_api,
        list_bans_api,
        get_ban_api,
        revoke_ban_api,
        list_broker_tools_api,
        get_broker_tool_api,
        set_broker_tool_status_api,
        slack_callback_api,
        list_control_commands_api,
        get_control_command_api,
        update_control_command_status_api,
        decision_timeseries_api,
        block_egress_api,
        check_egress_api,
        list_egress_events_api,
        unblock_egress_api,
        ingest_event_api,
        ingest_runtime_event_api,
        get_openapi_json_api,
        list_playbooks_api,
        delete_playbook_api,
        test_playbook_api,
        list_policy_audit_log_api,
        upload_policy_bundle_api,
        compile_policy_api,
        list_policy_templates_api,
        list_quarantine_api,
        get_quarantine_api,
        release_quarantine_api,
        get_receipt_chain_head_api,
        verify_receipt_range_api,
        list_run_events_api,
        list_sensors_api,
        register_sensor_api,
        get_sensor_api,
        sensor_heartbeat_api,
        receive_github_webhook_api,
    ),
    components(
        schemas(
            RegisterAgentRequest,
            RegisterAgentResponse,
            PatchAgentRequest,
            RegisterToolAction,
            RegisterToolRequest,
            RegisterMcpServerRequest,
            RegisterMcpServerResponse,
            McpToolManifestItem,
            DiscoverMcpToolsRequest,
            ActiveResponseRequest,
            ActiveResponseStatusResponse,
            McpToolStatusResponse,
            AuthorizeAgentContext,
            AuthorizeUserContext,
            AuthorizeToolCall,
            AuthorizeDynamicContext,
            AuthorizeTraceContext,
            ApprovalCallback,
            AuthorizeRequest,
            ApprovalResponseInfo,
            AuthorizeResponse,
            ApproveRequest,
            EditApprovalRequest,
            TenantRecord,
            AgentRecord,
            AgentToolPermission,
            GrantToolPermissionRequest,
            McpServerRecord,
            McpToolRecord,
            PolicyRecord,
            PolicyVersionRecord,
            DecisionRecord,
            ApprovalRecord,
            ApprovalQueueItem,
            WebhookSubscriptionRecord,
            DetectionRuleRecord,
            ApiKeyRecord,
            AuditEventRecord,
            TenantExport,
            SocAlertRecord,
            SocIncidentRecord,
            SocSummary,
            SocQueryFilters,
            SocQueryRequest,
            SocQueryFieldDescriptor,
            SocQueryMeta,
            SocQueryResponse,
            ActionReceiptRecord,
            PolicyAuditLogRecord,
            CreateTenantRequest,
            UpdateMcpServerRequest,
            InspectMcpResponseRequest,
            TenantStats,
            TrustLevelCount,
            RiskWeights,
            RiskEscalationConfig,
            StatusError,
            ErrorReason,
        )
    ),
    modifiers(&SecurityModifier),
    info(
        title = "AegisAgent Control Plane API",
        version = "0.1.0",
        description = "AegisAgent control plane integrity gateway API — fail-closed approval integrity, deterministic trust-provenance gating, and verifiable action receipts."
    )
)]
pub struct ApiDoc;

pub struct SecurityModifier;

impl utoipa::Modify for SecurityModifier {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.as_mut().unwrap();
        components.add_security_scheme(
            "bearer_auth",
            utoipa::openapi::security::SecurityScheme::Http(
                utoipa::openapi::security::HttpBuilder::new()
                    .scheme(utoipa::openapi::security::HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .build(),
            ),
        );
    }
}

// --- Path Metadata Annotations ---

#[utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 200, description = "System is healthy")
    )
)]
fn health_api() {}

#[utoipa::path(
    get,
    path = "/livez",
    responses(
        (status = 200, description = "System is live")
    )
)]
fn livez_api() {}

#[utoipa::path(
    get,
    path = "/readyz",
    responses(
        (status = 200, description = "System is ready")
    )
)]
fn readyz_api() {}

#[utoipa::path(
    get,
    path = "/startupz",
    responses(
        (status = 200, description = "System is started")
    )
)]
fn startupz_api() {}

#[utoipa::path(
    get,
    path = "/v1/version",
    responses(
        (status = 200, description = "Version details")
    )
)]
fn version_api() {}

#[utoipa::path(
    post,
    path = "/v1/agents/register",
    request_body = RegisterAgentRequest,
    responses(
        (status = 201, description = "Agent registered successfully", body = RegisterAgentResponse)
    )
)]
fn register_agent_api() {}

#[utoipa::path(
    get,
    path = "/v1/agents",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "List of agents", body = Vec<AgentRecord>)
    )
)]
fn list_agents_api() {}

#[utoipa::path(
    get,
    path = "/v1/agents/{id}",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Agent ID")
    ),
    responses(
        (status = 200, description = "Agent details", body = AgentRecord),
        (status = 404, description = "Agent not found", body = StatusError)
    )
)]
fn get_agent_api() {}

#[utoipa::path(
    patch,
    path = "/v1/agents/{id}",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Agent ID")
    ),
    request_body = PatchAgentRequest,
    responses(
        (status = 200, description = "Agent updated", body = AgentRecord),
        (status = 404, description = "Agent not found", body = StatusError)
    )
)]
fn patch_agent_api() {}

#[utoipa::path(
    delete,
    path = "/v1/agents/{id}",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Agent ID")
    ),
    responses(
        (status = 200, description = "Agent deleted"),
        (status = 404, description = "Agent not found", body = StatusError)
    )
)]
fn delete_agent_api() {}

#[utoipa::path(
    post,
    path = "/v1/agents/{id}/freeze",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Agent ID")
    ),
    request_body(
        content = ActiveResponseRequest,
        description = "Optional operator reason/comment recorded in the audit trail"
    ),
    responses(
        (status = 200, description = "Agent frozen", body = ActiveResponseStatusResponse),
        (status = 404, description = "Agent not found", body = StatusError)
    )
)]
fn freeze_agent_api() {}

#[utoipa::path(
    post,
    path = "/v1/agents/{id}/unfreeze",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Agent ID")
    ),
    request_body(
        content = ActiveResponseRequest,
        description = "Optional operator reason/comment recorded in the audit trail"
    ),
    responses(
        (status = 200, description = "Agent unfrozen", body = ActiveResponseStatusResponse),
        (status = 404, description = "Agent not found", body = StatusError)
    )
)]
fn unfreeze_agent_api() {}

#[utoipa::path(
    post,
    path = "/v1/agents/{id}/revoke",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Agent ID")
    ),
    request_body(
        content = ActiveResponseRequest,
        description = "Optional operator reason/comment recorded in the audit trail"
    ),
    responses(
        (status = 200, description = "Agent revoked", body = ActiveResponseStatusResponse),
        (status = 404, description = "Agent not found", body = StatusError)
    )
)]
fn revoke_agent_api() {}

#[utoipa::path(
    post,
    path = "/v1/agents/{id}/restore",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Agent ID")
    ),
    request_body(
        content = ActiveResponseRequest,
        description = "Optional operator reason/comment recorded in the audit trail"
    ),
    responses(
        (status = 200, description = "Agent restored", body = ActiveResponseStatusResponse),
        (status = 404, description = "Agent not found", body = StatusError)
    )
)]
fn restore_agent_api() {}

#[utoipa::path(
    post,
    path = "/v1/agents/{id}/rotate-token",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Agent ID")
    ),
    responses(
        (status = 200, description = "Agent token rotated", body = RegisterAgentResponse),
        (status = 404, description = "Agent not found", body = StatusError)
    )
)]
fn rotate_agent_token_api() {}

#[utoipa::path(
    post,
    path = "/v1/agents/{id}/report-leaked-token",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Agent ID")
    ),
    responses(
        (status = 200, description = "Token leak reported"),
        (status = 404, description = "Agent not found", body = StatusError)
    )
)]
fn report_leaked_agent_token_api() {}

#[utoipa::path(
    get,
    path = "/v1/agents/{id}/permissions",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Agent ID")
    ),
    responses(
        (status = 200, description = "List of permissions", body = Vec<AgentToolPermission>),
        (status = 404, description = "Agent not found", body = StatusError)
    )
)]
fn list_agent_tool_permissions_api() {}

#[utoipa::path(
    post,
    path = "/v1/agents/{id}/permissions",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Agent ID")
    ),
    request_body = GrantToolPermissionRequest,
    responses(
        (status = 200, description = "Permission granted"),
        (status = 404, description = "Agent not found", body = StatusError)
    )
)]
fn grant_agent_tool_permission_api() {}

#[utoipa::path(
    delete,
    path = "/v1/agents/{id}/permissions/{tool_key}",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Agent ID"),
        ("tool_key" = String, Path, description = "Tool Key")
    ),
    responses(
        (status = 200, description = "Permission revoked"),
        (status = 404, description = "Agent or permission not found", body = StatusError)
    )
)]
fn revoke_agent_tool_permission_api() {}

#[utoipa::path(
    post,
    path = "/v1/tools",
    security(("bearer_auth" = [])),
    request_body = RegisterToolRequest,
    responses(
        (status = 200, description = "Tool registered successfully")
    )
)]
fn register_tool_api() {}

#[utoipa::path(
    get,
    path = "/v1/mcp/servers",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "List of MCP servers", body = Vec<McpServerRecord>)
    )
)]
fn list_mcp_servers_api() {}

#[utoipa::path(
    post,
    path = "/v1/mcp/servers",
    security(("bearer_auth" = [])),
    request_body = RegisterMcpServerRequest,
    responses(
        (status = 201, description = "MCP server registered", body = RegisterMcpServerResponse)
    )
)]
fn create_mcp_server_api() {}

#[utoipa::path(
    get,
    path = "/v1/mcp/servers/{server_key}",
    security(("bearer_auth" = [])),
    params(
        ("server_key" = String, Path, description = "MCP Server Key")
    ),
    responses(
        (status = 200, description = "MCP server details", body = McpServerRecord),
        (status = 404, description = "Server not found", body = StatusError)
    )
)]
fn get_mcp_server_api() {}

#[utoipa::path(
    put,
    path = "/v1/mcp/servers/{server_key}",
    security(("bearer_auth" = [])),
    params(
        ("server_key" = String, Path, description = "MCP Server Key")
    ),
    request_body = UpdateMcpServerRequest,
    responses(
        (status = 200, description = "MCP server updated", body = McpServerRecord),
        (status = 404, description = "Server not found", body = StatusError)
    )
)]
fn update_mcp_server_api() {}

#[utoipa::path(
    get,
    path = "/v1/mcp/servers/{server_key}/tools",
    security(("bearer_auth" = [])),
    params(
        ("server_key" = String, Path, description = "MCP Server Key")
    ),
    responses(
        (status = 200, description = "List of tools", body = Vec<McpToolRecord>),
        (status = 404, description = "Server not found", body = StatusError)
    )
)]
fn get_mcp_server_tools_api() {}

#[utoipa::path(
    post,
    path = "/v1/mcp/servers/{server_key}/tools",
    security(("bearer_auth" = [])),
    params(
        ("server_key" = String, Path, description = "MCP Server Key")
    ),
    request_body = DiscoverMcpToolsRequest,
    responses(
        (status = 200, description = "Tools discovered successfully", body = Vec<McpToolStatusResponse>),
        (status = 404, description = "Server not found", body = StatusError)
    )
)]
fn discover_mcp_tools_api() {}

#[utoipa::path(
    post,
    path = "/v1/mcp/servers/{server_key}/tools/{tool_key}/approve",
    security(("bearer_auth" = [])),
    params(
        ("server_key" = String, Path, description = "MCP Server Key"),
        ("tool_key" = String, Path, description = "MCP Tool Key")
    ),
    responses(
        (status = 200, description = "Tool approved"),
        (status = 404, description = "Server or tool not found", body = StatusError)
    )
)]
fn approve_mcp_tool_api() {}

#[utoipa::path(
    post,
    path = "/v1/mcp/servers/{server_key}/tools/{tool_key}/disable",
    security(("bearer_auth" = [])),
    params(
        ("server_key" = String, Path, description = "MCP Server Key"),
        ("tool_key" = String, Path, description = "MCP Tool Key")
    ),
    responses(
        (status = 200, description = "Tool disabled"),
        (status = 404, description = "Server or tool not found", body = StatusError)
    )
)]
fn disable_mcp_tool_api() {}

#[utoipa::path(
    post,
    path = "/v1/mcp/servers/{server_key}/quarantine",
    security(("bearer_auth" = [])),
    params(
        ("server_key" = String, Path, description = "MCP Server Key")
    ),
    request_body(
        content = ActiveResponseRequest,
        description = "Optional operator reason/comment recorded in the audit trail"
    ),
    responses(
        (status = 200, description = "MCP Server quarantined", body = ActiveResponseStatusResponse),
        (status = 404, description = "Server not found", body = StatusError)
    )
)]
fn quarantine_mcp_server_api() {}

#[utoipa::path(
    post,
    path = "/v1/mcp/servers/{server_key}/restore",
    security(("bearer_auth" = [])),
    params(
        ("server_key" = String, Path, description = "MCP Server Key")
    ),
    request_body(
        content = ActiveResponseRequest,
        description = "Optional operator reason/comment recorded in the audit trail"
    ),
    responses(
        (status = 200, description = "MCP Server restored", body = ActiveResponseStatusResponse),
        (status = 404, description = "Server not found", body = StatusError)
    )
)]
fn restore_mcp_server_api() {}

#[utoipa::path(
    get,
    path = "/v1/mcp/servers/{server_key}/manifest-history",
    security(("bearer_auth" = [])),
    params(
        ("server_key" = String, Path, description = "MCP Server Key")
    ),
    responses(
        (status = 200, description = "Manifest drift snapshot history", body = Vec<McpManifestSnapshotRecord>),
        (status = 404, description = "Server not found", body = StatusError)
    )
)]
fn get_mcp_server_manifest_history_api() {}

#[utoipa::path(
    post,
    path = "/v1/mcp/servers/{server_key}/inspect",
    security(("bearer_auth" = [])),
    params(
        ("server_key" = String, Path, description = "MCP Server Key")
    ),
    request_body = InspectMcpResponseRequest,
    responses(
        (status = 200, description = "Inspection completed successfully"),
        (status = 404, description = "Server not found", body = StatusError)
    )
)]
fn inspect_mcp_response_api() {}

#[utoipa::path(
    post,
    path = "/v1/authorize",
    request_body = AuthorizeRequest,
    responses(
        (status = 200, description = "Authorization decision response", body = AuthorizeResponse)
    )
)]
fn authorize_action_api() {}

#[utoipa::path(
    get,
    path = "/v1/decisions",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "List of decisions", body = Vec<DecisionRecord>)
    )
)]
fn list_decisions_api() {}

#[utoipa::path(
    get,
    path = "/v1/decisions/{id}",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Decision ID")
    ),
    responses(
        (status = 200, description = "Decision details", body = DecisionRecord),
        (status = 404, description = "Decision not found", body = StatusError)
    )
)]
fn get_decision_api() {}

#[utoipa::path(
    get,
    path = "/v1/policies",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "List of custom policies", body = Vec<PolicyRecord>)
    )
)]
fn list_policies_api() {}

#[utoipa::path(
    post,
    path = "/v1/policies",
    security(("bearer_auth" = [])),
    responses(
        (status = 201, description = "Policy created successfully", body = PolicyRecord)
    )
)]
fn create_policy_api() {}

#[utoipa::path(
    put,
    path = "/v1/policies/{id}",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Policy ID")
    ),
    responses(
        (status = 200, description = "Policy updated successfully", body = PolicyRecord),
        (status = 404, description = "Policy not found", body = StatusError)
    )
)]
fn update_policy_api() {}

#[utoipa::path(
    delete,
    path = "/v1/policies/{id}",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Policy ID")
    ),
    responses(
        (status = 200, description = "Policy deleted successfully"),
        (status = 404, description = "Policy not found", body = StatusError)
    )
)]
fn delete_policy_api() {}

#[utoipa::path(
    post,
    path = "/v1/policies/{id}/rollback",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Policy ID")
    ),
    responses(
        (status = 200, description = "Policy rolled back to the previous version", body = PolicyRecord),
        (status = 404, description = "Policy not found or no archived version to roll back to", body = StatusError)
    )
)]
fn rollback_policy_api() {}

#[utoipa::path(
    post,
    path = "/v1/policies/reload",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Policies reloaded successfully")
    )
)]
fn reload_global_policies_api() {}

#[utoipa::path(
    get,
    path = "/v1/tenants/risk-weights",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Effective risk weights", body = RiskWeights)
    )
)]
fn get_tenant_risk_weights_api() {}

#[utoipa::path(
    put,
    path = "/v1/tenants/risk-weights",
    security(("bearer_auth" = [])),
    request_body = RiskWeights,
    responses(
        (status = 200, description = "Risk weights updated successfully", body = RiskWeights)
    )
)]
fn put_tenant_risk_weights_api() {}

#[utoipa::path(
    get,
    path = "/v1/tenants/risk-escalation",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Risk escalation thresholds", body = RiskEscalationConfig)
    )
)]
fn get_tenant_risk_escalation_config_api() {}

#[utoipa::path(
    put,
    path = "/v1/tenants/risk-escalation",
    security(("bearer_auth" = [])),
    request_body = RiskEscalationConfig,
    responses(
        (status = 200, description = "Risk escalation thresholds updated successfully", body = RiskEscalationConfig)
    )
)]
fn put_tenant_risk_escalation_config_api() {}

#[utoipa::path(
    get,
    path = "/v1/tenants/slack-approver-group",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Slack approver group config", body = SlackApproverGroupRequest)
    )
)]
fn get_tenant_slack_approver_group_api() {}

#[utoipa::path(
    put,
    path = "/v1/tenants/slack-approver-group",
    security(("bearer_auth" = [])),
    request_body = SlackApproverGroupRequest,
    responses(
        (status = 200, description = "Slack approver group updated", body = SlackApproverGroupRequest)
    )
)]
fn put_tenant_slack_approver_group_api() {}

#[utoipa::path(
    get,
    path = "/v1/webhook_subscriptions",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "List of webhook subscriptions", body = Vec<WebhookSubscriptionRecord>)
    )
)]
fn list_webhook_subscriptions_api() {}

#[utoipa::path(
    post,
    path = "/v1/webhook_subscriptions",
    security(("bearer_auth" = [])),
    responses(
        (status = 201, description = "Webhook subscription created successfully", body = WebhookSubscriptionRecord)
    )
)]
fn create_webhook_subscription_api() {}

#[utoipa::path(
    delete,
    path = "/v1/webhook_subscriptions/{id}",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Webhook subscription ID")
    ),
    responses(
        (status = 200, description = "Webhook subscription deleted successfully"),
        (status = 404, description = "Subscription not found", body = StatusError)
    )
)]
fn delete_webhook_subscription_api() {}

#[utoipa::path(
    post,
    path = "/v1/webhook_subscriptions/{id}/reactivate",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Webhook subscription ID")
    ),
    responses(
        (status = 200, description = "Webhook subscription reactivated successfully"),
        (status = 404, description = "Subscription not found", body = StatusError)
    )
)]
fn reactivate_webhook_subscription_api() {}

#[utoipa::path(
    get,
    path = "/v1/detection_rules",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "List of detection rules", body = Vec<DetectionRuleRecord>)
    )
)]
fn list_detection_rules_api() {}

#[utoipa::path(
    post,
    path = "/v1/detection_rules",
    security(("bearer_auth" = [])),
    responses(
        (status = 201, description = "Detection rule created or updated", body = DetectionRuleRecord)
    )
)]
fn upsert_detection_rule_api() {}

#[utoipa::path(
    delete,
    path = "/v1/detection_rules/{id}",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Detection rule ID")
    ),
    responses(
        (status = 200, description = "Detection rule deleted successfully"),
        (status = 404, description = "Detection rule not found", body = StatusError)
    )
)]
fn delete_detection_rule_api() {}

#[utoipa::path(
    get,
    path = "/v1/soc/rules",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "List of effective SOC rules")
    )
)]
fn get_soc_rules_api() {}

#[utoipa::path(
    post,
    path = "/v1/soc/rules",
    security(("bearer_auth" = [])),
    responses(
        (status = 201, description = "Custom rule created or updated successfully")
    )
)]
fn create_soc_rule_api() {}

#[utoipa::path(
    post,
    path = "/v1/soc/rules/reload",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Detection rules reloaded successfully")
    )
)]
fn reload_soc_rules_api() {}

#[utoipa::path(
    post,
    path = "/v1/soc/rules/{rule_key}/backtest",
    security(("bearer_auth" = [])),
    params(
        ("rule_key" = String, Path, description = "SOC rule key")
    ),
    responses(
        (status = 200, description = "Backtest run completed successfully"),
        (status = 404, description = "Rule not found", body = StatusError)
    )
)]
fn backtest_soc_rule_api() {}

#[utoipa::path(
    get,
    path = "/v1/graph/run/{run_id}",
    security(("bearer_auth" = [])),
    params(
        ("run_id" = String, Path, description = "Run ID")
    ),
    responses(
        (status = 200, description = "Run evidence graph details"),
        (status = 404, description = "Run not found", body = StatusError)
    )
)]
fn get_graph_for_run_api() {}

#[utoipa::path(
    get,
    path = "/v1/graph/incident/{incident_id}",
    security(("bearer_auth" = [])),
    params(
        ("incident_id" = String, Path, description = "Incident ID")
    ),
    responses(
        (status = 200, description = "Incident evidence graph details"),
        (status = 404, description = "Incident not found", body = StatusError)
    )
)]
fn get_graph_for_incident_api() {}

#[utoipa::path(
    get,
    path = "/v1/graph/agent/{agent_id}",
    security(("bearer_auth" = [])),
    params(
        ("agent_id" = String, Path, description = "Agent ID")
    ),
    responses(
        (status = 200, description = "Agent-centric evidence graph details"),
        (status = 404, description = "Agent not found", body = StatusError)
    )
)]
fn get_graph_for_agent_api() {}

#[utoipa::path(
    get,
    path = "/v1/api_keys",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "List of API keys", body = Vec<ApiKeyRecord>)
    )
)]
fn list_api_keys_api() {}

#[utoipa::path(
    post,
    path = "/v1/api_keys",
    security(("bearer_auth" = [])),
    responses(
        (status = 201, description = "API key created successfully", body = ApiKeyRecord)
    )
)]
fn create_api_key_api() {}

#[utoipa::path(
    post,
    path = "/v1/api_keys/{id}/revoke",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "API key ID")
    ),
    responses(
        (status = 200, description = "API key revoked successfully"),
        (status = 404, description = "API key not found", body = StatusError)
    )
)]
fn revoke_api_key_api() {}

#[utoipa::path(
    get,
    path = "/v1/approvals",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "List of pending approvals", body = Vec<ApprovalQueueItem>)
    )
)]
fn list_approvals_api() {}

#[utoipa::path(
    get,
    path = "/v1/approvals/{id}",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Approval ID")
    ),
    responses(
        (status = 200, description = "Approval details", body = ApprovalQueueItem),
        (status = 404, description = "Approval not found", body = StatusError)
    )
)]
fn get_approval_api() {}

#[utoipa::path(
    post,
    path = "/v1/approvals/{id}/approve",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Approval ID")
    ),
    request_body = ApproveRequest,
    responses(
        (status = 200, description = "Approved successfully"),
        (status = 404, description = "Approval not found", body = StatusError)
    )
)]
fn approve_approval_api() {}

#[utoipa::path(
    post,
    path = "/v1/approvals/{id}/reject",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Approval ID")
    ),
    request_body = ApproveRequest,
    responses(
        (status = 200, description = "Rejected successfully"),
        (status = 404, description = "Approval not found", body = StatusError)
    )
)]
fn reject_approval_api() {}

#[utoipa::path(
    post,
    path = "/v1/approvals/{id}/edit",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Approval ID")
    ),
    request_body = EditApprovalRequest,
    responses(
        (status = 200, description = "Approval parameters updated", body = ApprovalRecord),
        (status = 404, description = "Approval not found", body = StatusError)
    )
)]
fn edit_approval_api() {}

#[utoipa::path(
    post,
    path = "/v1/approvals/{id}/consume",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Approval ID")
    ),
    responses(
        (status = 200, description = "Approval consumed successfully"),
        (status = 404, description = "Approval not found", body = StatusError)
    )
)]
fn consume_approval_api() {}

#[utoipa::path(
    get,
    path = "/v1/runs/{id}/timeline",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Run ID")
    ),
    responses(
        (status = 200, description = "List of timeline events", body = Vec<AuditEventRecord>),
        (status = 404, description = "Run not found", body = StatusError)
    )
)]
fn get_timeline_api() {}

#[utoipa::path(
    get,
    path = "/v1/audit/events",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "List of audit events", body = Vec<AuditEventRecord>)
    )
)]
fn get_audit_events_api() {}

#[utoipa::path(
    get,
    path = "/v1/compliance/evidence-pack",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "ZIP archive of compliance evidence pack"),
        (status = 400, description = "Invalid parameters", body = StatusError)
    )
)]
fn get_evidence_pack_api() {}

#[utoipa::path(
    get,
    path = "/v1/receipts",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "List of action receipts", body = Vec<ActionReceiptRecord>)
    )
)]
fn list_receipts_api() {}

#[utoipa::path(
    get,
    path = "/v1/receipts/{id}",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Receipt ID")
    ),
    responses(
        (status = 200, description = "Receipt details", body = ActionReceiptRecord),
        (status = 404, description = "Receipt not found", body = StatusError)
    )
)]
fn get_receipt_api() {}

#[utoipa::path(
    get,
    path = "/v1/receipts/{id}/verify",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Receipt ID")
    ),
    responses(
        (status = 200, description = "Receipt verification status"),
        (status = 404, description = "Receipt not found", body = StatusError)
    )
)]
fn verify_receipt_api() {}

#[utoipa::path(
    post,
    path = "/v1/receipts/verify-chain",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Chain verification result")
    )
)]
fn verify_receipt_chain_api() {}

#[utoipa::path(
    get,
    path = "/v1/alerts",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "List of SOC alerts", body = Vec<SocAlertRecord>)
    )
)]
fn list_alerts_api() {}

#[utoipa::path(
    get,
    path = "/v1/incidents",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "List of SOC incidents", body = Vec<SocIncidentRecord>)
    )
)]
fn list_incidents_api() {}

#[utoipa::path(
    get,
    path = "/v1/incidents/{id}",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Incident ID")
    ),
    responses(
        (status = 200, description = "Incident details", body = SocIncidentRecord),
        (status = 404, description = "Incident not found", body = StatusError)
    )
)]
fn get_incident_api() {}

#[utoipa::path(
    post,
    path = "/v1/incidents/{id}/close",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Incident ID")
    ),
    responses(
        (status = 200, description = "Incident closed successfully"),
        (status = 404, description = "Incident not found", body = StatusError)
    )
)]
fn close_incident_api() {}

#[utoipa::path(
    get,
    path = "/v1/incidents/{id}/narrate",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Incident ID")
    ),
    responses(
        (status = 200, description = "Incident narrative text"),
        (status = 404, description = "Incident not found", body = StatusError)
    )
)]
fn narrate_incident_api() {}

#[utoipa::path(
    get,
    path = "/v1/incidents/{id}/evidence-pack",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Incident ID")
    ),
    responses(
        (status = 200, description = "ZIP archive of incident evidence pack"),
        (status = 404, description = "Incident not found", body = StatusError)
    )
)]
fn get_incident_evidence_pack_api() {}

#[utoipa::path(
    get,
    path = "/v1/soc/summary",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "SOC statistics summary details", body = SocSummary)
    )
)]
fn soc_summary_api() {}

#[utoipa::path(
    post,
    path = "/v1/soc/query",
    security(("bearer_auth" = [])),
    request_body = SocQueryRequest,
    responses(
        (status = 200, description = "Structured SOC query result", body = SocQueryResponse),
        (status = 400, description = "Invalid entity, aggregate, or filter shape", body = StatusError)
    )
)]
fn soc_query_api() {}

#[utoipa::path(
    get,
    path = "/v1/soc/semantic-search",
    security(("bearer_auth" = [])),
    params(
        ("query" = String, Query, description = "Semantic search query string"),
        ("limit" = Option<usize>, Query, description = "Limit on returned results")
    ),
    responses(
        (status = 200, description = "List of semantically similar alerts/incidents"),
        (status = 400, description = "Empty query parameter", body = StatusError),
        (status = 501, description = "Semantic search not configured", body = StatusError)
    )
)]
fn semantic_search_api() {}

#[utoipa::path(
    get,
    path = "/v1/soc/contact-points",
    security(("bearer_auth" = [])),
    responses((status = 200, description = "List contact points"))
)]
fn list_contact_points_api() {}

#[utoipa::path(
    post,
    path = "/v1/soc/contact-points",
    security(("bearer_auth" = [])),
    responses((status = 201, description = "Contact point created"))
)]
fn create_contact_point_api() {}

#[utoipa::path(
    put,
    path = "/v1/soc/contact-points/{id}",
    security(("bearer_auth" = [])),
    responses((status = 200, description = "Contact point updated"))
)]
fn update_contact_point_api() {}

#[utoipa::path(
    delete,
    path = "/v1/soc/contact-points/{id}",
    security(("bearer_auth" = [])),
    responses((status = 200, description = "Contact point deleted"))
)]
fn delete_contact_point_api() {}

#[utoipa::path(
    get,
    path = "/v1/soc/notification-policies",
    security(("bearer_auth" = [])),
    responses((status = 200, description = "List notification policies"))
)]
fn list_notification_policies_api() {}

#[utoipa::path(
    post,
    path = "/v1/soc/notification-policies",
    security(("bearer_auth" = [])),
    responses((status = 201, description = "Notification policy created"))
)]
fn create_notification_policy_api() {}

#[utoipa::path(
    put,
    path = "/v1/soc/notification-policies/{id}",
    security(("bearer_auth" = [])),
    responses((status = 200, description = "Notification policy updated"))
)]
fn update_notification_policy_api() {}

#[utoipa::path(
    delete,
    path = "/v1/soc/notification-policies/{id}",
    security(("bearer_auth" = [])),
    responses((status = 200, description = "Notification policy deleted"))
)]
fn delete_notification_policy_api() {}

#[utoipa::path(
    get,
    path = "/v1/soc/silences",
    security(("bearer_auth" = [])),
    responses((status = 200, description = "List alert silences"))
)]
fn list_silences_api() {}

#[utoipa::path(
    post,
    path = "/v1/soc/silences",
    security(("bearer_auth" = [])),
    responses((status = 201, description = "Silence created"))
)]
fn create_silence_api() {}

#[utoipa::path(
    delete,
    path = "/v1/soc/silences/{id}",
    security(("bearer_auth" = [])),
    responses((status = 200, description = "Silence deleted"))
)]
fn delete_silence_api() {}

#[utoipa::path(
    get,
    path = "/v1/soc/dashboards",
    security(("bearer_auth" = [])),
    responses((status = 200, description = "List tenant dashboards"))
)]
fn list_soc_dashboards_api() {}

#[utoipa::path(
    get,
    path = "/v1/soc/dashboards/{uid}",
    security(("bearer_auth" = [])),
    responses((status = 200, description = "Get dashboard by uid"))
)]
fn get_soc_dashboard_api() {}

#[utoipa::path(
    post,
    path = "/v1/soc/dashboards",
    security(("bearer_auth" = [])),
    responses((status = 201, description = "Dashboard created"))
)]
fn create_soc_dashboard_api() {}

#[utoipa::path(
    put,
    path = "/v1/soc/dashboards/{uid}",
    security(("bearer_auth" = [])),
    responses((status = 200, description = "Dashboard updated"))
)]
fn update_soc_dashboard_api() {}

#[utoipa::path(
    delete,
    path = "/v1/soc/dashboards/{uid}",
    security(("bearer_auth" = [])),
    responses((status = 204, description = "Dashboard deleted"))
)]
fn delete_soc_dashboard_api() {}

#[utoipa::path(
    post,
    path = "/v1/tenants",
    security(("bearer_auth" = [])),
    request_body = CreateTenantRequest,
    responses(
        (status = 201, description = "Tenant created successfully", body = TenantRecord)
    )
)]
fn create_tenant_api() {}

#[utoipa::path(
    get,
    path = "/v1/tenants/{id}",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Tenant ID")
    ),
    responses(
        (status = 200, description = "Tenant details", body = TenantRecord),
        (status = 404, description = "Tenant not found", body = StatusError)
    )
)]
fn get_tenant_api() {}

#[utoipa::path(
    delete,
    path = "/v1/tenants/{id}",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Tenant ID")
    ),
    responses(
        (status = 204, description = "Tenant deleted successfully"),
        (status = 404, description = "Tenant not found", body = StatusError)
    )
)]
fn delete_tenant_api() {}

#[utoipa::path(
    get,
    path = "/v1/tenants/{id}/export",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Tenant ID")
    ),
    responses(
        (status = 200, description = "Tenant data portability export details", body = TenantExport),
        (status = 404, description = "Tenant not found", body = StatusError)
    )
)]
fn export_tenant_api() {}

#[utoipa::path(
    get,
    path = "/v1/ws/events",
    security(("bearer_auth" = [])),
    responses(
        (status = 101, description = "Protocol upgraded to WebSocket")
    )
)]
fn ws_events_api() {}

#[utoipa::path(
    get,
    path = "/v1/soc/stream",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Server-Sent Events stream of ASE, alert, and approval deltas")
    )
)]
fn soc_stream_api() {}

#[utoipa::path(
    get,
    path = "/v1/stats",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Tenant stats summary details", body = TenantStats)
    )
)]
fn get_tenant_stats_api() {}

#[utoipa::path(
    get,
    path = "/v1/admin/db-stats",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Database stats summary details", body = DbStats)
    )
)]
fn get_db_stats_api() {}

#[utoipa::path(
    post,
    path = "/v1/admin/backup",
    security(("bearer_auth" = [])),
    request_body = CreateBackupRequest,
    responses(
        (status = 200, description = "Backup created successfully", body = CreateBackupResponse),
        (status = 400, description = "Invalid filename", body = StatusError),
        (status = 409, description = "Backup file already exists", body = StatusError)
    )
)]
fn create_db_backup_api() {}

// #1607: routes added after the initial OpenAPI snapshot — kept in parity with api_routes().

#[utoipa::path(
    get,
    path = "/v1/agent-cage/runs",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "List agent cage runs")
    )
)]
fn list_agent_cage_runs_api() {}

#[utoipa::path(
    get,
    path = "/v1/agent-cage/runs/{id}",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Get agent cage run")
    )
)]
fn get_agent_cage_run_api() {}

#[utoipa::path(
    post,
    path = "/v1/agent-cage/runs/{id}/kill",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Kill agent cage run")
    )
)]
fn kill_agent_cage_run_api() {}

#[utoipa::path(
    post,
    path = "/v1/agent-cage/runs/{id}/pause",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Pause agent cage run")
    )
)]
fn pause_agent_cage_run_api() {}

#[utoipa::path(
    post,
    path = "/v1/agent-cage/runs/{id}/quarantine",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Quarantine agent cage run")
    )
)]
fn quarantine_agent_cage_run_api() {}

#[utoipa::path(
    post,
    path = "/v1/agent-cage/runs/{id}/resume",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Resume agent cage run")
    )
)]
fn resume_agent_cage_run_api() {}

#[utoipa::path(
    get,
    path = "/v1/agents/risk-scoreboard",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Agent risk scoreboard")
    )
)]
fn get_agent_risk_scoreboard_api() {}

#[utoipa::path(
    get,
    path = "/v1/bans",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "List bans")
    )
)]
fn list_bans_api() {}

#[utoipa::path(
    get,
    path = "/v1/bans/{id}",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Get ban")
    )
)]
fn get_ban_api() {}

#[utoipa::path(
    post,
    path = "/v1/bans/{id}/revoke",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Revoke ban")
    )
)]
fn revoke_ban_api() {}

#[utoipa::path(
    get,
    path = "/v1/broker/tools",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "List broker tools")
    )
)]
fn list_broker_tools_api() {}

#[utoipa::path(
    get,
    path = "/v1/broker/tools/{id}",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Get broker tool")
    )
)]
fn get_broker_tool_api() {}

#[utoipa::path(
    post,
    path = "/v1/broker/tools/{id}/status",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Set broker tool status")
    )
)]
fn set_broker_tool_status_api() {}

#[utoipa::path(
    post,
    path = "/v1/callbacks/slack",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Slack interactive callback")
    )
)]
fn slack_callback_api() {}

#[utoipa::path(
    get,
    path = "/v1/control/commands",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "List control commands")
    )
)]
fn list_control_commands_api() {}

#[utoipa::path(
    get,
    path = "/v1/control/commands/{id}",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Get control command")
    )
)]
fn get_control_command_api() {}

#[utoipa::path(
    post,
    path = "/v1/control/commands/{id}/status",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Update control command status")
    )
)]
fn update_control_command_status_api() {}

#[utoipa::path(
    get,
    path = "/v1/decisions/timeseries",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Decision timeseries")
    )
)]
fn decision_timeseries_api() {}

#[utoipa::path(
    post,
    path = "/v1/egress/block",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Block egress")
    )
)]
fn block_egress_api() {}

#[utoipa::path(
    post,
    path = "/v1/egress/check",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Check egress policy")
    )
)]
fn check_egress_api() {}

#[utoipa::path(
    get,
    path = "/v1/egress/events",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "List egress events")
    )
)]
fn list_egress_events_api() {}

#[utoipa::path(
    post,
    path = "/v1/egress/unblock",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Unblock egress")
    )
)]
fn unblock_egress_api() {}

#[utoipa::path(
    post,
    path = "/v1/ingest",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Ingest external event")
    )
)]
fn ingest_event_api() {}

#[utoipa::path(
    post,
    path = "/v1/ingest/runtime-events",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Ingest runtime event")
    )
)]
fn ingest_runtime_event_api() {}

#[utoipa::path(
    get,
    path = "/v1/openapi.json",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "OpenAPI specification")
    )
)]
fn get_openapi_json_api() {}

#[utoipa::path(
    get,
    path = "/v1/playbooks",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "List playbooks")
    )
)]
fn list_playbooks_api() {}

#[utoipa::path(
    delete,
    path = "/v1/playbooks/{id}",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Delete playbook")
    )
)]
fn delete_playbook_api() {}

#[utoipa::path(
    post,
    path = "/v1/playbooks/{id}/test",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Test playbook")
    )
)]
fn test_playbook_api() {}

#[utoipa::path(
    get,
    path = "/v1/policies/audit-log",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Policy audit log")
    )
)]
fn list_policy_audit_log_api() {}

#[utoipa::path(
    post,
    path = "/v1/policies/bundles",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Upload policy bundle")
    )
)]
fn upload_policy_bundle_api() {}

#[utoipa::path(
    post,
    path = "/v1/policies/compile",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Compile policy")
    )
)]
fn compile_policy_api() {}

#[utoipa::path(
    get,
    path = "/v1/policies/templates",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "List policy templates")
    )
)]
fn list_policy_templates_api() {}

#[utoipa::path(
    get,
    path = "/v1/quarantine",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "List quarantine records")
    )
)]
fn list_quarantine_api() {}

#[utoipa::path(
    get,
    path = "/v1/quarantine/{id}",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Get quarantine record")
    )
)]
fn get_quarantine_api() {}

#[utoipa::path(
    post,
    path = "/v1/quarantine/{id}/release",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Release quarantine")
    )
)]
fn release_quarantine_api() {}

#[utoipa::path(
    get,
    path = "/v1/receipts/chain-head",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Receipt chain head")
    )
)]
fn get_receipt_chain_head_api() {}

#[utoipa::path(
    post,
    path = "/v1/receipts/verify-range",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Verify receipt range")
    )
)]
fn verify_receipt_range_api() {}

#[utoipa::path(
    get,
    path = "/v1/runtime/runs/{id}/events",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "List run runtime events")
    )
)]
fn list_run_events_api() {}

#[utoipa::path(
    get,
    path = "/v1/sensors",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "List sensors")
    )
)]
fn list_sensors_api() {}

#[utoipa::path(
    post,
    path = "/v1/sensors/register",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Register sensor")
    )
)]
fn register_sensor_api() {}

#[utoipa::path(
    get,
    path = "/v1/sensors/{id}",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Get sensor")
    )
)]
fn get_sensor_api() {}

#[utoipa::path(
    post,
    path = "/v1/sensors/{id}/heartbeat",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Sensor heartbeat")
    )
)]
fn sensor_heartbeat_api() {}

#[utoipa::path(
    post,
    path = "/v1/webhooks/github",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "GitHub App webhook")
    )
)]
fn receive_github_webhook_api() {}
