use crate::routes::AppState;
use aegis_api::grpc::aegis::{
    admin_service_server::{AdminService, AdminServiceServer},
    aegis_service_server::{AegisService, AegisServiceServer},
    soc_service_server::{SocService, SocServiceServer},
    ApproveRequest, ApproveResponse, AuthorizeRequest, AuthorizeResponse, CloseIncidentRequest,
    CloseIncidentResponse, ContactPointItem, CreateContactPointRequest, CreateContactPointResponse,
    CreateNotificationPolicyRequest, CreateNotificationPolicyResponse, CreatePlaybookRequest,
    CreatePlaybookResponse, CreateSilenceRequest, CreateSilenceResponse, CreateSocDashboardRequest,
    CreateSocDashboardResponse, CreateTenantRequest, CreateTenantResponse,
    DeleteContactPointRequest, DeleteContactPointResponse, DeleteNotificationPolicyRequest,
    DeleteNotificationPolicyResponse, DeletePlaybookRequest, DeletePlaybookResponse,
    DeleteSilenceRequest, DeleteSilenceResponse, DeleteSocDashboardRequest,
    DeleteSocDashboardResponse, DiscoverMcpToolsRequest, DiscoverMcpToolsResponse,
    GetSocDashboardRequest, GetSocDashboardResponse, ListAlertsRequest, ListAlertsResponse,
    ListContactPointsRequest, ListContactPointsResponse, ListIncidentsRequest,
    ListIncidentsResponse, ListNotificationPoliciesRequest, ListNotificationPoliciesResponse,
    ListPlaybooksRequest, ListPlaybooksResponse, ListSilencesRequest, ListSilencesResponse,
    ListSocDashboardsRequest, ListSocDashboardsResponse, McpToolStatusResponse,
    NotificationPolicyItem, RegisterAgentRequest, RegisterAgentResponse, RegisterMcpServerRequest,
    RegisterMcpServerResponse, SemanticSearchRequest, SemanticSearchResponse, SemanticSearchResult,
    SilenceItem, SocDashboardItem, SocQueryRequest as GrpcSocQueryRequest, SocQueryResponse,
    UpdateSocDashboardRequest, UpdateSocDashboardResponse,
};
use axum::response::IntoResponse;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use uuid::Uuid;

pub struct AegisGrpcServiceImpl {
    _state: Arc<AppState>,
}

impl AegisGrpcServiceImpl {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { _state: state }
    }
}

fn map_authorize_request(
    req: aegis_api::grpc::aegis::AuthorizeRequest,
) -> crate::models::AuthorizeRequest {
    crate::models::AuthorizeRequest {
        request_id: if req.request_id.is_empty() {
            None
        } else {
            Some(req.request_id)
        },
        callback: req.callback.map(|c| crate::models::ApprovalCallback {
            url: c.url,
            secret: None,
        }),
        dry_run: Some(req.dry_run),
        agent: req
            .agent
            .map(|a| crate::models::AuthorizeAgentContext {
                id: a.id,
                environment: a.environment,
            })
            .unwrap_or_else(|| crate::models::AuthorizeAgentContext {
                id: String::new(),
                environment: String::new(),
            }),
        user: req.user.map(|u| crate::models::AuthorizeUserContext {
            id: u.id,
            role: u.role,
        }),
        tool_call: req
            .tool_call
            .map(|t| crate::models::AuthorizeToolCall {
                tool: t.tool,
                action: t.action,
                resource: if t.resource.is_empty() {
                    None
                } else {
                    Some(t.resource)
                },
                mutates_state: t.mutates_state,
                parameters: serde_json::from_str(&t.parameters_json)
                    .unwrap_or(serde_json::Value::Null),
            })
            .unwrap_or_else(|| crate::models::AuthorizeToolCall {
                tool: String::new(),
                action: String::new(),
                resource: None,
                mutates_state: false,
                parameters: serde_json::Value::Null,
            }),
        context: req
            .context
            .map(|c| crate::models::AuthorizeDynamicContext {
                source_trust: c.source_trust,
                contains_sensitive_data: c.contains_sensitive_data,
            })
            .unwrap_or_else(|| crate::models::AuthorizeDynamicContext {
                source_trust: "unknown".to_string(),
                contains_sensitive_data: false,
            }),
        trace: req.trace.map(|t| crate::models::AuthorizeTraceContext {
            run_id: t.run_id,
            trace_id: t.trace_id,
            parent_run_id: if t.parent_run_id.is_empty() {
                None
            } else {
                Some(t.parent_run_id)
            },
            root_trust_level: if t.root_trust_level.is_empty() {
                None
            } else {
                Some(t.root_trust_level)
            },
        }),
        nonce: if req.nonce.is_empty() {
            None
        } else {
            Some(req.nonce)
        },
        timestamp: if req.timestamp.is_empty() {
            None
        } else {
            chrono::DateTime::parse_from_rfc3339(&req.timestamp)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .ok()
        },
    }
}

fn map_authorize_response(
    res: crate::models::AuthorizeResponse,
) -> aegis_api::grpc::aegis::AuthorizeResponse {
    aegis_api::grpc::aegis::AuthorizeResponse {
        decision_id: res.decision_id.to_string(),
        decision: res.decision,
        risk_score: res.risk_score,
        risk_level: res.risk_level,
        composite_risk_score: res.composite_risk_score,
        reason: res.reason,
        matched_policies: res.matched_policies,
        approval: res
            .approval
            .map(|a| aegis_api::grpc::aegis::ApprovalResponseInfo {
                approval_id: a.approval_id.to_string(),
                status: a.status,
                approver_group: a.approver_group.unwrap_or_default(),
                expires_at: a.expires_at.to_rfc3339(),
                action_hash: a.action_hash,
            }),
        redacted_fields: res.redacted_fields,
        root_trust_level: res.root_trust_level,
        dry_run: res.dry_run,
    }
}

#[tonic::async_trait]
impl AegisService for AegisGrpcServiceImpl {
    async fn authorize(
        &self,
        request: Request<AuthorizeRequest>,
    ) -> Result<Response<AuthorizeResponse>, Status> {
        // architecture.md §5: parse/auth → typed service → map Status.
        // Service returns AuthorizedOutcome; adapter never buffers an Axum body.
        use crate::authorize_service::{
            authorize, outcome_to_tonic, AuthCredential, AuthorizeContext, Transport,
        };

        let client_addr = request
            .remote_addr()
            .unwrap_or_else(|| std::net::SocketAddr::from(([0, 0, 0, 0], 0)));

        let metadata = request.metadata();
        let bearer = metadata
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim())
            .and_then(|s| {
                s.strip_prefix("Bearer ")
                    .or_else(|| s.strip_prefix("bearer "))
                    .map(|t| t.to_string())
            });
        let mtls_cn = metadata
            .get("x-aegis-mtls-cn")
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());
        let request_signature = metadata
            .get("x-aegis-request-signature")
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        let credential = if let Some(cn) = mtls_cn {
            AuthCredential::MtlsCn(cn)
        } else if let Some(token) = bearer {
            AuthCredential::BearerToken(token)
        } else {
            return Err(Status::unauthenticated(
                "Missing agent token (authorization metadata) or mTLS CN",
            ));
        };

        let req = request.into_inner();
        if req.tenant_id.is_empty() {
            return Err(Status::invalid_argument(
                "Missing tenant_id on AuthorizeRequest",
            ));
        }

        let ctx = AuthorizeContext::new(
            req.tenant_id.clone(),
            client_addr,
            Transport::Grpc,
            credential,
        )
        .with_request_signature(request_signature);

        let rest_req = map_authorize_request(req);
        let outcome = authorize(self._state.clone(), ctx, &rest_req).await;
        let res = outcome_to_tonic(outcome)?;
        Ok(Response::new(map_authorize_response(res)))
    }

    async fn register_agent(
        &self,
        request: Request<RegisterAgentRequest>,
    ) -> Result<Response<RegisterAgentResponse>, Status> {
        use crate::authorize_service::outcome_to_tonic_json;

        let req = request.into_inner();
        if req.tenant_id.is_empty() {
            return Err(Status::invalid_argument("Missing tenant_id"));
        }
        let rest_req = crate::models::RegisterAgentRequest {
            agent_key: req.agent_key,
            name: req.name,
            owner_team: if req.owner_team.is_empty() {
                None
            } else {
                Some(req.owner_team)
            },
            environment: req.environment,
            framework: if req.framework.is_empty() {
                None
            } else {
                Some(req.framework)
            },
            model_provider: if req.model_provider.is_empty() {
                None
            } else {
                Some(req.model_provider)
            },
            model_name: if req.model_name.is_empty() {
                None
            } else {
                Some(req.model_name)
            },
            purpose: if req.purpose.is_empty() {
                None
            } else {
                Some(req.purpose)
            },
            risk_tier: req.risk_tier,
            signing_key: None,
            allowed_environments: if req.allowed_environments.is_empty() {
                None
            } else {
                Some(req.allowed_environments)
            },
        };

        let outcome =
            crate::routes::register_agent_inner(self._state.clone(), req.tenant_id, rest_req).await;
        let value = outcome_to_tonic_json(outcome)?;
        let res: crate::models::RegisterAgentResponse =
            serde_json::from_value(value).map_err(|e| {
                Status::internal(format!("Failed to parse register_agent response: {e}"))
            })?;

        Ok(Response::new(RegisterAgentResponse {
            id: res.id.to_string(),
            agent_key: res.agent_key,
        }))
    }

    async fn approve(
        &self,
        request: Request<ApproveRequest>,
    ) -> Result<Response<ApproveResponse>, Status> {
        use crate::authorize_service::outcome_to_tonic_json;

        let req = request.into_inner();
        let payload = crate::models::ApproveRequest {
            approver_user_id: req.approver_user_id,
            reason: if req.reason.is_empty() {
                None
            } else {
                Some(req.reason)
            },
        };

        let approval_uuid = match Uuid::parse_str(&req.approval_id) {
            Ok(u) => u,
            Err(_) => return Err(Status::invalid_argument("Invalid approval_id UUID")),
        };

        let outcome = crate::routes::approve_approval_inner(
            self._state.clone(),
            req.tenant_id,
            approval_uuid,
            payload,
        )
        .await;

        let value = outcome_to_tonic_json(outcome)?;
        let status_str = value["status"].as_str().unwrap_or_default().to_string();
        let approval_id_str = value["approval_id"]
            .as_str()
            .unwrap_or_default()
            .to_string();

        Ok(Response::new(ApproveResponse {
            status: status_str,
            approval_id: approval_id_str,
        }))
    }
}

pub struct AdminGrpcServiceImpl {
    _state: Arc<AppState>,
}

impl AdminGrpcServiceImpl {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { _state: state }
    }
}

#[tonic::async_trait]
impl AdminService for AdminGrpcServiceImpl {
    async fn create_tenant(
        &self,
        request: Request<CreateTenantRequest>,
    ) -> Result<Response<CreateTenantResponse>, Status> {
        use crate::authorize_service::outcome_to_tonic_json;

        let req = request.into_inner();
        let payload = crate::models::CreateTenantRequest {
            id: req.id,
            name: req.name,
            plan: req.plan,
        };

        let outcome = crate::routes::create_tenant_inner(self._state.clone(), payload).await;
        let value = outcome_to_tonic_json(outcome)?;
        let res: crate::models::TenantRecord = serde_json::from_value(value).map_err(|e| {
            Status::internal(format!("Failed to parse create_tenant response: {e}"))
        })?;

        Ok(Response::new(CreateTenantResponse {
            id: res.id,
            name: res.name,
            plan: res.plan,
            created_at: res.created_at.to_rfc3339(),
        }))
    }

    async fn register_mcp_server(
        &self,
        request: Request<RegisterMcpServerRequest>,
    ) -> Result<Response<RegisterMcpServerResponse>, Status> {
        use crate::authorize_service::outcome_to_tonic_json;

        let req = request.into_inner();
        if req.tenant_id.is_empty() {
            return Err(Status::invalid_argument("Missing tenant_id"));
        }
        let payload = crate::models::RegisterMcpServerRequest {
            server_key: req.server_key,
            name: req.name,
            owner_team: if req.owner_team.is_empty() {
                None
            } else {
                Some(req.owner_team)
            },
            transport: req.transport,
            source: if req.source.is_empty() {
                None
            } else {
                Some(req.source)
            },
            trust_level: req.trust_level,
            endpoint: req.endpoint,
            // The gRPC admin API has no manifest-signing-key field in its
            // .proto contract (lib/api/proto/admin.proto) — servers
            // registered via gRPC always start unsigned; pin a key
            // afterward via PATCH /v1/mcp/servers/:server_key over REST if
            // desired.
            manifest_signing_public_key: None,
        };

        let outcome =
            crate::routes::register_mcp_server_inner(self._state.clone(), req.tenant_id, payload)
                .await;
        let value = outcome_to_tonic_json(outcome)?;
        let res: crate::models::RegisterMcpServerResponse = serde_json::from_value(value)
            .map_err(|e| Status::internal(format!("Failed to parse register_mcp_server: {e}")))?;

        Ok(Response::new(RegisterMcpServerResponse {
            server_id: res.server_id,
            server_key: res.server_key,
            status: res.status,
        }))
    }

    async fn discover_mcp_tools(
        &self,
        request: Request<DiscoverMcpToolsRequest>,
    ) -> Result<Response<DiscoverMcpToolsResponse>, Status> {
        use crate::authorize_service::outcome_to_tonic_json;

        let req = request.into_inner();
        if req.tenant_id.is_empty() {
            return Err(Status::invalid_argument("Missing tenant_id"));
        }
        if req.server_key.is_empty() {
            return Err(Status::invalid_argument("Missing server_key"));
        }
        let payload = crate::models::DiscoverMcpToolsRequest {
            tools: req
                .tools
                .into_iter()
                .map(|t| crate::models::McpToolManifestItem {
                    tool_key: t.tool_key,
                    name: t.name,
                    description: if t.description.is_empty() {
                        None
                    } else {
                        Some(t.description)
                    },
                    input_schema: if t.input_schema_json.is_empty() {
                        None
                    } else {
                        serde_json::from_str(&t.input_schema_json).ok()
                    },
                    risk: t.risk,
                    mutates_state: t.mutates_state,
                    approval_required: t.approval_required,
                })
                .collect(),
            // No manifest-signature field in the gRPC .proto contract.
            // Servers with no pinned signing key are unaffected; a server
            // WITH a pinned key correctly fails closed (403) for gRPC-based
            // discovery, since there's no way for this caller to supply a
            // valid signature — consistent with the fail-closed invariant,
            // not a bypass.
            manifest_signature: None,
        };

        let outcome = crate::routes::discover_mcp_tools_inner(
            self._state.clone(),
            req.tenant_id,
            req.server_key,
            payload,
        )
        .await;
        let json_val = outcome_to_tonic_json(outcome)?;

        let tools_array = json_val["tools"]
            .as_array()
            .ok_or_else(|| Status::internal("Response tools field is missing or not an array"))?;

        let server_key = json_val["server_key"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let mut tools = Vec::new();
        for t in tools_array {
            tools.push(McpToolStatusResponse {
                server_key: server_key.clone(),
                tool_key: t["tool_key"].as_str().unwrap_or_default().to_string(),
                status: t["status"].as_str().unwrap_or_default().to_string(),
            });
        }

        Ok(Response::new(DiscoverMcpToolsResponse { tools }))
    }
}

pub struct SocGrpcServiceImpl {
    _state: Arc<AppState>,
}

impl SocGrpcServiceImpl {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { _state: state }
    }
}

#[tonic::async_trait]
impl SocService for SocGrpcServiceImpl {
    /// gRPC counterpart of `POST /v1/soc/query`.
    ///
    /// This adapter maps the protobuf request to the same REST model and invokes
    /// the same tenant-scoped query path, keeping validation and storage
    /// behavior identical across protocols.
    async fn query(
        &self,
        request: Request<GrpcSocQueryRequest>,
    ) -> Result<Response<SocQueryResponse>, Status> {
        let req = request.into_inner();
        if req.tenant_id.trim().is_empty() {
            return Err(Status::invalid_argument("tenant_id is required"));
        }

        let optional = |value: String| (!value.is_empty()).then_some(value);
        let filters = req.filters.unwrap_or_default();
        let rest_request = crate::models::SocQueryRequest {
            version: if req.version == 0 { 1 } else { req.version },
            entity: req.entity,
            filters: crate::models::SocQueryFilters {
                event_type: optional(filters.event_type),
                severity: optional(filters.severity),
                agent_id: optional(filters.agent_id),
                decision: optional(filters.decision),
                source_trust: optional(filters.source_trust),
                skill: optional(filters.skill),
                tool: optional(filters.tool),
                source_component: optional(filters.source_component),
                action: optional(filters.action),
                resource: optional(filters.resource),
                run_id: optional(filters.run_id),
                trace_id: optional(filters.trace_id),
                action_hash: optional(filters.action_hash),
                receipt_hash: optional(filters.receipt_hash),
                from: optional(filters.from),
                to: optional(filters.to),
                q: optional(filters.q),
            },
            aggregate: optional(req.aggregate),
            interval: optional(req.interval),
            group_by: optional(req.group_by),
            limit: req.limit,
            cursor: req.cursor,
        };

        let response = crate::routes::soc_query(
            axum::extract::State(self._state.clone()),
            crate::routes::TenantId(req.tenant_id),
            axum::Json(rest_request),
        )
        .await
        .into_response();
        // Transitional: faithful StatusError→tonic mapping; full typed SOC
        // service extraction is follow-on work.
        let (_status, value) =
            crate::authorize_service::axum_response_to_tonic_json(response).await?;
        let result_json = value.to_string();
        Ok(Response::new(SocQueryResponse { result_json }))
    }

    async fn list_alerts(
        &self,
        request: Request<ListAlertsRequest>,
    ) -> Result<Response<ListAlertsResponse>, Status> {
        let req = request.into_inner();
        let cursor_val = if req.cursor.is_empty() {
            None
        } else {
            req.cursor.parse::<i64>().ok()
        };
        let agent_id = if req.agent_id.is_empty() {
            None
        } else {
            Some(req.agent_id.as_str())
        };
        let limit_val = if req.limit <= 0 { 20 } else { req.limit };

        match self
            ._state
            .storage
            .list_soc_alerts(
                &req.tenant_id,
                agent_id,
                None, // severity
                limit_val,
                cursor_val,
            )
            .await
        {
            Ok((alerts, next_cursor)) => {
                let items = alerts
                    .into_iter()
                    .map(|a| aegis_api::grpc::aegis::AlertItem {
                        id: a.id,
                        tenant_id: a.tenant_id,
                        rule: a.rule,
                        severity: a.severity,
                        agent_id: a.agent_id,
                        source_event_id: a.source_event_id,
                        summary: a.summary,
                        created_at: a.created_at,
                    })
                    .collect();
                Ok(Response::new(ListAlertsResponse {
                    items,
                    next_cursor: next_cursor.map(|c| c.to_string()).unwrap_or_default(),
                }))
            }
            Err(e) => Err(Status::internal(format!("Database error: {:?}", e))),
        }
    }

    async fn list_incidents(
        &self,
        request: Request<ListIncidentsRequest>,
    ) -> Result<Response<ListIncidentsResponse>, Status> {
        let req = request.into_inner();
        let cursor_val = if req.cursor.is_empty() {
            None
        } else {
            req.cursor.parse::<i64>().ok()
        };
        let agent_id = if req.agent_id.is_empty() {
            None
        } else {
            Some(req.agent_id.as_str())
        };
        let limit_val = if req.limit <= 0 { 20 } else { req.limit };

        match self
            ._state
            .storage
            .list_soc_incidents(
                &req.tenant_id,
                agent_id,
                None, // severity
                None, // status
                None, // kind
                limit_val,
                cursor_val,
            )
            .await
        {
            Ok((incidents, next_cursor)) => {
                let items = incidents
                    .into_iter()
                    .map(|i| aegis_api::grpc::aegis::IncidentItem {
                        id: i.id,
                        tenant_id: i.tenant_id,
                        kind: i.kind,
                        severity: i.severity,
                        agent_id: i.agent_id,
                        summary: i.summary,
                        source_event_ids: serde_json::from_str(&i.source_event_ids)
                            .unwrap_or_default(),
                        opened_at: i.opened_at,
                        status: i.status,
                        closed_at: i.closed_at.unwrap_or_default(),
                    })
                    .collect();
                Ok(Response::new(ListIncidentsResponse {
                    items,
                    next_cursor: next_cursor.map(|c| c.to_string()).unwrap_or_default(),
                }))
            }
            Err(e) => Err(Status::internal(format!("Database error: {:?}", e))),
        }
    }

    async fn close_incident(
        &self,
        request: Request<CloseIncidentRequest>,
    ) -> Result<Response<CloseIncidentResponse>, Status> {
        let req = request.into_inner();
        if req.tenant_id.is_empty() {
            return Err(Status::invalid_argument("Missing tenant_id"));
        }
        if req.incident_id.is_empty() {
            return Err(Status::invalid_argument("Missing incident_id"));
        }

        let response = crate::routes::close_incident(
            axum::extract::State(self._state.clone()),
            crate::routes::TenantId(req.tenant_id),
            axum::extract::Path(req.incident_id.clone()),
        )
        .await
        .into_response();

        // Transitional bridge with StatusError→tonic mapping.
        let _value = crate::authorize_service::axum_response_to_tonic_json(response).await?;

        Ok(Response::new(CloseIncidentResponse {
            status: "closed".to_string(),
            incident_id: req.incident_id,
        }))
    }

    async fn create_playbook(
        &self,
        request: Request<CreatePlaybookRequest>,
    ) -> Result<Response<CreatePlaybookResponse>, Status> {
        let req = request.into_inner();

        // Parse and validate the playbook steps using the engine validator
        let steps: Vec<aegis_soc::playbook::PlaybookStep> =
            serde_json::from_str(&req.steps_json)
                .map_err(|e| Status::invalid_argument(format!("Invalid steps_json: {e}")))?;

        let trigger_sev = aegis_soc::playbook::TriggerSeverity::List(req.trigger_severity.clone());
        let trigger_agent_id = if req.trigger_agent_id.is_empty() {
            None
        } else {
            Some(req.trigger_agent_id.as_str())
        };
        let trigger_env = if req.trigger_environment.is_empty() {
            None
        } else {
            Some(req.trigger_environment.as_str())
        };

        let playbook = aegis_soc::playbook::ResponsePlaybook {
            name: req.name.clone(),
            trigger: aegis_soc::playbook::PlaybookTrigger {
                kind: req.trigger_kind.clone(),
                severity: trigger_sev,
                agent_id: trigger_agent_id.map(|s| s.to_string()),
                environment: trigger_env.map(|s| s.to_string()),
            },
            steps,
        };

        playbook
            .validate()
            .map_err(|e| Status::invalid_argument(format!("Playbook validation failed: {e}")))?;

        match self
            ._state
            .storage
            .insert_playbook(
                &req.tenant_id,
                &req.name,
                &req.trigger_kind,
                &req.trigger_severity,
                trigger_agent_id,
                trigger_env,
                &req.steps_json,
            )
            .await
        {
            Ok(pb) => Ok(Response::new(CreatePlaybookResponse {
                playbook: Some(aegis_api::grpc::aegis::PlaybookItem {
                    id: pb.id,
                    tenant_id: pb.tenant_id,
                    name: pb.name,
                    trigger_kind: pb.trigger_kind,
                    trigger_severity: req.trigger_severity,
                    trigger_agent_id: pb.trigger_agent_id.unwrap_or_default(),
                    trigger_environment: pb.trigger_environment.unwrap_or_default(),
                    steps_json: pb.steps_json,
                    enabled: pb.enabled,
                    created_at: pb.created_at.to_rfc3339(),
                }),
            })),
            Err(e) => Err(Status::internal(format!("Database error: {:?}", e))),
        }
    }

    async fn list_playbooks(
        &self,
        request: Request<ListPlaybooksRequest>,
    ) -> Result<Response<ListPlaybooksResponse>, Status> {
        let req = request.into_inner();
        match self._state.storage.list_playbooks(&req.tenant_id).await {
            Ok(playbooks) => {
                let items = playbooks
                    .into_iter()
                    .map(|pb| {
                        let trigger_severity: Vec<String> =
                            serde_json::from_str(&pb.trigger_severity).unwrap_or_default();
                        aegis_api::grpc::aegis::PlaybookItem {
                            id: pb.id,
                            tenant_id: pb.tenant_id,
                            name: pb.name,
                            trigger_kind: pb.trigger_kind,
                            trigger_severity,
                            trigger_agent_id: pb.trigger_agent_id.unwrap_or_default(),
                            trigger_environment: pb.trigger_environment.unwrap_or_default(),
                            steps_json: pb.steps_json,
                            enabled: pb.enabled,
                            created_at: pb.created_at.to_rfc3339(),
                        }
                    })
                    .collect();
                Ok(Response::new(ListPlaybooksResponse { items }))
            }
            Err(e) => Err(Status::internal(format!("Database error: {:?}", e))),
        }
    }

    async fn delete_playbook(
        &self,
        request: Request<DeletePlaybookRequest>,
    ) -> Result<Response<DeletePlaybookResponse>, Status> {
        let req = request.into_inner();
        match self
            ._state
            .storage
            .delete_playbook(&req.tenant_id, &req.id)
            .await
        {
            Ok(success) => Ok(Response::new(DeletePlaybookResponse { success })),
            Err(e) => Err(Status::internal(format!("Database error: {:?}", e))),
        }
    }

    /// #1451: gRPC counterpart of `GET /v1/soc/semantic-search`.
    ///
    /// Thin protocol adapter — delegates to `QdrantExporter::search_similar_events`
    /// (the same service method the REST handler calls).
    async fn semantic_search(
        &self,
        request: Request<SemanticSearchRequest>,
    ) -> Result<Response<SemanticSearchResponse>, Status> {
        let req = request.into_inner();

        // Validate: query must be non-empty.
        if req.query.trim().is_empty() {
            return Err(Status::invalid_argument("Query parameter cannot be empty"));
        }

        // Check that the Qdrant exporter is configured.
        let exporter = self._state.qdrant_exporter.as_ref().ok_or_else(|| {
            Status::unimplemented("Qdrant semantic search is not configured on this gateway")
        })?;

        let limit = if req.limit <= 0 {
            10
        } else {
            req.limit as usize
        };

        let raw_results = exporter
            .search_similar_events(&req.tenant_id, &req.query, limit)
            .await
            .map_err(|e| Status::internal(format!("Semantic search error: {}", e)))?;

        // Map untyped JSON results into typed proto messages.
        let results = raw_results
            .into_iter()
            .map(|val| {
                let obj = val.as_object();
                let s = |key: &str| -> String {
                    obj.and_then(|m| m.get(key))
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string()
                };
                SemanticSearchResult {
                    event_id: s("event_id"),
                    occurred_at: s("occurred_at"),
                    tenant_id: s("tenant_id"),
                    kind: s("kind"),
                    agent_id: s("agent_id"),
                    decision: s("decision"),
                    tool: s("tool"),
                    action: s("action"),
                    resource: s("resource"),
                    risk_score: obj
                        .and_then(|m| m.get("risk_score"))
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0),
                    reason: s("reason"),
                    run_id: s("run_id"),
                    trace_id: s("trace_id"),
                    matched_policies: obj
                        .and_then(|m| m.get("matched_policies"))
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default(),
                    similarity_score: obj
                        .and_then(|m| m.get("similarity_score"))
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.0),
                }
            })
            .collect();

        Ok(Response::new(SemanticSearchResponse { results }))
    }

    // #1627: alerting settings gRPC (thin storage adapters)
    async fn list_contact_points(
        &self,
        request: Request<ListContactPointsRequest>,
    ) -> Result<Response<ListContactPointsResponse>, Status> {
        let req = request.into_inner();
        let limit = if req.limit <= 0 { 50 } else { req.limit };
        let cursor = req
            .cursor
            .parse::<i64>()
            .ok()
            .filter(|_| !req.cursor.is_empty());
        match self
            ._state
            .storage
            .list_contact_points_cursor(&req.tenant_id, limit, 0, cursor)
            .await
        {
            Ok((items, next)) => Ok(Response::new(ListContactPointsResponse {
                items: items.into_iter().map(contact_point_to_proto).collect(),
                next_cursor: next.map(|c| c.to_string()).unwrap_or_default(),
            })),
            Err(e) => Err(Status::internal(format!("Database error: {:?}", e))),
        }
    }

    async fn create_contact_point(
        &self,
        request: Request<CreateContactPointRequest>,
    ) -> Result<Response<CreateContactPointResponse>, Status> {
        let req = request.into_inner();
        if !aegis_soc::alerting::channel_type_is_supported(&req.channel_type) {
            return Err(Status::invalid_argument("unsupported channel_type"));
        }
        if let Err(msg) = aegis_soc::alerting::validate_destination_url(&req.url) {
            return Err(Status::invalid_argument(msg));
        }
        let secret_hash = if req.secret.is_empty() {
            None
        } else {
            Some(crate::routes::authorize_canon::sha256_hex(
                req.secret.as_bytes(),
            ))
        };
        let mut delivery_secret = String::new();
        let mut webhook_id = None;
        if matches!(
            req.channel_type.as_str(),
            aegis_soc::alerting::CHANNEL_WEBHOOK | aegis_soc::alerting::CHANNEL_SLACK
        ) {
            delivery_secret = format!("whsec_{}", Uuid::new_v4().simple());
            let sub = self
                ._state
                .storage
                .insert_webhook_subscription(
                    &req.tenant_id,
                    &req.url,
                    secret_hash.as_deref(),
                    "*",
                    &delivery_secret,
                    "info",
                    "json",
                )
                .await
                .map_err(|e| Status::internal(format!("Database error: {:?}", e)))?;
            webhook_id = Some(sub.id);
        }
        let cp = self
            ._state
            .storage
            .insert_contact_point(
                &req.tenant_id,
                &req.name,
                &req.channel_type,
                Some(&req.url),
                secret_hash.as_deref(),
                webhook_id.as_deref(),
                &req.settings_json,
                "unknown",
            )
            .await
            .map_err(|e| Status::internal(format!("Database error: {:?}", e)))?;
        Ok(Response::new(CreateContactPointResponse {
            contact_point: Some(contact_point_to_proto(cp)),
            delivery_secret,
        }))
    }

    async fn delete_contact_point(
        &self,
        request: Request<DeleteContactPointRequest>,
    ) -> Result<Response<DeleteContactPointResponse>, Status> {
        let req = request.into_inner();
        if let Ok(Some(cp)) = self
            ._state
            .storage
            .get_contact_point_by_id(&req.tenant_id, &req.id)
            .await
        {
            if let Some(sub_id) = cp.webhook_subscription_id.as_deref() {
                let _ = self
                    ._state
                    .storage
                    .delete_webhook_subscription(&req.tenant_id, sub_id)
                    .await;
            }
        }
        match self
            ._state
            .storage
            .delete_contact_point(&req.tenant_id, &req.id)
            .await
        {
            Ok(success) => Ok(Response::new(DeleteContactPointResponse { success })),
            Err(e) => Err(Status::internal(format!("Database error: {:?}", e))),
        }
    }

    async fn list_notification_policies(
        &self,
        request: Request<ListNotificationPoliciesRequest>,
    ) -> Result<Response<ListNotificationPoliciesResponse>, Status> {
        let req = request.into_inner();
        let limit = if req.limit <= 0 { 50 } else { req.limit };
        let cursor = req
            .cursor
            .parse::<i64>()
            .ok()
            .filter(|_| !req.cursor.is_empty());
        match self
            ._state
            .storage
            .list_notification_policies_cursor(&req.tenant_id, limit, 0, cursor)
            .await
        {
            Ok((items, next)) => Ok(Response::new(ListNotificationPoliciesResponse {
                items: items
                    .into_iter()
                    .map(notification_policy_to_proto)
                    .collect(),
                next_cursor: next.map(|c| c.to_string()).unwrap_or_default(),
            })),
            Err(e) => Err(Status::internal(format!("Database error: {:?}", e))),
        }
    }

    async fn create_notification_policy(
        &self,
        request: Request<CreateNotificationPolicyRequest>,
    ) -> Result<Response<CreateNotificationPolicyResponse>, Status> {
        let req = request.into_inner();
        let policy = self
            ._state
            .storage
            .insert_notification_policy(
                &req.tenant_id,
                &req.name,
                req.enabled,
                &req.matchers_json,
                &req.contact_point_ids_json,
                if req.group_by.is_empty() {
                    None
                } else {
                    Some(req.group_by.as_str())
                },
                if req.repeat_interval_secs <= 0 {
                    None
                } else {
                    Some(req.repeat_interval_secs)
                },
            )
            .await
            .map_err(|e| Status::internal(format!("Database error: {:?}", e)))?;
        Ok(Response::new(CreateNotificationPolicyResponse {
            policy: Some(notification_policy_to_proto(policy)),
        }))
    }

    async fn delete_notification_policy(
        &self,
        request: Request<DeleteNotificationPolicyRequest>,
    ) -> Result<Response<DeleteNotificationPolicyResponse>, Status> {
        let req = request.into_inner();
        match self
            ._state
            .storage
            .delete_notification_policy(&req.tenant_id, &req.id)
            .await
        {
            Ok(success) => Ok(Response::new(DeleteNotificationPolicyResponse { success })),
            Err(e) => Err(Status::internal(format!("Database error: {:?}", e))),
        }
    }

    async fn list_silences(
        &self,
        request: Request<ListSilencesRequest>,
    ) -> Result<Response<ListSilencesResponse>, Status> {
        let req = request.into_inner();
        let limit = if req.limit <= 0 { 50 } else { req.limit };
        let cursor = req
            .cursor
            .parse::<i64>()
            .ok()
            .filter(|_| !req.cursor.is_empty());
        match self
            ._state
            .storage
            .list_alert_silences_cursor(&req.tenant_id, limit, 0, cursor)
            .await
        {
            Ok((items, next)) => Ok(Response::new(ListSilencesResponse {
                items: items.into_iter().map(silence_to_proto).collect(),
                next_cursor: next.map(|c| c.to_string()).unwrap_or_default(),
            })),
            Err(e) => Err(Status::internal(format!("Database error: {:?}", e))),
        }
    }

    async fn create_silence(
        &self,
        request: Request<CreateSilenceRequest>,
    ) -> Result<Response<CreateSilenceResponse>, Status> {
        let req = request.into_inner();
        let starts_at = if req.starts_at.is_empty() {
            chrono::Utc::now()
        } else {
            chrono::DateTime::parse_from_rfc3339(&req.starts_at)
                .map_err(|_| Status::invalid_argument("invalid starts_at"))?
                .with_timezone(&chrono::Utc)
        };
        let ends_at = chrono::DateTime::parse_from_rfc3339(&req.ends_at)
            .map_err(|_| Status::invalid_argument("invalid ends_at"))?
            .with_timezone(&chrono::Utc);
        if ends_at <= starts_at {
            return Err(Status::invalid_argument("ends_at must be after starts_at"));
        }
        let silence = self
            ._state
            .storage
            .insert_alert_silence(
                &req.tenant_id,
                if req.rule_key.is_empty() {
                    None
                } else {
                    Some(req.rule_key.as_str())
                },
                if req.agent_id.is_empty() {
                    None
                } else {
                    Some(req.agent_id.as_str())
                },
                if req.comment.is_empty() {
                    None
                } else {
                    Some(req.comment.as_str())
                },
                starts_at,
                ends_at,
                if req.created_by.is_empty() {
                    None
                } else {
                    Some(req.created_by.as_str())
                },
            )
            .await
            .map_err(|e| Status::internal(format!("Database error: {:?}", e)))?;
        Ok(Response::new(CreateSilenceResponse {
            silence: Some(silence_to_proto(silence)),
        }))
    }

    async fn delete_silence(
        &self,
        request: Request<DeleteSilenceRequest>,
    ) -> Result<Response<DeleteSilenceResponse>, Status> {
        let req = request.into_inner();
        match self
            ._state
            .storage
            .delete_alert_silence(&req.tenant_id, &req.id)
            .await
        {
            Ok(success) => Ok(Response::new(DeleteSilenceResponse { success })),
            Err(e) => Err(Status::internal(format!("Database error: {:?}", e))),
        }
    }

    // #1634: dashboard editor gRPC (thin storage adapters)
    async fn list_soc_dashboards(
        &self,
        request: Request<ListSocDashboardsRequest>,
    ) -> Result<Response<ListSocDashboardsResponse>, Status> {
        let req = request.into_inner();
        match self
            ._state
            .storage
            .list_soc_dashboards(&req.tenant_id)
            .await
        {
            Ok(items) => Ok(Response::new(ListSocDashboardsResponse {
                items: items.into_iter().map(soc_dashboard_to_proto).collect(),
            })),
            Err(e) => Err(Status::internal(format!("Database error: {:?}", e))),
        }
    }

    async fn get_soc_dashboard(
        &self,
        request: Request<GetSocDashboardRequest>,
    ) -> Result<Response<GetSocDashboardResponse>, Status> {
        let req = request.into_inner();
        match self
            ._state
            .storage
            .get_soc_dashboard_by_uid(&req.tenant_id, &req.uid)
            .await
        {
            Ok(Some(record)) => Ok(Response::new(GetSocDashboardResponse {
                dashboard: Some(soc_dashboard_to_proto(record)),
            })),
            Ok(None) => Err(Status::not_found("Dashboard not found")),
            Err(e) => Err(Status::internal(format!("Database error: {:?}", e))),
        }
    }

    async fn create_soc_dashboard(
        &self,
        request: Request<CreateSocDashboardRequest>,
    ) -> Result<Response<CreateSocDashboardResponse>, Status> {
        let req = request.into_inner();
        let schema =
            aegis_api::dashboard_schema::parse_and_validate_dashboard_json(&req.schema_json)
                .map_err(Status::invalid_argument)?;
        if let Ok(Some(_)) = self
            ._state
            .storage
            .get_soc_dashboard_by_uid(&req.tenant_id, &schema.uid)
            .await
        {
            return Err(Status::already_exists(format!(
                "Dashboard uid '{}' already exists",
                schema.uid
            )));
        }
        let schema_json = serde_json::to_string(&schema)
            .map_err(|e| Status::internal(format!("serialize dashboard: {e}")))?;
        let record = self
            ._state
            .storage
            .insert_soc_dashboard(
                &req.tenant_id,
                &schema.uid,
                &schema.title,
                i64::from(schema.schema_version),
                &schema_json,
            )
            .await
            .map_err(|e| Status::internal(format!("Database error: {:?}", e)))?;
        Ok(Response::new(CreateSocDashboardResponse {
            dashboard: Some(soc_dashboard_to_proto(record)),
        }))
    }

    async fn update_soc_dashboard(
        &self,
        request: Request<UpdateSocDashboardRequest>,
    ) -> Result<Response<UpdateSocDashboardResponse>, Status> {
        let req = request.into_inner();
        let schema =
            aegis_api::dashboard_schema::parse_and_validate_dashboard_json(&req.schema_json)
                .map_err(Status::invalid_argument)?;
        if schema.uid != req.uid {
            return Err(Status::invalid_argument(
                "uid in schema_json must match request uid",
            ));
        }
        let schema_json = serde_json::to_string(&schema)
            .map_err(|e| Status::internal(format!("serialize dashboard: {e}")))?;
        match self
            ._state
            .storage
            .update_soc_dashboard(
                &req.tenant_id,
                &req.uid,
                &schema.title,
                i64::from(schema.schema_version),
                &schema_json,
            )
            .await
        {
            Ok(Some(record)) => Ok(Response::new(UpdateSocDashboardResponse {
                dashboard: Some(soc_dashboard_to_proto(record)),
            })),
            Ok(None) => Err(Status::not_found("Dashboard not found")),
            Err(e) => Err(Status::internal(format!("Database error: {:?}", e))),
        }
    }

    async fn delete_soc_dashboard(
        &self,
        request: Request<DeleteSocDashboardRequest>,
    ) -> Result<Response<DeleteSocDashboardResponse>, Status> {
        let req = request.into_inner();
        match self
            ._state
            .storage
            .delete_soc_dashboard(&req.tenant_id, &req.uid)
            .await
        {
            Ok(success) => Ok(Response::new(DeleteSocDashboardResponse { success })),
            Err(e) => Err(Status::internal(format!("Database error: {:?}", e))),
        }
    }
}

fn contact_point_to_proto(cp: aegis_api::models::ContactPointRecord) -> ContactPointItem {
    ContactPointItem {
        id: cp.id,
        tenant_id: cp.tenant_id,
        name: cp.name,
        channel_type: cp.channel_type,
        url: cp.url.unwrap_or_default(),
        webhook_subscription_id: cp.webhook_subscription_id.unwrap_or_default(),
        settings_json: cp.settings_json,
        health_status: cp.health_status,
        created_at: cp.created_at.to_rfc3339(),
        updated_at: cp.updated_at.to_rfc3339(),
    }
}

fn notification_policy_to_proto(
    p: aegis_api::models::NotificationPolicyRecord,
) -> NotificationPolicyItem {
    NotificationPolicyItem {
        id: p.id,
        tenant_id: p.tenant_id,
        name: p.name,
        enabled: p.enabled,
        matchers_json: p.matchers_json,
        contact_point_ids_json: p.contact_point_ids_json,
        group_by: p.group_by.unwrap_or_default(),
        repeat_interval_secs: p.repeat_interval_secs.unwrap_or(0),
        created_at: p.created_at.to_rfc3339(),
        updated_at: p.updated_at.to_rfc3339(),
    }
}

fn soc_dashboard_to_proto(d: aegis_api::models::SocDashboardRecord) -> SocDashboardItem {
    SocDashboardItem {
        id: d.id,
        tenant_id: d.tenant_id,
        uid: d.uid,
        title: d.title,
        schema_version: d.schema_version,
        schema_json: d.schema_json,
        created_at: d.created_at.to_rfc3339(),
        updated_at: d.updated_at.to_rfc3339(),
    }
}

fn silence_to_proto(s: aegis_api::models::AlertSilenceRecord) -> SilenceItem {
    SilenceItem {
        id: s.id,
        tenant_id: s.tenant_id,
        rule_key: s.rule_key.unwrap_or_default(),
        agent_id: s.agent_id.unwrap_or_default(),
        comment: s.comment.unwrap_or_default(),
        starts_at: s.starts_at.to_rfc3339(),
        ends_at: s.ends_at.to_rfc3339(),
        created_by: s.created_by.unwrap_or_default(),
        status: s.status,
        created_at: s.created_at.to_rfc3339(),
    }
}

pub async fn start_grpc_server(
    state: Arc<AppState>,
    addr: std::net::SocketAddr,
) -> Result<(), tonic::transport::Error> {
    let aegis_service = AegisServiceServer::new(AegisGrpcServiceImpl::new(state.clone()));
    let admin_service = AdminServiceServer::new(AdminGrpcServiceImpl::new(state.clone()));
    let soc_service = SocServiceServer::new(SocGrpcServiceImpl::new(state.clone()));

    tracing::info!("gRPC server listening on {}", addr);

    tonic::transport::Server::builder()
        .add_service(aegis_service)
        .add_service(admin_service)
        .add_service(soc_service)
        .serve(addr)
        .await
}
