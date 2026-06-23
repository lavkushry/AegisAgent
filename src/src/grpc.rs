use crate::routes::AppState;
use aegis_api::grpc::aegis::{
    admin_service_server::{AdminService, AdminServiceServer},
    aegis_service_server::{AegisService, AegisServiceServer},
    soc_service_server::{SocService, SocServiceServer},
    ApproveRequest, ApproveResponse, AuthorizeRequest, AuthorizeResponse, CloseIncidentRequest,
    CloseIncidentResponse, CreateTenantRequest, CreateTenantResponse, DiscoverMcpToolsRequest,
    DiscoverMcpToolsResponse, ListAlertsRequest, ListAlertsResponse, ListIncidentsRequest,
    ListIncidentsResponse, McpToolStatusResponse, RegisterAgentRequest, RegisterAgentResponse,
    RegisterMcpServerRequest, RegisterMcpServerResponse,
    CreatePlaybookRequest, CreatePlaybookResponse, ListPlaybooksRequest, ListPlaybooksResponse,
    DeletePlaybookRequest, DeletePlaybookResponse,
};
use axum::http::HeaderMap;
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
        let mut headers = HeaderMap::new();
        if let Some(auth_val) = request.metadata().get("authorization") {
            if let Ok(val) = axum::http::HeaderValue::from_bytes(auth_val.as_bytes()) {
                headers.insert(axum::http::header::AUTHORIZATION, val);
            }
        }

        let req = request.into_inner();
        if !req.tenant_id.is_empty() {
            if let Ok(val) = axum::http::HeaderValue::from_str(&req.tenant_id) {
                headers.insert("X-Aegis-Tenant-ID", val);
            }
        }

        let rest_req = map_authorize_request(req);
        let body_bytes = serde_json::to_vec(&rest_req).unwrap_or_default();

        let response = crate::routes::authorize_action(
            axum::extract::State(self._state.clone()),
            headers,
            axum::body::Bytes::from(body_bytes),
        )
        .await
        .into_response();

        let status = response.status();
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        if status != axum::http::StatusCode::OK && status != axum::http::StatusCode::CREATED {
            let err_msg = String::from_utf8_lossy(&body_bytes).into_owned();
            return Err(Status::internal(err_msg));
        }

        let res: crate::models::AuthorizeResponse = serde_json::from_slice(&body_bytes)
            .map_err(|e| Status::internal(format!("Failed to parse response JSON: {}", e)))?;

        Ok(Response::new(map_authorize_response(res)))
    }

    async fn register_agent(
        &self,
        request: Request<RegisterAgentRequest>,
    ) -> Result<Response<RegisterAgentResponse>, Status> {
        let mut headers = HeaderMap::new();
        if let Some(auth_val) = request.metadata().get("authorization") {
            if let Ok(val) = axum::http::HeaderValue::from_bytes(auth_val.as_bytes()) {
                headers.insert(axum::http::header::AUTHORIZATION, val);
            }
        }

        let req = request.into_inner();
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

        let response = crate::routes::register_agent(
            axum::extract::State(self._state.clone()),
            crate::routes::TenantId(req.tenant_id),
            axum::Json(rest_req),
        )
        .await
        .into_response();

        let status = response.status();
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        if status != axum::http::StatusCode::OK && status != axum::http::StatusCode::CREATED {
            let err_msg = String::from_utf8_lossy(&body_bytes).into_owned();
            return Err(Status::internal(err_msg));
        }

        let res: crate::models::RegisterAgentResponse = serde_json::from_slice(&body_bytes)
            .map_err(|e| Status::internal(format!("Failed to parse response JSON: {}", e)))?;

        Ok(Response::new(RegisterAgentResponse {
            id: res.id.to_string(),
            agent_key: res.agent_key,
        }))
    }

    async fn approve(
        &self,
        request: Request<ApproveRequest>,
    ) -> Result<Response<ApproveResponse>, Status> {
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

        let response = crate::routes::approve_approval_inner(
            self._state.clone(),
            req.tenant_id,
            approval_uuid,
            payload,
        )
        .await;

        let status = response.status();
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        if status != axum::http::StatusCode::OK {
            let err_msg = String::from_utf8_lossy(&body_bytes).into_owned();
            return Err(Status::internal(err_msg));
        }

        let res: serde_json::Value = serde_json::from_slice(&body_bytes)
            .map_err(|e| Status::internal(format!("Failed to parse response JSON: {}", e)))?;

        let status_str = res["status"].as_str().unwrap_or_default().to_string();
        let approval_id_str = res["approval_id"].as_str().unwrap_or_default().to_string();

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
        let req = request.into_inner();
        let payload = crate::models::CreateTenantRequest {
            id: req.id,
            name: req.name,
            plan: req.plan,
        };

        let response = crate::routes::create_tenant(
            axum::extract::State(self._state.clone()),
            axum::Json(payload),
        )
        .await
        .into_response();

        let status = response.status();
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        if status != axum::http::StatusCode::CREATED {
            let err_msg = String::from_utf8_lossy(&body_bytes).into_owned();
            return Err(Status::internal(err_msg));
        }

        let res: crate::models::TenantRecord = serde_json::from_slice(&body_bytes)
            .map_err(|e| Status::internal(format!("Failed to parse response JSON: {}", e)))?;

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
        let req = request.into_inner();
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
        };

        let response = crate::routes::register_mcp_server(
            axum::extract::State(self._state.clone()),
            crate::routes::TenantId(req.tenant_id),
            axum::Json(payload),
        )
        .await
        .into_response();

        let status = response.status();
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        if status != axum::http::StatusCode::CREATED {
            let err_msg = String::from_utf8_lossy(&body_bytes).into_owned();
            return Err(Status::internal(err_msg));
        }

        let res: crate::models::RegisterMcpServerResponse = serde_json::from_slice(&body_bytes)
            .map_err(|e| Status::internal(format!("Failed to parse response JSON: {}", e)))?;

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
        let req = request.into_inner();
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
        };

        let response = crate::routes::discover_mcp_tools(
            axum::extract::State(self._state.clone()),
            crate::routes::TenantId(req.tenant_id),
            axum::extract::Path(req.server_key),
            axum::Json(payload),
        )
        .await
        .into_response();

        let status = response.status();
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        if status != axum::http::StatusCode::OK {
            let err_msg = String::from_utf8_lossy(&body_bytes).into_owned();
            return Err(Status::internal(err_msg));
        }

        let json_val: serde_json::Value = serde_json::from_slice(&body_bytes)
            .map_err(|e| Status::internal(format!("Failed to parse response JSON: {}", e)))?;

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

        let response = crate::routes::close_incident(
            axum::extract::State(self._state.clone()),
            crate::routes::TenantId(req.tenant_id),
            axum::extract::Path(req.incident_id.clone()),
        )
        .await
        .into_response();

        let status = response.status();
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        if status != axum::http::StatusCode::OK {
            let err_msg = String::from_utf8_lossy(&body_bytes).into_owned();
            return Err(Status::internal(err_msg));
        }

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
        let steps: Vec<aegis_soc::playbook::PlaybookStep> = serde_json::from_str(&req.steps_json)
            .map_err(|e| Status::invalid_argument(format!("Invalid steps_json: {e}")))?;

        let trigger_sev = aegis_soc::playbook::TriggerSeverity::List(req.trigger_severity.clone());
        let trigger_agent_id = if req.trigger_agent_id.is_empty() { None } else { Some(req.trigger_agent_id.as_str()) };
        let trigger_env = if req.trigger_environment.is_empty() { None } else { Some(req.trigger_environment.as_str()) };

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

        playbook.validate()
            .map_err(|e| Status::invalid_argument(format!("Playbook validation failed: {e}")))?;

        match self._state.storage.insert_playbook(
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
            Ok(pb) => {
                Ok(Response::new(CreatePlaybookResponse {
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
                }))
            }
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
                        let trigger_severity: Vec<String> = serde_json::from_str(&pb.trigger_severity)
                            .unwrap_or_default();
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
        match self._state.storage.delete_playbook(&req.tenant_id, &req.id).await {
            Ok(success) => {
                Ok(Response::new(DeletePlaybookResponse { success }))
            }
            Err(e) => Err(Status::internal(format!("Database error: {:?}", e))),
        }
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
