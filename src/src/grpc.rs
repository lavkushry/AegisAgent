use crate::routes::AppState;
use aegis_api::grpc::aegis::{
    admin_service_server::{AdminService, AdminServiceServer},
    aegis_service_server::{AegisService, AegisServiceServer},
    soc_service_server::{SocService, SocServiceServer},
    ApproveRequest, ApproveResponse, AuthorizeRequest, AuthorizeResponse, CloseIncidentRequest,
    CloseIncidentResponse, CreateTenantRequest, CreateTenantResponse, DiscoverMcpToolsRequest,
    DiscoverMcpToolsResponse, ListAlertsRequest, ListAlertsResponse, ListIncidentsRequest,
    ListIncidentsResponse, RegisterAgentRequest, RegisterAgentResponse, RegisterMcpServerRequest,
    RegisterMcpServerResponse,
};
use std::sync::Arc;
use tonic::{Request, Response, Status};

pub struct AegisGrpcServiceImpl {
    _state: Arc<AppState>,
}

impl AegisGrpcServiceImpl {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { _state: state }
    }
}

#[tonic::async_trait]
impl AegisService for AegisGrpcServiceImpl {
    async fn authorize(
        &self,
        _request: Request<AuthorizeRequest>,
    ) -> Result<Response<AuthorizeResponse>, Status> {
        Err(Status::unimplemented("AegisService::Authorize is stubbed"))
    }

    async fn register_agent(
        &self,
        _request: Request<RegisterAgentRequest>,
    ) -> Result<Response<RegisterAgentResponse>, Status> {
        Err(Status::unimplemented(
            "AegisService::RegisterAgent is stubbed",
        ))
    }

    async fn approve(
        &self,
        _request: Request<ApproveRequest>,
    ) -> Result<Response<ApproveResponse>, Status> {
        Err(Status::unimplemented("AegisService::Approve is stubbed"))
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
        _request: Request<CreateTenantRequest>,
    ) -> Result<Response<CreateTenantResponse>, Status> {
        Err(Status::unimplemented(
            "AdminService::CreateTenant is stubbed",
        ))
    }

    async fn register_mcp_server(
        &self,
        _request: Request<RegisterMcpServerRequest>,
    ) -> Result<Response<RegisterMcpServerResponse>, Status> {
        Err(Status::unimplemented(
            "AdminService::RegisterMcpServer is stubbed",
        ))
    }

    async fn discover_mcp_tools(
        &self,
        _request: Request<DiscoverMcpToolsRequest>,
    ) -> Result<Response<DiscoverMcpToolsResponse>, Status> {
        Err(Status::unimplemented(
            "AdminService::DiscoverMcpTools is stubbed",
        ))
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
        _request: Request<ListAlertsRequest>,
    ) -> Result<Response<ListAlertsResponse>, Status> {
        Err(Status::unimplemented("SocService::ListAlerts is stubbed"))
    }

    async fn list_incidents(
        &self,
        _request: Request<ListIncidentsRequest>,
    ) -> Result<Response<ListIncidentsResponse>, Status> {
        Err(Status::unimplemented(
            "SocService::ListIncidents is stubbed",
        ))
    }

    async fn close_incident(
        &self,
        _request: Request<CloseIncidentRequest>,
    ) -> Result<Response<CloseIncidentResponse>, Status> {
        Err(Status::unimplemented(
            "SocService::CloseIncident is stubbed",
        ))
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
