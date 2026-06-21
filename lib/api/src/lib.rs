//! aegis-api library.
pub mod graph;
pub mod models;
pub mod records;

pub mod grpc {
    pub mod aegis {
        tonic::include_proto!("aegis");
    }
}
