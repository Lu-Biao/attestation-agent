// SPDX-License-Identifier: Apache-2.0
//

use attestation_agent::AttestationAPIs;
use log::*;
use std::sync::Arc;

use crate::rpc::AGENT_NAME;

#[derive(Debug, Default)]
pub struct GetToken {}

#[cfg(feature = "grpc")]
pub mod grpc {
    use super::*;
    use crate::grpc::ASYNC_ATTESTATION_AGENT;
    use anyhow::*;
    use get_token::get_token_service_server::{GetTokenService, GetTokenServiceServer};
    use get_token::{GetTokenRequest, GetTokenResponse};
    use std::net::SocketAddr;
    use tonic::{transport::Server, Request, Response, Status};

    mod get_token {
        tonic::include_proto!("gettoken");
    }

    pub async fn do_get_token(kbc_name : &str, kbs_uri: &str)-> Result<String> {
            let attestation_agent_mutex_clone = Arc::clone(&ASYNC_ATTESTATION_AGENT);
            let mut attestation_agent = attestation_agent_mutex_clone.lock().await;

            debug!("Call AA-KBC to download token ...");

            let target_token = attestation_agent
                .attestation(kbc_name, kbs_uri)
                .await
                .map_err(|e| {
                    error!("Call AA-KBC to get token failed: {}", e);
                    Status::internal(format!(
                        "[ERROR:{}] AA-KBC get token failed: {}",
                        AGENT_NAME, e
                    ))
                })?;

            debug!("Get token from AS successfully!");

            Ok(target_token)
    }

    #[tonic::async_trait]
    impl GetTokenService for GetToken {
        async fn get_token(
            &self,
            request: Request<GetTokenRequest>,
        ) -> Result<Response<GetTokenResponse>, Status> {
            let request = request.into_inner();

            let target_token = do_get_token(&request.kbc_name, &request.kbs_uri).await.unwrap();

            let reply = GetTokenResponse {
                token: target_token,
            };

            Result::Ok(Response::new(reply))
        }
    }

    pub async fn start_grpc_service(socket: SocketAddr) -> Result<()> {
        let service = GetToken::default();
        let _server = Server::builder()
            .add_service(GetTokenServiceServer::new(service))
            .serve(socket)
            .await?;
        Ok(())
    }
}
