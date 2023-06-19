// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use super::*;
use std::net::SocketAddr;

const DEFAULT_KEYPROVIDER_ADDR: &str = "127.0.0.1:50000";
const DEFAULT_GETRESOURCE_ADDR: &str = "127.0.0.1:50001";
const DEFAULT_GETTOKEN_ADDR: &str = "0.0.0.0:50002";

lazy_static! {
    pub static ref ASYNC_ATTESTATION_AGENT: Arc<tokio::sync::Mutex<AttestationAgent>> =
        Arc::new(tokio::sync::Mutex::new(AttestationAgent::new()));
}

pub async fn do_attestation() -> Result<()> {
    let token = rpc::gettoken::grpc::do_get_token("cc_kbc", "http://127.0.0.1:8080").await.unwrap();
    log::info!("Attestation result: {}", token);
    Ok(())
}

pub async fn grpc_main() -> Result<()> {
    let app_matches = App::new(rpc::AGENT_NAME)
        .version(env!("CARGO_PKG_VERSION"))
        .about(rpc::ABOUT.as_str())
        .arg(
            Arg::with_name("KeyProvider gRPC socket addr")
                .long("keyprovider_sock")
                .takes_value(true)
                .help("This socket address which the KeyProvider gRPC service will listen to, for example: --keyprovider_sock 127.0.0.1:11223",
                ),
        )
        .arg(
            Arg::with_name("GetResource gRPC socket addr")
                .long("getresource_sock")
                .takes_value(true)
                .help("This socket address which the GetResource gRPC service will listen to, for example: --getresource_sock 127.0.0.1:11223",
                ),
        )
        .arg(
            Arg::with_name("GetToken gRPC socket addr")
                .long("gettoken_sock")
                .takes_value(true)
                .help("This socket address which the GetToken gRPC service will listen to, for example: --gettoken_sock 127.0.0.1:11223",
                ),
        )
        .get_matches();

    let keyprovider_socket = app_matches
        .value_of("KeyProvider gRPC socket addr")
        .unwrap_or(DEFAULT_KEYPROVIDER_ADDR)
        .parse::<SocketAddr>()?;

    let getresource_socket = app_matches
        .value_of("GetResource gRPC socket addr")
        .unwrap_or(DEFAULT_GETRESOURCE_ADDR)
        .parse::<SocketAddr>()?;

    let gettoken_socket = app_matches
        .value_of("GetToken gRPC socket addr")
        .unwrap_or(DEFAULT_GETTOKEN_ADDR)
        .parse::<SocketAddr>()?;

    debug!(
        "KeyProvider gRPC service listening on: {:?}",
        keyprovider_socket
    );
    debug!(
        "GetResource gRPC service listening on: {:?}",
        getresource_socket
    );
    debug!("GetToken gRPC service listening on: {:?}", gettoken_socket);

    let keyprovider_server = rpc::keyprovider::grpc::start_grpc_service(keyprovider_socket);
    let getresource_server = rpc::getresource::grpc::start_grpc_service(getresource_socket);
    let gettoken_server = rpc::gettoken::grpc::start_grpc_service(gettoken_socket);

    do_attestation().await.unwrap();

    tokio::join!(keyprovider_server, getresource_server, gettoken_server).0
}
