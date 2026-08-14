use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::process::ExitCode;
use std::sync::Arc;

use tokio::net::{TcpListener, UnixListener};
use tokio_util::sync::CancellationToken;
use xodus::tokens::TokenManager;

/// Loopback-only TCP mirror of the Unix socket, for clients that can't
/// reach an AF_UNIX socket at all (this fork's Wine build's CreateProcessW
/// doesn't reliably launch native Unix helper processes, and its ws2_32
/// doesn't implement AF_UNIX - so a wine-side XODUS_IPC_PROXY client
/// connects here over ordinary TCP/winsock instead). Bound to
/// 127.0.0.1 only - never exposed off this machine.
const TCP_BRIDGE_PORT: u16 = 47810;

mod connection;
mod simple_context;
mod utils;

const XML_MAGIC: u32 = 0x58445358;
const PROTO_MAGIC: u32 = 0x58445350;

#[tokio::main]
async fn main() -> ExitCode {
    xodus::secrets::init_secrets().expect("Failed to init keychain");
    let tokens = Arc::new(TokenManager::with_keychain_and_memory());
    if let Err(err) =
        xodus::tokens::device::ensure_device_credentials(&reqwest::Client::new(), &tokens).await
    {
        eprintln!("Failed to set up device credentials: {err}");
        return ExitCode::FAILURE;
    }
    let xodus::models::secrets::Token::Legacy(device_token) =
        tokens.get_device_sts_token().unwrap()
    else {
        panic!("Device token isnt legacy")
    };

    env_logger::init_from_env("XODUS_LOG");
    let runtime_dir = utils::get_runtime_dir();
    let cancellation = CancellationToken::new();
    let socket_path = format!("{runtime_dir}/xodus.sock");
    let trigger = cancellation.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("Failure to handle ctrl_c");
        trigger.cancel();
    });
    {
        let tcp_listener = TcpListener::bind(("127.0.0.1", TCP_BRIDGE_PORT)).await.ok();
        if tcp_listener.is_none() {
            log::warn!(
                "Could not bind TCP bridge on 127.0.0.1:{TCP_BRIDGE_PORT} (already running elsewhere?) - continuing with the Unix socket only."
            );
        }
        let tcp_cancellation = cancellation.clone();
        let tcp_device_token = device_token.clone();
        let tcp_tokens = tokens.clone();
        let tcp_task = tokio::spawn(async move {
            let Some(tcp_listener) = tcp_listener else {
                return;
            };
            loop {
                let accept = tokio::select! {
                    r = tcp_listener.accept() => r,
                    _ = tcp_cancellation.cancelled() => break,
                };
                let Ok((stream, _addr)) = accept else { break };

                let token = tcp_cancellation.clone();
                let device_token = tcp_device_token.clone();
                let tokens = tcp_tokens.clone();
                tokio::spawn(async move {
                    connection::router::route_tcp(stream, token, device_token, tokens).await
                });
            }
        });

        let listener = UnixListener::bind(&socket_path).expect("Unable to bind to socket");
        let mode = 0o600;
        let perms = Permissions::from_mode(mode);
        _ = tokio::fs::set_permissions(&socket_path, perms).await;
        loop {
            let accept = tokio::select! {
                r = listener.accept() => r,
                _ = cancellation.cancelled() => break,
            }
            .expect("Failed to accept");

            let token = cancellation.clone();
            let device_token = device_token.clone();
            let tokens = tokens.clone();
            tokio::spawn(async move {
                connection::router::route(accept.0, token, device_token, tokens).await
            });
        }
        _ = tcp_task.await;
    }

    _ = tokio::fs::remove_file(socket_path).await;
    ExitCode::SUCCESS
}
