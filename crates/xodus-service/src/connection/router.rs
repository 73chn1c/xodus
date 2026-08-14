use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio_util::sync::CancellationToken;
use xodus::models::secrets::LegacyToken;
use xodus::tokens::TokenManager;

use crate::simple_context::SimpleContext;

pub async fn route(
    socket: tokio::net::UnixStream,
    token: CancellationToken,
    device_token: LegacyToken,
    tokens: Arc<TokenManager>,
) {
    let cred = socket.peer_cred().ok().and_then(|cred| cred.pid());
    log::debug!("Connection from pid {cred:?}");
    route_generic(socket, token, device_token, tokens).await
}

/// TCP variant of [`route`] - same protocol, no peer-credential logging
/// (TCP has no equivalent of SO_PEERCRED). Only ever bound to
/// 127.0.0.1/::1 (see main.rs) - this is a same-machine-only bridge for
/// clients (like a wine-side native-process-exec shim) that can't reach a
/// Unix domain socket, not a network-facing service.
pub async fn route_tcp(
    socket: tokio::net::TcpStream,
    token: CancellationToken,
    device_token: LegacyToken,
    tokens: Arc<TokenManager>,
) {
    log::debug!("TCP connection from {:?}", socket.peer_addr());
    route_generic(socket, token, device_token, tokens).await
}

async fn route_generic<S: AsyncRead + AsyncWrite + Unpin>(
    mut socket: S,
    token: CancellationToken,
    device_token: LegacyToken,
    tokens: Arc<TokenManager>,
) {
    let mut context = SimpleContext::new(device_token, tokens);
    loop {
        let mut read_magic = [0; 4];
        if token.is_cancelled() {
            return;
        }
        let read = socket.read_exact(&mut read_magic).await;
        if let Err(err) = read {
            log::error!("Failed to read magic: {err:?}");
            return;
        }

        let magic = u32::from_le_bytes(read_magic);
        let res = match magic {
            crate::XML_MAGIC => super::xml::handle(&mut socket, &mut context).await,
            crate::PROTO_MAGIC => super::proto::handle(&mut socket, &mut context).await,
            _ => {
                log::error!("Unknown magic");
                return;
            }
        };

        if let Err(err) = res {
            log::error!("There was an error handling the message: {err}");
        }
    }
}
