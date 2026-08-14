use tokio::io::{AsyncRead, AsyncWrite};

use crate::simple_context::SimpleContext;

pub async fn handle<S: AsyncRead + AsyncWrite + Unpin>(
    _socket: &mut S,
    _context: &mut SimpleContext,
) -> tokio::io::Result<()> {
    unimplemented!("Protobuf path isnt implemented yet");
}
