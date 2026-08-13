pub mod proto;
pub mod router;
pub mod xml;

use std::io;

pub fn encode_message(magic: u32, msg_type: u16, message_buffer: Vec<u8>) -> io::Result<Vec<u8>> {
    let size = u16::try_from(message_buffer.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "message payload is {} bytes, exceeds the 65535-byte u16 length header",
                message_buffer.len()
            ),
        )
    })?;
    let mut buffer = Vec::with_capacity(8 + message_buffer.len());
    buffer.extend(magic.to_le_bytes());
    buffer.extend(msg_type.to_le_bytes());
    buffer.extend(size.to_le_bytes());
    buffer.extend(message_buffer);

    Ok(buffer)
}

#[cfg(test)]
mod bughunt_tests {
    use super::encode_message;

    #[test]
    fn payload_larger_than_64kib_is_a_clean_error_not_a_wrong_header() {
        let payload = vec![0x41u8; 70_000];
        let err = encode_message(0x11223344, 2, payload)
            .expect_err(">64KiB payload must be rejected, not silently truncated");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn payload_within_limit_round_trips() {
        let payload = vec![0x41u8; 65_535];
        let framed = encode_message(0x11223344, 2, payload.clone()).expect("must fit");
        let declared = u16::from_le_bytes([framed[6], framed[7]]) as usize;
        assert_eq!(declared, payload.len());
        assert_eq!(framed.len() - 8, payload.len());
    }
}
