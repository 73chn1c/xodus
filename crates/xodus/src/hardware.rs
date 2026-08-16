// Hardware probing utilities

use std::io;

use base64::prelude::*;
#[cfg(any(target_os = "macos", target_os = "ios", target_family = "windows"))]
use smbioslib::raw_smbios_from_device;
#[cfg(not(target_os = "linux"))]
use smbioslib::{SMBiosSystemInformation, SystemUuidData, table_load_from_device};

use crate::clep;
use crate::models::devicecredential::Component;

/// The SMBIOS Type 1 fields sent during provisioning, each independently
/// optional: firmware is free to omit any of them (a string index of 0 means
/// "not specified"), and a structure predating SMBIOS 2.1 has no UUID field at
/// all. A field that could not be read is reported as `Component::error`
/// rather than aborting the whole probe.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct SmbiosFields {
    pub version: Option<Vec<u8>>,
    pub serial: Option<Vec<u8>>,
    pub uuid: Option<[u8; 16]>,
}

fn push_field(components: &mut Vec<Component>, id: u32, value: Option<impl AsRef<[u8]>>) {
    match value {
        Some(value) => components.push(Component::new(id, BASE64_STANDARD.encode(value))),
        None => components.push(Component::error(id)),
    }
}

pub fn probe_provision_components() -> Vec<Component> {
    let mut components = Vec::with_capacity(16);
    let drive_serial = BASE64_STANDARD.decode("AA==").unwrap();
    let mut smbios_buf = [0; 256];
    let mut drive_buf = [0; 64];

    let smbios = load_raw_smbios().ok();
    let parsed_smbios = load_smbios_fields(smbios.as_deref());

    drive_buf
        .iter_mut()
        .zip(drive_serial.iter())
        .for_each(|(place, data)| *place = *data);
    if let Some(smbios) = smbios.as_ref() {
        smbios_buf
            .iter_mut()
            .zip(smbios.iter())
            .for_each(|(place, data)| *place = *data);
    }
    let (clepv2, clepv4) = clep::challenge::get_license_challange(smbios_buf, drive_buf);

    components.push(Component::new(4113, "AA==".to_string()));
    components.push(Component::error(4101));
    components.push(Component::new(8196, BASE64_STANDARD.encode(clepv2)));
    components.push(Component::new(8197, BASE64_STANDARD.encode(clepv4)));

    push_field(&mut components, 4100, parsed_smbios.version);
    push_field(&mut components, 4101, parsed_smbios.serial);
    push_field(&mut components, 4102, parsed_smbios.uuid);

    components.push(Component::new(4145, "AQAAAA==".to_string()));
    components.push(Component::error(4160));
    components.push(Component::error(4161));

    // Common values sent with the request
    // "4128"
    // "4130"
    // "4112"
    // "4113"
    // "4098"
    // "4099"
    // "4100"
    // "4101"
    // "4102"
    // "4097"
    // "8195"
    // "8196"
    // "8197"
    // "4144"
    // "4145"
    // "4160"
    // "4161"

    components
}

#[cfg(target_os = "linux")]
fn load_smbios_fields(raw: Option<&[u8]>) -> SmbiosFields {
    let mut fields = raw.map(parse_smbios).unwrap_or_default();

    if fields.version.is_none() {
        if let Ok(v) = std::fs::read_to_string("/sys/class/dmi/id/product_version") {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                fields.version = Some(trimmed.as_bytes().to_vec());
            }
        }
    }
    if fields.serial.is_none() {
        if let Ok(s) = std::fs::read_to_string("/sys/class/dmi/id/product_serial") {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                fields.serial = Some(trimmed.as_bytes().to_vec());
            }
        }
    }
    if fields.uuid.is_none() {
        if let Ok(u_str) = std::fs::read_to_string("/sys/class/dmi/id/product_uuid") {
            if let Some(parsed) = parse_uuid_string(u_str.trim()) {
                fields.uuid = Some(parsed);
            }
        }
        if fields.uuid.is_none() {
            if let Ok(mid) = std::fs::read_to_string("/etc/machine-id") {
                if let Some(parsed) = parse_hex_16(mid.trim()) {
                    fields.uuid = Some(parsed);
                }
            }
        }
    }

    fields
}

#[cfg(target_os = "linux")]
fn parse_uuid_string(s: &str) -> Option<[u8; 16]> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    parse_hex_16(&hex)
}

#[cfg(target_os = "linux")]
fn parse_hex_16(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(not(target_os = "linux"))]
fn load_smbios_fields(_raw: Option<&[u8]>) -> SmbiosFields {
    let Ok(data) = table_load_from_device() else {
        return SmbiosFields::default();
    };
    let Some(system_info) = data.first::<SMBiosSystemInformation>() else {
        return SmbiosFields::default();
    };

    SmbiosFields {
        version: system_info
            .version()
            .to_utf8_lossy()
            .map(String::into_bytes),
        serial: system_info
            .serial_number()
            .to_utf8_lossy()
            .map(String::into_bytes),
        uuid: match system_info.uuid() {
            Some(SystemUuidData::Uuid(uuid)) => Some(uuid.raw),
            _ => None,
        },
    }
}

/// Parses an SMBIOS Type 1 (System Information) structure.
///
/// Every field is read defensively: the blob comes from firmware (by way of
/// `pkexec cat`, which can succeed and return nothing), so a short, truncated
/// or simply older structure must degrade to `Component::error` rather than
/// take the process down.
#[cfg(target_os = "linux")]
fn parse_smbios(smbios: &[u8]) -> SmbiosFields {
    /// Offsets within the formatted section, per the SMBIOS spec.
    const LENGTH_OFFSET: usize = 1;
    const VERSION_INDEX_OFFSET: usize = 6;
    const SERIAL_INDEX_OFFSET: usize = 7;
    const UUID_OFFSET: usize = 8;
    const UUID_LEN: usize = 16;

    let (Some(&formatted_len), Some(&version_index), Some(&serial_index)) = (
        smbios.get(LENGTH_OFFSET),
        smbios.get(VERSION_INDEX_OFFSET),
        smbios.get(SERIAL_INDEX_OFFSET),
    ) else {
        // Shorter than the SMBIOS 2.0 formatted section - nothing to read.
        return SmbiosFields::default();
    };

    // The UUID only exists from SMBIOS 2.1 on; a 2.0 structure stops at 8
    // bytes, so anything at this offset would belong to the next field or to
    // the string set.
    let uuid = smbios
        .get(UUID_OFFSET..UUID_OFFSET + UUID_LEN)
        .filter(|_| usize::from(formatted_len) >= UUID_OFFSET + UUID_LEN)
        .and_then(|bytes| <[u8; UUID_LEN]>::try_from(bytes).ok());

    // `formatted_len` is firmware-supplied and may point past the blob.
    let strings = smbios
        .get(usize::from(formatted_len)..)
        .map(parse_smbios_strings)
        .unwrap_or_default();

    SmbiosFields {
        version: smbios_string(&strings, version_index),
        serial: smbios_string(&strings, serial_index),
        uuid,
    }
}

/// The unformatted section is a run of NUL-terminated strings, terminated by
/// an empty one (i.e. a double NUL).
#[cfg(target_os = "linux")]
fn parse_smbios_strings(buf: &[u8]) -> Vec<&[u8]> {
    let mut strings = Vec::new();
    let mut cursor = 0;

    while cursor < buf.len() {
        let end = buf[cursor..]
            .iter()
            .position(|&b| b == 0)
            .map_or(buf.len(), |offset| cursor + offset);

        if end == cursor {
            // Empty string: end of the string set.
            break;
        }

        strings.push(&buf[cursor..end]);
        cursor = end + 1;
    }

    strings
}

/// String references are 1-based; index 0 means "not specified", which is
/// reported as a field error rather than as an empty value.
#[cfg(target_os = "linux")]
fn smbios_string(strings: &[&[u8]], index: u8) -> Option<Vec<u8>> {
    let index = usize::from(index).checked_sub(1)?;
    strings.get(index).map(|string| string.to_vec())
}

#[cfg(any(target_os = "macos", target_os = "ios", target_family = "windows"))]
fn load_raw_smbios() -> io::Result<Vec<u8>> {
    raw_smbios_from_device()
}

#[cfg(target_os = "linux")]
fn load_raw_smbios() -> io::Result<Vec<u8>> {
    // Read directly if accessible; never invoke pkexec/sudo to prevent popups or blocking
    std::fs::read("/sys/firmware/dmi/entries/1-0/raw")
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "ios",
    target_family = "windows"
)))]
fn load_raw_smbios() -> io::Result<Vec<u8>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "raw SMBIOS loading is unsupported on this platform",
    ))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::{SmbiosFields, parse_smbios};

    /// A well-formed SMBIOS 2.4 Type 1 structure: manufacturer=1, product=2,
    /// version=3, serial=4, a 16-byte UUID, wake-up type, sku=5, family=6.
    fn type1(version_index: u8, serial_index: u8) -> Vec<u8> {
        let mut structure = vec![
            0x01,
            0x1b,
            0x01,
            0x00,
            0x01,
            0x02,
            version_index,
            serial_index,
        ];
        structure.extend_from_slice(&[0xAA; 16]);
        structure.extend_from_slice(&[0x06, 0x05, 0x06]);
        for string in ["ACME", "Box", "1.0", "SN123", "SKU", "FAM"] {
            structure.extend_from_slice(string.as_bytes());
            structure.push(0);
        }
        structure.push(0);
        structure
    }

    #[test]
    fn reads_all_three_fields_from_a_well_formed_structure() {
        assert_eq!(
            parse_smbios(&type1(3, 4)),
            SmbiosFields {
                version: Some(b"1.0".to_vec()),
                serial: Some(b"SN123".to_vec()),
                uuid: Some([0xAA; 16]),
            }
        );
    }

    #[test]
    fn an_empty_blob_yields_no_fields() {
        assert_eq!(parse_smbios(&[]), SmbiosFields::default());
    }

    #[test]
    fn a_blob_shorter_than_the_formatted_section_yields_no_fields() {
        assert_eq!(parse_smbios(&[0x01, 0x1b, 0x01]), SmbiosFields::default());
    }

    #[test]
    fn smbios_2_0_has_no_uuid_but_still_has_strings() {
        // Type 1 was 8 bytes before SMBIOS 2.1 - the UUID field did not exist.
        let mut structure = vec![0x01, 0x08, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04];
        structure.extend_from_slice(b"ACME\0Box\01.0\0SN123\0\0");

        let fields = parse_smbios(&structure);
        assert_eq!(fields.version.as_deref(), Some(&b"1.0"[..]));
        assert_eq!(fields.serial.as_deref(), Some(&b"SN123"[..]));
        assert_eq!(fields.uuid, None, "a 2.0 structure has no UUID to report");
    }

    #[test]
    fn a_length_field_past_the_end_of_the_blob_yields_no_strings() {
        let mut structure = type1(3, 4);
        structure[1] = 0x7f;

        let fields = parse_smbios(&structure);
        assert_eq!(fields.version, None);
        assert_eq!(fields.serial, None);
        // the UUID sits in the formatted section and is still readable
        assert_eq!(fields.uuid, Some([0xAA; 16]));
    }

    #[test]
    fn a_string_index_past_the_string_set_is_a_field_error() {
        let fields = parse_smbios(&type1(7, 4));
        assert_eq!(fields.version, None);
        assert_eq!(fields.serial.as_deref(), Some(&b"SN123"[..]));
    }

    #[test]
    fn string_index_zero_means_not_specified() {
        let fields = parse_smbios(&type1(0, 4));
        assert_eq!(fields.version, None);
        assert_eq!(fields.serial.as_deref(), Some(&b"SN123"[..]));
    }

    #[test]
    fn a_truncated_string_set_still_yields_what_it_can() {
        // No terminating double NUL - the last string runs to the end.
        let mut structure = vec![0x01, 0x1b, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04];
        structure.extend_from_slice(&[0xAA; 16]);
        structure.extend_from_slice(&[0x06, 0x05, 0x06]);
        structure.extend_from_slice(b"ACME\0Box\01.0");

        let fields = parse_smbios(&structure);
        assert_eq!(fields.version.as_deref(), Some(&b"1.0"[..]));
        assert_eq!(fields.serial, None);
    }

    #[test]
    fn parses_valid_uuid_and_hex_strings() {
        use super::{parse_hex_16, parse_uuid_string};
        assert_eq!(
            parse_uuid_string("c3c86121-a1bf-4b2a-b0d7-2ebcb38dc2a8"),
            Some([
                0xc3, 0xc8, 0x61, 0x21, 0xa1, 0xbf, 0x4b, 0x2a, 0xb0, 0xd7, 0x2e, 0xbc, 0xb3,
                0x8d, 0xc2, 0xa8
            ])
        );
        assert_eq!(
            parse_hex_16("0123456789abcdef0123456789abcdef"),
            Some([
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
                0xab, 0xcd, 0xef
            ])
        );
        assert_eq!(parse_hex_16("short"), None);
        assert_eq!(parse_hex_16("invalid-hex-characters-here-!!!!"), None);
    }
}
