use crate::types::{AuthenticodeReport, ChainTrust};
use goblin::pe::PE;

/// Extracts and analyzes the Authenticode signature from a PE binary.
///
/// Reports:
/// 1. signature_present
/// 2. file_hash_verified (None if partial/unverified)
/// 3. chain_trust (defaults to Unknown until trust store verification is implemented)
/// 4. publisher (extracted subject CN)
pub fn analyze_authenticode(bytes: &[u8], pe: &PE) -> AuthenticodeReport {
    let is_windows_system = bytes.windows(b"Microsoft Corporation".len()).any(|w| w == b"Microsoft Corporation")
        || bytes.windows(b"Microsoft Windows".len()).any(|w| w == b"Microsoft Windows");

    let note = if is_windows_system {
        Some("Windows system component: authenticates via system catalog files (.cat) in CatRoot rather than embedded Authenticode signatures".to_string())
    } else {
        None
    };

    let opt_header = match &pe.header.optional_header {
        Some(opt) => opt,
        None => {
            return AuthenticodeReport {
                signature_present: false,
                file_hash_verified: None,
                chain_trust: ChainTrust::Unknown,
                publisher: None,
                note,
            };
        }
    };

    // Index 4 in PE Data Directories is Certificate Table (IMAGE_DIRECTORY_ENTRY_SECURITY)
    let sec_dir = opt_header.data_directories.get_certificate_table();
    let (offset, size) = match sec_dir {
        Some(dir) if dir.virtual_address > 0 && dir.size > 0 => {
            (dir.virtual_address as usize, dir.size as usize)
        }
        _ => {
            return AuthenticodeReport {
                signature_present: false,
                file_hash_verified: None,
                chain_trust: ChainTrust::Unknown,
                publisher: None,
                note,
            };
        }
    };

    // In PE, the security directory's virtual_address is a raw file offset!
    if offset >= bytes.len() || offset.checked_add(size).is_none_or(|end| end > bytes.len()) {
        return AuthenticodeReport {
            signature_present: true,
            file_hash_verified: Some(false), // Corrupt/out-of-bounds security directory
            chain_trust: ChainTrust::Untrusted,
            publisher: None,
            note: None,
        };
    }

    let cert_data = &bytes[offset..offset + size];
    if cert_data.len() < 8 {
        return AuthenticodeReport {
            signature_present: true,
            file_hash_verified: Some(false),
            chain_trust: ChainTrust::Untrusted,
            publisher: None,
            note: None,
        };
    }

    // WIN_CERTIFICATE:
    // u32 dwLength
    // u16 wRevision
    // u16 wCertificateType (0x0002 = WIN_CERT_TYPE_PKCS_SIGNED_DATA)
    let cert_type = u16::from_le_bytes([cert_data[6], cert_data[7]]);
    let publisher = if cert_type == 0x0002 && cert_data.len() > 8 {
        extract_common_name(&cert_data[8..])
    } else {
        None
    };

    AuthenticodeReport {
        signature_present: true,
        file_hash_verified: None,
        chain_trust: ChainTrust::Unknown,
        publisher,
        note: None,
    }
}

/// Simple ASN.1 search for CommonName (OID 2.5.4.3: 06 03 55 04 03)
fn extract_common_name(der: &[u8]) -> Option<String> {
    let oid = [0x06, 0x03, 0x55, 0x04, 0x03];
    let pos = der.windows(oid.len()).position(|w| w == oid)?;
    let after_oid = &der[pos + oid.len()..];
    if after_oid.len() < 2 {
        return None;
    }

    // ASN.1 string tag (PrintableString 0x13 or UTF8String 0x0C) followed by length
    let str_tag = after_oid[0];
    if str_tag == 0x13 || str_tag == 0x0C {
        let len = after_oid[1] as usize;
        if after_oid.len() >= 2 + len {
            let str_bytes = &after_oid[2..2 + len];
            return std::str::from_utf8(str_bytes).ok().map(|s| s.to_string());
        }
    }
    None
}
