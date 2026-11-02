use std::io::Cursor;

/// Helper to build deterministic synthetic PE binaries for unit tests without external compilers.
pub struct PeBuilder {
    pub machine: u16,        // 0x8664 = x64, 0x014c = x86
    pub subsystem: u16,      // 2 = GUI, 3 = CUI
    pub is_pe32_plus: bool,  // true = 64-bit, false = 32-bit
    pub entry_point: u32,
    pub extra_payload: Vec<u8>,
    pub clr_descriptor: bool,
    pub security_directory: Option<(u32, u32)>, // (raw_offset, size)
}

impl PeBuilder {
    pub fn x64_gui() -> Self {
        Self {
            machine: 0x8664,
            subsystem: 2,
            is_pe32_plus: true,
            entry_point: 0x1000,
            extra_payload: Vec::new(),
            clr_descriptor: false,
            security_directory: None,
        }
    }

    pub fn x86_console() -> Self {
        Self {
            machine: 0x014c,
            subsystem: 3,
            is_pe32_plus: false,
            entry_point: 0x1000,
            extra_payload: Vec::new(),
            clr_descriptor: false,
            security_directory: None,
        }
    }

    pub fn with_payload(mut self, payload: &[u8]) -> Self {
        self.extra_payload.extend_from_slice(payload);
        self
    }

    pub fn with_clr(mut self) -> Self {
        self.clr_descriptor = true;
        self
    }

    pub fn with_security_cert(mut self, offset: u32, size: u32) -> Self {
        self.security_directory = Some((offset, size));
        self
    }

    pub fn build(self) -> Vec<u8> {
        let mut buf = vec![0u8; 0x400];

        // 1. DOS Header
        buf[0] = b'M';
        buf[1] = b'Z';
        // e_lfanew at offset 0x3C -> 0x80
        buf[0x3c] = 0x80;

        let pe_offset = 0x80;
        // 2. PE Signature
        buf[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");

        // 3. COFF File Header (20 bytes)
        let coff = pe_offset + 4;
        buf[coff..coff + 2].copy_from_slice(&self.machine.to_le_bytes()); // Machine
        buf[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());     // NumberOfSections = 1
        let opt_size: u16 = if self.is_pe32_plus { 0xF0 } else { 0xE0 };
        buf[coff + 16..coff + 18].copy_from_slice(&opt_size.to_le_bytes()); // SizeOfOptionalHeader
        buf[coff + 18..coff + 20].copy_from_slice(&0x0022u16.to_le_bytes()); // Characteristics

        // 4. Optional Header
        let opt = coff + 20;
        let opt_magic: u16 = if self.is_pe32_plus { 0x020b } else { 0x010b };
        buf[opt..opt + 2].copy_from_slice(&opt_magic.to_le_bytes());
        buf[opt + 16..opt + 20].copy_from_slice(&self.entry_point.to_le_bytes()); // AddressOfEntryPoint

        if self.is_pe32_plus {
            // Windows specific fields (offset opt + 24)
            buf[opt + 24..opt + 32].copy_from_slice(&0x0000000140000000u64.to_le_bytes()); // ImageBase
            buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
            buf[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());  // FileAlignment
            buf[opt + 68..opt + 70].copy_from_slice(&self.subsystem.to_le_bytes()); // Subsystem
            buf[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes

            // Data directories start at opt + 112
            let dd = opt + 112;
            if let Some((sec_offset, sec_size)) = self.security_directory {
                let sec_entry = dd + (4 * 8); // Index 4: Certificate table
                buf[sec_entry..sec_entry + 4].copy_from_slice(&sec_offset.to_le_bytes());
                buf[sec_entry + 4..sec_entry + 8].copy_from_slice(&sec_size.to_le_bytes());
            }

            if self.clr_descriptor {
                let clr_entry = dd + (14 * 8); // Index 14: CLR Runtime header
                buf[clr_entry..clr_entry + 4].copy_from_slice(&0x2000u32.to_le_bytes());
                buf[clr_entry + 4..clr_entry + 8].copy_from_slice(&0x48u32.to_le_bytes());
            }
        } else {
            // 32-bit PE
            buf[opt + 28..opt + 32].copy_from_slice(&0x00400000u32.to_le_bytes()); // ImageBase
            buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
            buf[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());  // FileAlignment
            buf[opt + 68..opt + 70].copy_from_slice(&self.subsystem.to_le_bytes()); // Subsystem
            buf[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
        }

        // 5. Section Header .text (at opt + opt_size)
        let sect = opt + (opt_size as usize);
        buf[sect..sect + 5].copy_from_slice(b".text");
        buf[sect + 8..sect + 12].copy_from_slice(&0x100u32.to_le_bytes()); // VirtualSize
        buf[sect + 12..sect + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
        buf[sect + 16..sect + 20].copy_from_slice(&0x200u32.to_le_bytes());  // SizeOfRawData
        buf[sect + 20..sect + 24].copy_from_slice(&0x200u32.to_le_bytes());  // PointerToRawData
        buf[sect + 36..sect + 40].copy_from_slice(&0x60000020u32.to_le_bytes()); // Characteristics

        // 6. Section data at offset 0x200
        if !self.extra_payload.is_empty() {
            let max_copy = self.extra_payload.len().min(0x200);
            buf[0x200..0x200 + max_copy].copy_from_slice(&self.extra_payload[..max_copy]);
        }

        buf
    }
}

/// Helper to create a minimal synthetic MSI compound file using cfb crate
pub fn create_synthetic_msi() -> Vec<u8> {
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut comp = cfb::CompoundFile::create(&mut cursor).expect("Failed to create CFBF");
        // Create the required MSI streams
        comp.create_stream("/\u{0005}SummaryInformation")
            .expect("Failed to create SummaryInformation stream");
        comp.create_stream("/Property")
            .expect("Failed to create Property stream");
    }
    cursor.into_inner()
}

