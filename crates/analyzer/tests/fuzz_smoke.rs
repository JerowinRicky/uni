use universalrun_analyzer::limits::AnalyzerLimits;
use universalrun_analyzer::analyze_bytes;

/// Deterministic Pseudo-Random Generator (Xorshift64) to fuzz test without external dependencies.
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self { state: if seed == 0 { 0x54321 } else { seed } }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn fill_bytes(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let val = self.next_u64().to_le_bytes();
            let len = chunk.len();
            chunk.copy_from_slice(&val[..len]);
        }
    }
}

#[test]
fn test_fuzz_smoke_arbitrary_inputs() {
    let limits = AnalyzerLimits::default();
    let mut rng = XorShift64::new(0xDEADBEEFCAFE);

    // Run 5,000 fuzz iterations on random byte buffers from 0 to 4096 bytes
    for i in 0..5_000 {
        let len = (rng.next_u64() % 4096) as usize;
        let mut buf = vec![0u8; len];
        rng.fill_bytes(&mut buf);

        // Inject magic prefixes occasionally
        if i % 4 == 0 && len >= 2 {
            buf[0] = b'M';
            buf[1] = b'Z';
        } else if i % 4 == 1 && len >= 8 {
            buf[..8].copy_from_slice(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1");
        }

        // Must never panic or crash!
        let _ = analyze_bytes("fuzz_input.bin", &buf, &limits);
    }
}

