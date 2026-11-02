use std::time::Duration;

pub struct AnalyzerLimits {
    pub max_file_size_bytes: u64,
    pub max_sections: usize,
    pub max_imports: usize,
    pub max_resources: usize,
    pub analysis_timeout: Duration,
}

impl Default for AnalyzerLimits {
    fn default() -> Self {
        Self {
            max_file_size_bytes: 2 * 1024 * 1024 * 1024, // 2 GB max
            max_sections: 128,
            max_imports: 4096,
            max_resources: 65536,
            analysis_timeout: Duration::from_secs(15),
        }
    }
}

