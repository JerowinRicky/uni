use regex::Regex;
use std::collections::{HashMap, HashSet};
use universalrun_profile_manager::ProfileManifest;

pub const SAFE_ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
    "DISPLAY",
    "WINEPREFIX",
    "WINEDEBUG",
    "XAUTHORITY",
    "XDG_RUNTIME_DIR",
    "TZ",
];

/// Redacts sensitive information from text logs, environment variables, and manifests.
pub struct PiiScrubber {
    jwt_re: Regex,
    gh_token_re: Regex,
    aws_key_re: Regex,
    bearer_re: Regex,
    email_re: Regex,
    ip_re: Regex,
    unc_re: Regex,
    prefix_user_re: Regex,
    home_user_re: Regex,
    allowlist: HashSet<String>,
}

impl PiiScrubber {
    pub fn new() -> Self {
        Self {
            // Token regexes
            jwt_re: Regex::new(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}").unwrap(),
            gh_token_re: Regex::new(r"(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})").unwrap(),
            aws_key_re: Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap(),
            bearer_re: Regex::new(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{10,}").unwrap(),

            // Email regex
            email_re: Regex::new(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+").unwrap(),

            // IP address regex
            ip_re: Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap(),

            // UNC path regex: \\server\share
            unc_re: Regex::new(r"\\\\[a-zA-Z0-9_.-]+\\[a-zA-Z0-9_.$ -]+").unwrap(),

            // Username inside Windows prefix: drive_c/users/username or C:\Users\username
            prefix_user_re: Regex::new(r"(?i)(drive_c[/\\]users[/\\])([a-zA-Z0-9_.-]+)").unwrap(),

            // Username inside host home path: /home/username or /Users/username
            home_user_re: Regex::new(r"(?i)(/(?:home|Users)/)([a-zA-Z0-9_.-]+)").unwrap(),

            allowlist: SAFE_ENV_ALLOWLIST.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Redact tokens, emails, IPs, UNC paths, and usernames from log string.
    pub fn scrub_text(&self, text: &str) -> String {
        let mut scrubbed = text.to_string();

        // 1. Tokens
        scrubbed = self.jwt_re.replace_all(&scrubbed, "<REDACTED_JWT>").into_owned();
        scrubbed = self.gh_token_re.replace_all(&scrubbed, "<REDACTED_TOKEN>").into_owned();
        scrubbed = self.aws_key_re.replace_all(&scrubbed, "<REDACTED_AWS_KEY>").into_owned();
        scrubbed = self.bearer_re.replace_all(&scrubbed, "Bearer <REDACTED_BEARER>").into_owned();

        // 2. Emails
        scrubbed = self.email_re.replace_all(&scrubbed, "<REDACTED_EMAIL>").into_owned();

        // 3. IPs
        scrubbed = self.ip_re.replace_all(&scrubbed, "<REDACTED_IP>").into_owned();

        // 4. UNC paths
        scrubbed = self.unc_re.replace_all(&scrubbed, "<REDACTED_UNC>").into_owned();

        // 5. Usernames in prefix paths
        scrubbed = self.prefix_user_re.replace_all(&scrubbed, "${1}<REDACTED_USER>").into_owned();

        // 6. Usernames in home paths
        scrubbed = self.home_user_re.replace_all(&scrubbed, "${1}<REDACTED_USER>").into_owned();

        scrubbed
    }

    /// Scrub environment variables according to strict ALLOWLIST.
    /// Only variables in SAFE_ENV_ALLOWLIST are retained; all others are deleted.
    pub fn scrub_env_vars(&self, env: &HashMap<String, String>) -> HashMap<String, String> {
        let mut scrubbed = HashMap::new();

        for (k, v) in env {
            if self.allowlist.contains(k) {
                // Scrub potential username paths in allowlisted value
                scrubbed.insert(k.clone(), self.scrub_text(v));
            }
        }

        scrubbed
    }

    /// Scrub sensitive host paths and environment from profile manifest.
    pub fn scrub_manifest(&self, manifest: &ProfileManifest) -> ProfileManifest {
        let mut scrubbed = manifest.clone();

        // Scrub environment variables via allowlist
        scrubbed.env_vars = self.scrub_env_vars(&manifest.env_vars);

        // Scrub host paths in filesystem mappings
        for mapping in &mut scrubbed.filesystem_mappings {
            mapping.host_path = "<REDACTED_HOST_PATH>".to_string();
            mapping.guest_path = self.scrub_text(&mapping.guest_path);
        }

        scrubbed
    }
}

impl Default for PiiScrubber {
    fn default() -> Self {
        Self::new()
    }
}

