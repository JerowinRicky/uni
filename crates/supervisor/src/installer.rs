use crate::lnk_parser::ShellLinkParser;
use crate::prefix_snapshot::PrefixDiff;
use crate::registry_parser::WineRegistryParser;
use crate::types::CandidateExecutable;
use std::fs;
use std::path::Path;

pub struct InstallerCandidateEngine;

impl InstallerCandidateEngine {
    /// Rank all candidate executables created or modified during installation.
    pub fn rank_candidates(
        prefix_dir: &Path,
        diff: &PrefixDiff,
        expected_product_name: Option<&str>,
    ) -> (Vec<CandidateExecutable>, bool) {
        let registry_entries = WineRegistryParser::parse_prefix_uninstall_keys(prefix_dir)
            .unwrap_or_default();
        let shortcuts = Self::find_start_menu_shortcuts(prefix_dir);

        let mut candidates = Vec::new();

        // Examine all newly added or modified .exe files
        for rel_path in diff.added.iter().chain(diff.modified.iter()) {
            let path_str = rel_path.to_string_lossy();
            if !path_str.ends_with(".exe") {
                continue;
            }

            let host_path = prefix_dir.join(rel_path);
            let metadata = fs::metadata(&host_path).ok();
            let size = metadata.as_ref().map(|m| m.len()).unwrap_or(0);

            let (score, rationale) = Self::score_candidate(
                rel_path,
                size,
                &registry_entries,
                &shortcuts,
                expected_product_name,
            );

            // Strip "drive_c/" prefix for Windows container path representation
            let win_path = rel_path
                .strip_prefix("drive_c")
                .unwrap_or(rel_path)
                .to_string_lossy()
                .replace('/', "\\");

            candidates.push(CandidateExecutable {
                path: win_path,
                host_path: host_path.to_string_lossy().into_owned(),
                confidence_score: score,
                rationale,
            });
        }

        // Sort descending by confidence score
        candidates.sort_by_key(|b| std::cmp::Reverse(b.confidence_score));

        // Evaluate whether choice is ambiguous
        let needs_user_choice = if candidates.is_empty() {
            true
        } else if candidates[0].confidence_score < 40 {
            // Low confidence: never auto-launch
            true
        } else if candidates.len() >= 2
            && (candidates[0].confidence_score - candidates[1].confidence_score) <= 15
        {
            // Close top two scores: require user confirmation
            true
        } else {
            false
        };

        (candidates, needs_user_choice)
    }

    fn score_candidate(
        rel_path: &Path,
        size_bytes: u64,
        reg_entries: &[crate::registry_parser::UninstallRegistryEntry],
        shortcuts: &[(String, String)], // (target_exe, shortcut_name)
        product_name: Option<&str>,
    ) -> (u32, Vec<String>) {
        let path_str = rel_path.to_string_lossy().to_lowercase();
        let file_name = rel_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();

        let mut score: i32 = 0;
        let mut rationale = Vec::new();

        // 1. Start Menu Shortcut Signal (Strongest signal: user desktop target)
        for (target, shortcut_name) in shortcuts {
            let target_lower = target.to_lowercase().replace('\\', "/");
            if target_lower.ends_with(&path_str) || path_str.ends_with(&target_lower) {
                score += 40;
                rationale.push(format!("Referenced by Start Menu shortcut '{}'", shortcut_name));
                break;
            }
        }

        // 2. Registry DisplayIcon and InstallLocation Signal
        for reg in reg_entries {
            if let Some(icon) = &reg.display_icon {
                let icon_lower = icon.to_lowercase().replace('\\', "/");
                if icon_lower.contains(&file_name) {
                    score += 35;
                    rationale.push(format!("Matches registry DisplayIcon for '{}'", reg.key_name));
                }
            }

            if let Some(install_loc) = &reg.install_location {
                let loc_lower = install_loc.to_lowercase().replace('\\', "/");
                if path_str.contains(&loc_lower) {
                    score += 20;
                    rationale.push(format!("Located in registry InstallLocation '{}'", install_loc));
                }
            }

            if let Some(display_name) = &reg.display_name {
                let disp_lower = display_name.to_lowercase();
                if disp_lower.contains(file_name.trim_end_matches(".exe")) {
                    score += 15;
                    rationale.push(format!("Name matches registry DisplayName '{}'", display_name));
                }
            }
        }

        // 3. Product Name Signal
        if let Some(p_name) = product_name {
            let p_lower = p_name.to_lowercase();
            if file_name.contains(&p_lower) || p_lower.contains(file_name.trim_end_matches(".exe")) {
                score += 15;
                rationale.push(format!("Matches expected product name '{}'", p_name));
            }
        }

        // 4. File Size Signal
        if size_bytes > 1024 * 1024 {
            score += 10;
            rationale.push(format!("Primary executable size ({:.1} MB)", size_bytes as f64 / 1_048_576.0));
        } else if size_bytes > 100 * 1024 {
            score += 5;
        } else if size_bytes < 25 * 1024 {
            score -= 20;
            rationale.push("Very small binary size (likely helper or stub)".to_string());
        }

        // 5. Program Files Location Signal
        if path_str.contains("program files") {
            score += 10;
        }

        // 6. Exclusion and Penalty Rules
        if file_name.contains("unins") || file_name.contains("uninstall") || file_name.contains("remove") {
            score -= 80;
            rationale.push("Heavy penalty: uninstaller binary".to_string());
        }

        if file_name.contains("update") || file_name.contains("updater") {
            score -= 50;
            rationale.push("Penalty: updater binary".to_string());
        }

        if file_name.contains("crash") || file_name.contains("reporter") || file_name.contains("feedback") {
            score -= 50;
            rationale.push("Penalty: crash reporter or telemetry helper".to_string());
        }

        if file_name.contains("setup") || file_name.contains("install") || file_name.contains("vcredist") || file_name.contains("dxsetup") {
            score -= 60;
            rationale.push("Penalty: nested redistributable or setup binary".to_string());
        }

        if file_name.contains("helper") || file_name.contains("service") || file_name.contains("proxy") {
            score -= 30;
            rationale.push("Penalty: secondary helper or service".to_string());
        }

        let clamped = score.clamp(0, 100) as u32;
        (clamped, rationale)
    }

    /// Search prefix for Start Menu .lnk shortcut files.
    fn find_start_menu_shortcuts(prefix_dir: &Path) -> Vec<(String, String)> {
        let mut shortcuts = Vec::new();
        let search_roots = [
            prefix_dir.join("drive_c/users/Public/Start Menu"),
            prefix_dir.join("drive_c/ProgramData/Microsoft/Windows/Start Menu"),
            prefix_dir.join("drive_c/users/steamuser/Start Menu"),
            prefix_dir.join("drive_c/users/default/Start Menu"),
        ];

        for root in &search_roots {
            if !root.exists() {
                continue;
            }
            Self::scan_shortcuts_dir(root, &mut shortcuts);
        }

        shortcuts
    }

    fn scan_shortcuts_dir(dir: &Path, shortcuts: &mut Vec<(String, String)>) {
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                Self::scan_shortcuts_dir(&path, shortcuts);
            } else if path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("lnk")) {
                if let Ok(info) = ShellLinkParser::parse_file(&path) {
                    if let Some(target) = info.target_path {
                        let name = path
                            .file_stem()
                            .and_then(|n| n.to_str())
                            .unwrap_or("Shortcut")
                            .to_string();
                        shortcuts.push((target, name));
                    }
                }
            }
        }
    }
}
