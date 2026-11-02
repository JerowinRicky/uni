use crate::process::ProcessSupervisor;
use crate::types::{LogChannel, ProcessExitInfo, ProcessState};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use universalrun_common::error::Result;

/// Mock runtime for host-agnostic and Windows testing without Wine execution.
pub struct MockRuntime {
    supervisor: Arc<ProcessSupervisor>,
}

impl MockRuntime {
    pub fn new(supervisor: Arc<ProcessSupervisor>) -> Self {
        Self { supervisor }
    }

    /// Simulate full normal application execution lifecycle.
    pub async fn run_simulation(
        &self,
        duration: Duration,
        simulated_logs: &[&str],
        exit_code: i32,
    ) -> Result<()> {
        self.supervisor.transition_state(ProcessState::Starting, None);

        // Simulate startup delay
        sleep(Duration::from_millis(50)).await;

        self.supervisor.transition_state(ProcessState::Running, None);

        // Emit simulated logs
        for log in simulated_logs {
            self.supervisor.record_log_line(log, LogChannel::Stdout);
            sleep(Duration::from_millis(10)).await;
        }

        sleep(duration).await;

        let exit_info = ProcessExitInfo::from_raw_code(exit_code);
        let final_state = if exit_info.is_success {
            ProcessState::Terminated
        } else {
            ProcessState::Crashed
        };

        self.supervisor.transition_state(final_state, Some(exit_info));
        Ok(())
    }

    /// Populate a mock prefix directory simulating an installed application.
    pub fn populate_mock_installed_prefix(prefix_dir: &Path) -> Result<()> {
        let drive_c = prefix_dir.join("drive_c");
        let app_dir = drive_c.join("Program Files/Notepad++");
        let start_menu_dir = drive_c.join("ProgramData/Microsoft/Windows/Start Menu/Programs/Notepad++");

        std::fs::create_dir_all(&app_dir).map_err(universalrun_common::error::UniversalRunError::Io)?;
        std::fs::create_dir_all(&start_menu_dir).map_err(universalrun_common::error::UniversalRunError::Io)?;

        // Main app binary (simulate 3.5 MB)
        let main_exe = app_dir.join("notepad++.exe");
        let large_dummy = vec![0u8; 3 * 1024 * 1024];
        std::fs::write(&main_exe, large_dummy).map_err(universalrun_common::error::UniversalRunError::Io)?;

        // Uninstaller binary (simulate 200 KB)
        let unins_exe = app_dir.join("uninstall.exe");
        let unins_dummy = vec![0u8; 200 * 1024];
        std::fs::write(&unins_exe, unins_dummy).map_err(universalrun_common::error::UniversalRunError::Io)?;

        // Updater binary (simulate 150 KB)
        let updater_exe = app_dir.join("updater.exe");
        let updater_dummy = vec![0u8; 150 * 1024];
        std::fs::write(&updater_exe, updater_dummy).map_err(universalrun_common::error::UniversalRunError::Io)?;

        // Mock Wine registry entry in system.reg
        let system_reg_content = r#"WINE REGISTRY Version 2
;; All keys relative to \\Machine

[Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Notepad++]
"DisplayName"="Notepad++ (64-bit x64)"
"InstallLocation"="C:\\Program Files\\Notepad++"
"DisplayIcon"="C:\\Program Files\\Notepad++\\notepad++.exe,0"
"UninstallString"="\"C:\\Program Files\\Notepad++\\uninstall.exe\""
"#;
        std::fs::write(prefix_dir.join("system.reg"), system_reg_content)
            .map_err(universalrun_common::error::UniversalRunError::Io)?;

        // Mock Start Menu shortcut pointing to notepad++.exe
        let lnk_path = start_menu_dir.join("Notepad++.lnk");
        let mock_lnk_bytes = create_mock_lnk_bytes("C:\\Program Files\\Notepad++\\notepad++.exe");
        std::fs::write(&lnk_path, mock_lnk_bytes)
            .map_err(universalrun_common::error::UniversalRunError::Io)?;

        Ok(())
    }
}

/// Synthesize a valid binary ShellLink (.lnk) pointing to a target path.
pub fn create_mock_lnk_bytes(target_path: &str) -> Vec<u8> {
    let mut bytes = Vec::new();

    // 0x00: HeaderSize = 0x4C
    bytes.extend_from_slice(&0x4Cu32.to_le_bytes());

    // 0x04: LinkCLSID
    bytes.extend_from_slice(&[
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ]);

    // 0x14: LinkFlags (HasLinkInfo = 0x02)
    bytes.extend_from_slice(&0x02u32.to_le_bytes());

    // 0x18: FileAttributes (0)
    bytes.extend_from_slice(&0u32.to_le_bytes());

    // 0x1C: CreationTime (0)
    bytes.extend_from_slice(&0u64.to_le_bytes());

    // 0x24: AccessTime (0)
    bytes.extend_from_slice(&0u64.to_le_bytes());

    // 0x2C: WriteTime (0)
    bytes.extend_from_slice(&0u64.to_le_bytes());

    // 0x34: FileSize (0)
    bytes.extend_from_slice(&0u32.to_le_bytes());

    // 0x38: IconIndex (0)
    bytes.extend_from_slice(&0u32.to_le_bytes());

    // 0x3C: ShowCommand (1 = SW_SHOWNORMAL)
    bytes.extend_from_slice(&1u32.to_le_bytes());

    // 0x40: HotKey (0)
    bytes.extend_from_slice(&0u16.to_le_bytes());

    // 0x42: Reserved (0)
    bytes.extend_from_slice(&[0u8; 10]);

    // LinkInfo Structure
    let link_info_header_size: u32 = 0x1C;
    let local_base_path_offset: u32 = 0x1C;
    let mut path_bytes = target_path.as_bytes().to_vec();
    path_bytes.push(0); // Null terminator

    let link_info_size: u32 = link_info_header_size + path_bytes.len() as u32;

    // LinkInfoSize
    bytes.extend_from_slice(&link_info_size.to_le_bytes());
    // LinkInfoHeaderSize
    bytes.extend_from_slice(&link_info_header_size.to_le_bytes());
    // LinkInfoFlags (1 = VolumeIDAndLocalBasePath)
    bytes.extend_from_slice(&1u32.to_le_bytes());
    // VolumeIDOffset (0)
    bytes.extend_from_slice(&0u32.to_le_bytes());
    // LocalBasePathOffset
    bytes.extend_from_slice(&local_base_path_offset.to_le_bytes());
    // CommonNetworkRelativeLinkOffset (0)
    bytes.extend_from_slice(&0u32.to_le_bytes());
    // CommonPathSuffixOffset (0)
    bytes.extend_from_slice(&0u32.to_le_bytes());

    // LocalBasePath string
    bytes.extend_from_slice(&path_bytes);

    bytes
}
