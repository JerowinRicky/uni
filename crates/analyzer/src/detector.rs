use crate::types::{Finding, GraphicsApi, SecurityFlags};
use goblin::pe::PE;

pub struct DetectedAttributes {
    pub graphics_apis: Vec<Finding<GraphicsApi>>,
    pub required_runtimes: Vec<Finding<String>>,
    pub security_flags: SecurityFlags,
    pub notable_apis: Vec<String>,
}

pub fn detect_attributes(bytes: &[u8], pe: &PE, requests_admin: bool) -> DetectedAttributes {
    let mut graphics_apis = Vec::new();
    let mut required_runtimes = Vec::new();
    let mut notable_apis = Vec::new();
    let mut has_drivers_or_services = false;
    let mut known_anticheat_or_drm = None;

    // Check imports for Graphics APIs & Runtimes
    for import in &pe.imports {
        let dll = import.dll.to_ascii_lowercase();

        // 1. Graphics APIs
        if dll == "d3d9.dll" {
            graphics_apis.push(Finding::certain(GraphicsApi::Direct3D9));
        } else if dll == "d3d10.dll" || dll == "d3d10_1.dll" {
            graphics_apis.push(Finding::certain(GraphicsApi::Direct3D10));
        } else if dll == "d3d11.dll" {
            graphics_apis.push(Finding::certain(GraphicsApi::Direct3D11));
        } else if dll == "d3d12.dll" {
            graphics_apis.push(Finding::certain(GraphicsApi::Direct3D12));
        } else if dll == "opengl32.dll" {
            graphics_apis.push(Finding::certain(GraphicsApi::OpenGL));
        } else if dll == "vulkan-1.dll" {
            graphics_apis.push(Finding::certain(GraphicsApi::Vulkan));
        }

        // 2. VC++ Runtimes
        if dll.starts_with("vcruntime140") || dll.starts_with("msvcp140") {
            let item = Finding::certain("Microsoft Visual C++ 2015-2022 Redistributable".to_string());
            if !required_runtimes.contains(&item) {
                required_runtimes.push(item);
            }
        } else if dll == "msvcr120.dll" || dll == "msvcp120.dll" {
            let item = Finding::certain("Microsoft Visual C++ 2013 Redistributable".to_string());
            if !required_runtimes.contains(&item) {
                required_runtimes.push(item);
            }
        } else if dll == "msvcr110.dll" || dll == "msvcp110.dll" {
            let item = Finding::certain("Microsoft Visual C++ 2012 Redistributable".to_string());
            if !required_runtimes.contains(&item) {
                required_runtimes.push(item);
            }
        } else if dll == "msvcr100.dll" || dll == "msvcp100.dll" {
            let item = Finding::certain("Microsoft Visual C++ 2010 Redistributable".to_string());
            if !required_runtimes.contains(&item) {
                required_runtimes.push(item);
            }
        } else if dll == "msvcr90.dll" || dll == "msvcp90.dll" {
            let item = Finding::certain("Microsoft Visual C++ 2008 Redistributable".to_string());
            if !required_runtimes.contains(&item) {
                required_runtimes.push(item);
            }
        }

        // 3. Notable APIs
        if dll == "winspool.drv" {
            notable_apis.push("Windows Print Spooler (winspool.drv)".to_string());
        } else if dll == "ws2_32.dll" || dll == "wininet.dll" || dll == "winhttp.dll" {
            let net = "Windows Sockets / HTTP Networking".to_string();
            if !notable_apis.contains(&net) {
                notable_apis.push(net);
            }
        }

        // 4. Driver / Kernel services
        if dll == "ntoskrnl.exe" || dll == "hal.dll" || dll.ends_with(".sys") {
            has_drivers_or_services = true;
        }
    }

    // Check subsystem
    if let Some(opt) = &pe.header.optional_header {
        if opt.windows_fields.subsystem == 1 {
            // IMAGE_SUBSYSTEM_NATIVE (Device driver or native NT service)
            has_drivers_or_services = true;
        }
    }

    // Scan for Anti-Cheat / DRM signatures in binary bytes
    if find_subsequence(bytes, b"EasyAntiCheat").is_some() {
        known_anticheat_or_drm = Some("EasyAntiCheat".to_string());
    } else if find_subsequence(bytes, b"BattlEye").is_some() || find_subsequence(bytes, b"BEService").is_some() {
        known_anticheat_or_drm = Some("BattlEye".to_string());
    } else if find_subsequence(bytes, b"Denuvo").is_some() {
        known_anticheat_or_drm = Some("Denuvo Anti-Tamper".to_string());
    } else if find_subsequence(bytes, b"VMProtect").is_some() {
        known_anticheat_or_drm = Some("VMProtect".to_string());
    }

    DetectedAttributes {
        graphics_apis,
        required_runtimes,
        security_flags: SecurityFlags {
            requests_admin,
            has_drivers_or_services,
            known_anticheat_or_drm,
        },
        notable_apis,
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
