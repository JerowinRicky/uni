use clap::{Args, Parser, Subcommand};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use universalrun_analyzer::analyze_file;
use universalrun_profile_manager::{
    ProfileManifest, ProfileStorage, ResolvedDependency, RuntimeConfig,
};
use universalrun_recipe_engine::{
    match_recipe, DependencyCatalog, DependencyResolver, Recipe,
};

#[derive(Parser)]
#[command(name = "universalrun")]
#[command(about = "UniversalRun desktop orchestration & compatibility platform", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Statically analyze a Windows PE executable or MSI installer without execution
    Analyze(AnalyzeArgs),
    /// Plan profile synthesis and dependency resolution for an application (no execution)
    Plan(PlanArgs),
    /// Manage isolated per-application profiles
    Profile(ProfileArgs),
    /// Classify failure signatures and recommend declarative fixes from execution logs
    Diagnose(DiagnoseArgs),
    /// Build a privacy-scrubbed diagnostic bug reporting bundle
    Bundle(BundleArgs),
    /// Plan bubblewrap sandbox argument vector for an application profile (no execution)
    SandboxPlan(SandboxPlanArgs),
}

#[derive(Args)]
struct DiagnoseArgs {
    /// Path to execution log file
    logfile: PathBuf,

    /// Process exit code
    #[arg(long)]
    exit_code: Option<i32>,

    /// Output report as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct BundleArgs {
    /// Path to raw execution log file
    logfile: PathBuf,

    /// Name or ID of configured application profile
    #[arg(long)]
    profile: String,

    /// Destination directory for diagnostic bundle
    #[arg(long)]
    out: PathBuf,
}

#[derive(Args)]
struct SandboxPlanArgs {
    /// Identifier of configured application profile
    profile: String,

    /// Output plan as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct AnalyzeArgs {
    /// Path to target Windows executable (.exe) or MSI package (.msi)
    path: PathBuf,

    /// Output full machine-readable JSON analysis report conforming to schema
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct PlanArgs {
    /// Path to target Windows executable (.exe) or MSI package (.msi)
    path: PathBuf,

    /// Output plan as JSON
    #[arg(long)]
    json: bool,

    /// Optional path to custom dependency catalog TOML
    #[arg(long)]
    catalog: Option<PathBuf>,
}

#[derive(Args)]
struct ProfileArgs {
    #[command(subcommand)]
    subcommand: ProfileSubcommands,
}

#[derive(Subcommand)]
enum ProfileSubcommands {
    /// Create a new profile from a manifest file
    Create {
        /// Unique profile identifier (1-64 chars, [a-zA-Z0-9_-])
        profile_id: String,
        /// Path to profile manifest (TOML or JSON)
        #[arg(long)]
        manifest: PathBuf,
    },
    /// List all currently configured profiles
    List,
    /// Delete a profile and its isolated state
    Delete {
        /// Profile identifier to delete
        profile_id: String,
    },
    /// Rebuild a profile from manifest alone
    Rebuild {
        /// Profile identifier to rebuild
        profile_id: String,
        /// Allow downgrade to older recipe revision
        #[arg(long)]
        allow_older: bool,
        /// Optional path to updated manifest
        #[arg(long)]
        manifest: Option<PathBuf>,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Analyze(args) => handle_analyze(args),
        Commands::Plan(args) => handle_plan(args),
        Commands::Profile(args) => handle_profile(args),
        Commands::Diagnose(args) => handle_diagnose(args),
        Commands::Bundle(args) => handle_bundle(args),
        Commands::SandboxPlan(args) => handle_sandbox_plan(args),
    }
}

fn handle_analyze(args: AnalyzeArgs) -> Result<(), Box<dyn std::error::Error>> {
    if !args.path.exists() {
        eprintln!("Error: target file '{}' does not exist", args.path.display());
        std::process::exit(1);
    }

    let report = match analyze_file(&args.path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Analysis failed: {}", e);
            std::process::exit(1);
        }
    };

    if args.json {
        let json_str = serde_json::to_string_pretty(&report)?;
        println!("{}", json_str);
    } else {
        println!("============================================================");
        println!(" UniversalRun Static Application Analysis");
        println!("============================================================");
        println!("File:         {}", report.file_name);
        println!("Size:         {} bytes", report.file_size_bytes);
        println!("SHA-256:      {}", report.sha256);
        println!(
            "Architecture: {}",
            report
                .architecture
                .map(|a| format!("{:?}", a))
                .unwrap_or_else(|| "none (MSI/Container)".to_string())
        );
        println!(
            "Subsystem:    {}",
            report
                .subsystem
                .map(|s| format!("{:?}", s))
                .unwrap_or_else(|| "none (MSI/Container)".to_string())
        );
        println!(
            "Installer:    {:?} (confidence: {:?})",
            report.installer_type.value, report.installer_type.confidence
        );

        if let Some(dotnet) = &report.dotnet {
            println!(
                ".NET CLR:     Detected (flavor: {:?}, target: {:?}, confidence: {:?})",
                dotnet.flavor, dotnet.target_framework, dotnet.confidence
            );
        }

        println!("Authenticode: Signature Present: {}", report.authenticode.signature_present);
        println!("              Chain Trust:       {:?}", report.authenticode.chain_trust);
        if let Some(note) = &report.authenticode.note {
            println!("              Note:              {}", note);
        }

        println!("\nCompatibility Rating: {:?}", report.compatibility_rating.category);
        println!("Summary: {}", report.compatibility_rating.summary);
        for ev in &report.compatibility_rating.evidence {
            println!("  - {}", ev);
        }
        println!("============================================================");
    }

    Ok(())
}

fn handle_plan(args: PlanArgs) -> Result<(), Box<dyn std::error::Error>> {
    if !args.path.exists() {
        eprintln!("Error: target file '{}' does not exist", args.path.display());
        std::process::exit(1);
    }

    // 1. Analyze binary statically
    let report = analyze_file(&args.path)?;

    // 2. Discover local recipes
    let candidates = load_local_recipes();

    // 3. Match recipe or synthesize fallback
    let match_result = match_recipe(&report, &candidates)?;
    let recipe = match_result.recipe();

    // 4. Load dependency catalog
    let catalog_path = args.catalog.unwrap_or_else(|| {
        PathBuf::from("recipes/catalog/dependencies.toml")
    });

    let catalog = if catalog_path.exists() {
        DependencyCatalog::from_file(&catalog_path).unwrap_or_default()
    } else {
        DependencyCatalog::default()
    };

    let resolver = DependencyResolver::new(catalog, None);
    let dep_plan = resolver.create_plan(&recipe.dependencies)?;

    // 5. Synthesize planned ProfileManifest
    let target_app = args
        .path
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| "app.exe".to_string());

    let resolved_deps: Vec<ResolvedDependency> = dep_plan
        .iter()
        .map(|d| ResolvedDependency {
            id: d.id.clone(),
            version: d.version.clone(),
            sha256: d.sha256.clone(),
        })
        .collect();

    let manifest = ProfileManifest {
        schema_version: ProfileManifest::SCHEMA_VERSION.to_string(),
        profile_id: recipe.id.clone(),
        display_name: recipe.name.clone(),
        target_app,
        target_app_sha256: Some(report.sha256.clone()),
        recipe_id: Some(recipe.id.clone()),
        recipe_revision: Some(recipe.revision),
        runtime: RuntimeConfig {
            name: recipe.runtime.preferred.clone(),
            version: recipe.runtime.min_version.clone(),
            architecture: recipe.runtime.architecture.clone(),
            windows_version: recipe.runtime.windows_version.clone(),
        },
        dependencies: resolved_deps,
        env_vars: HashMap::new(),
        dll_overrides: recipe.dll_overrides.clone(),
        filesystem_mappings: Vec::new(),
        permissions: recipe.permissions.clone(),
        wine_debug: None,
        rebuild_hash: None,
    };

    let mut finalized_manifest = manifest.clone();
    finalized_manifest.rebuild_hash = Some(manifest.compute_rebuild_hash());

    if args.json {
        let output = serde_json::json!({
            "disclaimer": "PLAN ONLY: No wine prefixes created, no files downloaded, nothing executed.",
            "match_type": match_result.match_type(),
            "matched_recipe_id": recipe.id,
            "recipe_revision": recipe.revision,
            "planned_dependencies": dep_plan,
            "profile_manifest": finalized_manifest
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("============================================================");
        println!(" UniversalRun Profile & Dependency Execution Plan");
        println!(" (PLAN ONLY: No wine prefixes created, no files downloaded, nothing executed)");
        println!("============================================================");
        println!("Target Application: {}", report.file_name);
        println!("SHA-256 Digest:     {}", report.sha256);
        println!("Matched Recipe:     {} (type: {})", recipe.id, match_result.match_type());
        println!("Recipe Revision:    {}", recipe.revision);
        println!(".NET Strategy:      {:?}", recipe.dotnet_runtime);
        println!("Runtime Backend:    {} (arch: {}, winver: {})",
            recipe.runtime.preferred, recipe.runtime.architecture, recipe.runtime.windows_version
        );

        println!("\nResolved Dependencies ({}):", dep_plan.len());
        if dep_plan.is_empty() {
            println!("  (none required)");
        } else {
            for dep in &dep_plan {
                let status = if dep.is_verified {
                    if dep.cached { "cached [verified]" } else { "pending download [verified hash]" }
                } else {
                    "UNVERIFIED (hash: TODO - resolver will refuse download)"
                };
                let url_display = if dep.is_verified {
                    format!("URL: {}", dep.source_url)
                } else {
                    format!("[UNVERIFIED URL: {}]", dep.source_url)
                };
                println!("  - {} v{} [{}] ({})", dep.id, dep.version, status, url_display);
            }
        }

        println!("\nDLL Overrides ({}):", recipe.dll_overrides.len());
        for (dll, mode) in &recipe.dll_overrides {
            println!("  - {}: {:?}", dll, mode);
        }

        println!("\nPermissions:");
        println!("  Network: {}", recipe.permissions.network);
        println!("  Audio:   {}", recipe.permissions.audio);
        println!("  Display: {}", recipe.permissions.display);
        println!("  DRI/GPU: {}", recipe.permissions.dri);

        println!("\nDeterministic Rebuild Hash:");
        println!("  {}", finalized_manifest.rebuild_hash.as_deref().unwrap_or("none"));
        println!("============================================================");
    }

    Ok(())
}

fn handle_profile(args: ProfileArgs) -> Result<(), Box<dyn std::error::Error>> {
    let storage = ProfileStorage::new(None);

    match args.subcommand {
        ProfileSubcommands::Create { profile_id, manifest } => {
            let content = fs::read_to_string(&manifest)?;
            let mut parsed: ProfileManifest = if manifest.extension().is_some_and(|e| e == "json") {
                serde_json::from_str(&content)?
            } else {
                toml::from_str(&content)?
            };
            parsed.profile_id = profile_id;
            let dir = storage.create_profile(&parsed)?;
            println!("Profile created at: {}", dir.display());
        }
        ProfileSubcommands::List => {
            let profiles = storage.list_profiles()?;
            println!("Installed Profiles ({}):", profiles.len());
            for p in profiles {
                println!(
                    "  - {} ('{}') [runtime: {} {}, rev: {}]",
                    p.profile_id,
                    p.display_name,
                    p.runtime.name,
                    p.runtime.architecture,
                    p.recipe_revision.unwrap_or(0)
                );
            }
        }
        ProfileSubcommands::Delete { profile_id } => {
            storage.delete_profile(&profile_id)?;
            println!("Profile '{}' deleted.", profile_id);
        }
        ProfileSubcommands::Rebuild { profile_id, allow_older, manifest } => {
            let new_m = if let Some(m_path) = manifest {
                let content = fs::read_to_string(&m_path)?;
                let parsed: ProfileManifest = if m_path.extension().is_some_and(|e| e == "json") {
                    serde_json::from_str(&content)?
                } else {
                    toml::from_str(&content)?
                };
                Some(parsed)
            } else {
                None
            };

            let rebuilt = storage.rebuild_profile(&profile_id, allow_older, new_m.as_ref())?;
            println!(
                "Profile '{}' rebuilt successfully (rebuild_hash: {}).",
                rebuilt.profile_id,
                rebuilt.rebuild_hash.as_deref().unwrap_or("none")
            );
        }
    }

    Ok(())
}

fn handle_diagnose(args: DiagnoseArgs) -> Result<(), Box<dyn std::error::Error>> {
    if !args.logfile.exists() {
        eprintln!("Error: log file '{}' does not exist", args.logfile.display());
        std::process::exit(1);
    }

    let catalog_path = PathBuf::from("diagnostics/catalog/fixes.toml");
    let catalog = if catalog_path.exists() {
        universalrun_diagnostics::FixCatalog::from_file(&catalog_path)?
    } else {
        universalrun_diagnostics::FixCatalog::default()
    };

    let log_bytes = fs::read(&args.logfile)?;
    let classifier = universalrun_diagnostics::LogClassifier::new(&catalog);
    let report = classifier.classify(&log_bytes, args.exit_code)?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("============================================================");
        println!(" UniversalRun Log Diagnostics & Failure Classification");
        println!("============================================================");
        println!("Log File:       {}", args.logfile.display());
        println!("Exit Code:      {:?}", report.exit_code);
        println!("Category:       {:?}", report.category);
        println!("Confidence:     {:?}", report.confidence);
        println!("Summary:        {}", report.summary);

        println!("\nEvidence Lines ({}):", report.evidence_lines.len());
        if report.evidence_lines.is_empty() {
            println!("  (none)");
        } else {
            for line in &report.evidence_lines {
                println!("  > {}", line);
            }
        }

        println!("\nRecommended Declarative Fixes ({}):", report.recommended_fixes.len());
        if report.recommended_fixes.is_empty() {
            println!("  (none)");
        } else {
            for fix in &report.recommended_fixes {
                println!("  - [{:?}] {}: {}", fix.risk_level, fix.title, fix.description);
                println!("    Target Change: {}", fix.target_change);
                if let Some(note) = &fix.status_note {
                    println!("    Note:          {}", note);
                }
            }
        }
        println!("============================================================");
    }

    Ok(())
}

fn handle_bundle(args: BundleArgs) -> Result<(), Box<dyn std::error::Error>> {
    if !args.logfile.exists() {
        eprintln!("Error: log file '{}' does not exist", args.logfile.display());
        std::process::exit(1);
    }

    let storage = ProfileStorage::new(None);
    let manifest = storage.get_profile(&args.profile)?;

    let catalog_path = PathBuf::from("diagnostics/catalog/fixes.toml");
    let catalog = if catalog_path.exists() {
        universalrun_diagnostics::FixCatalog::from_file(&catalog_path)?
    } else {
        universalrun_diagnostics::FixCatalog::default()
    };

    let log_bytes = fs::read(&args.logfile)?;
    let classifier = universalrun_diagnostics::LogClassifier::new(&catalog);
    let report = classifier.classify(&log_bytes, None)?;

    let builder = universalrun_diagnostics::BundleBuilder::new();
    let out = builder.build_bundle(&args.logfile, &manifest, &report, &args.out)?;

    println!("Diagnostic bundle created at: {}", out.display());
    Ok(())
}

fn handle_sandbox_plan(args: SandboxPlanArgs) -> Result<(), Box<dyn std::error::Error>> {
    let storage = ProfileStorage::new(None);
    let manifest = match storage.get_profile(&args.profile) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Error loading profile '{}': {}", args.profile, e);
            std::process::exit(1);
        }
    };

    let mut granted_folders = Vec::new();
    for mapping in &manifest.filesystem_mappings {
        granted_folders.push(universalrun_sandbox::GrantedFolder {
            host_path: PathBuf::from(&mapping.host_path),
            container_path: mapping.guest_path.clone(),
            read_only: mapping.read_only,
        });
    }

    let policy = universalrun_sandbox::SandboxPolicy {
        schema_version: "1.0.0".to_string(),
        files: if granted_folders.is_empty() {
            universalrun_sandbox::FilePermissionMode::Deny
        } else {
            universalrun_sandbox::FilePermissionMode::Allow
        },
        granted_folders,
        network: manifest.permissions.network,
        audio: manifest.permissions.audio,
        microphone: false,
        display: if manifest.permissions.display {
            universalrun_sandbox::DisplayBackend::X11
        } else {
            universalrun_sandbox::DisplayBackend::Headless
        },
        gpu: manifest.permissions.dri,
        camera: false,
        usb: false,
        system_access: false,
    };

    let p_dir = storage.profile_dir(&args.profile);
    let prefix_dir = p_dir.join("prefix");

    // Runtime directory from pinned configuration
    let runtimes_dir = storage
        .root_dir()
        .parent()
        .unwrap_or_else(|| storage.root_dir())
        .join("runtimes");
    let runtime_path = runtimes_dir.join(format!(
        "{}-{}",
        manifest.runtime.name, manifest.runtime.version
    ));

    // Derive display from host environment or fallback to :0
    let (host_display, display_source) = match std::env::var("DISPLAY") {
        Ok(val) if !val.trim().is_empty() => (
            Some(val.clone()),
            format!("host environment variable $DISPLAY ({})", val),
        ),
        _ => (
            Some(":0".to_string()),
            "fallback default (:0, $DISPLAY not set)".to_string(),
        ),
    };

    // PLAN MODE MUST NOT CREATE ANYTHING ON DISK.
    // Use an illustrative placeholder path for arguments display; real cookie is generated only at spawn time.
    let placeholder_xauth = PathBuf::from("/tmp/universalrun-xauth-placeholder/xauth_cookie");

    let ctx = universalrun_sandbox::SandboxContext {
        policy: policy.clone(),
        manifest: manifest.clone(),
        host_wine_runtime: runtime_path.clone(),
        host_prefix_dir: prefix_dir.clone(),
        host_x11_display: host_display.clone(),
        host_scoped_xauth: if manifest.permissions.display {
            Some(placeholder_xauth)
        } else {
            None
        },
        host_wayland_socket: None,
        host_pulse_socket: if manifest.permissions.audio {
            Some(PathBuf::from("/run/user/1000/pulse/native"))
        } else {
            None
        },
    };

    let backend = universalrun_sandbox::BwrapBackend::new();
    let bwrap_args = match backend.build_args(&ctx) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Error building sandbox arguments: {}", e);
            std::process::exit(1);
        }
    };

    let bwrap_args_str: Vec<String> = bwrap_args
        .iter()
        .map(|s| s.to_string_lossy().into_owned())
        .collect();

    let enforcement = policy.enforcement_status();

    let (net_lvl, net_desc) = &enforcement["network"];
    let (audio_lvl, audio_desc) = &enforcement["audio"];
    let (mic_lvl, mic_desc) = &enforcement["microphone"];
    let (disp_lvl, disp_desc) = &enforcement["display"];
    let (gpu_lvl, gpu_desc) = &enforcement["gpu"];

    if args.json {
        let output = serde_json::json!({
            "schema_version": "1.0.0",
            "profile_id": args.profile,
            "plan_only": true,
            "notice": "PLAN ONLY: Bubblewrap arguments generated as data, nothing executed or written to disk. Paths are illustrative until resolved on the target host.",
            "target_app": manifest.target_app,
            "display_source": display_source,
            "x11_cookie_policy": "Spawn-time generation via 'xauth generate <display> . untrusted timeout 0' in private 0700 dir (UNTESTED ON LINUX)",
            "prefix_layout": {
                "prefix_root": prefix_dir.to_string_lossy(),
                "wine_c_drive": format!("{}/drive_c", prefix_dir.to_string_lossy()),
                "app_entry": format!("{}/drive_c/{}", prefix_dir.to_string_lossy(), manifest.target_app),
            },
            "filesystem_mappings": manifest.filesystem_mappings,
            "bwrap_args": bwrap_args_str,
            "enforcement_status": enforcement,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("================================================================================");
        println!(" UniversalRun Sandbox Plan: {}", args.profile);
        println!("================================================================================");
        println!("PLAN ONLY: Bubblewrap arguments generated as data, nothing executed or written to disk.");
        println!("Note: paths are illustrative until resolved on the target host.\n");

        println!("Target Application: {}", manifest.target_app);
        println!("Display Source:     {}", display_source);
        println!("X11 Cookie Policy:  Spawn-time generation via 'xauth generate <display> . untrusted' in private 0700 dir [UNTESTED ON LINUX]\n");

        println!("Permission & Enforcement Policy Matrix:");
        println!("  {:<14} {:<12} {:<12} Mechanism & Details", "Resource", "Permission", "Enforced?");
        println!("  {}", "-".repeat(84));

        let (files_lvl, files_desc) = &enforcement["files"];

        let rows = [
            ("Network", if manifest.permissions.network { "Allowed" } else { "Denied" }, format!("{:?}", net_lvl), *net_desc),
            ("Audio", if manifest.permissions.audio { "Allowed" } else { "Denied" }, format!("{:?}", audio_lvl), *audio_desc),
            ("Microphone", "Denied", format!("{:?}", mic_lvl), *mic_desc),
            ("Display", if manifest.permissions.display { "Allowed" } else { "Denied" }, format!("{:?}", disp_lvl), *disp_desc),
            ("GPU / DRI", if manifest.permissions.dri { "Allowed" } else { "Denied" }, format!("{:?}", gpu_lvl), *gpu_desc),
            ("Files", if policy.granted_folders.is_empty() { "Denied" } else { "Allowed" }, format!("{:?}", files_lvl), *files_desc),
        ];

        for (resource, perm, enf, details) in rows {
            println!("  {:<14} {:<12} {:<12} {}", resource, perm, enf, details);
        }

        println!("\nApplication Files & Prefix Layout:");
        println!("  - Wine Prefix Root:    {}", prefix_dir.display());
        println!("  - Windows Drive C:     {}/drive_c", prefix_dir.display());
        println!("  - Application Binary:  {}/drive_c/{}", prefix_dir.display(), manifest.target_app);
        if manifest.filesystem_mappings.is_empty() {
            println!("  - Granted Data Folders: None configured (isolated prefix only)");
        } else {
            println!("  - Granted Data Folders:");
            for mapping in &manifest.filesystem_mappings {
                println!(
                    "      Host: {} -> Container: {} [{}]",
                    mapping.host_path,
                    mapping.guest_path,
                    if mapping.read_only { "Read-Only" } else { "Read-Write" }
                );
            }
        }

        println!("\nGenerated Bubblewrap Argument Vector ({} arguments):", bwrap_args_str.len());
        println!("  bwrap \\");
        for (i, arg) in bwrap_args_str.iter().enumerate() {
            if i + 1 < bwrap_args_str.len() {
                println!("    {} \\", arg);
            } else {
                println!("    {}", arg);
            }
        }
        println!();
    }

    Ok(())
}

fn load_local_recipes() -> Vec<Recipe> {
    let mut recipes = Vec::new();
    let search_dirs = ["recipes/dev", "recipes/community"];

    for dir in &search_dirs {
        let p = Path::new(dir);
        if let Ok(entries) = fs::read_dir(p) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|ext| ext == "toml") {
                    if let Ok(content) = fs::read_to_string(&path) {
                        if let Ok(recipe) = toml::from_str::<Recipe>(&content) {
                            recipes.push(recipe);
                        }
                    }
                }
            }
        }
    }

    recipes
}

