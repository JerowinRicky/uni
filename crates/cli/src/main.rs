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
                println!("  - {} v{} [{}] (URL: {})", dep.id, dep.version, status, dep.source_url);
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

