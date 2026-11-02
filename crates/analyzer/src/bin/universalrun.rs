use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "universalrun", about = "UniversalRun orchestration and compatibility platform")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze a Windows PE (.exe) or MSI file
    Analyze {
        /// Target executable or installer to analyze
        file: PathBuf,

        /// Output findings as formatted JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Analyze { file, json } => {
            let report = universalrun_analyzer::analyze_file(&file)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("UniversalRun Analysis Report");
                println!("============================");
                println!("Target: {}", report.file_name);
                println!("Architecture: {}", report.architecture.map(|a| a.to_string()).unwrap_or_else(|| "null (installer)".to_string()));
                println!("Installer: {:?}", report.installer_type.value);
                println!("Rating: {:?} ({})", report.compatibility_rating.category, report.compatibility_rating.summary);
            }
        }
    }
    Ok(())
}

