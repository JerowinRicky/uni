use thiserror::Error;

#[derive(Error, Debug)]
pub enum UniversalRunError {
    #[error("Sandbox error: {0}")]
    Sandbox(String),

    #[error("Runtime error: {0}")]
    Runtime(String),

    #[error("Analyzer error: {0}")]
    Analyzer(String),

    #[error("Profile error: {0}")]
    Profile(String),

    #[error("Recipe error: {0}")]
    Recipe(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, UniversalRunError>;
