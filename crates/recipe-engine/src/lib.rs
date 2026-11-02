pub mod catalog;
pub mod fallback;
pub mod matching;
pub mod resolver;
pub mod types;
pub mod verifier;

pub use catalog::{DependencyCatalog, DependencyEntry};
pub use fallback::generate_fallback_recipe;
pub use matching::{match_recipe, RecipeMatchResult};
pub use resolver::{DependencyResolver, ResolvedDependencyPlan};
pub use types::{
    MatchRules, Recipe, RecipeSignature, RegistryEntry, RegistryValueType, RuntimeRecipeConfig,
    TestedResult,
};
pub use verifier::{verify_recipe, KeyRegistry, DEV_KEY_ID, DEV_PUBKEY, PROD_KEY_ID_2026_V1};

#[cfg(test)]
mod tests;
