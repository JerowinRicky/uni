use crate::fallback::generate_fallback_recipe;
use crate::types::Recipe;
use universalrun_analyzer::AnalysisReport;
use universalrun_common::error::Result;

pub enum RecipeMatchResult {
    /// Exact SHA-256 cryptographic match (highest confidence).
    ExactSha256(Recipe),
    /// Product name and version match.
    ProductName(Recipe),
    /// Fallback recipe synthesized on-the-fly from static analysis.
    SynthesizedFallback(Recipe),
}

impl RecipeMatchResult {
    pub fn recipe(&self) -> &Recipe {
        match self {
            RecipeMatchResult::ExactSha256(r) => r,
            RecipeMatchResult::ProductName(r) => r,
            RecipeMatchResult::SynthesizedFallback(r) => r,
        }
    }

    pub fn match_type(&self) -> &'static str {
        match self {
            RecipeMatchResult::ExactSha256(_) => "exact_sha256",
            RecipeMatchResult::ProductName(_) => "product_name",
            RecipeMatchResult::SynthesizedFallback(_) => "synthesized_fallback",
        }
    }
}

/// Match candidate recipes against an executable's AnalysisReport.
///
/// Precedence:
/// 1. Exact SHA-256 match in `recipe.match_rules.sha256`.
/// 2. Product name match in `recipe.match_rules.product_name`.
/// 3. Generic fallback recipe synthesized from static binary analysis.
pub fn match_recipe(
    report: &AnalysisReport,
    candidate_recipes: &[Recipe],
) -> Result<RecipeMatchResult> {
    // 1. Highest precedence: Exact SHA-256 match
    for recipe in candidate_recipes {
        if recipe
            .match_rules
            .sha256
            .iter()
            .any(|hash| hash.eq_ignore_ascii_case(&report.sha256))
        {
            return Ok(RecipeMatchResult::ExactSha256(recipe.clone()));
        }
    }

    // 2. Product name match
    for recipe in candidate_recipes {
        if let Some(prod_name) = &recipe.match_rules.product_name {
            if report
                .file_name
                .to_ascii_lowercase()
                .contains(&prod_name.to_ascii_lowercase())
            {
                return Ok(RecipeMatchResult::ProductName(recipe.clone()));
            }
        }
    }

    // 3. Fallback: Synthesized recipe from static analysis
    let fallback = generate_fallback_recipe(report);
    Ok(RecipeMatchResult::SynthesizedFallback(fallback))
}

