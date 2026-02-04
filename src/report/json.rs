//! JSON report export

use crate::error::Result;
use crate::models::ScanResult;
use std::path::Path;
use tracing::info;

/// Exports scan results as a JSON file
pub fn export(result: &ScanResult, output_path: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(result)?;
    std::fs::write(output_path, json)?;
    info!("JSON report saved to {}", output_path.display());
    Ok(())
}

/// Loads a ScanResult from a JSON file
pub fn load(input_path: &Path) -> Result<ScanResult> {
    let content = std::fs::read_to_string(input_path)?;
    let result: ScanResult = serde_json::from_str(&content)?;
    Ok(result)
}
