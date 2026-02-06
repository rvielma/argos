//! JSONL (JSON Lines) report export — one JSON object per line

use crate::error::Result;
use crate::models::ScanResult;
use std::io::Write;
use std::path::Path;
use tracing::info;

/// Exports scan results as a JSONL file (one finding per line)
pub fn export(result: &ScanResult, output_path: &Path) -> Result<()> {
    let file = std::fs::File::create(output_path)?;
    let mut writer = std::io::BufWriter::new(file);

    for finding in &result.findings {
        let line = serde_json::to_string(finding)?;
        writeln!(writer, "{}", line)?;
    }

    writer.flush()?;
    info!("JSONL report saved to {}", output_path.display());
    Ok(())
}
