//! CSV report export (RFC 4180 compliant)

use crate::error::Result;
use crate::models::ScanResult;
use std::io::Write;
use std::path::Path;
use tracing::info;

/// Escapes a field for CSV according to RFC 4180
fn escape_csv(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') || field.contains('\r') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

/// Exports scan results as a CSV file
pub fn export(result: &ScanResult, output_path: &Path) -> Result<()> {
    let file = std::fs::File::create(output_path)?;
    let mut writer = std::io::BufWriter::new(file);

    // Header
    writeln!(
        writer,
        "severity,confidence,title,category,url,cwe_id,owasp_category,description,evidence"
    )?;

    for f in &result.findings {
        let row = format!(
            "{},{},{},{},{},{},{},{},{}",
            escape_csv(&f.severity.to_string()),
            escape_csv(&f.confidence.to_string()),
            escape_csv(&f.title),
            escape_csv(&f.category),
            escape_csv(&f.url),
            escape_csv(f.cwe_id.as_deref().unwrap_or("")),
            escape_csv(f.owasp_category.as_deref().unwrap_or("")),
            escape_csv(&f.description),
            escape_csv(&f.evidence),
        );
        writeln!(writer, "{}", row)?;
    }

    writer.flush()?;
    info!("CSV report saved to {}", output_path.display());
    Ok(())
}
