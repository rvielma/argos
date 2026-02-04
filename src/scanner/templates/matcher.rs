//! Response matching for CVE template evaluation

use regex::Regex;

use super::loader::TemplateMatcher;

/// Result of evaluating a response against matchers
pub struct MatchResult {
    pub matched: bool,
    pub evidence: String,
}

/// Evaluates a response against a single matcher
pub fn evaluate_matcher(
    matcher: &TemplateMatcher,
    status_code: u16,
    body: &str,
    headers: &[(String, String)],
    response_time_secs: f64,
) -> MatchResult {
    match matcher.matcher_type.as_str() {
        "status" => evaluate_status(matcher, status_code),
        "body" | "word" => evaluate_body_words(matcher, body),
        "regex" => evaluate_regex(matcher, body),
        "header" => evaluate_header(matcher, headers),
        "time" | "duration" => evaluate_response_time(matcher, response_time_secs),
        _ => MatchResult {
            matched: false,
            evidence: format!("Unknown matcher type: {}", matcher.matcher_type),
        },
    }
}

/// Evaluates a version matcher against extracted variables
pub fn evaluate_version_matcher(
    matcher: &TemplateMatcher,
    variables: &std::collections::HashMap<String, String>,
) -> MatchResult {
    let var_name = match &matcher.variable {
        Some(v) => v,
        None => {
            return MatchResult {
                matched: false,
                evidence: "No variable specified for version matcher".to_string(),
            }
        }
    };

    let version_str = match variables.get(var_name) {
        Some(v) => v,
        None => {
            return MatchResult {
                matched: false,
                evidence: format!("Variable '{}' not found", var_name),
            }
        }
    };

    let range_str = match &matcher.version_range {
        Some(r) => r,
        None => {
            return MatchResult {
                matched: false,
                evidence: "No version_range specified".to_string(),
            }
        }
    };

    let detected = parse_version(version_str);
    let matched = evaluate_version_range(&detected, range_str);

    MatchResult {
        matched,
        evidence: format!(
            "Version {} {} range {}",
            version_str,
            if matched { "matches" } else { "outside" },
            range_str
        ),
    }
}

/// Parses a version string like "2.4.51" into a comparable Vec<u64>
fn parse_version(s: &str) -> Vec<u64> {
    s.split('.')
        .filter_map(|part| {
            // Extract leading digits from each part (handles "8.5.78-beta" etc.)
            let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
            digits.parse().ok()
        })
        .collect()
}

/// Compares two version vectors
fn version_cmp(a: &[u64], b: &[u64]) -> std::cmp::Ordering {
    let max_len = a.len().max(b.len());
    for i in 0..max_len {
        let va = a.get(i).copied().unwrap_or(0);
        let vb = b.get(i).copied().unwrap_or(0);
        match va.cmp(&vb) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}

/// Evaluates a version range expression like "< 2.4.51" or ">= 8.0 < 8.5.78"
fn evaluate_version_range(detected: &[u64], range: &str) -> bool {
    // Split by spaces to handle compound ranges like ">= 8.0 < 8.5.78"
    let parts: Vec<&str> = range.split_whitespace().collect();
    let mut i = 0;

    while i < parts.len() {
        let (op, ver_str) = if parts[i].starts_with("<=")
            || parts[i].starts_with(">=")
            || parts[i].starts_with("!=")
        {
            if parts[i].len() > 2 {
                (&parts[i][..2], &parts[i][2..])
            } else if i + 1 < parts.len() {
                i += 1;
                (parts[i - 1], parts[i])
            } else {
                return false;
            }
        } else if parts[i].starts_with('<') || parts[i].starts_with('>') || parts[i].starts_with('=')
        {
            if parts[i].len() > 1 {
                (&parts[i][..1], &parts[i][1..])
            } else if i + 1 < parts.len() {
                i += 1;
                (parts[i - 1], parts[i])
            } else {
                return false;
            }
        } else {
            i += 1;
            continue;
        };

        let target = parse_version(ver_str);
        let cmp = version_cmp(detected, &target);

        let result = match op {
            "<" => cmp == std::cmp::Ordering::Less,
            "<=" => cmp != std::cmp::Ordering::Greater,
            ">" => cmp == std::cmp::Ordering::Greater,
            ">=" => cmp != std::cmp::Ordering::Less,
            "=" | "==" => cmp == std::cmp::Ordering::Equal,
            "!=" => cmp != std::cmp::Ordering::Equal,
            _ => return false,
        };

        if !result {
            return false;
        }

        i += 1;
    }

    true
}

/// Evaluates all matchers with AND/OR condition
pub fn evaluate_matchers(
    matchers: &[TemplateMatcher],
    condition: &str,
    status_code: u16,
    body: &str,
    headers: &[(String, String)],
    response_time_secs: f64,
) -> MatchResult {
    let results: Vec<MatchResult> = matchers
        .iter()
        .map(|m| evaluate_matcher(m, status_code, body, headers, response_time_secs))
        .collect();

    let evidence: Vec<String> = results
        .iter()
        .filter(|r| r.matched)
        .map(|r| r.evidence.clone())
        .collect();

    let matched = if condition == "or" {
        results.iter().any(|r| r.matched)
    } else {
        results.iter().all(|r| r.matched)
    };

    MatchResult {
        matched,
        evidence: evidence.join("\n"),
    }
}

fn evaluate_status(matcher: &TemplateMatcher, status_code: u16) -> MatchResult {
    if let Some(ref statuses) = matcher.status {
        let matched = statuses.contains(&status_code);
        MatchResult {
            matched,
            evidence: format!("Status code: {status_code}"),
        }
    } else {
        MatchResult {
            matched: false,
            evidence: "No status codes specified".to_string(),
        }
    }
}

fn evaluate_body_words(matcher: &TemplateMatcher, body: &str) -> MatchResult {
    if let Some(ref words) = matcher.words {
        let found: Vec<&String> = words.iter().filter(|w| body.contains(w.as_str())).collect();
        // ALL words must be present to match (AND logic)
        let matched = found.len() == words.len();
        MatchResult {
            matched,
            evidence: if matched {
                format!(
                    "Body contains all: {}",
                    found
                        .iter()
                        .map(|w| w.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            } else {
                format!(
                    "Body missing: {}",
                    words
                        .iter()
                        .filter(|w| !body.contains(w.as_str()))
                        .map(|w| w.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            },
        }
    } else {
        MatchResult {
            matched: false,
            evidence: "No words specified".to_string(),
        }
    }
}

fn evaluate_regex(matcher: &TemplateMatcher, body: &str) -> MatchResult {
    if let Some(ref patterns) = matcher.regex {
        for pattern in patterns {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(m) = re.find(body) {
                    return MatchResult {
                        matched: true,
                        evidence: format!("Regex match: {} -> '{}'", pattern, m.as_str()),
                    };
                }
            }
        }
        MatchResult {
            matched: false,
            evidence: "No regex patterns matched".to_string(),
        }
    } else {
        MatchResult {
            matched: false,
            evidence: "No regex patterns specified".to_string(),
        }
    }
}

fn evaluate_header(matcher: &TemplateMatcher, headers: &[(String, String)]) -> MatchResult {
    if let Some(ref header_name) = matcher.header {
        if let Some(ref words) = matcher.words {
            for (name, value) in headers {
                if name.to_lowercase() == header_name.to_lowercase() {
                    let found: Vec<&String> = words
                        .iter()
                        .filter(|w| value.contains(w.as_str()))
                        .collect();
                    if !found.is_empty() {
                        return MatchResult {
                            matched: true,
                            evidence: format!("Header {name}: {value}"),
                        };
                    }
                }
            }
        }
        MatchResult {
            matched: false,
            evidence: format!("Header '{header_name}' not matched"),
        }
    } else {
        MatchResult {
            matched: false,
            evidence: "No header specified".to_string(),
        }
    }
}

fn evaluate_response_time(matcher: &TemplateMatcher, response_time_secs: f64) -> MatchResult {
    if let Some(duration) = matcher.duration {
        let matched = response_time_secs >= duration;
        MatchResult {
            matched,
            evidence: format!(
                "Response time: {response_time_secs:.1}s (threshold: {duration:.1}s)"
            ),
        }
    } else {
        MatchResult {
            matched: false,
            evidence: "No duration specified".to_string(),
        }
    }
}
