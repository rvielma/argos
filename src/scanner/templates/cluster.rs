//! Template clustering: groups single-GET templates by path to reduce HTTP requests

use std::collections::HashMap;

use super::loader::CveTemplate;

/// Groups templates that can share a single HTTP response
pub struct TemplateCluster {
    /// Templates grouped by (method, path) — each group shares one request
    pub clusters: HashMap<String, Vec<CveTemplate>>,
    /// Templates that cannot be clustered (multi-step, POST, extractors, etc.)
    pub unclustered: Vec<CveTemplate>,
}

impl TemplateCluster {
    /// Groups templates into clusters based on method + path.
    /// Only single-request GET templates without extractors or variables can be clustered.
    pub fn from_templates(templates: Vec<CveTemplate>) -> Self {
        let mut clusters: HashMap<String, Vec<CveTemplate>> = HashMap::new();
        let mut unclustered = Vec::new();

        for template in templates {
            if Self::can_cluster(&template) {
                let key = Self::cluster_key(&template);
                clusters.entry(key).or_default().push(template);
            } else {
                unclustered.push(template);
            }
        }

        Self {
            clusters,
            unclustered,
        }
    }

    /// A template can be clustered if it has exactly 1 request, uses GET,
    /// has no extractors, no variables, and no stop_at_first_match.
    fn can_cluster(template: &CveTemplate) -> bool {
        if template.requests.len() != 1 {
            return false;
        }
        if !template.variables.is_empty() {
            return false;
        }
        let req = &template.requests[0];
        if req.method.to_uppercase() != "GET" {
            return false;
        }
        if !req.extractors.is_empty() {
            return false;
        }
        if req.stop_at_first_match {
            return false;
        }
        true
    }

    fn cluster_key(template: &CveTemplate) -> String {
        let req = &template.requests[0];
        format!("GET:{}", req.path.trim_start_matches('/'))
    }
}
