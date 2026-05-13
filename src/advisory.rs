// Advisory URL fetching and parsing

use semver::VersionReq;
use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct AffectedPackage {
    pub name: String,
    pub ecosystem: String,
    pub version_range: String,
    pub parsed_range: Option<VersionReq>,
}

#[derive(Debug)]
pub enum AdvisorySource {
    Ghsa { id: String },
    Nvd { id: String },
    Unknown,
}

/// Detect whether a URL points to a GHSA advisory, NVD advisory, or something else.
pub fn parse_advisory_url(url: &str) -> AdvisorySource {
    // Global GHSA: https://github.com/advisories/GHSA-xxxx-xxxx-xxxx
    // Repo GHSA:   https://github.com/{owner}/{repo}/security/advisories/GHSA-xxxx-xxxx-xxxx
    if url.starts_with("https://github.com/") {
        if let Some(pos) = url.find("GHSA-") {
            let id = url[pos..].split('/').next().unwrap_or("").split('?').next().unwrap_or("").to_string();
            if !id.is_empty() {
                return AdvisorySource::Ghsa { id };
            }
        }
    }

    // NVD URLs: https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN
    if let Some(rest) = url.strip_prefix("https://nvd.nist.gov/vuln/detail/") {
        let id = rest.split('/').next().unwrap_or("").to_string();
        if !id.is_empty() {
            return AdvisorySource::Nvd { id };
        }
    }

    AdvisorySource::Unknown
}

/// Dispatch to the appropriate fetcher based on the URL.
pub fn fetch_advisory(url: &str) -> Result<Vec<AffectedPackage>, String> {
    match parse_advisory_url(url) {
        AdvisorySource::Ghsa { .. } => fetch_ghsa(url),
        AdvisorySource::Nvd { id } => fetch_nvd(&id),
        AdvisorySource::Unknown => Err(format!("Unrecognized advisory URL: {}", url)),
    }
}

/// Extract GHSA ID from URL, call the GitHub Advisory REST API, and parse the response.
pub fn fetch_ghsa(url: &str) -> Result<Vec<AffectedPackage>, String> {
    let ghsa_id = match parse_advisory_url(url) {
        AdvisorySource::Ghsa { id } => id,
        _ => return Err(format!("Not a GHSA URL: {}", url)),
    };

    let api_url = format!("https://api.github.com/advisories/{}", ghsa_id);

    let client = reqwest::blocking::Client::builder()
        .user_agent("repo-audit/0.1.0")
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    let response = client
        .get(&api_url)
        .send()
        .map_err(|e| format!("Failed to fetch GHSA advisory {}: {}", ghsa_id, e))?;

    if !response.status().is_success() {
        return Err(format!(
            "GitHub API returned status {} for {}",
            response.status(),
            api_url
        ));
    }

    let json = response
        .text()
        .map_err(|e| format!("Failed to read GHSA response body: {}", e))?;

    Ok(parse_ghsa_json(&json))
}

// Internal deserialization types for the GitHub Advisory API response.
#[derive(Deserialize)]
struct GhsaResponse {
    vulnerabilities: Option<Vec<GhsaVulnerability>>,
}

#[derive(Deserialize)]
struct GhsaVulnerability {
    package: GhsaPackage,
    vulnerable_version_range: Option<String>,
}

#[derive(Deserialize)]
struct GhsaPackage {
    ecosystem: String,
    name: String,
}

/// Parse the JSON body of a GitHub Advisory API response into a list of affected packages.
pub fn parse_ghsa_json(json: &str) -> Vec<AffectedPackage> {
    let response: GhsaResponse = match serde_json::from_str(json) {
        Ok(r) => r,
        Err(_) => return vec![],
    };

    let vulnerabilities = match response.vulnerabilities {
        Some(v) => v,
        None => return vec![],
    };

    vulnerabilities
        .into_iter()
        .map(|vuln| {
            let version_range = vuln.vulnerable_version_range.unwrap_or_default();
            let parsed_range = VersionReq::parse(&version_range).ok();
            AffectedPackage {
                name: vuln.package.name,
                ecosystem: vuln.package.ecosystem.to_lowercase(),
                version_range,
                parsed_range,
            }
        })
        .collect()
}

// Internal deserialization types for the NVD API response.
#[derive(Deserialize)]
struct NvdResponse {
    vulnerabilities: Option<Vec<NvdItem>>,
}

#[derive(Deserialize)]
struct NvdItem {
    cve: NvdCve,
}

#[derive(Deserialize)]
struct NvdCve {
    configurations: Option<Vec<NvdConfiguration>>,
}

#[derive(Deserialize)]
struct NvdConfiguration {
    nodes: Vec<NvdNode>,
}

#[derive(Deserialize)]
struct NvdNode {
    #[serde(rename = "cpeMatch")]
    cpe_match: Option<Vec<NvdCpeMatch>>,
}

#[derive(Deserialize)]
struct NvdCpeMatch {
    criteria: String,
    #[serde(rename = "versionEndExcluding")]
    version_end_excluding: Option<String>,
    #[serde(rename = "versionStartIncluding")]
    version_start_including: Option<String>,
    #[serde(rename = "versionEndIncluding")]
    version_end_including: Option<String>,
}

/// Fetch a CVE from the NVD API and parse the CPE entries into affected packages.
pub fn fetch_nvd(cve_id: &str) -> Result<Vec<AffectedPackage>, String> {
    let api_url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}",
        cve_id
    );

    let client = reqwest::blocking::Client::builder()
        .user_agent("repo-audit/0.1.0")
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    let response = client
        .get(&api_url)
        .send()
        .map_err(|e| format!("Failed to fetch NVD advisory {}: {}", cve_id, e))?;

    if !response.status().is_success() {
        return Err(format!(
            "NVD API returned status {} for {}",
            response.status(),
            api_url
        ));
    }

    let json = response
        .text()
        .map_err(|e| format!("Failed to read NVD response body: {}", e))?;

    parse_nvd_response(&json)
}

/// Parse the JSON body of an NVD API response into a list of affected packages derived from CPEs.
pub fn parse_nvd_response(json: &str) -> Result<Vec<AffectedPackage>, String> {
    let response: NvdResponse =
        serde_json::from_str(json).map_err(|e| format!("Failed to parse NVD JSON: {}", e))?;

    let mut packages = Vec::new();

    let vulnerabilities = response.vulnerabilities.unwrap_or_default();
    for item in vulnerabilities {
        let configs = item.cve.configurations.unwrap_or_default();
        for config in configs {
            for node in config.nodes {
                let cpe_matches = node.cpe_match.unwrap_or_default();
                for cpe in cpe_matches {
                    // CPE format: cpe:2.3:a:<vendor>:<product>:*:...
                    let parts: Vec<&str> = cpe.criteria.split(':').collect();
                    // parts[3] = vendor, parts[4] = product
                    let name = if parts.len() > 4 {
                        format!("{}/{}", parts[3], parts[4])
                    } else {
                        cpe.criteria.clone()
                    };

                    // Build a version range string from the NVD fields.
                    let version_range = match (
                        &cpe.version_start_including,
                        &cpe.version_end_excluding,
                        &cpe.version_end_including,
                    ) {
                        (Some(start), Some(end), _) => {
                            format!(">= {}, < {}", start, end)
                        }
                        (Some(start), None, Some(end)) => {
                            format!(">= {}, <= {}", start, end)
                        }
                        (None, Some(end), _) => format!("< {}", end),
                        (None, None, Some(end)) => format!("<= {}", end),
                        _ => String::new(),
                    };

                    let parsed_range = if version_range.is_empty() {
                        None
                    } else {
                        VersionReq::parse(&version_range).ok()
                    };

                    packages.push(AffectedPackage {
                        name,
                        ecosystem: "nvd-cpe".to_string(),
                        version_range,
                        parsed_range,
                    });
                }
            }
        }
    }

    Ok(packages)
}

#[derive(Debug)]
pub enum PackageStatus {
    Vulnerable { name: String, version: String },
    NotVulnerable { name: String, version: String },
    NotFound { name: String },
    Unknown { name: String, version: String, reason: String },
    Clean { name: String, version: String },
}

pub fn check_repo_against_advisory(
    affected: &[AffectedPackage],
    installed: &std::collections::HashMap<String, String>,
) -> Vec<PackageStatus> {
    let mut results = Vec::new();
    let affected_names: std::collections::HashSet<&str> = affected.iter().map(|p| p.name.as_str()).collect();

    for pkg in affected {
        match installed.get(&pkg.name) {
            None => {
                results.push(PackageStatus::NotFound { name: pkg.name.clone() });
            }
            Some(version_str) => {
                let parsed_version = semver::Version::parse(version_str);
                match (&pkg.parsed_range, parsed_version) {
                    (Some(range), Ok(version)) => {
                        if range.matches(&version) {
                            results.push(PackageStatus::Vulnerable {
                                name: pkg.name.clone(),
                                version: version_str.clone(),
                            });
                        } else {
                            results.push(PackageStatus::NotVulnerable {
                                name: pkg.name.clone(),
                                version: version_str.clone(),
                            });
                        }
                    }
                    (None, _) => {
                        results.push(PackageStatus::Unknown {
                            name: pkg.name.clone(),
                            version: version_str.clone(),
                            reason: "could not parse version range".to_string(),
                        });
                    }
                    (_, Err(_)) => {
                        results.push(PackageStatus::Unknown {
                            name: pkg.name.clone(),
                            version: version_str.clone(),
                            reason: "could not parse installed version".to_string(),
                        });
                    }
                }
            }
        }
    }

    // Find related packages from the same scope that aren't affected
    let scopes: std::collections::HashSet<&str> = affected.iter()
        .filter_map(|p| {
            if p.name.starts_with('@') {
                p.name.find('/').map(|pos| &p.name[..pos])
            } else {
                None
            }
        })
        .collect();

    if !scopes.is_empty() {
        let mut clean: Vec<PackageStatus> = installed.iter()
            .filter(|(name, _)| {
                !affected_names.contains(name.as_str())
                    && scopes.iter().any(|scope| name.starts_with(scope))
            })
            .map(|(name, version)| PackageStatus::Clean {
                name: name.clone(),
                version: version.clone(),
            })
            .collect();
        clean.sort_by(|a, b| {
            let a_name = match a { PackageStatus::Clean { name, .. } => name, _ => "" };
            let b_name = match b { PackageStatus::Clean { name, .. } => name, _ => "" };
            a_name.cmp(b_name)
        });
        results.extend(clean);
    }

    results
}
