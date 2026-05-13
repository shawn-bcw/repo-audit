use repo_audit::advisory::{parse_advisory_url, AdvisorySource};

#[test]
fn detect_ghsa_url() {
    let source = parse_advisory_url("https://github.com/advisories/GHSA-qwcr-r2fm-qrc7");
    assert!(matches!(source, AdvisorySource::Ghsa { id } if id == "GHSA-qwcr-r2fm-qrc7"));
}

#[test]
fn detect_nvd_url() {
    let source = parse_advisory_url("https://nvd.nist.gov/vuln/detail/CVE-2024-48949");
    assert!(matches!(source, AdvisorySource::Nvd { id } if id == "CVE-2024-48949"));
}

#[test]
fn detect_unknown_url() {
    let source = parse_advisory_url("https://example.com/something");
    assert!(matches!(source, AdvisorySource::Unknown));
}

#[test]
fn parse_ghsa_json_extracts_packages() {
    let json = std::fs::read_to_string("tests/fixtures/ghsa_api_response.json").unwrap();
    let packages = repo_audit::advisory::parse_ghsa_json(&json);
    assert!(!packages.is_empty());
    assert!(packages.iter().any(|p| p.name == "body-parser"));
    assert!(packages.iter().any(|p| p.ecosystem == "npm"));
    // Check that version range was parsed
    assert!(packages[0].parsed_range.is_some());
}
