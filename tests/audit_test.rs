use std::fs;

#[test]
fn parse_npm_audit_json() {
    let json = fs::read_to_string("tests/fixtures/npm_audit_output.json").unwrap();
    let result = repo_audit::audit::parse_npm_audit(&json).unwrap();
    assert_eq!(result.low, 1);
    assert_eq!(result.medium, 1);
    assert_eq!(result.high, 1);
    assert_eq!(result.critical, 1);
    assert_eq!(result.total(), 4);
}

#[test]
fn parse_npm_audit_empty_vulnerabilities() {
    let json = r#"{"auditReportVersion":2,"vulnerabilities":{},"metadata":{"vulnerabilities":{"info":0,"low":0,"moderate":0,"high":0,"critical":0,"total":0}}}"#;
    let result = repo_audit::audit::parse_npm_audit(json).unwrap();
    assert_eq!(result.total(), 0);
}

#[test]
fn parse_npm_audit_malformed_json() {
    let result = repo_audit::audit::parse_npm_audit("not json");
    assert!(result.is_err());
}

#[test]
fn parse_cargo_audit_json() {
    let json = fs::read_to_string("tests/fixtures/cargo_audit_output.json").unwrap();
    let result = repo_audit::audit::parse_cargo_audit(&json).unwrap();
    assert_eq!(result.low, 1);     // cvss 2.5
    assert_eq!(result.medium, 0);
    assert_eq!(result.high, 1);    // cvss 8.1
    assert_eq!(result.critical, 1); // cvss 9.8
    assert_eq!(result.total(), 3);
}

#[test]
fn parse_cargo_audit_no_vulnerabilities() {
    let json = r#"{"database":{},"lockfile":{},"vulnerabilities":{"found":false,"count":0,"list":[]}}"#;
    let result = repo_audit::audit::parse_cargo_audit(json).unwrap();
    assert_eq!(result.total(), 0);
}

#[test]
fn parse_cargo_audit_missing_cvss_defaults_to_medium() {
    let json = r#"{"database":{},"lockfile":{},"vulnerabilities":{"found":true,"count":1,"list":[{"advisory":{"id":"RUSTSEC-0000","title":"test"},"versions":{"patched":[],"unaffected":[]},"package":{"name":"x","version":"1.0.0"}}]}}"#;
    let result = repo_audit::audit::parse_cargo_audit(json).unwrap();
    assert_eq!(result.medium, 1);
}
