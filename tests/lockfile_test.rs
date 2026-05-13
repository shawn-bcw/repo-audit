use std::path::Path;

#[test]
fn parse_npm_lockfile_extracts_packages() {
    let packages = repo_audit::lockfile::parse_npm_lockfile(
        Path::new("tests/fixtures/package-lock.json")
    ).unwrap();
    assert_eq!(packages.get("express"), Some(&"4.17.1".to_string()));
    assert_eq!(packages.get("lodash"), Some(&"4.17.21".to_string()));
    assert_eq!(packages.get("@tanstack/arktype-adapter"), Some(&"0.2.1".to_string()));
}

#[test]
fn parse_npm_lockfile_skips_root_package() {
    let packages = repo_audit::lockfile::parse_npm_lockfile(
        Path::new("tests/fixtures/package-lock.json")
    ).unwrap();
    assert!(!packages.contains_key("test-project"));
    assert!(!packages.contains_key(""));
}

#[test]
fn parse_cargo_lockfile_extracts_packages() {
    let packages = repo_audit::lockfile::parse_cargo_lockfile(
        Path::new("tests/fixtures/Cargo.lock")
    ).unwrap();
    assert_eq!(packages.get("serde"), Some(&"1.0.197".to_string()));
    assert_eq!(packages.get("tokio"), Some(&"1.37.0".to_string()));
    assert_eq!(packages.get("some-crate"), Some(&"1.0.0".to_string()));
}

#[test]
fn parse_npm_lockfile_missing_file_returns_error() {
    let result = repo_audit::lockfile::parse_npm_lockfile(Path::new("nonexistent.json"));
    assert!(result.is_err());
}

#[test]
fn parse_cargo_lockfile_missing_file_returns_error() {
    let result = repo_audit::lockfile::parse_cargo_lockfile(Path::new("nonexistent.lock"));
    assert!(result.is_err());
}

#[test]
fn parse_pnpm_lockfile_extracts_packages() {
    let packages = repo_audit::lockfile::parse_pnpm_lockfile(
        Path::new("tests/fixtures/pnpm-lock.yaml")
    ).unwrap();
    assert_eq!(packages.get("express"), Some(&"4.18.2".to_string()));
    assert_eq!(packages.get("lodash"), Some(&"4.17.21".to_string()));
    assert_eq!(packages.get("@babel/core"), Some(&"7.27.1".to_string()));
}

#[test]
fn parse_pnpm_lockfile_missing_file_returns_error() {
    let result = repo_audit::lockfile::parse_pnpm_lockfile(Path::new("nonexistent.yaml"));
    assert!(result.is_err());
}
