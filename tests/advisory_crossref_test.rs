use std::collections::HashMap;
use repo_audit::advisory::{AffectedPackage, PackageStatus, check_repo_against_advisory};
use semver::VersionReq;

fn make_affected(name: &str, range: &str, ecosystem: &str) -> AffectedPackage {
    AffectedPackage {
        name: name.to_string(),
        ecosystem: ecosystem.to_string(),
        version_range: range.to_string(),
        parsed_range: VersionReq::parse(range).ok(),
    }
}

#[test]
fn vulnerable_when_version_in_range() {
    let affected = vec![make_affected("express", ">=4.0.0, <4.17.3", "npm")];
    let mut installed = HashMap::new();
    installed.insert("express".to_string(), "4.17.1".to_string());

    let statuses = check_repo_against_advisory(&affected, &installed);
    assert_eq!(statuses.len(), 1);
    assert!(matches!(&statuses[0], PackageStatus::Vulnerable { name, version, .. } if name == "express" && version == "4.17.1"));
}

#[test]
fn not_vulnerable_when_version_outside_range() {
    let affected = vec![make_affected("express", ">=4.0.0, <4.17.3", "npm")];
    let mut installed = HashMap::new();
    installed.insert("express".to_string(), "4.18.2".to_string());

    let statuses = check_repo_against_advisory(&affected, &installed);
    assert!(matches!(&statuses[0], PackageStatus::NotVulnerable { name, version, .. } if name == "express" && version == "4.18.2"));
}

#[test]
fn not_found_when_package_missing() {
    let affected = vec![make_affected("express", ">=4.0.0, <4.17.3", "npm")];
    let installed = HashMap::new();

    let statuses = check_repo_against_advisory(&affected, &installed);
    assert!(matches!(&statuses[0], PackageStatus::NotFound { name, .. } if name == "express"));
}

#[test]
fn multiple_packages_checked() {
    let affected = vec![
        make_affected("express", ">=4.0.0, <4.17.3", "npm"),
        make_affected("lodash", ">=4.0.0, <4.17.21", "npm"),
    ];
    let mut installed = HashMap::new();
    installed.insert("express".to_string(), "4.17.1".to_string());

    let statuses = check_repo_against_advisory(&affected, &installed);
    assert_eq!(statuses.len(), 2);
    assert!(matches!(&statuses[0], PackageStatus::Vulnerable { .. }));
    assert!(matches!(&statuses[1], PackageStatus::NotFound { .. }));
}

#[test]
fn unparseable_range_gives_unknown() {
    let affected = vec![AffectedPackage {
        name: "weird".to_string(),
        ecosystem: "npm".to_string(),
        version_range: "not a version range".to_string(),
        parsed_range: None,
    }];
    let mut installed = HashMap::new();
    installed.insert("weird".to_string(), "1.0.0".to_string());

    let statuses = check_repo_against_advisory(&affected, &installed);
    assert!(matches!(&statuses[0], PackageStatus::Unknown { .. }));
}
