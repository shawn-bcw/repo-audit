use repo_audit::audit::{AuditResult, VulnSummary};
use repo_audit::report::render_full_audit_table;

#[test]
fn full_audit_table_contains_repo_names() {
    let rows = vec![
        ("alpha-repo".to_string(), AuditResult::Ok(VulnSummary { low: 1, medium: 2, high: 0, critical: 0 })),
        ("beta-repo".to_string(), AuditResult::Ok(VulnSummary::default())),
    ];
    let output = render_full_audit_table(&rows);
    assert!(output.contains("alpha-repo"));
    assert!(output.contains("beta-repo"));
}

#[test]
fn full_audit_table_shows_error_row() {
    let rows = vec![
        ("broken-repo".to_string(), AuditResult::Error("timed out".to_string())),
    ];
    let output = render_full_audit_table(&rows);
    assert!(output.contains("broken-repo"));
    assert!(output.contains("timed out"));
}

#[test]
fn full_audit_table_shows_correct_counts() {
    let rows = vec![
        ("my-repo".to_string(), AuditResult::Ok(VulnSummary { low: 3, medium: 1, high: 2, critical: 0 })),
    ];
    let output = render_full_audit_table(&rows);
    assert!(output.contains("3")); // low
    assert!(output.contains("6")); // total
}

use repo_audit::advisory::PackageStatus;
use repo_audit::report::render_advisory_table;

#[test]
fn advisory_table_groups_by_repo() {
    let rows = vec![
        ("repo-a".to_string(), vec![
            PackageStatus::Vulnerable { name: "express".to_string(), version: "4.17.1".to_string() },
            PackageStatus::NotFound { name: "lodash".to_string() },
        ]),
        ("repo-b".to_string(), vec![
            PackageStatus::NotVulnerable { name: "express".to_string(), version: "4.18.2".to_string() },
        ]),
    ];
    let output = render_advisory_table("GHSA-xxxx", "express < 4.17.3, lodash < 4.17.21 (npm)", &rows);
    assert!(output.contains("repo-a"));
    assert!(output.contains("repo-b"));
    assert!(output.contains("Vulnerable"));
    assert!(output.contains("Not vulnerable"));
    assert!(output.contains("Not found"));
}

#[test]
fn advisory_table_repo_with_no_packages_shows_dash() {
    let rows = vec![
        ("empty-repo".to_string(), vec![
            PackageStatus::NotFound { name: "express".to_string() },
            PackageStatus::NotFound { name: "lodash".to_string() },
        ]),
    ];
    let output = render_advisory_table("GHSA-xxxx", "express, lodash (npm)", &rows);
    assert!(output.contains("empty-repo"));
}

#[test]
fn advisory_table_header_shows_advisory_info() {
    let rows = vec![];
    let output = render_advisory_table("GHSA-xxxx-yyyy", "express < 4.17.3 (npm)", &rows);
    assert!(output.contains("GHSA-xxxx-yyyy"));
    assert!(output.contains("express < 4.17.3 (npm)"));
}
