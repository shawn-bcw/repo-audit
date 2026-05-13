use comfy_table::{Table, ContentArrangement};
use comfy_table::presets::UTF8_FULL;
use crate::audit::AuditResult;
use crate::advisory::PackageStatus;
use std::io::IsTerminal;
use colored::Colorize;

pub fn render_full_audit_table(rows: &[(String, AuditResult)]) -> String {
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec!["repo", "low", "medium", "high", "critical", "total"]);

    for (name, result) in rows {
        match result {
            AuditResult::Ok(summary) => {
                table.add_row(vec![
                    name.clone(),
                    summary.low.to_string(),
                    summary.medium.to_string(),
                    summary.high.to_string(),
                    summary.critical.to_string(),
                    summary.total().to_string(),
                ]);
            }
            AuditResult::Error(msg) => {
                table.add_row(vec![
                    name.clone(),
                    format!("Error: {msg}"),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                ]);
            }
        }
    }

    table.to_string()
}

pub fn print_full_audit_table(rows: &[(String, AuditResult)]) {
    let table_str = render_full_audit_table(rows);
    println!("{table_str}");

    let use_color = std::io::stdout().is_terminal();
    if use_color {
        let total_critical: u32 = rows.iter().filter_map(|(_, r)| match r {
            AuditResult::Ok(s) => Some(s.critical),
            _ => None,
        }).sum();
        let total_high: u32 = rows.iter().filter_map(|(_, r)| match r {
            AuditResult::Ok(s) => Some(s.high),
            _ => None,
        }).sum();
        let total_all: u32 = rows.iter().filter_map(|(_, r)| match r {
            AuditResult::Ok(s) => Some(s.total()),
            _ => None,
        }).sum();

        if total_all == 0 {
            println!("{}", "No vulnerabilities found.".green());
        } else {
            let msg = format!("{total_all} vulnerabilities ({total_critical} critical, {total_high} high)");
            if total_critical > 0 {
                println!("{}", msg.red().bold());
            } else if total_high > 0 {
                println!("{}", msg.yellow().bold());
            } else {
                println!("{}", msg.normal());
            }
        }
    }
}

pub fn render_advisory_table(
    advisory_id: &str,
    affected_summary: &str,
    rows: &[(String, Vec<PackageStatus>)],
) -> String {
    let mut output = format!("Advisory: {advisory_id}\nAffected: {affected_summary}\n\n");

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec!["repo", "package", "status"]);

    for (repo_name, statuses) in rows.iter() {
        // Filter to only show statuses that aren't NotFound
        let visible: Vec<_> = statuses.iter()
            .filter(|s| !matches!(s, PackageStatus::NotFound { .. }))
            .collect();

        if visible.is_empty() {
            table.add_row(vec![
                repo_name.clone(),
                "\u{2014}".to_string(),
                "Not found".to_string(),
            ]);
        } else {
            for (j, status) in visible.iter().enumerate() {
                let repo_col = if j == 0 { repo_name.clone() } else { String::new() };
                let (pkg_col, status_col) = match status {
                    PackageStatus::Vulnerable { name, version } => {
                        (format!("{name}@{version}"), "Vulnerable".to_string())
                    }
                    PackageStatus::NotVulnerable { name, version } => {
                        (format!("{name}@{version}"), "Not vulnerable".to_string())
                    }
                    PackageStatus::NotFound { name } => {
                        (name.clone(), "Not found".to_string())
                    }
                    PackageStatus::Unknown { name, version, reason } => {
                        (format!("{name}@{version}"), format!("Unknown \u{2014} {reason}"))
                    }
                    PackageStatus::Clean { name, version } => {
                        (format!("{name}@{version}"), "Clean".to_string())
                    }
                };
                table.add_row(vec![repo_col, pkg_col, status_col]);
            }
        }
    }

    output.push_str(&table.to_string());
    output
}

pub fn print_advisory_table(
    advisory_id: &str,
    affected_summary: &str,
    rows: &[(String, Vec<PackageStatus>)],
) {
    let table_str = render_advisory_table(advisory_id, affected_summary, rows);
    println!("{table_str}");

    let use_color = std::io::stdout().is_terminal();
    if use_color {
        let vuln_count = rows.iter()
            .flat_map(|(_, statuses)| statuses)
            .filter(|s| matches!(s, PackageStatus::Vulnerable { .. }))
            .count();

        if vuln_count == 0 {
            println!("{}", "No repositories affected.".green());
        } else {
            println!("{}", format!("{vuln_count} vulnerable package(s) found.").red().bold());
        }
    }
}
