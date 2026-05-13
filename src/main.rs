use clap::Parser;
use std::path::PathBuf;
use std::process;
use repo_audit::{discover, tools, audit, lockfile, advisory, report};

#[derive(Parser)]
#[command(name = "repo-audit", about = "Audit sibling repositories for package vulnerabilities")]
struct Cli {
    #[arg(long, help = "Root directory to scan (defaults to current directory)")]
    dir: Option<PathBuf>,

    #[arg(long, help = "Advisory URL (GHSA or CVE/NVD) to check against repos")]
    advisory: Vec<String>,

    #[arg(long, help = "Show scan details and raw audit commands")]
    verbose: bool,
}

fn main() {
    let cli = Cli::parse();
    let root = cli.dir.unwrap_or_else(|| std::env::current_dir().expect("cannot read current directory"));

    if !root.is_dir() {
        eprintln!("Error: {} is not a directory", root.display());
        process::exit(2);
    }

    if cli.advisory.is_empty() {
        match run_full_audit(&root, cli.verbose) {
            Ok(found_vulns) => process::exit(if found_vulns { 1 } else { 0 }),
            Err(e) => {
                eprintln!("Error: {e}");
                process::exit(2);
            }
        }
    } else {
        match run_advisory_check(&root, &cli.advisory, cli.verbose) {
            Ok(found_vulns) => process::exit(if found_vulns { 1 } else { 0 }),
            Err(e) => {
                eprintln!("Error: {e}");
                process::exit(2);
            }
        }
    }
}

fn run_full_audit(root: &std::path::Path, verbose: bool) -> Result<bool, String> {
    let repos = discover::discover_repos(root)?;

    if repos.is_empty() {
        return Err(format!(
            "No auditable repositories found in {}. Repos must contain a package-lock.json, pnpm-lock.yaml, or Cargo.lock.",
            root.display()
        ));
    }

    let all_ecosystems: Vec<_> = repos.iter()
        .flat_map(|r| r.ecosystems.clone())
        .collect();
    let available = tools::check_tools(&all_ecosystems);

    let repos: Vec<_> = repos.into_iter().filter_map(|mut repo| {
        repo.ecosystems.retain(|e| available.contains(e));
        if repo.ecosystems.is_empty() { None } else { Some(repo) }
    }).collect();

    if repos.is_empty() {
        return Err(format!(
            "No auditable repositories found in {}. Required tools are not installed.",
            root.display()
        ));
    }

    if verbose {
        eprintln!("Scanning {} repositories in {}", repos.len(), root.display());
    }

    let mut results: Vec<(String, audit::AuditResult)> = Vec::new();

    for repo in &repos {
        if verbose {
            eprintln!("\nAuditing {}...", repo.name);
        }

        let mut combined = audit::VulnSummary::default();
        let mut had_error: Option<String> = None;

        for eco in &repo.ecosystems {
            let result = match eco {
                discover::Ecosystem::Npm => audit::run_npm_audit(&repo.path, verbose),
                discover::Ecosystem::Pnpm => audit::run_pnpm_audit(&repo.path, verbose),
                discover::Ecosystem::Cargo => audit::run_cargo_audit(&repo.path, verbose),
            };
            match result {
                audit::AuditResult::Ok(summary) => combined.merge(&summary),
                audit::AuditResult::Error(e) => { had_error = Some(e); break; }
            }
        }

        let result = match had_error {
            Some(e) => audit::AuditResult::Error(e),
            None => audit::AuditResult::Ok(combined),
        };
        results.push((repo.name.clone(), result));
    }

    let has_vulns = results.iter().any(|(_, r)| matches!(r, audit::AuditResult::Ok(s) if s.total() > 0));
    report::print_full_audit_table(&results);
    Ok(has_vulns)
}

fn run_advisory_check(root: &std::path::Path, urls: &[String], verbose: bool) -> Result<bool, String> {
    let repos = discover::discover_repos(root)?;

    if repos.is_empty() {
        return Err(format!(
            "No auditable repositories found in {}. Repos must contain a package-lock.json, pnpm-lock.yaml, or Cargo.lock.",
            root.display()
        ));
    }

    let all_ecosystems: Vec<_> = repos.iter()
        .flat_map(|r| r.ecosystems.clone())
        .collect();
    let available = tools::check_tools(&all_ecosystems);

    let repos: Vec<_> = repos.into_iter().filter_map(|mut repo| {
        repo.ecosystems.retain(|e| available.contains(e));
        if repo.ecosystems.is_empty() { None } else { Some(repo) }
    }).collect();

    if repos.is_empty() {
        return Err(format!(
            "No auditable repositories found in {}. Required tools are not installed.",
            root.display()
        ));
    }

    if verbose {
        eprintln!("Scanning {} repositories in {}", repos.len(), root.display());
    }

    let mut any_vulnerable = false;

    for url in urls {
        if verbose {
            eprintln!("\nFetching advisory: {url}");
        }

        let affected = advisory::fetch_advisory(url)?;

        if affected.is_empty() {
            eprintln!("warning: no affected packages found for {url}");
            continue;
        }

        let advisory_id = match advisory::parse_advisory_url(url) {
            advisory::AdvisorySource::Ghsa { id } => id,
            advisory::AdvisorySource::Nvd { id } => id,
            advisory::AdvisorySource::Unknown => url.clone(),
        };

        let affected_summary = affected
            .iter()
            .map(|p| {
                if p.version_range.is_empty() {
                    format!("{} ({})", p.name, p.ecosystem)
                } else {
                    format!("{} {} ({})", p.name, p.version_range, p.ecosystem)
                }
            })
            .collect::<Vec<_>>()
            .join(", ");

        let mut table_rows: Vec<(String, Vec<advisory::PackageStatus>)> = Vec::new();

        for repo in &repos {
            if verbose {
                eprintln!("  checking {}...", repo.name);
            }

            let mut installed = std::collections::HashMap::new();

            for eco in &repo.ecosystems {
                let lockfile_packages = match eco {
                    discover::Ecosystem::Npm => {
                        lockfile::parse_npm_lockfile(&repo.path.join("package-lock.json"))
                    }
                    discover::Ecosystem::Pnpm => {
                        lockfile::parse_pnpm_lockfile(&repo.path.join("pnpm-lock.yaml"))
                    }
                    discover::Ecosystem::Cargo => {
                        lockfile::parse_cargo_lockfile(&repo.path.join("Cargo.lock"))
                    }
                };

                match lockfile_packages {
                    Ok(pkgs) => installed.extend(pkgs),
                    Err(e) => {
                        if verbose {
                            eprintln!("    warning: {e}");
                        }
                    }
                }
            }

            let statuses = advisory::check_repo_against_advisory(&affected, &installed);

            if statuses.iter().any(|s| matches!(s, advisory::PackageStatus::Vulnerable { .. })) {
                any_vulnerable = true;
            }

            table_rows.push((repo.name.clone(), statuses));
        }

        report::print_advisory_table(&advisory_id, &affected_summary, &table_rows);
        println!();
    }

    Ok(any_vulnerable)
}
