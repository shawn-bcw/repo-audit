use serde_json::Value;
use std::path::Path;
use std::process::Command;
use std::time::Duration;
use std::io::Read;
use wait_timeout::ChildExt;

fn run_audit_command(cmd: &str, args: &[&str], repo_path: &Path, verbose: bool) -> Result<String, String> {
    if verbose {
        eprintln!("  running: {} {} (in {})", cmd, args.join(" "), repo_path.display());
    }

    let mut child = Command::new(cmd)
        .args(args)
        .current_dir(repo_path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to run {cmd}: {e}"))?;

    // Read stdout in a thread to avoid pipe buffer deadlock.
    let stdout_pipe = child.stdout.take();
    let reader = std::thread::spawn(move || {
        let mut buf = String::new();
        if let Some(mut pipe) = stdout_pipe {
            let _ = pipe.read_to_string(&mut buf);
        }
        buf
    });

    let timeout = Duration::from_secs(60);
    match child.wait_timeout(timeout) {
        Ok(Some(_status)) => {
            let stdout = reader.join().unwrap_or_default();
            if stdout.trim().is_empty() {
                Err(format!("{cmd} returned empty output"))
            } else {
                Ok(stdout)
            }
        }
        Ok(None) => {
            let _ = child.kill();
            let _ = child.wait();
            Err("timed out".to_string())
        }
        Err(e) => Err(format!("failed to wait on {cmd}: {e}")),
    }
}

#[derive(Debug, Clone, Default)]
pub struct VulnSummary {
    pub low: u32,
    pub medium: u32,
    pub high: u32,
    pub critical: u32,
}

impl VulnSummary {
    pub fn total(&self) -> u32 {
        self.low + self.medium + self.high + self.critical
    }

    pub fn merge(&mut self, other: &VulnSummary) {
        self.low += other.low;
        self.medium += other.medium;
        self.high += other.high;
        self.critical += other.critical;
    }
}

#[derive(Debug)]
pub enum AuditResult {
    Ok(VulnSummary),
    Error(String),
}

pub fn parse_npm_audit(json: &str) -> Result<VulnSummary, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("malformed JSON: {e}"))?;

    let vulns = v.get("vulnerabilities")
        .and_then(|v| v.as_object())
        .ok_or("missing 'vulnerabilities' object")?;

    let mut summary = VulnSummary::default();

    for (_name, vuln) in vulns {
        match vuln.get("severity").and_then(|s| s.as_str()) {
            Some("low") => summary.low += 1,
            Some("moderate") => summary.medium += 1,
            Some("high") => summary.high += 1,
            Some("critical") => summary.critical += 1,
            Some("info") => {}
            Some(other) => eprintln!("warning: unknown severity '{other}'"),
            None => {}
        }
    }

    Ok(summary)
}

pub fn run_npm_audit(repo_path: &Path, verbose: bool) -> AuditResult {
    match run_audit_command("npm", &["audit", "--json"], repo_path, verbose) {
        Ok(stdout) => match parse_npm_audit(&stdout) {
            Ok(summary) => AuditResult::Ok(summary),
            Err(e) => AuditResult::Error(e),
        },
        Err(e) => AuditResult::Error(e),
    }
}

pub fn parse_cargo_audit(json: &str) -> Result<VulnSummary, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("malformed JSON: {e}"))?;

    let list = v
        .pointer("/vulnerabilities/list")
        .and_then(|v| v.as_array())
        .ok_or("missing 'vulnerabilities.list' array")?;

    let mut summary = VulnSummary::default();

    for entry in list {
        let cvss = entry
            .pointer("/advisory/cvss")
            .and_then(|v| v.as_f64());

        match cvss {
            Some(s) if s >= 9.0 => summary.critical += 1,
            Some(s) if s >= 7.0 => summary.high += 1,
            Some(s) if s >= 4.0 => summary.medium += 1,
            Some(s) if s >= 0.1 => summary.low += 1,
            Some(_) => {}
            None => summary.medium += 1,
        }
    }

    Ok(summary)
}

pub fn run_cargo_audit(repo_path: &Path, verbose: bool) -> AuditResult {
    match run_audit_command("cargo", &["audit", "--json"], repo_path, verbose) {
        Ok(stdout) => match parse_cargo_audit(&stdout) {
            Ok(summary) => AuditResult::Ok(summary),
            Err(e) => AuditResult::Error(e),
        },
        Err(e) => AuditResult::Error(e),
    }
}

pub fn parse_pnpm_audit(json: &str) -> Result<VulnSummary, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("malformed JSON: {e}"))?;

    // pnpm audit uses metadata.vulnerabilities with pre-tallied counts
    let meta = v.pointer("/metadata/vulnerabilities")
        .ok_or("missing 'metadata.vulnerabilities' object")?;

    let low = meta.get("low").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let moderate = meta.get("moderate").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let high = meta.get("high").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let critical = meta.get("critical").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

    Ok(VulnSummary { low, medium: moderate, high, critical })
}

pub fn run_pnpm_audit(repo_path: &Path, verbose: bool) -> AuditResult {
    match run_audit_command("pnpm", &["audit", "--json"], repo_path, verbose) {
        Ok(stdout) => match parse_pnpm_audit(&stdout) {
            Ok(summary) => AuditResult::Ok(summary),
            Err(e) => AuditResult::Error(e),
        },
        Err(e) => AuditResult::Error(e),
    }
}
