use std::process::Command;
use crate::discover::Ecosystem;

pub fn check_tools(ecosystems: &[Ecosystem]) -> Vec<Ecosystem> {
    let mut available = Vec::new();

    let needs_npm = ecosystems.contains(&Ecosystem::Npm);
    let needs_pnpm = ecosystems.contains(&Ecosystem::Pnpm);
    let needs_cargo = ecosystems.contains(&Ecosystem::Cargo);

    if needs_npm {
        if is_tool_available("npm", &["--version"]) {
            available.push(Ecosystem::Npm);
        } else {
            eprintln!(
                "warning: npm is not installed — skipping npm repos\n{}",
                npm_install_message()
            );
        }
    }

    if needs_pnpm {
        if is_tool_available("pnpm", &["--version"]) {
            available.push(Ecosystem::Pnpm);
        } else {
            eprintln!(
                "warning: pnpm is not installed — skipping pnpm repos\n{}",
                pnpm_install_message()
            );
        }
    }

    if needs_cargo {
        if is_tool_available("cargo", &["audit", "--version"]) {
            available.push(Ecosystem::Cargo);
        } else {
            eprintln!(
                "warning: cargo-audit is not installed — skipping Cargo repos\n{}",
                cargo_audit_install_message()
            );
        }
    }

    available
}

fn is_tool_available(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn npm_install_message() -> String {
    "  macOS:  brew install node\n  Linux:  sudo apt install nodejs npm".to_string()
}

pub fn pnpm_install_message() -> String {
    "  macOS:  brew install pnpm\n  Linux:  npm install -g pnpm".to_string()
}

pub fn cargo_audit_install_message() -> String {
    "  Install with: cargo install cargo-audit".to_string()
}
