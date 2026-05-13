use repo_audit::discover::Ecosystem;
use repo_audit::tools::check_tools;

#[test]
fn returns_npm_when_npm_available() {
    let available = check_tools(&[Ecosystem::Npm]);
    assert!(available.contains(&Ecosystem::Npm));
}

#[test]
fn returns_empty_for_empty_input() {
    let available = check_tools(&[]);
    assert!(available.is_empty());
}

#[test]
fn deduplicates_ecosystems() {
    let available = check_tools(&[Ecosystem::Npm, Ecosystem::Npm]);
    assert_eq!(available.iter().filter(|e| **e == Ecosystem::Npm).count(), 1);
}

#[test]
fn npm_install_message_includes_both_platforms() {
    let msg = repo_audit::tools::npm_install_message();
    assert!(msg.contains("brew install node"));
    assert!(msg.contains("sudo apt install nodejs npm"));
}

#[test]
fn pnpm_install_message_includes_both_platforms() {
    let msg = repo_audit::tools::pnpm_install_message();
    assert!(msg.contains("brew install pnpm"));
    assert!(msg.contains("npm install -g pnpm"));
}

#[test]
fn cargo_audit_install_message_includes_command() {
    let msg = repo_audit::tools::cargo_audit_install_message();
    assert!(msg.contains("cargo install cargo-audit"));
}
