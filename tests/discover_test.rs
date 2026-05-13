use std::fs;
use tempfile::TempDir;

#[test]
fn discovers_npm_repo_by_lockfile() {
    let tmp = TempDir::new().unwrap();
    let npm_repo = tmp.path().join("my-app");
    fs::create_dir(&npm_repo).unwrap();
    fs::write(npm_repo.join("package.json"), "{}").unwrap();
    fs::write(npm_repo.join("package-lock.json"), "{}").unwrap();

    let repos = repo_audit::discover::discover_repos(tmp.path()).unwrap();
    assert_eq!(repos.len(), 1);
    assert_eq!(repos[0].name, "my-app");
    assert!(repos[0].ecosystems.contains(&repo_audit::discover::Ecosystem::Npm));
}

#[test]
fn discovers_cargo_repo_by_lockfile() {
    let tmp = TempDir::new().unwrap();
    let cargo_repo = tmp.path().join("my-cli");
    fs::create_dir(&cargo_repo).unwrap();
    fs::write(cargo_repo.join("Cargo.toml"), "[package]\nname = \"x\"\nversion = \"0.1.0\"").unwrap();
    fs::write(cargo_repo.join("Cargo.lock"), "").unwrap();

    let repos = repo_audit::discover::discover_repos(tmp.path()).unwrap();
    assert_eq!(repos.len(), 1);
    assert!(repos[0].ecosystems.contains(&repo_audit::discover::Ecosystem::Cargo));
}

#[test]
fn skips_hidden_directories() {
    let tmp = TempDir::new().unwrap();
    let hidden = tmp.path().join(".hidden");
    fs::create_dir(&hidden).unwrap();
    fs::write(hidden.join("package-lock.json"), "{}").unwrap();

    let repos = repo_audit::discover::discover_repos(tmp.path()).unwrap();
    assert!(repos.is_empty());
}

#[test]
fn warns_on_manifest_without_lockfile() {
    let tmp = TempDir::new().unwrap();
    let npm_repo = tmp.path().join("no-lock");
    fs::create_dir(&npm_repo).unwrap();
    fs::write(npm_repo.join("package.json"), "{}").unwrap();

    let repos = repo_audit::discover::discover_repos(tmp.path()).unwrap();
    assert!(repos.is_empty());
}

#[test]
fn discovers_dual_ecosystem_repo() {
    let tmp = TempDir::new().unwrap();
    let dual = tmp.path().join("dual");
    fs::create_dir(&dual).unwrap();
    fs::write(dual.join("package-lock.json"), "{}").unwrap();
    fs::write(dual.join("Cargo.lock"), "").unwrap();

    let repos = repo_audit::discover::discover_repos(tmp.path()).unwrap();
    assert_eq!(repos.len(), 1);
    assert_eq!(repos[0].ecosystems.len(), 2);
}

#[test]
fn returns_error_for_empty_directory() {
    let tmp = TempDir::new().unwrap();
    let result = repo_audit::discover::discover_repos(tmp.path());
    assert!(result.is_err());
}

#[test]
fn discovers_pnpm_repo_by_lockfile() {
    let tmp = TempDir::new().unwrap();
    let pnpm_repo = tmp.path().join("my-pnpm-app");
    fs::create_dir(&pnpm_repo).unwrap();
    fs::write(pnpm_repo.join("package.json"), "{}").unwrap();
    fs::write(pnpm_repo.join("pnpm-lock.yaml"), "lockfileVersion: '9.0'").unwrap();

    let repos = repo_audit::discover::discover_repos(tmp.path()).unwrap();
    assert_eq!(repos.len(), 1);
    assert_eq!(repos[0].name, "my-pnpm-app");
    assert!(repos[0].ecosystems.contains(&repo_audit::discover::Ecosystem::Pnpm));
}

#[test]
fn pnpm_takes_priority_over_npm_when_both_exist() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("both-locks");
    fs::create_dir(&repo).unwrap();
    fs::write(repo.join("package.json"), "{}").unwrap();
    fs::write(repo.join("package-lock.json"), "{}").unwrap();
    fs::write(repo.join("pnpm-lock.yaml"), "lockfileVersion: '9.0'").unwrap();

    let repos = repo_audit::discover::discover_repos(tmp.path()).unwrap();
    assert_eq!(repos.len(), 1);
    assert!(repos[0].ecosystems.contains(&repo_audit::discover::Ecosystem::Pnpm));
    assert!(!repos[0].ecosystems.contains(&repo_audit::discover::Ecosystem::Npm));
}

#[test]
fn discovers_pnpm_and_cargo_dual_ecosystem() {
    let tmp = TempDir::new().unwrap();
    let dual = tmp.path().join("dual-pnpm-cargo");
    fs::create_dir(&dual).unwrap();
    fs::write(dual.join("pnpm-lock.yaml"), "lockfileVersion: '9.0'").unwrap();
    fs::write(dual.join("Cargo.lock"), "").unwrap();

    let repos = repo_audit::discover::discover_repos(tmp.path()).unwrap();
    assert_eq!(repos.len(), 1);
    assert!(repos[0].ecosystems.contains(&repo_audit::discover::Ecosystem::Pnpm));
    assert!(repos[0].ecosystems.contains(&repo_audit::discover::Ecosystem::Cargo));
}
