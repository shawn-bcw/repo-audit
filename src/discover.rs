use std::path::{Path, PathBuf};
use std::fs;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ecosystem {
    Npm,
    Pnpm,
    Cargo,
}

#[derive(Debug, Clone)]
pub struct Repo {
    pub name: String,
    pub path: PathBuf,
    pub ecosystems: Vec<Ecosystem>,
}

pub fn discover_repos(root: &Path) -> Result<Vec<Repo>, String> {
    let entries: Vec<_> = fs::read_dir(root)
        .map_err(|e| format!("cannot read directory {}: {e}", root.display()))?
        .filter_map(|e| e.ok())
        .collect();

    if entries.is_empty() {
        return Err(format!("No repositories found in {}", root.display()));
    }

    let child_dirs: Vec<_> = entries
        .iter()
        .filter(|e| {
            let path = e.path();
            let name = e.file_name().to_string_lossy().to_string();
            !name.starts_with('.') && path.is_dir()
        })
        .collect();

    let mut repos = Vec::new();

    for entry in &child_dirs {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        let mut ecosystems = Vec::new();

        let has_pnpm_lock = path.join("pnpm-lock.yaml").exists();
        let has_npm_lock = path.join("package-lock.json").exists();
        let has_npm_manifest = path.join("package.json").exists();
        let has_cargo_lock = path.join("Cargo.lock").exists();

        if has_pnpm_lock {
            ecosystems.push(Ecosystem::Pnpm);
        } else if has_npm_lock {
            ecosystems.push(Ecosystem::Npm);
        } else if has_npm_manifest {
            eprintln!("warning: skipping {name} — no lockfile found (run pnpm install or npm install first)");
        }

        if has_cargo_lock {
            ecosystems.push(Ecosystem::Cargo);
        }

        if !ecosystems.is_empty() {
            repos.push(Repo { name, path, ecosystems });
        }
    }

    repos.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(repos)
}
