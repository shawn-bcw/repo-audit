use std::collections::HashMap;
use std::fs;
use std::path::Path;
use serde_json::Value;

pub fn parse_npm_lockfile(path: &Path) -> Result<HashMap<String, String>, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;

    let v: Value = serde_json::from_str(&content)
        .map_err(|e| format!("malformed JSON in {}: {e}", path.display()))?;

    let packages = v.get("packages")
        .and_then(|p| p.as_object())
        .ok_or_else(|| format!("missing 'packages' in {}", path.display()))?;

    let mut result = HashMap::new();

    for (key, val) in packages {
        if key.is_empty() {
            continue;
        }

        let name = key.strip_prefix("node_modules/").unwrap_or(key);

        if let Some(version) = val.get("version").and_then(|v| v.as_str()) {
            result.insert(name.to_string(), version.to_string());
        }
    }

    Ok(result)
}

pub fn parse_cargo_lockfile(path: &Path) -> Result<HashMap<String, String>, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;

    let parsed: toml::Value = content.parse()
        .map_err(|e| format!("malformed TOML in {}: {e}", path.display()))?;

    let packages = parsed.get("package")
        .and_then(|p| p.as_array())
        .ok_or_else(|| format!("missing [[package]] in {}", path.display()))?;

    let mut result = HashMap::new();

    for pkg in packages {
        let name = pkg.get("name").and_then(|n| n.as_str());
        let version = pkg.get("version").and_then(|v| v.as_str());

        if let (Some(name), Some(version)) = (name, version) {
            result.insert(name.to_string(), version.to_string());
        }
    }

    Ok(result)
}

pub fn parse_pnpm_lockfile(path: &Path) -> Result<HashMap<String, String>, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;

    let parsed: serde_yaml::Value = serde_yaml::from_str(&content)
        .map_err(|e| format!("malformed YAML in {}: {e}", path.display()))?;

    let packages = parsed.get("packages")
        .and_then(|p| p.as_mapping())
        .ok_or_else(|| format!("missing 'packages' in {}", path.display()))?;

    let mut result = HashMap::new();

    for (key, _val) in packages {
        let key_str = key.as_str().unwrap_or("");
        if key_str.is_empty() {
            continue;
        }

        // Keys are "name@version" — split on the last '@'
        // Scoped packages start with '@', so find the last '@' that isn't at position 0
        let at_pos = if let Some(stripped) = key_str.strip_prefix('@') {
            stripped.rfind('@').map(|p| p + 1)
        } else {
            key_str.rfind('@')
        };

        if let Some(pos) = at_pos {
            let name = &key_str[..pos];
            let version = &key_str[pos + 1..];
            if !name.is_empty() && !version.is_empty() {
                result.insert(name.to_string(), version.to_string());
            }
        }
    }

    Ok(result)
}
