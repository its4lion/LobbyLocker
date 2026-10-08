use crate::Result;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, net::IpAddr};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Any,
    Tcp,
    Udp,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Endpoint {
    pub id: String,
    pub address: String,
    pub protocol: Protocol,
    pub ports: Option<String>,
    #[serde(default)]
    pub custom: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Region {
    pub id: String,
    pub name: String,
    pub area: String,
    pub probe_target: Option<String>,
    /// Exact Google Cloud scope to refresh; absent for manual and Valve regions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_scope: Option<String>,
    pub endpoints: Vec<Endpoint>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Game {
    pub schema_version: u32,
    pub id: String,
    pub name: String,
    pub accent: String,
    pub source: Option<String>,
    pub updated_at: Option<String>,
    /// Never launched. Windows uses this executable for per-program firewall rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_path: Option<String>,
    pub note: String,
    pub regions: Vec<Region>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Preferences {
    pub schema_version: u32,
    pub blocked_regions: Vec<String>,
    /// Additional local launcher/library roots chosen by the user.
    #[serde(default)]
    pub game_library_paths: Vec<String>,
    /// Removed default/registered folders must not silently return on discovery.
    #[serde(default)]
    pub excluded_game_library_paths: Vec<String>,
    /// User-curated sidebar membership; detection alone never adds a game here.
    #[serde(default)]
    pub library_game_ids: Vec<String>,
    /// Recovery hint only, not proof that firewall rules are still active.
    #[serde(default)]
    pub last_applied_game_ids: Vec<String>,
    #[serde(default = "default_language")]
    pub language: String,
}

fn default_language() -> String {
    "en".into()
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            schema_version: 1,
            blocked_regions: vec![],
            game_library_paths: vec![],
            excluded_game_library_paths: vec![],
            library_game_ids: vec![],
            last_applied_game_ids: vec![],
            language: default_language(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub games: Vec<Game>,
    pub preferences: Preferences,
    pub config_dir: String,
    pub platform: String,
}

pub fn validate_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 96
        || !id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        return Err("IDs must contain 1–96 letters, digits, hyphens, or underscores.".into());
    }
    Ok(())
}

pub fn normalize_address(address: &str) -> Result<String> {
    let address = address.trim();
    let net: IpNet = if let Ok(ip) = address.parse::<IpAddr>() {
        ip.into()
    } else {
        address
            .parse()
            .map_err(|_| "Enter a valid IPv4, IPv6, or CIDR address.")?
    };
    // Avoid whole-internet, loopback, unspecified, and multicast rules by mistake.
    if net.prefix_len() == 0
        || net.network().is_unspecified()
        || net.addr().is_loopback()
        || net.addr().is_multicast()
    {
        return Err(
            "Whole-internet, unspecified, loopback, and multicast targets are not allowed.".into(),
        );
    }
    if (net.addr().is_ipv4() && net.prefix_len() < 8)
        || (net.addr().is_ipv6() && net.prefix_len() < 16)
    {
        return Err(
            "Subnet is too broad. Use IPv4 /8 or narrower, or IPv6 /16 or narrower.".into(),
        );
    }
    Ok(if address.contains('/') {
        net.trunc().to_string()
    } else {
        net.addr().to_string()
    })
}

pub fn parse_ports(ports: &Option<String>) -> Result<Option<(u16, u16)>> {
    let Some(raw) = ports.as_ref().filter(|p| !p.trim().is_empty()) else {
        return Ok(None);
    };
    let parts: Vec<_> = raw.trim().split('-').collect();
    if parts.len() > 2 {
        return Err("Use a port (27015) or range (27015-27060).".into());
    }
    let start: u16 = parts[0]
        .parse()
        .map_err(|_| "Ports must be between 1 and 65535.")?;
    let end: u16 = parts
        .last()
        .unwrap()
        .parse()
        .map_err(|_| "Ports must be between 1 and 65535.")?;
    if start == 0 || end < start {
        return Err("Port range must be ordered and between 1 and 65535.".into());
    }
    Ok(Some((start, end)))
}

impl Endpoint {
    pub fn validate(&self) -> Result<()> {
        validate_id(&self.id)?;
        normalize_address(&self.address)?;
        parse_ports(&self.ports)?;
        Ok(())
    }
}

impl Game {
    /// Disk/import compatibility only: obsolete independent rules are ignored,
    /// never activated or exposed to IPC. All other unknown fields remain errors.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        read_compatible(bytes, &["rules"])
    }

    pub fn area_keys(&self, area: &str) -> Vec<String> {
        self.regions
            .iter()
            .filter(|r| r.area == area && !r.endpoints.is_empty())
            .map(|r| format!("{}:{}", self.id, r.id))
            .collect()
    }

    pub fn validate(&self) -> Result<()> {
        validate_id(&self.id)?;
        if self.schema_version != 1
            || self.name.trim().is_empty()
            || self.name.len() > 120
            || self.regions.len() > 300
        {
            return Err("Unsupported game schema, empty name, or too many regions.".into());
        }
        if self
            .executable_path
            .as_ref()
            .is_some_and(|path| path.is_empty() || path.len() > 4096 || path.contains('\0'))
        {
            return Err("Invalid game executable path.".into());
        }
        let mut regions = HashSet::new();
        let mut endpoints = HashSet::new();
        for region in &self.regions {
            validate_id(&region.id)?;
            if let Some(scope) = &region.provider_scope {
                validate_id(scope)?;
                if scope == "global" || !scope.contains('-') {
                    return Err("Provider scopes must identify a specific Google Cloud region, not global ranges.".into());
                }
            }
            if !regions.insert(&region.id)
                || region.name.len() > 160
                || region.endpoints.len() > 1000
            {
                return Err("Duplicate region or too many endpoints.".into());
            }
            if let Some(target) = &region.probe_target {
                let _: IpAddr = target.parse().map_err(|_| {
                    "Ping targets must be literal IP addresses, not subnets or hostnames."
                })?;
                normalize_address(target)?;
            }
            for endpoint in &region.endpoints {
                endpoint.validate()?;
                if !endpoints.insert(&endpoint.id) {
                    return Err("Duplicate endpoint ID.".into());
                }
            }
        }
        Ok(())
    }
}

impl Preferences {
    /// Existing files can still load, but removed features are not retained in
    /// runtime state or new saves. Loading itself does not rewrite the old file.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        read_compatible(
            bytes,
            &[
                "profiles",
                "enabledRules",
                "threshold",
                "autoEnabled",
                "monitorEnabled",
            ],
        )
    }

    pub fn set_area_blocked(&mut self, game: &Game, area: &str, blocked: bool) {
        let all_keys: HashSet<_> = game
            .regions
            .iter()
            .filter(|r| r.area == area)
            .map(|r| format!("{}:{}", game.id, r.id))
            .collect();
        self.blocked_regions.retain(|key| !all_keys.contains(key));
        if blocked {
            self.blocked_regions.extend(game.area_keys(area));
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || self.blocked_regions.len() > 5000
            || self.game_library_paths.len() > 32
            || self.excluded_game_library_paths.len() > 256
            || self.library_game_ids.len() > 500
            || self.last_applied_game_ids.len() > 5000
        {
            return Err("Invalid preferences version or collection size.".into());
        }
        validate_id(&self.language)?;
        for id in &self.library_game_ids {
            validate_id(id)?;
        }
        for id in &self.last_applied_game_ids {
            validate_id(id)?;
        }
        for path in self
            .game_library_paths
            .iter()
            .chain(&self.excluded_game_library_paths)
        {
            if path.len() > 4096 || path.contains('\0') || !std::path::Path::new(path).is_absolute()
            {
                return Err("Game library paths must be absolute local folders.".into());
            }
        }
        Ok(())
    }
}

fn read_compatible<T: serde::de::DeserializeOwned>(bytes: &[u8], obsolete: &[&str]) -> Result<T> {
    let mut json: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    if let Some(object) = json.as_object_mut() {
        for key in obsolete {
            object.remove(*key);
        }
    }
    serde_json::from_value(json).map_err(|e| e.to_string())
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FirewallTarget {
    pub game_id: String,
    pub game_name: String,
    pub region_id: String,
    pub region_name: String,
    pub executable_path: Option<String>,
    pub endpoints: Vec<Endpoint>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FirewallRule {
    pub endpoint: Endpoint,
    pub program: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FirewallScope {
    SystemWide,
    Executable,
}

impl FirewallScope {
    pub fn native() -> Self {
        if cfg!(target_os = "windows") {
            Self::Executable
        } else {
            Self::SystemWide
        }
    }
}

/// Portable validation for helper input and Windows script generation. Use a
/// literal local-drive .exe, never an environment variable, wildcard, or device.
pub fn windows_program(path: &str) -> Result<String> {
    let path = path.replace('/', "\\");
    let bytes = path.as_bytes();
    if path.len() > 4096
        || bytes.len() < 7
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || bytes[2] != b'\\'
        || !path.to_ascii_lowercase().ends_with(".exe")
        || path[2..].contains([':', '*', '?', '"', '<', '>', '|', '%'])
        || path.chars().any(char::is_control)
        || path[3..].split('\\').any(|part| {
            part.is_empty() || part == "." || part == ".." || part.ends_with([' ', '.'])
        })
    {
        return Err("Choose a full local Windows .exe path. Relative paths, wildcards, and environment variables are not supported.".into());
    }
    Ok(path)
}

/// Check availability before UAC; the privileged helper also uses Test-Path.
pub fn validate_program_files(rules: &[FirewallRule]) -> Result<()> {
    for rule in rules {
        if let Some(program) = &rule.program {
            if !std::path::Path::new(program).is_file() {
                return Err(format!("Game executable is unavailable: {program}. Choose its current .exe before Apply. No firewall command was started."));
            }
        }
    }
    Ok(())
}

/// Preserve attribution even when multiple games share a deduplicated OS rule.
pub fn selected_targets(games: &[Game], preferences: &Preferences) -> Vec<FirewallTarget> {
    selected_targets_for_scope(games, preferences, FirewallScope::native())
}

pub fn selected_targets_for_scope(
    games: &[Game],
    preferences: &Preferences,
    scope: FirewallScope,
) -> Vec<FirewallTarget> {
    let selected: HashSet<_> = preferences.blocked_regions.iter().collect();
    games
        .iter()
        .flat_map(|game| {
            game.regions
                .iter()
                .filter(|region| {
                    !region.endpoints.is_empty()
                        && selected.contains(&format!("{}:{}", game.id, region.id))
                })
                .map(|region| FirewallTarget {
                    game_id: game.id.clone(),
                    game_name: game.name.clone(),
                    region_id: region.id.clone(),
                    region_name: region.name.clone(),
                    executable_path: if scope == FirewallScope::Executable {
                        game.executable_path.clone()
                    } else {
                        None
                    },
                    endpoints: region.endpoints.clone(),
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Games requesting non-empty target sets. These become active indicators only
/// after Apply succeeds; saved selections alone are never proof of active rules.
pub fn selected_game_ids(games: &[Game], preferences: &Preferences) -> Vec<String> {
    let selected: HashSet<_> = preferences.blocked_regions.iter().collect();
    games
        .iter()
        .filter(|game| {
            game.regions.iter().any(|region| {
                !region.endpoints.is_empty()
                    && selected.contains(&format!("{}:{}", game.id, region.id))
            })
        })
        .map(|game| game.id.clone())
        .collect()
}

pub fn resolve_rules(games: &[Game], preferences: &Preferences) -> Result<Vec<FirewallRule>> {
    resolve_rules_for_scope(games, preferences, FirewallScope::native())
}

pub fn resolve_rules_for_scope(
    games: &[Game],
    preferences: &Preferences,
    scope: FirewallScope,
) -> Result<Vec<FirewallRule>> {
    preferences.validate()?;
    let selected: HashSet<_> = preferences.blocked_regions.iter().collect();
    let mut rules = Vec::new();
    let mut seen = HashSet::new();
    for game in games {
        game.validate()?;
        for region in &game.regions {
            if selected.contains(&format!("{}:{}", game.id, region.id)) {
                if region.endpoints.is_empty() {
                    continue;
                }
                let program = if scope == FirewallScope::Executable {
                    let path = game.executable_path.as_deref().ok_or_else(|| format!("Choose a game executable for {} before Apply. Windows blocking never falls back to system-wide rules.", game.name))?;
                    Some(windows_program(path).map_err(|error| format!("{}: {error}", game.name))?)
                } else {
                    None
                };
                for endpoint in &region.endpoints {
                    let mut rule = endpoint.clone();
                    // Different games can share SDR endpoints and source IDs.
                    rule.id = format!("{}-{}", game.id, endpoint.id);
                    rule.validate()?;
                    let key = (
                        normalize_address(&rule.address)?,
                        format!("{:?}", rule.protocol),
                        parse_ports(&rule.ports)?,
                        program.as_ref().map(|path| path.to_lowercase()),
                    );
                    if seen.insert(key) {
                        rules.push(FirewallRule {
                            endpoint: rule,
                            program: program.clone(),
                        });
                    }
                }
            }
        }
    }
    if rules.len() > 5000 {
        return Err("Too many firewall rules (maximum 5000).".into());
    }
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_program_paths_are_literal_absolute_local_executables() {
        assert_eq!(
            windows_program("D:/Games/Example/game.EXE").unwrap(),
            r"D:\Games\Example\game.EXE"
        );
        assert!(windows_program(r"C:\Program Files\O'Brien\العربية.exe").is_ok());
        for invalid in [
            "",
            "game.exe",
            r"C:game.exe",
            r"\Games\game.exe",
            r"C:\Games\*.exe",
            r"%PROGRAMFILES%\game.exe",
            r"C:\Games\game.exe:stream",
            r"C:\Games\..\game.exe",
            r"C:\Games\game.cmd",
            r"\\server\share\game.exe",
            r"\\?\C:\Games\game.exe",
            "C:\\Games\\bad\nname.exe",
            "C:\\Games\\bad\0name.exe",
        ] {
            assert!(windows_program(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn windows_resolution_never_falls_back_and_deduplicates_within_each_program() {
        let mut one = crate::installed::custom_game(
            "one".into(),
            "One",
            "Custom",
            "203.0.113.7",
            Protocol::Udp,
            None,
        )
        .unwrap();
        let mut two = one.clone();
        two.id = "two".into();
        two.name = "Two".into();
        let mut preferences = Preferences {
            blocked_regions: vec!["one:custom".into(), "two:custom".into()],
            ..Default::default()
        };
        assert!(resolve_rules_for_scope(
            &[one.clone(), two.clone()],
            &preferences,
            FirewallScope::Executable
        )
        .unwrap_err()
        .contains("One"));
        one.executable_path = Some(r"C:\Games\One\game.exe".into());
        two.executable_path = Some(r"D:\Games\Two\game.exe".into());
        let games = vec![one.clone(), two.clone()];
        let windows =
            resolve_rules_for_scope(&games, &preferences, FirewallScope::Executable).unwrap();
        assert_eq!(windows.len(), 2);
        assert_ne!(windows[0].program, windows[1].program);
        assert_eq!(
            resolve_rules_for_scope(&games, &preferences, FirewallScope::SystemWide)
                .unwrap()
                .len(),
            1
        );
        let targets = selected_targets_for_scope(&games, &preferences, FirewallScope::Executable);
        assert_eq!(targets[0].executable_path, one.executable_path);
        assert!(
            selected_targets_for_scope(&games, &preferences, FirewallScope::SystemWide)[0]
                .executable_path
                .is_none()
        );
        two.executable_path = Some(r"c:\games\ONE\GAME.exe".into());
        assert_eq!(
            resolve_rules_for_scope(&[one.clone(), two], &preferences, FirewallScope::Executable)
                .unwrap()
                .len(),
            1
        );
        preferences.blocked_regions.clear();
        one.executable_path = None;
        assert!(
            resolve_rules_for_scope(&[one], &preferences, FirewallScope::Executable)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn program_availability_is_checked_without_executing_it() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("game.exe");
        let game = crate::installed::custom_game(
            "one".into(),
            "One",
            "Custom",
            "203.0.113.7",
            Protocol::Udp,
            None,
        )
        .unwrap();
        let rule = FirewallRule {
            endpoint: game.regions[0].endpoints[0].clone(),
            program: Some(path.to_str().unwrap().into()),
        };
        assert!(validate_program_files(std::slice::from_ref(&rule)).is_err());
        std::fs::write(path, b"not executed").unwrap();
        validate_program_files(&[rule]).unwrap();
    }

    #[test]
    fn removed_default_folders_are_optional_for_old_files_and_strictly_validated() {
        let mut preferences = Preferences::default();
        let mut json = serde_json::to_value(&preferences).unwrap();
        json.as_object_mut()
            .unwrap()
            .remove("excludedGameLibraryPaths");
        assert!(Preferences::from_json(&serde_json::to_vec(&json).unwrap())
            .unwrap()
            .excluded_game_library_paths
            .is_empty());
        preferences.excluded_game_library_paths = vec!["relative-folder".into()];
        assert!(preferences.validate().is_err());
        let root = tempfile::tempdir().unwrap();
        preferences.excluded_game_library_paths =
            vec![root.path().join("disconnected").to_str().unwrap().into()];
        assert!(preferences.validate().is_ok());
        preferences.excluded_game_library_paths = vec![root.path().to_str().unwrap().into(); 257];
        assert!(preferences.validate().is_err());
    }

    #[test]
    fn applied_game_tracking_ignores_empty_and_unknown_regions_and_includes_shared_targets() {
        let one = crate::installed::custom_game(
            "one".into(),
            "One",
            "Custom",
            "203.0.113.8",
            Protocol::Udp,
            None,
        )
        .unwrap();
        let mut two = one.clone();
        two.id = "two".into();
        let mut empty = one.clone();
        empty.id = "empty".into();
        empty.regions[0].endpoints.clear();
        let games = vec![one, two, empty];
        let preferences = Preferences {
            blocked_regions: vec![
                "one:custom".into(),
                "two:custom".into(),
                "empty:custom".into(),
                "unknown:custom".into(),
            ],
            ..Default::default()
        };
        assert_eq!(selected_game_ids(&games, &preferences), vec!["one", "two"]);
        let targets = selected_targets(&games, &preferences);
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].game_name, "One");
        assert_eq!(targets[0].endpoints, targets[1].endpoints);
        assert_eq!(
            resolve_rules_for_scope(&games, &preferences, FirewallScope::SystemWide)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn library_selection_defaults_empty_and_is_bounded_and_validated() {
        let legacy =
            br#"{"schemaVersion":1,"blockedRegions":[],"threshold":100,"autoEnabled":false}"#;
        let preferences = Preferences::from_json(legacy).unwrap();
        assert!(preferences.library_game_ids.is_empty());
        let mut preferences = Preferences {
            library_game_ids: vec!["../escape".into()],
            ..Default::default()
        };
        assert!(preferences.validate().is_err());
        preferences.library_game_ids = vec!["cs2".into(); 501];
        assert!(preferences.validate().is_err());
    }

    #[test]
    fn area_toggles_group_servers_without_touching_other_games() {
        let endpoint = Endpoint {
            id: "server".into(),
            address: "203.0.113.1".into(),
            protocol: Protocol::Udp,
            ports: None,
            custom: false,
        };
        let mut game = Game {
            schema_version: 1,
            id: "test-game".into(),
            name: "Test".into(),
            accent: "#a6d9b2".into(),
            source: None,
            updated_at: None,
            executable_path: None,
            note: String::new(),
            regions: vec![Region {
                id: "eu-one".into(),
                name: "Europe one".into(),
                area: "Europe".into(),
                probe_target: None,
                provider_scope: None,
                endpoints: vec![endpoint],
            }],
        };
        let mut other = game.regions[0].clone();
        other.id = "eu-two".into();
        other.endpoints[0].id = "custom-server".into();
        other.endpoints[0].address = "203.0.113.2".into();
        other.endpoints[0].custom = true;
        game.regions.push(other.clone());
        other.id = "eu-empty".into();
        other.endpoints.clear();
        game.regions.push(other.clone());
        other.id = "middle-east".into();
        other.area = "Middle East".into();
        game.regions.push(other);
        let mut preferences = Preferences {
            blocked_regions: vec![
                "other-game:eu-one".into(),
                "test-game:middle-east".into(),
                "test-game:eu-empty".into(),
            ],
            ..Default::default()
        };
        assert_eq!(
            game.area_keys("Europe"),
            vec!["test-game:eu-one", "test-game:eu-two"]
        );
        preferences.set_area_blocked(&game, "Europe", true);
        preferences.set_area_blocked(&game, "Europe", true);
        assert_eq!(preferences.blocked_regions.len(), 4);
        assert!(!preferences
            .blocked_regions
            .contains(&"test-game:eu-empty".into()));
        let rules =
            resolve_rules_for_scope(&[game.clone()], &preferences, FirewallScope::SystemWide)
                .unwrap();
        assert_eq!(rules.len(), 2);
        assert!(rules.iter().any(|r| r.endpoint.custom));
        preferences.set_area_blocked(&game, "Europe", false);
        assert_eq!(
            preferences.blocked_regions,
            vec!["other-game:eu-one", "test-game:middle-east"]
        );
        assert!(resolve_rules(&[game], &preferences).unwrap().is_empty());
    }

    #[test]
    fn removed_latency_settings_load_only_from_disk_and_are_not_retained() {
        let mut json = serde_json::to_value(Preferences::default()).unwrap();
        json["autoEnabled"] = serde_json::json!(true);
        json["monitorEnabled"] = serde_json::json!(true);
        json["threshold"] = serde_json::json!(100);
        let loaded = Preferences::from_json(&serde_json::to_vec(&json).unwrap()).unwrap();
        loaded.validate().unwrap();
        let saved = serde_json::to_value(loaded).unwrap();
        for key in ["autoEnabled", "monitorEnabled", "threshold"] {
            assert!(saved.get(key).is_none());
        }
        assert!(serde_json::from_value::<Preferences>(json).is_err());
    }

    #[test]
    fn compatibility_loaders_ignore_only_removed_fields_and_ipc_remains_strict() {
        let mut preferences = serde_json::to_value(Preferences::default()).unwrap();
        preferences["profiles"] = serde_json::json!([]);
        preferences["enabledRules"] = serde_json::json!(["cs2:legacy"]);
        let bytes = serde_json::to_vec(&preferences).unwrap();
        assert!(Preferences::from_json(&bytes).is_ok());
        assert!(serde_json::from_slice::<Preferences>(&bytes).is_err());
        preferences["unknown"] = serde_json::json!(true);
        assert!(Preferences::from_json(&serde_json::to_vec(&preferences).unwrap()).is_err());

        let game = crate::installed::custom_game(
            "custom-example".into(),
            "Example",
            "Custom",
            "203.0.113.7",
            Protocol::Udp,
            None,
        )
        .unwrap();
        let mut game = serde_json::to_value(game).unwrap();
        game["rules"] = serde_json::json!([]);
        let bytes = serde_json::to_vec(&game).unwrap();
        assert!(Game::from_json(&bytes).is_ok());
        assert!(serde_json::from_slice::<Game>(&bytes).is_err());
        game["unknown"] = serde_json::json!(true);
        assert!(Game::from_json(&serde_json::to_vec(&game).unwrap()).is_err());
    }

    #[test]
    fn library_paths_are_bounded_and_disconnected_folders_remain_loadable() {
        let root = tempfile::tempdir().unwrap();
        let mut preferences = Preferences {
            game_library_paths: vec![root
                .path()
                .join("currently-disconnected")
                .to_str()
                .unwrap()
                .to_owned()],
            ..Default::default()
        };
        assert!(preferences.validate().is_ok());
        preferences.game_library_paths = vec!["relative-folder".into()];
        assert!(preferences.validate().is_err());
        preferences.game_library_paths = vec![root.path().to_str().unwrap().to_owned(); 33];
        assert!(preferences.validate().is_err());
    }

    #[test]
    fn addresses_are_normalized_and_shell_input_rejected() {
        assert_eq!(
            normalize_address("203.0.113.9/24").unwrap(),
            "203.0.113.0/24"
        );
        assert_eq!(normalize_address("2001:db8::1").unwrap(), "2001:db8::1");
        for invalid in [
            "0.0.0.0/0",
            "::/0",
            "127.0.0.1",
            "203.0.113.1; reboot",
            "example.com",
            "10.0.0.0/1",
        ] {
            assert!(normalize_address(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn ports_are_strict() {
        assert_eq!(
            parse_ports(&Some("27015-27060".into())).unwrap(),
            Some((27015, 27060))
        );
        for invalid in ["0", "65536", "20-10", "1; whoami", "1-2-3"] {
            assert!(parse_ports(&Some(invalid.into())).is_err());
        }
    }
}
