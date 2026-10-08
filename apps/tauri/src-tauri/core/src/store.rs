use crate::{
    model::{validate_id, Game, Preferences, Snapshot},
    Result,
};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

pub struct Store {
    pub directory: PathBuf,
    defaults: PathBuf,
}

fn atomic_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path.parent().ok_or("Invalid configuration path.")?;
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let mut file = tempfile::NamedTempFile::new_in(parent).map_err(|e| e.to_string())?;
    serde_json::to_writer_pretty(&mut file, value).map_err(|e| e.to_string())?;
    file.write_all(b"\n").map_err(|e| e.to_string())?;
    file.as_file().sync_all().map_err(|e| e.to_string())?;
    file.persist(path).map_err(|e| e.to_string())?;
    Ok(())
}

impl Store {
    pub fn default_directory() -> Result<PathBuf> {
        dirs::config_dir()
            .map(|p| p.join("lobbylocker"))
            .ok_or("Could not find your configuration directory.".into())
    }

    pub fn open(directory: PathBuf, defaults: &Path) -> Result<Self> {
        let store = Self {
            directory,
            defaults: defaults.to_path_buf(),
        };
        fs::create_dir_all(store.directory.join("games")).map_err(|e| e.to_string())?;
        if defaults.is_dir() {
            for entry in fs::read_dir(defaults).map_err(|e| e.to_string())? {
                let path = entry.map_err(|e| e.to_string())?.path();
                if path.extension().and_then(|e| e.to_str()) == Some("json") {
                    let game = Game::from_json(&fs::read(&path).map_err(|e| e.to_string())?)
                        .map_err(|e| format!("Invalid {}: {e}", path.display()))?;
                    game.validate()?;
                    // Never overwrite a user's existing game file on app upgrades.
                    if !store.game_path(&game.id)?.exists() {
                        store.save_game(&game)?;
                    }
                }
            }
        }
        if !store.directory.join("preferences.json").exists() {
            store.save_preferences(&Preferences::default())?;
        }
        Ok(store)
    }

    fn game_path(&self, id: &str) -> Result<PathBuf> {
        validate_id(id)?;
        Ok(self.directory.join("games").join(format!("{id}.json")))
    }

    pub fn default_game(&self, id: &str) -> Result<Game> {
        validate_id(id)?;
        let path = self.defaults.join(format!("{id}.json"));
        let game = Game::from_json(
            &fs::read(&path)
                .map_err(|e| format!("Could not load game defaults {}: {e}", path.display()))?,
        )
        .map_err(|e| e.to_string())?;
        game.validate()?;
        if game.id != id {
            return Err("Default game filename does not match its ID.".into());
        }
        Ok(game)
    }

    pub fn save_game(&self, game: &Game) -> Result<()> {
        game.validate()?;
        atomic_json(&self.game_path(&game.id)?, game)
    }

    pub fn save_preferences(&self, preferences: &Preferences) -> Result<()> {
        preferences.validate()?;
        atomic_json(&self.directory.join("preferences.json"), preferences)
    }

    pub fn snapshot(&self) -> Result<Snapshot> {
        let mut games = Vec::new();
        for entry in fs::read_dir(self.directory.join("games")).map_err(|e| e.to_string())? {
            let path = entry.map_err(|e| e.to_string())?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let game = Game::from_json(&fs::read(&path).map_err(|e| e.to_string())?)
                .map_err(|e| format!("Invalid game file {}: {e}", path.display()))?;
            game.validate()?;
            if path.file_stem().and_then(|p| p.to_str()) != Some(game.id.as_str()) {
                return Err(format!(
                    "Game filename must match its ID: {}",
                    path.display()
                ));
            }
            games.push(game);
        }
        games.sort_by_key(|g| match g.id.as_str() {
            "cs2" => 0,
            "deadlock" => 1,
            "overwatch2" => 2,
            _ => 3,
        });
        let preferences = Preferences::from_json(
            &fs::read(self.directory.join("preferences.json")).map_err(|e| e.to_string())?,
        )
        .map_err(|e| format!("Invalid preferences.json: {e}"))?;
        preferences.validate()?;
        Ok(Snapshot {
            games,
            preferences,
            config_dir: self.directory.display().to_string(),
            platform: std::env::consts::OS.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separate_game_files_and_no_overwrite() {
        let root = tempfile::tempdir().unwrap();
        let defaults = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../data/games");
        let store = Store::open(root.path().into(), &defaults).unwrap();
        let mut snapshot = store.snapshot().unwrap();
        assert!(root.path().join("games/cs2.json").exists());
        assert!(root.path().join("games/deadlock.json").exists());
        snapshot.games[0].name = "My custom name".into();
        store.save_game(&snapshot.games[0]).unwrap();
        let reopened = Store::open(root.path().into(), &defaults).unwrap();
        assert_eq!(reopened.snapshot().unwrap().games[0].name, "My custom name");
        assert!(store.game_path("../escape").is_err());
    }

    #[test]
    fn older_game_files_without_provider_mappings_are_not_silently_replaced() {
        let root = tempfile::tempdir().unwrap();
        let defaults = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../data/games");
        let store = Store::open(root.path().into(), &defaults).unwrap();
        let mut legacy: serde_json::Value =
            serde_json::to_value(store.default_game("overwatch2").unwrap()).unwrap();
        for region in legacy["regions"].as_array_mut().unwrap() {
            region.as_object_mut().unwrap().remove("providerScope");
        }
        let path = root.path().join("games/overwatch2.json");
        fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();
        let before = fs::read(&path).unwrap();
        let reopened = Store::open(root.path().into(), &defaults).unwrap();
        let old = reopened
            .snapshot()
            .unwrap()
            .games
            .into_iter()
            .find(|g| g.id == "overwatch2")
            .unwrap();
        assert!(old.regions.iter().all(|r| r.provider_scope.is_none()));
        assert_eq!(fs::read(path).unwrap(), before);
        assert!(reopened
            .default_game("overwatch2")
            .unwrap()
            .regions
            .iter()
            .filter(|r| r.id.starts_with("gcp-"))
            .all(|r| r.provider_scope.is_some()));
        assert!(reopened
            .default_game("overwatch2")
            .unwrap()
            .regions
            .iter()
            .filter(|r| r.id.starts_with("blizzard-"))
            .all(|r| r.provider_scope.is_none()));
    }

    #[test]
    fn removed_features_in_old_files_are_ignored_without_rewriting_or_activating_them() {
        let root = tempfile::tempdir().unwrap();
        let defaults = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../data/games");
        let store = Store::open(root.path().into(), &defaults).unwrap();
        let game_path = root.path().join("games/cs2.json");
        let preferences_path = root.path().join("preferences.json");
        let mut game = serde_json::to_value(store.default_game("cs2").unwrap()).unwrap();
        game["rules"] = serde_json::json!([{
            "label": "Old independent target",
            "endpoint": {"id": "legacy", "address": "203.0.113.8", "protocol": "udp", "ports": null, "custom": true}
        }]);
        let mut preferences = serde_json::to_value(Preferences::default()).unwrap();
        preferences["enabledRules"] = serde_json::json!(["cs2:legacy"]);
        preferences["profiles"] = serde_json::json!([{"id": "legacy", "name": "Old profile"}]);
        preferences["autoEnabled"] = serde_json::json!(true);
        preferences["monitorEnabled"] = serde_json::json!(true);
        preferences["threshold"] = serde_json::json!(50);
        fs::write(&game_path, serde_json::to_vec(&game).unwrap()).unwrap();
        fs::write(&preferences_path, serde_json::to_vec(&preferences).unwrap()).unwrap();
        let game_before = fs::read(&game_path).unwrap();
        let preferences_before = fs::read(&preferences_path).unwrap();

        let reopened = Store::open(root.path().into(), &defaults).unwrap();
        let snapshot = reopened.snapshot().unwrap();
        assert!(
            crate::model::resolve_rules(&snapshot.games, &snapshot.preferences)
                .unwrap()
                .is_empty()
        );
        assert_eq!(fs::read(&game_path).unwrap(), game_before);
        assert_eq!(fs::read(&preferences_path).unwrap(), preferences_before);

        let game = snapshot.games.iter().find(|game| game.id == "cs2").unwrap();
        reopened.save_game(game).unwrap();
        reopened.save_preferences(&snapshot.preferences).unwrap();
        let saved_game: serde_json::Value =
            serde_json::from_slice(&fs::read(game_path).unwrap()).unwrap();
        let saved_preferences: serde_json::Value =
            serde_json::from_slice(&fs::read(preferences_path).unwrap()).unwrap();
        assert!(saved_game.get("rules").is_none());
        assert!(saved_preferences.get("profiles").is_none());
        assert!(saved_preferences.get("enabledRules").is_none());
    }
}
