use crate::{
    catalogue,
    firewall::{self, FirewallOutcome, Request},
    inspection::{self, Inspection, RegionState, Verification},
    latency::{self, PingSample},
    model::{
        resolve_rules, selected_game_ids, selected_targets, FirewallRule, FirewallScope,
        FirewallTarget, Game, Preferences, Snapshot,
    },
    store::Store,
    Result,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};

fn merge_overwatch_defaults(game: &mut Game, defaults: Game) {
    let mut endpoint_ids: BTreeSet<String> = game
        .regions
        .iter()
        .flat_map(|region| region.endpoints.iter().map(|endpoint| endpoint.id.clone()))
        .collect();
    for region in defaults.regions {
        if let Some(saved) = game.regions.iter_mut().find(|saved| saved.id == region.id) {
            // Older bundled Google templates predate providerScope. Adding the
            // trusted mapping lets explicit refresh update them while preserving
            // custom endpoints.
            if saved.provider_scope.is_none() && region.provider_scope.is_some() {
                saved.provider_scope = region.provider_scope;
            }
            // Explicit refresh also migrates newly bundled trusted ranges into
            // existing regions and updates older bundled entries by their stable
            // IDs. Custom endpoints are never replaced.
            for endpoint in region.endpoints {
                if let Some(saved_endpoint) = saved
                    .endpoints
                    .iter_mut()
                    .find(|saved_endpoint| saved_endpoint.id == endpoint.id)
                {
                    if !saved_endpoint.custom {
                        *saved_endpoint = endpoint;
                    }
                    continue;
                }
                let target_exists = saved.endpoints.iter().any(|saved_endpoint| {
                    saved_endpoint.address == endpoint.address
                        && saved_endpoint.protocol == endpoint.protocol
                        && saved_endpoint.ports == endpoint.ports
                });
                if !target_exists && endpoint_ids.insert(endpoint.id.clone()) {
                    saved.endpoints.push(endpoint);
                }
            }
        } else {
            endpoint_ids.extend(region.endpoints.iter().map(|endpoint| endpoint.id.clone()));
            game.regions.push(region);
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PendingKeys {
    Resolved(BTreeSet<inspection::RuleKey>),
    // Invalid imported program scopes still need an edit baseline. Comparing
    // error strings would miss target edits while the same validation error remains.
    Invalid(BTreeSet<(String, String, Option<String>, Option<String>)>),
}

#[derive(Clone)]
pub struct Runtime {
    pub snapshot: Snapshot,
    pub samples: BTreeMap<String, PingSample>,
    pub histories: BTreeMap<String, Vec<f64>>,
    /// Immutable OS readback, independent of the pending catalogue and selections.
    pub applied_targets: Option<Vec<FirewallTarget>>,
    pub applied_count: Option<usize>,
    /// Attribution of observed rules; IDs alone do not prove current target coverage.
    pub applied_game_ids: Vec<String>,
    pub region_states: BTreeMap<String, RegionState>,
    pub inspected_at: Option<u64>,
    pub inspection: Option<Inspection>,
    pub verification: Verification,
    pub verification_error: String,
    /// Comparison baseline only, never active-state evidence. Before the first
    /// successful read this is the loaded selection; afterwards it is native keys.
    pending_baseline: PendingKeys,
    pub dirty: bool,
    pub message: String,
    pub generation: u64,
}

pub struct Engine {
    store: Store,
    state: Mutex<Runtime>,
    operation: Mutex<()>,
}

impl Engine {
    pub fn new(store: Store) -> Result<Arc<Self>> {
        let snapshot = store.snapshot()?;
        let pending_baseline = Self::pending_keys(&snapshot);
        Ok(Arc::new(Self {
            store,
            state: Mutex::new(Runtime {
                snapshot,
                samples: BTreeMap::new(),
                histories: BTreeMap::new(),
                applied_targets: None,
                region_states: BTreeMap::new(),
                inspected_at: None,
                inspection: None,
                verification: Verification::Unverified,
                verification_error: String::new(),
                applied_count: None,
                applied_game_ids: vec![],
                pending_baseline,
                dirty: false,
                message: "Loading firewall status. No rules are changed automatically.".into(),
                generation: 0,
            }),
            operation: Mutex::new(()),
        }))
    }

    pub fn runtime(&self) -> Runtime {
        self.state.lock().unwrap().clone()
    }

    /// Never writes preferences, recovery hints, or firewall rules. The UI reads
    /// on launch and allows authentication if existing privileges are insufficient.
    pub fn verify_firewall(&self, elevated: bool) -> Result<()> {
        let _operation = self.operation.lock().map_err(|e| e.to_string())?;
        // Inspection is independent of desired-rule validation, missing games,
        // executable paths, and saved switch positions.
        self.accept_readback(firewall::inspect_firewall(elevated))
    }

    fn record_inspection(&self, report: Inspection) -> Result<()> {
        report.validate()?;
        let mut state = self.state.lock().map_err(|e| e.to_string())?;
        let relevant = state
            .snapshot
            .preferences
            .library_game_ids
            .iter()
            .chain(&state.snapshot.preferences.last_applied_game_ids)
            .chain(&state.applied_game_ids)
            .cloned()
            .chain(selected_game_ids(
                &state.snapshot.games,
                &state.snapshot.preferences,
            ))
            .collect::<BTreeSet<_>>();
        let targets = inspection::observed_targets(
            &state.snapshot.games,
            &report,
            FirewallScope::native(),
            &relevant,
        );
        state.applied_game_ids = targets
            .iter()
            .filter(|t| !t.game_id.is_empty())
            .map(|t| t.game_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        state.applied_count = Some(report.rules.len());
        state.applied_targets = Some(targets);
        state.pending_baseline = PendingKeys::Resolved(report.keys());
        state.inspected_at = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_millis() as u64,
        );
        state.inspection = Some(report);
        state.verification_error.clear();
        Self::reconcile(&mut state);
        state.message = match state.verification {
            Verification::Matched => "Saved selections match active LobbyLocker rules.",
            Verification::Empty => "No active LobbyLocker rules found. Saved selections are unchanged.",
            _ => "Active LobbyLocker rules were read from the OS firewall. They differ from saved selections; the active list remains authoritative.",
        }.into();
        Ok(())
    }

    /// Desired edits only affect pending differences. They cannot manufacture or
    /// erase the observed addresses, executable scopes, or active status.
    fn reconcile(state: &mut Runtime) {
        let Some(report) = &state.inspection else {
            state.dirty = Self::pending_keys(&state.snapshot) != state.pending_baseline;
            return;
        };
        let actual = report.keys();
        let desired = resolve_rules(&state.snapshot.games, &state.snapshot.preferences)
            .and_then(|rules| inspection::expected_keys(&rules));
        state.dirty = desired.as_ref().map_or(true, |keys| *keys != actual);
        state.verification = if actual.is_empty() {
            Verification::Empty
        } else if state.dirty {
            Verification::Different
        } else {
            Verification::Matched
        };
        state.region_states =
            inspection::region_states(&state.snapshot.games, report, FirewallScope::native());
    }

    /// Ignore names, probe settings, ordering, duplicates, and library curation.
    /// Missing Windows programs are allowed in this comparison only: generating
    /// rules still requires resolve_rules and can never fall back to global scope.
    fn pending_keys(snapshot: &Snapshot) -> PendingKeys {
        let rules = selected_targets(&snapshot.games, &snapshot.preferences)
            .into_iter()
            .flat_map(|target| {
                target
                    .endpoints
                    .into_iter()
                    .map(move |endpoint| FirewallRule {
                        endpoint,
                        program: target.executable_path.clone(),
                    })
            })
            .collect::<Vec<_>>();
        Self::pending_rules(&rules)
    }

    fn pending_rules(rules: &[FirewallRule]) -> PendingKeys {
        match inspection::expected_keys(rules) {
            Ok(keys) => PendingKeys::Resolved(keys),
            Err(_) => PendingKeys::Invalid(
                rules
                    .iter()
                    .map(|rule| {
                        (
                            rule.endpoint.address.clone(),
                            format!("{:?}", rule.endpoint.protocol),
                            rule.endpoint.ports.clone(),
                            rule.program
                                .as_ref()
                                .map(|path| path.replace('/', "\\").to_lowercase()),
                        )
                    })
                    .collect(),
            ),
        }
    }

    fn invalidate_inspection(&self, error: &str) -> Result<()> {
        let mut state = self.state.lock().map_err(|e| e.to_string())?;
        state.applied_count = None;
        state.applied_targets = None;
        state.inspection = None;
        state.region_states.clear();
        state.inspected_at = None;
        state.verification = Verification::Unverified;
        state.verification_error = error.into();
        // Keep attributed IDs accessible as recovery hints, never active proof.
        Self::reconcile(&mut state);
        state.message =
            "Could not read firewall status. Existing blocks have not been changed by this check."
                .into();
        Ok(())
    }

    pub fn preferences(&self, mut preferences: Preferences) -> Result<()> {
        let _operation = self.operation.lock().map_err(|e| e.to_string())?;
        // Only successful firewall operations change the recovery hint.
        preferences.last_applied_game_ids =
            self.runtime().snapshot.preferences.last_applied_game_ids;
        self.store.save_preferences(&preferences)?;
        let mut state = self.state.lock().map_err(|e| e.to_string())?;
        state.snapshot.preferences = preferences;
        state.generation += 1;
        Self::reconcile(&mut state);
        state.message = if state.dirty {
            "Selection saved. Apply changes to update the firewall."
        } else {
            "Selection saved."
        }
        .into();
        Ok(())
    }

    /// Persists a UI language without changing pending firewall selections or measurements.
    pub fn set_language(&self, code: &str) -> Result<()> {
        crate::model::validate_id(code)?;
        let _operation = self.operation.lock().map_err(|e| e.to_string())?;
        let mut state = self.state.lock().map_err(|e| e.to_string())?;
        let mut preferences = state.snapshot.preferences.clone();
        preferences.language = code.into();
        self.store.save_preferences(&preferences)?;
        state.snapshot.preferences = preferences;
        Ok(())
    }

    pub fn save_game(&self, game: &Game) -> Result<()> {
        let _operation = self.operation.lock().map_err(|e| e.to_string())?;
        self.store.save_game(game)?;
        let snapshot = self.store.snapshot()?;
        let mut state = self.state.lock().map_err(|e| e.to_string())?;
        state.snapshot = snapshot;
        state.generation += 1;
        Self::reconcile(&mut state);
        state.message = format!(
            "Saved games/{}.json. Existing firewall rules are unchanged until Apply.",
            game.id
        );
        Ok(())
    }

    /// Library discovery settings never change pending firewall selections or probes.
    pub fn set_game_library_paths(&self, paths: Vec<String>) -> Result<()> {
        let excluded = self
            .runtime()
            .snapshot
            .preferences
            .excluded_game_library_paths;
        self.set_game_library_settings(paths, excluded)
    }

    pub fn set_game_library_settings(
        &self,
        paths: Vec<String>,
        excluded: Vec<String>,
    ) -> Result<()> {
        let _operation = self.operation.lock().map_err(|e| e.to_string())?;
        let mut state = self.state.lock().map_err(|e| e.to_string())?;
        let mut preferences = state.snapshot.preferences.clone();
        preferences.game_library_paths = paths;
        preferences.excluded_game_library_paths = excluded;
        self.store.save_preferences(&preferences)?;
        state.snapshot.preferences = preferences;
        Ok(())
    }

    /// Curating the sidebar is not a firewall operation. Newly selected detected
    /// games get empty configs; existing files and block selections are preserved.
    pub fn set_library_games(
        &self,
        mut ids: Vec<String>,
        detected: &[crate::installed::InstalledGame],
    ) -> Result<()> {
        let _operation = self.operation.lock().map_err(|e| e.to_string())?;
        ids.sort();
        ids.dedup();
        let mut preferences = self.runtime().snapshot.preferences;
        preferences.library_game_ids = ids;
        preferences.validate()?;
        let snapshot = self.store.snapshot()?;
        let mut new_games = Vec::new();
        for id in &preferences.library_game_ids {
            if snapshot.games.iter().any(|game| &game.id == id) {
                continue;
            }
            let installed = detected
                .iter()
                .find(|game| &game.id == id && !crate::installed::is_launcher_tool(game))
                .ok_or("Choose a detected or configured game.")?;
            new_games.push(crate::installed::empty_game(id.clone(), &installed.name)?);
        }
        for game in &new_games {
            self.store.save_game(game)?;
        }
        self.store.save_preferences(&preferences)?;
        let snapshot = self.store.snapshot()?;
        self.state.lock().map_err(|e| e.to_string())?.snapshot = snapshot;
        Ok(())
    }

    pub fn refresh_game(&self, game_id: &str) -> Result<()> {
        // Serialize the full refresh so custom edits cannot be overwritten by a late response.
        let _operation = self.operation.lock().map_err(|e| e.to_string())?;
        let mut game = self
            .runtime()
            .snapshot
            .games
            .into_iter()
            .find(|g| g.id == game_id)
            .ok_or("Game not found.")?;
        if game.id == "overwatch2" {
            // Upgrade bundled targets only on an explicit refresh, never on startup.
            // Existing regions, custom endpoints, and selections remain untouched.
            let defaults = self.store.default_game(game_id)?;
            merge_overwatch_defaults(&mut game, defaults);
        }
        let updated = catalogue::refresh(&game)?;
        self.store.save_game(&updated)?;
        let mut state = self.state.lock().map_err(|e| e.to_string())?;
        state.snapshot = self.store.snapshot()?;
        state.generation += 1;
        Self::reconcile(&mut state);
        state.message = "Server file refreshed. Review the new targets before applying.".into();
        Ok(())
    }

    pub fn apply(&self) -> Result<()> {
        let _operation = self.operation.lock().map_err(|e| e.to_string())?;
        let runtime = self.runtime();
        // Invalid desired input cannot change or invalidate a prior OS snapshot.
        let rules = resolve_rules(&runtime.snapshot.games, &runtime.snapshot.preferences)?;
        let result = firewall::change_with_readback(&Request::Apply { rules });
        match result {
            Ok(outcome) => {
                let ids = selected_game_ids(&runtime.snapshot.games, &runtime.snapshot.preferences);
                self.finish_apply(ids, outcome)
            }
            Err(error) => {
                self.invalidate_inspection(&error)?;
                self.state.lock().map_err(|e| e.to_string())?.message = error.clone();
                Err(error)
            }
        }
    }

    // Recovery hints never confirm blocking. Only the helper's OS readback does.
    fn save_recovery(&self, ids: Vec<String>) -> Result<()> {
        let mut state = self.state.lock().map_err(|e| e.to_string())?;
        state.snapshot.preferences.last_applied_game_ids = ids;
        self.store
            .save_preferences(&state.snapshot.preferences)
            .map_err(|error| {
                let message =
                    format!("Firewall updated, but saving recovery information failed: {error}");
                state.message = message.clone();
                message
            })
    }

    fn accept_readback(&self, result: Result<Inspection>) -> Result<()> {
        match result.and_then(|report| self.record_inspection(report)) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.invalidate_inspection(&error)?;
                Err(error)
            }
        }
    }

    fn finish_apply(&self, ids: Vec<String>, outcome: FirewallOutcome) -> Result<()> {
        let readback = self.accept_readback(outcome.inspection);
        let recovery = if outcome.operation_error.is_none() {
            let state = self.runtime();
            let hints = if readback.is_ok() && !state.dirty {
                // Preserve known games affected by shared system-wide rules,
                // even when their own switches are now off.
                state.applied_game_ids
            } else {
                // An unreadable or incomplete result must not erase recovery
                // access to previously owned targets.
                state
                    .snapshot
                    .preferences
                    .last_applied_game_ids
                    .into_iter()
                    .chain(state.applied_game_ids)
                    .chain(ids)
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect()
            };
            self.save_recovery(hints)
        } else {
            Ok(())
        };
        if let Some(error) = outcome.operation_error {
            self.state.lock().map_err(|e| e.to_string())?.message = error.clone();
            return Err(error);
        }
        readback.map_err(|error| {
            format!("Firewall update completed, but its active rules could not be read: {error}")
        })?;
        recovery?;
        if self.runtime().dirty {
            return Err("Apply completed, but active LobbyLocker rules differ from saved selections. The firewall list shows the actual rules.".into());
        }
        self.state.lock().map_err(|e| e.to_string())?.message = "Firewall updated and read back successfully. Rules remain active when the app is closed.".into();
        Ok(())
    }

    pub fn reset(&self) -> Result<()> {
        let _operation = self.operation.lock().map_err(|e| e.to_string())?;
        {
            let mut state = self.state.lock().map_err(|e| e.to_string())?;
            state.generation += 1;
        }
        match firewall::change_with_readback(&Request::Reset {}) {
            Ok(outcome) => self.finish_reset(outcome),
            Err(error) => {
                self.invalidate_inspection(&error)?;
                self.state.lock().map_err(|e| e.to_string())?.message = error.clone();
                Err(error)
            }
        }
    }

    fn finish_reset(&self, outcome: FirewallOutcome) -> Result<()> {
        let readback = self.accept_readback(outcome.inspection);
        if let Some(error) = outcome.operation_error {
            self.state.lock().map_err(|e| e.to_string())?.message = error.clone();
            return Err(error);
        }
        readback.map_err(|error| format!("Reset completed, but remaining rules could not be read. Saved selections and recovery hints were kept: {error}"))?;
        if self.runtime().applied_count != Some(0) {
            return Err("Reset completed, but active LobbyLocker rules remain. Saved selections and recovery hints were kept.".into());
        }
        let mut state = self.state.lock().map_err(|e| e.to_string())?;
        state.snapshot.preferences.last_applied_game_ids.clear();
        state.dirty = false;
        state.snapshot.preferences.blocked_regions.clear();
        self.store
            .save_preferences(&state.snapshot.preferences)
            .map_err(|e| {
                format!("Firewall rules were removed, but saving preferences failed: {e}")
            })?;
        state.message =
            "No active LobbyLocker blocks remain. Other firewall rules were untouched.".into();
        Ok(())
    }

    /// A read-only network check invoked by the user, never by a timer or startup.
    /// Measurements never change selections or firewall rules.
    pub fn measure_latency(&self, game_id: &str, region_id: Option<&str>) -> Result<()> {
        self.measure_latency_filtered(game_id, region_id, None)
    }

    pub fn measure_area_latency(&self, game_id: &str, area: &str) -> Result<()> {
        self.measure_latency_filtered(game_id, None, Some(area))
    }

    fn measure_latency_filtered(
        &self,
        game_id: &str,
        region_id: Option<&str>,
        area: Option<&str>,
    ) -> Result<()> {
        let before = self.runtime();
        let mut game = before
            .snapshot
            .games
            .iter()
            .find(|g| g.id == game_id)
            .cloned()
            .ok_or("Game not found.")?;
        if let Some(region_id) = region_id {
            game.regions.retain(|r| r.id == region_id);
            if game.regions.is_empty() {
                return Err("Server location not found.".into());
            }
        }
        if let Some(area) = area {
            game.regions.retain(|r| r.area == area);
            if game.regions.is_empty() {
                return Err("Server region not found.".into());
            }
        }
        if !game.regions.iter().any(|r| r.probe_target.is_some()) {
            return Err(
                "No ping targets configured. Open Advanced and add a responding probe IP.".into(),
            );
        }
        let samples = latency::measure(&[game]);
        let _operation = self.operation.lock().map_err(|e| e.to_string())?;
        self.record_latency(before.generation, &samples)
    }

    fn record_latency(&self, generation: u64, samples: &[PingSample]) -> Result<()> {
        let mut state = self.state.lock().map_err(|e| e.to_string())?;
        if state.generation != generation {
            return Ok(());
        }
        for sample in samples {
            if let Some(ms) = sample.latency_ms {
                let history = state
                    .histories
                    .entry(sample.region_key.clone())
                    .or_default();
                history.push(ms);
                if history.len() > 24 {
                    history.remove(0);
                }
            }
            state
                .samples
                .insert(sample.region_key.clone(), sample.clone());
        }
        state.message = "Manual ping check complete. No firewall rules changed.".into();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_rules(games: &[Game], preferences: &Preferences) -> Inspection {
        let rules = resolve_rules(games, preferences).unwrap();
        Inspection {
            rules: rules
                .iter()
                .flat_map(|rule| {
                    inspection::expected_keys(std::slice::from_ref(rule))
                        .unwrap()
                        .into_iter()
                        .map(|key| inspection::ObservedRule {
                            key,
                            source_id: Some(rule.endpoint.id.clone()),
                        })
                })
                .collect(),
        }
    }

    fn selected_fixture(engine: &Engine) -> Inspection {
        let mut game = engine
            .runtime()
            .snapshot
            .games
            .into_iter()
            .find(|g| g.id == "deadlock")
            .unwrap();
        game.executable_path = Some(r"C:\Games\deadlock.exe".into());
        engine.save_game(&game).unwrap();
        let mut preferences = engine.runtime().snapshot.preferences;
        preferences.blocked_regions = vec!["deadlock:dxb".into()];
        engine.preferences(preferences).unwrap();
        let snapshot = engine.runtime().snapshot;
        fixture_rules(&snapshot.games, &snapshot.preferences)
    }

    #[test]
    fn invalid_imported_programs_do_not_hide_new_edits_behind_the_same_error() {
        let mut rule = FirewallRule {
            endpoint: crate::model::Endpoint {
                id: "test".into(),
                address: "203.0.113.7".into(),
                protocol: crate::model::Protocol::Udp,
                ports: None,
                custom: false,
            },
            program: Some("old-linux-path".into()),
        };
        let baseline = Engine::pending_rules(&[rule.clone()]);
        assert!(matches!(baseline, PendingKeys::Invalid(_)));
        rule.endpoint.id = "renamed-source".into();
        assert_eq!(
            Engine::pending_rules(&[rule.clone(), rule.clone()]),
            baseline
        );
        rule.endpoint.address = "203.0.113.8".into();
        assert_ne!(Engine::pending_rules(&[rule.clone()]), baseline);
        rule.endpoint.address = "203.0.113.7".into();
        assert_eq!(Engine::pending_rules(&[rule.clone()]), baseline);
        rule.program = Some(r"C:\Games\example.exe".into());
        assert_ne!(Engine::pending_rules(&[rule]), baseline);
    }

    #[test]
    fn unreadable_restart_is_not_a_pending_apply_and_edits_can_be_undone() {
        let root = tempfile::tempdir().unwrap();
        let defaults =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../data/games");
        let store = Store::open(root.path().into(), &defaults).unwrap();
        let mut snapshot = store.snapshot().unwrap();
        snapshot.preferences.blocked_regions = vec!["deadlock:dxb".into()];
        store.save_preferences(&snapshot.preferences).unwrap();
        let engine = Engine::new(store).unwrap();
        let saved = std::fs::read(root.path().join("preferences.json")).unwrap();
        assert!(!engine.runtime().dirty);
        assert!(engine
            .accept_readback(Err("Authorization cancelled".into()))
            .is_err());
        let before = engine.runtime();
        assert!(!before.dirty);
        assert!(before.applied_count.is_none());
        assert!(before.region_states.is_empty());
        assert_eq!(
            std::fs::read(root.path().join("preferences.json")).unwrap(),
            saved
        );

        let mut preferences = before.snapshot.preferences.clone();
        preferences.blocked_regions.clear();
        engine.preferences(preferences).unwrap();
        assert!(engine.runtime().dirty);
        assert!(engine.runtime().applied_count.is_none());
        engine
            .preferences(before.snapshot.preferences.clone())
            .unwrap();
        assert!(!engine.runtime().dirty);

        let mut game = before
            .snapshot
            .games
            .iter()
            .find(|g| g.id == "deadlock")
            .unwrap()
            .clone();
        game.name = "Renamed".into();
        game.regions
            .iter_mut()
            .find(|r| r.id == "dxb")
            .unwrap()
            .probe_target = Some("203.0.113.5".into());
        engine.save_game(&game).unwrap();
        assert!(!engine.runtime().dirty);
        let original = game.clone();
        game.regions
            .iter_mut()
            .find(|r| r.id == "dxb")
            .unwrap()
            .endpoints[0]
            .address = "203.0.113.9".into();
        engine.save_game(&game).unwrap();
        assert!(engine.runtime().dirty);
        engine.save_game(&original).unwrap();
        assert!(!engine.runtime().dirty);
        engine.set_language("ar").unwrap();
        engine.set_library_games(vec![], &[]).unwrap();
        assert!(!engine.runtime().dirty);
    }

    #[test]
    fn unreadable_retry_preserves_a_known_difference_but_never_active_status() {
        let root = tempfile::tempdir().unwrap();
        let defaults =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../data/games");
        let engine = Engine::new(Store::open(root.path().into(), &defaults).unwrap()).unwrap();
        let report = selected_fixture(&engine);
        engine.record_inspection(Inspection::default()).unwrap();
        assert!(engine.runtime().dirty);
        engine
            .invalidate_inspection("Authorization cancelled")
            .unwrap();
        assert!(engine.runtime().dirty);
        assert!(engine.runtime().applied_count.is_none());
        engine.record_inspection(report).unwrap();
        assert!(!engine.runtime().dirty);
        engine.invalidate_inspection("Read failed").unwrap();
        assert!(!engine.runtime().dirty);
    }

    #[test]
    fn failed_or_incomplete_updates_show_observed_rules_instead_of_requested_success() {
        let root = tempfile::tempdir().unwrap();
        let defaults =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../data/games");
        let engine = Engine::new(Store::open(root.path().into(), &defaults).unwrap()).unwrap();
        let mut report = selected_fixture(&engine);
        report.rules.pop();
        let saved = std::fs::read(root.path().join("preferences.json")).unwrap();
        let outcome = FirewallOutcome {
            operation_error: Some("Fixture mutation failure".into()),
            inspection: Ok(report.clone()),
        };
        assert!(engine
            .finish_apply(vec!["deadlock".into()], outcome)
            .is_err());
        let runtime = engine.runtime();
        assert_eq!(runtime.applied_count, Some(1));
        assert_eq!(runtime.region_states["deadlock:dxb"], RegionState::Partial);
        assert_eq!(runtime.verification, Verification::Different);
        assert_eq!(
            std::fs::read(root.path().join("preferences.json")).unwrap(),
            saved
        );
        let outcome = FirewallOutcome {
            operation_error: None,
            inspection: Ok(report),
        };
        assert!(engine
            .finish_apply(vec!["deadlock".into()], outcome)
            .is_err());
        assert_eq!(engine.runtime().applied_count, Some(1));
        let outcome = FirewallOutcome {
            operation_error: None,
            inspection: Err("Fixture read denied".into()),
        };
        assert!(engine
            .finish_apply(vec!["deadlock".into()], outcome)
            .is_err());
        let runtime = engine.runtime();
        assert!(runtime.applied_count.is_none());
        assert!(runtime.applied_targets.is_none());
        assert!(runtime.region_states.is_empty());
        assert!(runtime.inspected_at.is_none());
        assert_eq!(runtime.verification, Verification::Unverified);
        assert_eq!(
            runtime.snapshot.preferences.blocked_regions,
            vec!["deadlock:dxb"]
        );
    }

    #[test]
    fn reset_clears_choices_only_when_readback_proves_no_owned_blocks_remain() {
        let root = tempfile::tempdir().unwrap();
        let defaults =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../data/games");
        let engine = Engine::new(Store::open(root.path().into(), &defaults).unwrap()).unwrap();
        let report = selected_fixture(&engine);
        engine.save_recovery(vec!["deadlock".into()]).unwrap();
        let saved = std::fs::read(root.path().join("preferences.json")).unwrap();
        assert!(engine
            .finish_reset(FirewallOutcome {
                operation_error: None,
                inspection: Ok(report)
            })
            .is_err());
        assert_eq!(engine.runtime().applied_count, Some(2));
        assert_eq!(
            engine.runtime().region_states["deadlock:dxb"],
            RegionState::Blocked
        );
        assert_eq!(
            std::fs::read(root.path().join("preferences.json")).unwrap(),
            saved
        );
        assert!(engine
            .finish_reset(FirewallOutcome {
                operation_error: None,
                inspection: Err("Unreadable".into())
            })
            .is_err());
        assert_eq!(
            std::fs::read(root.path().join("preferences.json")).unwrap(),
            saved
        );
        engine
            .finish_reset(FirewallOutcome {
                operation_error: None,
                inspection: Ok(Inspection::default()),
            })
            .unwrap();
        assert_eq!(engine.runtime().applied_count, Some(0));
        assert!(engine
            .runtime()
            .snapshot
            .preferences
            .blocked_regions
            .is_empty());
        assert!(engine
            .runtime()
            .snapshot
            .preferences
            .last_applied_game_ids
            .is_empty());
        assert!(!engine.runtime().dirty);
    }

    #[test]
    fn reverting_desired_edits_matches_the_same_os_snapshot_without_reapplying() {
        let root = tempfile::tempdir().unwrap();
        let defaults =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../data/games");
        let engine = Engine::new(Store::open(root.path().into(), &defaults).unwrap()).unwrap();
        let report = selected_fixture(&engine);
        engine.record_inspection(report).unwrap();
        let before = engine.runtime();
        let mut preferences = before.snapshot.preferences.clone();
        preferences.blocked_regions.clear();
        engine.preferences(preferences).unwrap();
        assert!(engine.runtime().dirty);
        assert_eq!(
            engine.runtime().region_states["deadlock:dxb"],
            RegionState::Blocked
        );
        engine.preferences(before.snapshot.preferences).unwrap();
        let after = engine.runtime();
        assert!(!after.dirty);
        assert_eq!(after.applied_targets, before.applied_targets);
        assert_eq!(after.inspected_at, before.inspected_at);
        assert_eq!(after.verification, Verification::Matched);
    }

    #[test]
    fn active_count_reports_native_rules_not_saved_target_or_game_counts() {
        let root = tempfile::tempdir().unwrap();
        let defaults =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../data/games");
        let engine = Engine::new(Store::open(root.path().into(), &defaults).unwrap()).unwrap();
        let mut report = selected_fixture(&engine);
        report.rules.push(report.rules[0].clone());
        engine.record_inspection(report).unwrap();
        assert_eq!(engine.runtime().applied_count, Some(3));
        assert_eq!(
            engine.runtime().region_states["deadlock:dxb"],
            RegionState::Blocked
        );
        assert!(!engine.runtime().dirty);
        assert_eq!(
            engine.runtime().applied_targets.unwrap()[0].endpoints.len(),
            3
        );
    }

    #[test]
    fn unverified_removals_keep_recovery_hints_until_absence_is_read_back() {
        let root = tempfile::tempdir().unwrap();
        let defaults =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../data/games");
        let engine = Engine::new(Store::open(root.path().into(), &defaults).unwrap()).unwrap();
        engine.save_recovery(vec!["cs2".into()]).unwrap();
        assert!(engine
            .finish_apply(
                vec![],
                FirewallOutcome {
                    operation_error: None,
                    inspection: Err("Unreadable".into())
                }
            )
            .is_err());
        assert_eq!(
            engine.runtime().snapshot.preferences.last_applied_game_ids,
            vec!["cs2"]
        );
        assert!(engine.runtime().applied_count.is_none());
        engine
            .finish_apply(
                vec![],
                FirewallOutcome {
                    operation_error: None,
                    inspection: Ok(Inspection::default()),
                },
            )
            .unwrap();
        assert!(engine
            .runtime()
            .snapshot
            .preferences
            .last_applied_game_ids
            .is_empty());
        assert_eq!(engine.runtime().applied_count, Some(0));
    }

    #[test]
    fn read_only_verification_restores_matching_blocks_without_saving_or_applying() {
        let root = tempfile::tempdir().unwrap();
        let defaults =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../data/games");
        let engine = Engine::new(Store::open(root.path().into(), &defaults).unwrap()).unwrap();
        let report = selected_fixture(&engine);
        let before = std::fs::read(root.path().join("preferences.json")).unwrap();
        let restarted = Engine::new(Store::open(root.path().into(), &defaults).unwrap()).unwrap();
        assert!(!restarted.runtime().dirty);
        assert!(restarted.runtime().applied_count.is_none());
        restarted.record_inspection(report.clone()).unwrap();
        assert!(!restarted.runtime().dirty);
        assert_eq!(
            restarted.runtime().region_states["deadlock:dxb"],
            RegionState::Blocked
        );
        assert_eq!(restarted.runtime().applied_count, Some(2));
        engine.record_inspection(report.clone()).unwrap();
        let state = engine.runtime();
        assert_eq!(state.applied_count, Some(2));
        assert_eq!(state.applied_game_ids, vec!["deadlock"]);
        assert!(state
            .applied_targets
            .unwrap()
            .iter()
            .any(|target| target.region_id == "dxb"));
        assert!(!state.dirty);
        assert!(state.snapshot.preferences.last_applied_game_ids.is_empty());
        assert_eq!(
            std::fs::read(root.path().join("preferences.json")).unwrap(),
            before
        );
        engine.record_inspection(Inspection::default()).unwrap();
        assert_eq!(engine.runtime().applied_count, Some(0));
        assert!(engine.runtime().dirty);
        assert_eq!(
            engine.runtime().snapshot.preferences.blocked_regions,
            vec!["deadlock:dxb"]
        );
        let mut pending = engine.runtime().snapshot.preferences;
        pending.blocked_regions.clear();
        engine.preferences(pending).unwrap();
        let saved = std::fs::read(root.path().join("preferences.json")).unwrap();
        engine.record_inspection(report).unwrap();
        assert_eq!(engine.runtime().applied_count, Some(2));
        assert_eq!(
            engine.runtime().region_states["deadlock:dxb"],
            RegionState::Blocked
        );
        assert!(engine.runtime().dirty);
        assert_eq!(engine.runtime().verification, Verification::Different);
        assert_eq!(
            std::fs::read(root.path().join("preferences.json")).unwrap(),
            saved
        );
    }

    #[test]
    fn last_applied_game_hints_survive_restart_and_do_not_claim_verified_firewall_state() {
        let root = tempfile::tempdir().unwrap();
        let defaults =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../data/games");
        let engine = Engine::new(Store::open(root.path().into(), &defaults).unwrap()).unwrap();
        engine.save_recovery(vec!["cs2".into()]).unwrap();
        let mut preferences = engine.runtime().snapshot.preferences;
        preferences.blocked_regions.clear();
        preferences.last_applied_game_ids.clear();
        engine.preferences(preferences).unwrap();
        engine.set_library_games(vec![], &[]).unwrap();
        let reopened = Engine::new(Store::open(root.path().into(), &defaults).unwrap()).unwrap();
        let loaded = reopened.runtime();
        assert!(loaded.snapshot.preferences.library_game_ids.is_empty());
        assert!(loaded.snapshot.preferences.blocked_regions.is_empty());
        assert_eq!(
            loaded.snapshot.preferences.last_applied_game_ids,
            vec!["cs2"]
        );
        assert!(loaded.applied_count.is_none());
        assert!(loaded.applied_targets.is_none());
        assert!(loaded.applied_game_ids.is_empty());
        reopened.save_recovery(vec![]).unwrap();
        reopened.record_inspection(Inspection::default()).unwrap();
        assert_eq!(reopened.runtime().applied_targets, Some(vec![]));
        let cleared = Store::open(root.path().into(), &defaults)
            .unwrap()
            .snapshot()
            .unwrap();
        assert!(cleared.preferences.last_applied_game_ids.is_empty());
    }

    #[test]
    fn curating_games_persists_without_replacing_files_or_changing_firewall_state() {
        let root = tempfile::tempdir().unwrap();
        let defaults =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../data/games");
        let engine = Engine::new(Store::open(root.path().into(), &defaults).unwrap()).unwrap();
        {
            let mut state = engine.state.lock().unwrap();
            state.snapshot.preferences.blocked_regions = vec!["cs2:dxb".into()];
            state.applied_count = Some(1);
            state.applied_game_ids = vec!["cs2".into()];
            state.dirty = false;
            state.generation = 5;
            state
                .samples
                .insert("cs2:dxb".into(), sample(Some(50.0), 1000));
        }
        let original = std::fs::read(root.path().join("games/cs2.json")).unwrap();
        let before = engine.runtime();
        let detected = vec![crate::installed::InstalledGame {
            id: "steam-123".into(),
            name: "Example".into(),
            launcher: "Steam".into(),
            directory: root.path().into(),
        }];
        engine
            .set_library_games(
                vec!["cs2".into(), "steam-123".into(), "cs2".into()],
                &detected,
            )
            .unwrap();
        let after = engine.runtime();
        assert_eq!(
            after.snapshot.preferences.library_game_ids,
            vec!["cs2", "steam-123"]
        );
        assert!(after
            .snapshot
            .games
            .iter()
            .find(|game| game.id == "steam-123")
            .unwrap()
            .regions
            .is_empty());
        assert_eq!(
            before.snapshot.preferences.blocked_regions,
            after.snapshot.preferences.blocked_regions
        );
        assert_eq!(before.applied_count, after.applied_count);
        assert_eq!(before.applied_game_ids, after.applied_game_ids);
        assert_eq!(before.dirty, after.dirty);
        assert_eq!(before.generation, after.generation);
        assert_eq!(before.message, after.message);
        assert_eq!(after.samples["cs2:dxb"].latency_ms, Some(50.0));
        assert_eq!(
            std::fs::read(root.path().join("games/cs2.json")).unwrap(),
            original
        );
        let reopened = Engine::new(Store::open(root.path().into(), &defaults).unwrap()).unwrap();
        assert_eq!(
            reopened.runtime().snapshot.preferences.library_game_ids,
            vec!["cs2", "steam-123"]
        );
        assert!(reopened.runtime().applied_game_ids.is_empty());
        assert!(reopened.runtime().applied_count.is_none());
        engine.set_library_games(vec![], &[]).unwrap();
        assert!(engine
            .runtime()
            .snapshot
            .preferences
            .library_game_ids
            .is_empty());
        assert_eq!(engine.runtime().applied_game_ids, vec!["cs2"]);
        assert!(root.path().join("games/steam-123.json").exists());
        assert!(engine
            .set_library_games(vec!["unknown".into()], &[])
            .is_err());
        assert!(engine
            .runtime()
            .snapshot
            .preferences
            .library_game_ids
            .is_empty());
    }

    #[test]
    fn manual_samples_never_change_selections_or_firewall_state() {
        let root = tempfile::tempdir().unwrap();
        let defaults =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../data/games");
        let store = Store::open(root.path().into(), &defaults).unwrap();
        let preferences = Preferences::default();
        store.save_preferences(&preferences).unwrap();
        let engine = Engine::new(store).unwrap();
        // No startup measurements or automatic selections.
        assert!(engine.runtime().samples.is_empty());
        {
            let mut state = engine.state.lock().unwrap();
            state.applied_count = Some(0);
            state.dirty = false;
        }
        for time in [1000, 2000, 3000] {
            engine
                .record_latency(0, &[sample(Some(150.0), time)])
                .unwrap();
        }
        let runtime = engine.runtime();
        assert!(runtime.snapshot.preferences.blocked_regions.is_empty());
        assert!(runtime.applied_targets.is_none());
        assert_eq!(runtime.applied_count, Some(0));
        assert!(!runtime.dirty);
        assert!(runtime.message.contains("No firewall rules changed"));
        assert_eq!(runtime.histories["cs2:dxb"].len(), 3);
    }

    #[test]
    fn changed_configuration_discards_late_manual_results() {
        let root = tempfile::tempdir().unwrap();
        let defaults =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../data/games");
        let engine = Engine::new(Store::open(root.path().into(), &defaults).unwrap()).unwrap();
        let generation = engine.runtime().generation;
        engine.preferences(Preferences::default()).unwrap();
        engine
            .record_latency(generation, &[sample(Some(150.0), 1000)])
            .unwrap();
        assert!(engine.runtime().samples.is_empty());
    }

    #[test]
    fn changing_library_folders_preserves_known_firewall_state_and_measurements() {
        let root = tempfile::tempdir().unwrap();
        let defaults =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../data/games");
        let engine = Engine::new(Store::open(root.path().into(), &defaults).unwrap()).unwrap();
        {
            let mut state = engine.state.lock().unwrap();
            state.snapshot.preferences.blocked_regions = vec!["cs2:dxb".into()];
            state.applied_count = Some(1);
            state.dirty = false;
            state.generation = 5;
            state
                .samples
                .insert("cs2:dxb".into(), sample(Some(50.0), 1000));
            state.histories.insert("cs2:dxb".into(), vec![50.0]);
        }
        let before = engine.runtime();
        engine
            .set_game_library_paths(vec![root
                .path()
                .join("extra-library")
                .to_str()
                .unwrap()
                .to_owned()])
            .unwrap();
        let after = engine.runtime();
        assert_eq!(
            before.snapshot.preferences.blocked_regions,
            after.snapshot.preferences.blocked_regions
        );
        assert_eq!(before.applied_count, after.applied_count);
        assert_eq!(before.dirty, after.dirty);
        assert_eq!(before.generation, after.generation);
        assert_eq!(before.histories, after.histories);
        assert_eq!(before.message, after.message);
        assert_eq!(after.samples["cs2:dxb"].latency_ms, Some(50.0));
    }

    #[test]
    fn manual_checks_report_missing_targets_without_network_access() {
        let root = tempfile::tempdir().unwrap();
        let defaults =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../data/games");
        let engine = Engine::new(Store::open(root.path().into(), &defaults).unwrap()).unwrap();
        assert!(engine
            .measure_latency("overwatch2", None)
            .unwrap_err()
            .contains("No ping targets"));
        assert!(engine
            .measure_latency("overwatch2", Some("not-found"))
            .is_err());
        assert!(engine.measure_latency("not-found", None).is_err());
        assert!(engine.runtime().samples.is_empty());
        assert_eq!(engine.runtime().applied_count, None);
    }

    #[test]
    fn explicit_overwatch_refresh_migration_adds_bundled_ranges_and_preserves_saved_data() {
        let defaults_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../data/games/overwatch2.json");
        let defaults: Game =
            serde_json::from_slice(&std::fs::read(defaults_path).unwrap()).unwrap();
        let mut saved = defaults.clone();
        saved
            .regions
            .retain(|region| region.id == "gcp-europe-north1" || region.id == "blizzard-ams1");
        saved
            .regions
            .iter_mut()
            .find(|region| region.id == "gcp-europe-north1")
            .unwrap()
            .provider_scope = None;
        let amsterdam = saved
            .regions
            .iter_mut()
            .find(|region| region.id == "blizzard-ams1")
            .unwrap();
        amsterdam.endpoints[0].protocol = crate::model::Protocol::Udp;
        amsterdam.endpoints.push(crate::model::Endpoint {
            id: "my-ams-server".into(),
            address: "203.0.113.8".into(),
            protocol: crate::model::Protocol::Udp,
            ports: None,
            custom: true,
        });
        saved.regions.push(crate::model::Region {
            id: "my-server".into(),
            name: "My server".into(),
            area: "Custom".into(),
            probe_target: Some("203.0.113.7".into()),
            provider_scope: None,
            endpoints: vec![crate::model::Endpoint {
                id: "mine".into(),
                address: "203.0.113.7".into(),
                protocol: crate::model::Protocol::Udp,
                ports: None,
                custom: true,
            }],
        });

        merge_overwatch_defaults(&mut saved, defaults);

        assert_eq!(
            saved
                .regions
                .iter()
                .find(|region| region.id == "gcp-europe-north1")
                .unwrap()
                .provider_scope
                .as_deref(),
            Some("europe-north1")
        );
        assert_eq!(
            saved
                .regions
                .iter()
                .filter(|region| region.id.starts_with("blizzard-"))
                .count(),
            5
        );
        let amsterdam = saved
            .regions
            .iter()
            .find(|region| region.id == "blizzard-ams1")
            .unwrap();
        assert!(amsterdam
            .endpoints
            .iter()
            .any(|endpoint| endpoint.address == "64.224.26.0/23"
                && endpoint.protocol == crate::model::Protocol::Any
                && !endpoint.custom));
        assert!(amsterdam
            .endpoints
            .iter()
            .any(|endpoint| endpoint.id == "my-ams-server" && endpoint.custom));
        assert!(saved.regions.iter().any(|region| region.id == "my-server"));
    }

    fn sample(ms: Option<f64>, time: u64) -> PingSample {
        PingSample {
            region_key: "cs2:dxb".into(),
            target: "203.0.113.1".into(),
            latency_ms: ms,
            error: None,
            measured_at: time,
        }
    }
    #[test]
    fn applied_targets_are_immutable_across_pending_edits() {
        let root = tempfile::tempdir().unwrap();
        let defaults =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../data/games");
        let engine = Engine::new(Store::open(root.path().into(), &defaults).unwrap()).unwrap();
        let mut game = crate::installed::custom_game(
            "example".into(),
            "Example",
            "Custom",
            "203.0.113.7",
            crate::model::Protocol::Udp,
            None,
        )
        .unwrap();
        game.executable_path = Some(r"C:\Games\example.exe".into());
        engine.save_game(&game).unwrap();
        let mut preferences = engine.runtime().snapshot.preferences;
        preferences.blocked_regions = vec!["example:custom".into()];
        engine.preferences(preferences).unwrap();
        let before = engine.runtime();
        let report = fixture_rules(&before.snapshot.games, &before.snapshot.preferences);
        engine.record_inspection(report).unwrap();
        let targets = engine.runtime().applied_targets;
        game.regions[0].endpoints[0].address = "203.0.113.9".into();
        engine.save_game(&game).unwrap();
        let mut preferences = engine.runtime().snapshot.preferences;
        preferences.blocked_regions.clear();
        engine.preferences(preferences).unwrap();
        let after = engine.runtime();
        assert!(after.dirty);
        assert_eq!(after.applied_targets, targets);
        assert_eq!(after.applied_count, Some(1));
        assert!(
            crate::model::selected_targets(&after.snapshot.games, &after.snapshot.preferences)
                .is_empty()
        );
    }
}
