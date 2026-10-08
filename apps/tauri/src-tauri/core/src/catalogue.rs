use crate::{
    model::{normalize_address, Endpoint, Game, Protocol, Region},
    Result,
};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Deserialize)]
struct SdrConfig {
    success: bool,
    pops: BTreeMap<String, Pop>,
}
#[derive(Deserialize)]
struct Pop {
    desc: String,
    #[serde(default)]
    relays: Vec<Relay>,
}
#[derive(Deserialize)]
struct Relay {
    ipv4: String,
    port_range: [u16; 2],
}

fn area(code: &str) -> &'static str {
    match code {
        "dxb" | "bah" => "Middle East",
        "gru" | "eze" | "lim" | "scl" => "South America",
        "ams" | "fra" | "lhr" | "sto" | "sto2" | "vie" | "waw" | "mad" | "par" | "hel" | "fsn"
        | "dfra" | "dvie" | "dsto" | "dlhr" => "Europe",
        "iad" | "ord" | "lax" | "sea" | "atl" | "dfw" | "eat" => "North America",
        "syd" | "mel" | "gum" => "Oceania",
        "jnb" => "Africa",
        _ => "Asia",
    }
}

pub fn refresh(game: &Game) -> Result<Game> {
    if game.id == "overwatch2" {
        return refresh_overwatch(game);
    }
    // Upstream URL is selected by trusted code, not user input (no arbitrary URL fetch / SSRF).
    let appid = match game.id.as_str() {
        "cs2" => 730,
        "deadlock" => 1422450,
        _ => return Err(
            "This game has no official automatic feed. Import a reviewed game JSON file instead."
                .into(),
        ),
    };
    let url = format!("https://api.steampowered.com/ISteamApps/GetSDRConfig/v1/?appid={appid}");
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(20))
        .https_only(true)
        .build()
        .map_err(|e| e.to_string())?;
    let response = client
        .get(&url)
        .send()
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?;
    if response.content_length().is_some_and(|n| n > 2_000_000) {
        return Err("Server feed is too large.".into());
    }
    // Bound the body even when the upstream omits Content-Length.
    use std::io::Read;
    let mut body = Vec::new();
    response
        .take(2_000_001)
        .read_to_end(&mut body)
        .map_err(|e| e.to_string())?;
    if body.len() > 2_000_000 {
        return Err("Server feed is too large.".into());
    }
    let config: SdrConfig = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
    if !config.success || config.pops.is_empty() {
        return Err("Valve returned no relay configuration.".into());
    }
    let mut updated = game.clone();
    let mut regions = Vec::new();
    for (code, pop) in config.pops {
        if pop.relays.is_empty() {
            continue;
        }
        let mut endpoints: Vec<_> = pop
            .relays
            .iter()
            .enumerate()
            .map(|(i, relay)| Endpoint {
                id: format!("{code}-{i}"),
                address: relay.ipv4.clone(),
                protocol: Protocol::Udp,
                ports: Some(format!("{}-{}", relay.port_range[0], relay.port_range[1])),
                custom: false,
            })
            .collect();
        let old = game.regions.iter().find(|r| r.id == code);
        if let Some(old) = old {
            endpoints.extend(old.endpoints.iter().filter(|e| e.custom).cloned());
        }
        regions.push(Region {
            id: code.clone(),
            name: pop.desc,
            area: area(&code).into(),
            probe_target: old
                .and_then(|r| r.probe_target.clone())
                .or_else(|| endpoints.first().map(|e| e.address.clone())),
            provider_scope: None,
            endpoints,
        });
    }
    // Preserve manually added regions and custom endpoints for retired upstream locations.
    for old in &game.regions {
        if !regions.iter().any(|r| r.id == old.id) {
            let mut custom = old.clone();
            custom.endpoints.retain(|e| e.custom);
            if !custom.endpoints.is_empty() {
                regions.push(custom);
            }
        }
    }
    updated.regions = regions;
    updated.source = Some(url);
    updated.updated_at = Some(format!(
        "unix:{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    ));
    updated.note = "Official Valve SDR relays. Shared with other Steam games; region blocking does not guarantee matchmaking location. ICMP may be unavailable.".into();
    updated.validate()?;
    Ok(updated)
}

const GOOGLE_CLOUD_URL: &str = "https://www.gstatic.com/ipranges/cloud.json";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GoogleNetworkFeed {
    creation_time: Option<String>,
    prefixes: Vec<GoogleNetworkPrefix>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GoogleNetworkPrefix {
    ipv4_prefix: Option<String>,
    ipv6_prefix: Option<String>,
    service: String,
    scope: String,
}

fn refresh_overwatch(game: &Game) -> Result<Game> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(20))
        .https_only(true)
        .build()
        .map_err(|e| e.to_string())?;
    let response = client
        .get(GOOGLE_CLOUD_URL)
        .send()
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?;
    use std::io::Read;
    let mut body = Vec::new();
    response
        .take(2_000_001)
        .read_to_end(&mut body)
        .map_err(|e| e.to_string())?;
    if body.len() > 2_000_000 {
        return Err("Google Cloud feed is too large.".into());
    }
    update_google_regions(game, &body)
}

/// Parse provider-owned data without relying on another blocker's code or IP list.
/// Only scopes explicitly configured in this game's file can contribute rules.
fn update_google_regions(game: &Game, body: &[u8]) -> Result<Game> {
    game.validate()?;
    if body.len() > 2_000_000 {
        return Err("Google Cloud feed is too large.".into());
    }
    let requested: BTreeSet<_> = game
        .regions
        .iter()
        .filter_map(|r| r.provider_scope.as_deref())
        .collect();
    if requested.is_empty() {
        return Err("No Google Cloud region mappings configured. Add providerScope to a region in this game's JSON file.".into());
    }
    let feed: GoogleNetworkFeed =
        serde_json::from_slice(body).map_err(|e| format!("Invalid Google Cloud feed: {e}"))?;
    if feed.prefixes.len() > 20_000 {
        return Err("Google Cloud feed contains too many prefixes.".into());
    }
    let mut by_scope: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for prefix in feed.prefixes {
        if prefix.service != "Google Cloud" || !requested.contains(prefix.scope.as_str()) {
            continue;
        }
        let (address, ipv6) = match (prefix.ipv4_prefix, prefix.ipv6_prefix) {
            (Some(address), None) => (address, false),
            (None, Some(address)) => (address, true),
            _ => {
                return Err(
                    "A configured Google Cloud prefix has missing or ambiguous address fields."
                        .into(),
                )
            }
        };
        if !address.contains('/') || address.contains(':') != ipv6 {
            return Err("Invalid Google Cloud CIDR or address family.".into());
        }
        let address = normalize_address(&address)?;
        by_scope.entry(prefix.scope).or_default().insert(address);
    }
    // Refuse incomplete updates instead of silently removing a location's rules.
    for scope in &requested {
        if !by_scope.contains_key(*scope) {
            return Err(format!("Google returned no ranges for configured scope {scope}. Your saved file was not changed."));
        }
    }
    let mut updated = game.clone();
    for region in &mut updated.regions {
        let Some(scope) = &region.provider_scope else {
            continue;
        };
        let custom: Vec<_> = region
            .endpoints
            .iter()
            .filter(|e| e.custom)
            .cloned()
            .collect();
        region.endpoints = by_scope[scope]
            .iter()
            .enumerate()
            .map(|(i, address)| Endpoint {
                id: format!("gcp-{}-{i}", region.id),
                address: address.clone(),
                protocol: Protocol::Udp,
                ports: None,
                custom: false,
            })
            .collect();
        region.endpoints.extend(custom);
        // A cloud subnet's base address is not a known responding server.
        // Preserve explicit probes, but never fabricate one from its CIDR.
    }
    updated.source = Some(GOOGLE_CLOUD_URL.into());
    updated.updated_at = feed.creation_time;
    updated.note = "Provider-managed entries are Google Cloud regional network ranges, NOT Blizzard-verified Overwatch server IPs. Blocks cover all applications' UDP traffic to those shared ranges. They do not cover every Blizzard/other-provider server or guarantee matchmaking location. Other saved regions are unchanged. Add a known responding IP for latency monitoring; no probe is guessed from a subnet.".into();
    updated.validate()?;
    Ok(updated)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn template() -> Game {
        let defaults = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../data/games/overwatch2.json");
        let mut game: Game = serde_json::from_slice(&std::fs::read(defaults).unwrap()).unwrap();
        game.regions
            .retain(|region| region.id == "gcp-europe-north1");
        game
    }

    #[test]
    fn google_refresh_filters_scopes_and_normalizes_both_families() {
        let mut game = template();
        let custom = Endpoint {
            id: "custom-target".into(),
            address: "198.51.100.7".into(),
            protocol: Protocol::Tcp,
            ports: Some("443".into()),
            custom: true,
        };
        game.regions[0].endpoints.push(custom.clone());
        game.regions[0].probe_target = Some("198.51.100.7".into());
        let body = br#"{"creationTime":"2026-10-03","prefixes":[
            {"ipv4Prefix":"203.0.113.8/24","service":"Google Cloud","scope":"europe-north1"},
            {"ipv4Prefix":"203.0.113.0/24","service":"Google Cloud","scope":"europe-north1"},
            {"ipv6Prefix":"2001:db8::/48","service":"Google Cloud","scope":"europe-north1"},
            {"ipv4Prefix":"198.51.100.0/24","service":"Google Cloud","scope":"global"}
        ]}"#;
        let updated = update_google_regions(&game, body).unwrap();
        assert_eq!(updated.regions[0].endpoints.len(), 3);
        assert!(updated.regions[0].endpoints.contains(&custom));
        assert_eq!(
            updated.regions[0].probe_target,
            game.regions[0].probe_target
        );
        assert_eq!(updated.source.as_deref(), Some(GOOGLE_CLOUD_URL));
        assert_eq!(game.regions[0].endpoints.len(), 1);
    }

    #[test]
    fn google_refresh_does_not_invent_ping_targets() {
        let body = br#"{"prefixes":[{"ipv4Prefix":"203.0.113.0/24","service":"Google Cloud","scope":"europe-north1"}]}"#;
        let updated = update_google_regions(&template(), body).unwrap();
        assert_eq!(updated.regions[0].probe_target, None);
    }

    #[test]
    fn google_refresh_preserves_unmanaged_regions() {
        let mut game = template();
        let manual_region = Region {
            id: "manual-region".into(),
            name: "Manually maintained server".into(),
            area: "Custom".into(),
            probe_target: Some("198.51.100.7".into()),
            provider_scope: None,
            endpoints: vec![Endpoint {
                id: "manual-server".into(),
                address: "198.51.100.7".into(),
                protocol: Protocol::Udp,
                ports: Some("27015".into()),
                custom: true,
            }],
        };
        game.regions.push(manual_region.clone());
        let body = br#"{"prefixes":[{"ipv4Prefix":"203.0.113.0/24","service":"Google Cloud","scope":"europe-north1"}]}"#;
        let updated = update_google_regions(&game, body).unwrap();
        assert_eq!(updated.regions[1], manual_region);
    }

    #[test]
    fn invalid_and_incomplete_provider_updates_are_rejected() {
        for body in [
            br#"{"prefixes":[]}"#.as_slice(),
            br#"{"prefixes":[{"ipv4Prefix":"0.0.0.0/0","service":"Google Cloud","scope":"europe-north1"}]}"#.as_slice(),
            br#"{"prefixes":[{"ipv4Prefix":"203.0.113.1; reboot","service":"Google Cloud","scope":"europe-north1"}]}"#.as_slice(),
            br#"{"prefixes":[{"ipv6Prefix":"203.0.113.0/24","service":"Google Cloud","scope":"europe-north1"}]}"#.as_slice(),
        ] {
            assert!(update_google_regions(&template(), body).is_err());
        }
        let mut game = template();
        game.regions[0].provider_scope = Some("global".into());
        assert!(game.validate().is_err());
    }
}
