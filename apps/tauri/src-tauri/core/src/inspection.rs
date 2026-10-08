//! Read-only, conservative verification. Never infer active rules from disk
//! preferences, rule names alone, or an unsuccessful OS query.
use crate::{
    firewall::{OWNER, TABLE, WINDOWS_GROUP, WINDOWS_NETSECURITY},
    model::{
        normalize_address, parse_ports, windows_program, Endpoint, FirewallRule, FirewallScope,
        FirewallTarget, Game, Protocol,
    },
    Result,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

pub const MAX_READBACK_BYTES: usize = 5_000_000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Verification {
    #[default]
    Unverified,
    Matched,
    Empty,
    Different,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleKey {
    address: String,
    protocol: String,
    ports: Option<(u16, u16)>,
    program: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObservedRule {
    pub key: RuleKey,
    pub source_id: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Inspection {
    pub rules: Vec<ObservedRule>,
}

impl Inspection {
    pub fn validate(&self) -> Result<()> {
        if self.rules.len() > 10000 {
            return Err("Too many observed firewall rules.".into());
        }
        for rule in &self.rules {
            if address_key(&rule.key.address)? != rule.key.address {
                return Err("Non-canonical observed address.".into());
            }
            if !matches!(rule.key.protocol.as_str(), "tcp" | "udp" | "any") {
                return Err("Invalid observed protocol.".into());
            }
            if let Some((start, end)) = rule.key.ports {
                if start == 0 || start > end || rule.key.protocol == "any" {
                    return Err("Invalid observed port filter.".into());
                }
            }
            if let Some(program) = &rule.key.program {
                if windows_program(program)?.to_lowercase() != *program {
                    return Err("Non-canonical observed program.".into());
                }
            }
            if let Some(id) = &rule.source_id {
                crate::model::validate_id(id)?;
            }
        }
        Ok(())
    }
    pub fn keys(&self) -> BTreeSet<RuleKey> {
        self.rules.iter().map(|rule| rule.key.clone()).collect()
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_READBACK_BYTES {
            return Err("Firewall readback is too large.".into());
        }
        let report: Self = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        report.validate()?;
        Ok(report)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RegionState {
    Blocked,
    Partial,
    None,
    Unknown,
}

impl RuleKey {
    fn overlaps(&self, required: &Self) -> bool {
        let a = self.address.parse::<ipnet::IpNet>().ok();
        let b = required.address.parse::<ipnet::IpNet>().ok();
        let addresses = a
            .zip(b)
            .is_some_and(|(a, b)| a.contains(&b.network()) || b.contains(&a.network()));
        let program = self.program.is_none() || self.program == required.program;
        let proto = self.protocol == "any"
            || required.protocol == "any"
            || self.protocol == required.protocol;
        let ports = match (self.ports, required.ports) {
            (Some((a, b)), Some((c, d))) => a <= d && c <= b,
            _ => true,
        };
        addresses && program && proto && ports
    }
    fn covers(&self, required: &Self) -> bool {
        let a = self.address.parse::<ipnet::IpNet>().ok();
        let b = required.address.parse::<ipnet::IpNet>().ok();
        let addresses = a
            .zip(b)
            .is_some_and(|(a, b)| a.prefix_len() <= b.prefix_len() && a.contains(&b.network()));
        let ports = match (self.ports, required.ports) {
            (None, _) => true,
            (Some((a, b)), Some((c, d))) => a <= c && b >= d,
            _ => false,
        };
        addresses
            && ports
            && (self.program.is_none() || self.program == required.program)
            && (self.protocol == "any" || self.protocol == required.protocol)
    }
    fn endpoint(&self, index: usize) -> Endpoint {
        Endpoint {
            id: format!("observed-{index}"),
            address: self.address.clone(),
            protocol: match self.protocol.as_str() {
                "tcp" => Protocol::Tcp,
                "udp" => Protocol::Udp,
                _ => Protocol::Any,
            },
            ports: self.ports.map(|(a, b)| {
                if a == b {
                    a.to_string()
                } else {
                    format!("{a}-{b}")
                }
            }),
            custom: false,
        }
    }
}

fn endpoint_keys(
    endpoint: &Endpoint,
    game: &Game,
    scope: FirewallScope,
) -> Result<BTreeSet<RuleKey>> {
    expected_keys(&[FirewallRule {
        endpoint: endpoint.clone(),
        program: if scope == FirewallScope::Executable {
            game.executable_path.clone()
        } else {
            None
        },
    }])
}

fn address_range(net: ipnet::IpNet) -> (u128, u128) {
    match net {
        ipnet::IpNet::V4(net) => (
            u32::from(net.network()) as u128,
            u32::from(net.broadcast()) as u128,
        ),
        ipnet::IpNet::V6(net) => (u128::from(net.network()), u128::from(net.broadcast())),
    }
}

fn ranges_cover(mut ranges: Vec<(u128, u128)>, (start, end): (u128, u128)) -> bool {
    ranges.sort_unstable();
    let mut next = start;
    for (a, b) in ranges {
        if b < next {
            continue;
        }
        if a > next {
            return false;
        }
        if b >= end {
            return true;
        }
        next = b + 1;
    }
    false
}

/// Multiple narrow OS rules can collectively cover a catalogue range. Partition
/// port intervals, then merge address intervals in each partition. Do not count
/// separate TCP/UDP rules as covering a genuine Any-protocol/no-port target.
fn covered_by(actual: &BTreeSet<RuleKey>, required: &RuleKey) -> bool {
    if actual.iter().any(|key| key.covers(required)) {
        return true;
    }
    let Ok(net) = required.address.parse::<ipnet::IpNet>() else {
        return false;
    };
    let addresses = address_range(net);
    let candidates: Vec<_> = actual
        .iter()
        .filter(|key| {
            key.overlaps(required) && (key.protocol == "any" || key.protocol == required.protocol)
        })
        .filter_map(|key| {
            key.address
                .parse::<ipnet::IpNet>()
                .ok()
                .map(|net| (address_range(net), key.ports))
        })
        .collect();
    let Some((start, end)) = required.ports else {
        return ranges_cover(
            candidates
                .into_iter()
                .filter(|(_, ports)| ports.is_none())
                .map(|(range, _)| range)
                .collect(),
            addresses,
        );
    };
    let mut boundaries = BTreeSet::from([start as u32, end as u32 + 1]);
    for (_, ports) in &candidates {
        if let Some((a, b)) = ports {
            boundaries.insert((*a).max(start) as u32);
            boundaries.insert((*b).min(end) as u32 + 1);
        }
    }
    let boundaries: Vec<_> = boundaries.into_iter().collect();
    boundaries.windows(2).all(|segment| {
        ranges_cover(
            candidates
                .iter()
                .filter(|(_, ports)| {
                    ports.is_none_or(|(a, b)| a as u32 <= segment[0] && b as u32 >= segment[1] - 1)
                })
                .map(|(range, _)| *range)
                .collect(),
            addresses,
        )
    })
}

/// Region status ignores saved switches. Conservative coverage supports broader
/// existing address/port rules and partial TCP/UDP blocks without overclaiming.
pub fn region_states(
    games: &[Game],
    report: &Inspection,
    scope: FirewallScope,
) -> BTreeMap<String, RegionState> {
    let actual = report.keys();
    let mut states = BTreeMap::new();
    for game in games {
        for region in &game.regions {
            let keys = region
                .endpoints
                .iter()
                .map(|e| endpoint_keys(e, game, scope))
                .collect::<Result<Vec<_>>>();
            let state = if actual.is_empty() {
                RegionState::None
            } else {
                match keys {
                    Ok(keys) => {
                        let required: BTreeSet<_> = keys.into_iter().flatten().collect();
                        if required.is_empty() {
                            RegionState::None
                        } else if required
                            .iter()
                            .all(|required| covered_by(&actual, required))
                        {
                            RegionState::Blocked
                        } else if scope == FirewallScope::Executable
                            && game.executable_path.is_none()
                        {
                            RegionState::Unknown
                        } else if required
                            .iter()
                            .any(|required| actual.iter().any(|key| key.overlaps(required)))
                        {
                            RegionState::Partial
                        } else {
                            RegionState::None
                        }
                    }
                    Err(_) => RegionState::Unknown,
                }
            };
            states.insert(format!("{}:{}", game.id, region.id), state);
        }
    }
    states
}

/// Every displayed endpoint is from OS readback, including old/removed targets.
/// Catalogue data and owner IDs only supply labels; unmatched rules stay visible.
pub fn observed_targets(
    games: &[Game],
    report: &Inspection,
    scope: FirewallScope,
    relevant: &BTreeSet<String>,
) -> Vec<FirewallTarget> {
    let mut groups: BTreeMap<(String, String, Option<String>), FirewallTarget> = BTreeMap::new();
    for (index, observed) in report.rules.iter().enumerate() {
        let mut labels = Vec::new();
        for game in games {
            let owned_endpoint = observed
                .source_id
                .as_deref()
                .and_then(|id| id.strip_prefix(&format!("{}-", game.id)));
            for region in &game.regions {
                if region.endpoints.iter().any(|endpoint| {
                    owned_endpoint == Some(endpoint.id.as_str())
                        || (relevant.contains(&game.id)
                            && endpoint_keys(endpoint, game, scope).is_ok_and(|keys| {
                                keys.iter().any(|key| observed.key.overlaps(key))
                            }))
                }) {
                    labels.push((
                        game.id.clone(),
                        game.name.clone(),
                        region.id.clone(),
                        region.name.clone(),
                    ));
                }
            }
        }
        if labels.is_empty() {
            let owner = games
                .iter()
                .filter(|game| {
                    observed
                        .source_id
                        .as_deref()
                        .is_some_and(|id| id.starts_with(&format!("{}-", game.id)))
                })
                .max_by_key(|game| game.id.len());
            labels.push(
                owner
                    .map(|game| {
                        (
                            game.id.clone(),
                            game.name.clone(),
                            String::new(),
                            "Unmapped managed rules".into(),
                        )
                    })
                    .unwrap_or((
                        String::new(),
                        "Unmapped managed rules".into(),
                        String::new(),
                        "From the OS firewall".into(),
                    )),
            );
        }
        for (game_id, game_name, region_id, region_name) in labels {
            let target = groups
                .entry((
                    game_id.clone(),
                    region_id.clone(),
                    observed.key.program.clone(),
                ))
                .or_insert_with(|| FirewallTarget {
                    game_id,
                    game_name,
                    region_id,
                    region_name,
                    executable_path: observed.key.program.clone(),
                    endpoints: vec![],
                });
            target.endpoints.push(observed.key.endpoint(index));
        }
    }
    groups.into_values().collect()
}

fn address_key(address: &str) -> Result<String> {
    let normalized = normalize_address(address)?;
    let net = normalized
        .parse::<ipnet::IpNet>()
        .or_else(|_| normalized.parse::<IpAddr>().map(Into::into))
        .map_err(|e| e.to_string())?;
    Ok(net.to_string())
}

pub fn expected_keys(rules: &[FirewallRule]) -> Result<BTreeSet<RuleKey>> {
    let mut keys = BTreeSet::new();
    for rule in rules {
        rule.endpoint.validate()?;
        let ports = parse_ports(&rule.endpoint.ports)?;
        let protocols = match (&rule.endpoint.protocol, ports) {
            (Protocol::Any, Some(_)) => vec!["tcp", "udp"],
            (Protocol::Any, None) => vec!["any"],
            (Protocol::Tcp, _) => vec!["tcp"],
            (Protocol::Udp, _) => vec!["udp"],
        };
        for protocol in protocols {
            keys.insert(RuleKey {
                address: address_key(&rule.endpoint.address)?,
                protocol: protocol.into(),
                ports,
                program: rule
                    .program
                    .as_deref()
                    .map(windows_program)
                    .transpose()?
                    .map(|p| p.to_lowercase()),
            });
        }
    }
    Ok(keys)
}

pub fn compare(actual: &BTreeSet<RuleKey>, expected: &BTreeSet<RuleKey>) -> Verification {
    if actual.is_empty() {
        Verification::Empty
    } else if actual == expected {
        Verification::Matched
    } else {
        Verification::Different
    }
}

fn nft_address(value: &Value) -> Result<String> {
    if let Some(address) = value.as_str() {
        return address_key(address);
    }
    let prefix = &value["prefix"];
    let address = prefix["addr"]
        .as_str()
        .ok_or("Unsupported nft address expression.")?;
    let length = prefix["len"]
        .as_u64()
        .ok_or("Unsupported nft address prefix.")?;
    address_key(&format!("{address}/{length}"))
}

fn protocol(value: &Value) -> Result<String> {
    match value.as_str().map(str::to_ascii_lowercase).as_deref() {
        Some("tcp" | "6") => Ok("tcp".into()),
        Some("udp" | "17") => Ok("udp".into()),
        Some("any" | "256") => Ok("any".into()),
        _ => match value.as_u64() {
            Some(6) => Ok("tcp".into()),
            Some(17) => Ok("udp".into()),
            Some(256) => Ok("any".into()),
            _ => Err("Unsupported firewall protocol.".into()),
        },
    }
}

fn nft_ports(value: &Value) -> Result<(u16, u16)> {
    let (start, end) = if let Some(port) = value.as_u64() {
        (port, port)
    } else {
        let range = value["range"]
            .as_array()
            .filter(|r| r.len() == 2)
            .ok_or("Unsupported nft port expression.")?;
        (
            range[0].as_u64().ok_or("Invalid nft port.")?,
            range[1].as_u64().ok_or("Invalid nft port.")?,
        )
    };
    if start == 0 || end > 65535 || start > end {
        return Err("Invalid nft ports.".into());
    }
    Ok((start as u16, end as u16))
}

/// Only recognize the owned outbound chain and the exact expressions emitted by
/// LobbyLocker. An altered jump/allow/extra constraint must not look verified.
pub fn linux_keys(json: &Value) -> Result<BTreeSet<RuleKey>> {
    Ok(linux_snapshot(json)?.keys())
}

pub fn linux_snapshot(json: &Value) -> Result<Inspection> {
    let entries = json["nftables"]
        .as_array()
        .ok_or("Invalid nftables response.")?;
    let mut table = false;
    let mut chain = false;
    let mut rules = Vec::new();
    for entry in entries {
        if entry.get("metainfo").is_some() {
            continue;
        }
        if let Some(value) = entry.get("table") {
            if table
                || value["family"] != "inet"
                || value["name"] != TABLE
                || value["comment"] != OWNER
                || value
                    .get("flags")
                    .is_some_and(|flags| flags.as_array().is_none_or(|flags| !flags.is_empty()))
            {
                return Err("The firewall table is not owned by LobbyLocker.".into());
            }
            table = true;
            continue;
        }
        if let Some(value) = entry.get("chain") {
            if chain
                || value["family"] != "inet"
                || value["table"] != TABLE
                || value["name"] != "outbound"
                || value["type"] != "filter"
                || value["hook"] != "output"
                || value["prio"] != 10
                || value["policy"] != "accept"
                || value
                    .get("flags")
                    .is_some_and(|flags| flags.as_array().is_none_or(|flags| !flags.is_empty()))
            {
                return Err("LobbyLocker's firewall chain has changed.".into());
            }
            chain = true;
            continue;
        }
        let rule = entry
            .get("rule")
            .ok_or("Unsupported object in LobbyLocker's firewall table.")?;
        if rule["family"] != "inet" || rule["table"] != TABLE || rule["chain"] != "outbound" {
            return Err("Unexpected LobbyLocker rule chain.".into());
        }
        let id = rule["comment"]
            .as_str()
            .and_then(|c| c.strip_prefix("ll:"))
            .ok_or("Unrecognized firewall rule ownership.")?;
        crate::model::validate_id(id)?;
        let mut address = None;
        let mut proto = None;
        let mut ports = None;
        let mut dropped = false;
        let expressions = rule["expr"]
            .as_array()
            .filter(|e| e.len() <= 5)
            .ok_or("Unsupported nft rule expressions.")?;
        for expression in expressions {
            if dropped {
                return Err("Unexpected expression after drop.".into());
            }
            if expression.get("counter").is_some() {
                continue;
            }
            if expression.get("drop").is_some() {
                dropped = true;
                continue;
            }
            let matched = expression
                .get("match")
                .filter(|m| m["op"] == "==" || m["op"] == "in")
                .ok_or("Unsupported nft firewall expression.")?;
            let left = &matched["left"];
            let right = &matched["right"];
            if left["payload"]["field"] == "daddr"
                && ["ip", "ip6"]
                    .iter()
                    .any(|p| left["payload"]["protocol"] == *p)
                && address.is_none()
            {
                let parsed = nft_address(right)?;
                if parsed.contains(':') != (left["payload"]["protocol"] == "ip6") {
                    return Err("Mismatched nft address family.".into());
                }
                address = Some(parsed);
            } else if left["meta"]["key"] == "l4proto" && proto.is_none() {
                proto = Some(protocol(right)?);
            } else if left["payload"]["field"] == "dport" && ports.is_none() {
                let port_proto = protocol(&left["payload"]["protocol"])?;
                if proto.as_deref().is_some_and(|p| p != port_proto) || port_proto == "any" {
                    return Err("Unexpected nft port protocol.".into());
                }
                proto = Some(port_proto);
                ports = Some(nft_ports(right)?);
            } else {
                return Err("Unsupported or repeated nft match.".into());
            }
        }
        if !dropped {
            return Err("LobbyLocker rule does not drop traffic.".into());
        }
        rules.push(ObservedRule {
            source_id: Some(id.into()),
            key: RuleKey {
                address: address.ok_or("Missing nft destination address.")?,
                protocol: proto.unwrap_or("any".into()),
                ports,
                program: None,
            },
        });
        if rules.len() > 10000 {
            return Err("Too many firewall rules to verify.".into());
        }
    }
    if !table || !chain {
        return Err("Incomplete LobbyLocker firewall table.".into());
    }
    let report = Inspection { rules };
    report.validate()?;
    Ok(report)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WindowsReport {
    enforced: bool,
    supported: bool,
    rules: Vec<WindowsRule>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WindowsRule {
    address: String,
    protocol: Value,
    ports: String,
    program: Option<String>,
    #[serde(default)]
    source_id: Option<String>,
}

pub fn windows_keys(json: &Value) -> Result<BTreeSet<RuleKey>> {
    Ok(windows_snapshot(json)?.keys())
}

pub fn windows_snapshot(json: &Value) -> Result<Inspection> {
    let report: WindowsReport = serde_json::from_value(json.clone()).map_err(|e| e.to_string())?;
    if !report.supported || (!report.enforced && !report.rules.is_empty()) {
        return Err(
            "Windows firewall is disabled or LobbyLocker rules have unsupported filters.".into(),
        );
    }
    if report.rules.len() > 10000 {
        return Err("Too many firewall rules to verify.".into());
    }
    let rules = report
        .rules
        .into_iter()
        .map(|rule| {
            let ports = if rule.ports.eq_ignore_ascii_case("any") {
                None
            } else {
                Some(rule.ports)
            };
            Ok(ObservedRule {
                source_id: rule.source_id,
                key: RuleKey {
                    address: address_key(&rule.address)?,
                    protocol: protocol(&rule.protocol)?,
                    ports: parse_ports(&ports)?,
                    program: rule
                        .program
                        .filter(|p| !p.eq_ignore_ascii_case("any"))
                        .as_deref()
                        .map(windows_program)
                        .transpose()?
                        .map(|p| p.to_lowercase()),
                },
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let snapshot = Inspection { rules };
    snapshot.validate()?;
    Ok(snapshot)
}

/// ActiveStore reflects effective rules, not just disk configuration. This script
/// contains no write cmdlets and never runs a selected game executable.
pub fn windows_inspection_script() -> String {
    format!(
        r#"$ErrorActionPreference='Stop'; {WINDOWS_NETSECURITY}[Console]::OutputEncoding=(New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false); $supported=$true; $rows=@(); $profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore); $services=@(Get-Service -Name MpsSvc,BFE); $enforced=$profiles.Count -eq 3 -and $services.Count -eq 2 -and @($services | Where-Object {{[string]$_.Status -ne 'Running'}}).Count -eq 0 -and @($profiles | Where-Object {{[string]$_.Enabled -ne 'True' -or [string]$_.AllowLocalFirewallRules -eq 'False'}}).Count -eq 0;
$owned=@(Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object {{$_.Group -eq '{WINDOWS_GROUP}'}});
foreach ($r in $owned) {{
 if ([string]$r.Enabled -ne 'True' -or [string]$r.Direction -ne 'Outbound' -or [string]$r.Action -ne 'Block') {{continue}}
 $a=$r|Get-NetFirewallAddressFilter; $p=$r|Get-NetFirewallPortFilter; $app=$r|Get-NetFirewallApplicationFilter; $svc=$r|Get-NetFirewallServiceFilter; $iface=$r|Get-NetFirewallInterfaceFilter; $type=$r|Get-NetFirewallInterfaceTypeFilter; $security=$r|Get-NetFirewallSecurityFilter;
  if ([string]$r.Profile -ne 'Any' -or @($a.RemoteAddress).Count -ne 1 -or [string]$a.LocalAddress -ne 'Any' -or [string]$p.LocalPort -ne 'Any' -or @($p.RemotePort).Count -ne 1 -or [string]$svc.Service -ne 'Any' -or [string]$iface.InterfaceAlias -ne 'Any' -or [string]$type.InterfaceType -ne 'Any' -or ($app.Package -and [string]$app.Package -ne 'Any') -or [string]$security.Authentication -ne 'NotRequired' -or [string]$security.Encryption -ne 'NotRequired' -or [string]$security.LocalUser -ne 'Any' -or [string]$security.RemoteUser -ne 'Any' -or [string]$security.RemoteMachine -ne 'Any') {{$supported=$false}}
 $source=$null; if ([string]$r.Name -match '^LobbyLocker\.[a-fA-F0-9]{{32}}\.([a-zA-Z0-9_-]{{1,96}})\.(TCP|UDP|Any)$') {{$source=$Matches[1]}}
 $rows += [pscustomobject]@{{address=[string]$a.RemoteAddress[0];protocol=[string]$p.Protocol;ports=[string]$p.RemotePort[0];program=[string]$app.Program;sourceId=$source}}
}}
[pscustomobject]@{{enforced=$enforced;supported=$supported;rules=@($rows)}}|ConvertTo-Json -Depth 5 -Compress"#
    )
}

fn query(command: &mut std::process::Command) -> Result<Value> {
    use std::{
        io::Read,
        process::Stdio,
        time::{Duration, Instant},
    };
    // A stalled OS query must not trap startup in Working forever. Drain both
    // pipes concurrently, with caps, so noisy errors cannot deadlock or exhaust memory.
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Could not inspect firewall rules: {e}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or("Missing inspection output pipe.")?;
    let stderr = child
        .stderr
        .take()
        .ok_or("Missing inspection error pipe.")?;
    let out = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(5_000_001)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let err = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.take(65_536).read_to_end(&mut bytes).map(|_| bytes)
    });
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(error.to_string());
            }
            Ok(None) if started.elapsed() >= Duration::from_secs(15) => {
                let _ = child.kill();
                let _ = child.wait();
                break Err("Firewall inspection timed out. No rules were changed.".into());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    let stdout = out
        .join()
        .map_err(|_| "Inspection output reader failed.")?
        .map_err(|e| e.to_string())?;
    let stderr = err
        .join()
        .map_err(|_| "Inspection error reader failed.")?
        .map_err(|e| e.to_string())?;
    if !status?.success() {
        return Err(String::from_utf8_lossy(&stderr).trim().to_owned());
    }
    if stdout.len() > MAX_READBACK_BYTES {
        return Err("Firewall inspection response is too large.".into());
    }
    serde_json::from_slice(&stdout)
        .map_err(|e| format!("Invalid firewall inspection response: {e}"))
}

pub fn inspect() -> Result<Inspection> {
    #[cfg(target_os = "linux")]
    {
        let tables =
            query(std::process::Command::new("/usr/bin/nft").args(["-j", "-n", "list", "tables"]))?;
        if !owned_table_present(&tables)? {
            return Ok(Inspection::default());
        }
        let json = query(
            std::process::Command::new("/usr/bin/nft")
                .args(["-j", "-n", "list", "table", "inet", TABLE]),
        )?;
        linux_snapshot(&json)
    }
    #[cfg(target_os = "windows")]
    {
        let json = query(crate::firewall::powershell_command()?.args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &windows_inspection_script(),
        ]))?;
        windows_snapshot(&json)
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Err("Firewall verification supports Linux and Windows only.".into())
    }
}

#[cfg(any(target_os = "linux", test))]
fn owned_table_present(json: &Value) -> Result<bool> {
    let entries = json["nftables"]
        .as_array()
        .ok_or("Invalid nftables table response.")?;
    let mut found = false;
    for entry in entries {
        if entry.get("metainfo").is_some() {
            continue;
        }
        let table = entry
            .get("table")
            .ok_or("Unexpected nftables table response.")?;
        let family = table["family"]
            .as_str()
            .ok_or("Missing nftables table family.")?;
        let name = table["name"]
            .as_str()
            .ok_or("Missing nftables table name.")?;
        found |= family == "inet" && name == TABLE;
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn expected(program: Option<&str>) -> Vec<FirewallRule> {
        vec![FirewallRule {
            endpoint: crate::model::Endpoint {
                id: "test-rule".into(),
                address: "185.25.183.163".into(),
                protocol: Protocol::Udp,
                ports: Some("27015-27060".into()),
                custom: false,
            },
            program: program.map(str::to_owned),
        }]
    }
    fn nft() -> Value {
        json!({"nftables":[
            {"metainfo":{"json_schema_version":1}},
            {"table":{"family":"inet","name":TABLE,"comment":OWNER,"handle":7}},
            {"chain":{"family":"inet","table":TABLE,"name":"outbound","type":"filter","hook":"output","prio":10,"policy":"accept"}},
            {"rule":{"family":"inet","table":TABLE,"chain":"outbound","comment":"ll:test-rule","expr":[
                {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"185.25.183.163"}},
                {"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"udp"}},
                {"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":{"range":[27015,27060]}}},
                {"counter":{"packets":183,"bytes":9120}}, {"drop":null}
            ]}}
        ]})
    }
    fn windows() -> Value {
        json!({"enforced":true,"supported":true,"rules":[{"address":"185.25.183.163/32","protocol":"17","ports":"27015-27060","program":"C:\\Games\\game.exe"}]})
    }
    fn game() -> Game {
        let mut game = crate::installed::custom_game(
            "example".into(),
            "Example",
            "Europe",
            "185.25.183.163",
            Protocol::Udp,
            Some("27015-27060".into()),
        )
        .unwrap();
        game.executable_path = Some(r"C:\Games\game.exe".into());
        game
    }
    #[test]
    fn observed_blocks_are_independent_of_saved_choices_and_source_labels() {
        let game = game();
        let report = linux_snapshot(&nft()).unwrap();
        assert_eq!(
            region_states(
                std::slice::from_ref(&game),
                &report,
                FirewallScope::SystemWide
            )["example:custom"],
            RegionState::Blocked
        );
        let mut narrower = report.clone();
        narrower.rules[0].key.ports = Some((27015, 27020));
        assert_eq!(
            region_states(
                std::slice::from_ref(&game),
                &narrower,
                FirewallScope::SystemWide
            )["example:custom"],
            RegionState::Partial
        );
        narrower.rules[0].key.address = "203.0.113.7/32".into();
        narrower.rules[0].source_id = Some(format!("example-{}", game.regions[0].endpoints[0].id));
        assert_eq!(
            region_states(
                std::slice::from_ref(&game),
                &narrower,
                FirewallScope::SystemWide
            )["example:custom"],
            RegionState::None
        );
        let targets = observed_targets(
            std::slice::from_ref(&game),
            &narrower,
            FirewallScope::SystemWide,
            &BTreeSet::new(),
        );
        assert_eq!(targets[0].endpoints[0].address, "203.0.113.7/32");
        assert_eq!(
            targets[0].endpoints[0].ports.as_deref(),
            Some("27015-27020")
        );
        let empty = Inspection::default();
        assert_eq!(
            region_states(&[game], &empty, FirewallScope::SystemWide)["example:custom"],
            RegionState::None
        );
    }
    #[test]
    fn program_scope_not_rule_name_determines_windows_coverage() {
        let mut game = game();
        let report = windows_snapshot(&windows()).unwrap();
        assert_eq!(
            region_states(
                std::slice::from_ref(&game),
                &report,
                FirewallScope::Executable
            )["example:custom"],
            RegionState::Blocked
        );
        game.executable_path = Some(r"D:\Games\other.exe".into());
        assert_eq!(
            region_states(
                std::slice::from_ref(&game),
                &report,
                FirewallScope::Executable
            )["example:custom"],
            RegionState::None
        );
        game.executable_path = None;
        assert_eq!(
            region_states(
                std::slice::from_ref(&game),
                &report,
                FirewallScope::Executable
            )["example:custom"],
            RegionState::Unknown
        );
        let mut legacy = windows();
        legacy["rules"][0]["program"] = json!("Any");
        assert_eq!(
            region_states(
                std::slice::from_ref(&game),
                &windows_snapshot(&legacy).unwrap(),
                FirewallScope::Executable
            )["example:custom"],
            RegionState::Blocked
        );
        assert_eq!(
            region_states(&[game], &Inspection::default(), FirewallScope::Executable)
                ["example:custom"],
            RegionState::None
        );
    }
    #[test]
    fn broader_ranges_and_partial_protocols_are_taken_from_the_os() {
        let mut game = game();
        let mut report = linux_snapshot(&nft()).unwrap();
        report.rules[0].key.address = "185.25.183.0/24".into();
        report.rules[0].key.ports = None;
        assert_eq!(
            region_states(
                std::slice::from_ref(&game),
                &report,
                FirewallScope::SystemWide
            )["example:custom"],
            RegionState::Blocked
        );
        game.regions[0].endpoints[0].protocol = Protocol::Any;
        assert_eq!(
            region_states(
                std::slice::from_ref(&game),
                &report,
                FirewallScope::SystemWide
            )["example:custom"],
            RegionState::Partial
        );
        let mut tcp = report.rules[0].clone();
        tcp.key.protocol = "tcp".into();
        report.rules.push(tcp);
        assert_eq!(
            region_states(
                std::slice::from_ref(&game),
                &report,
                FirewallScope::SystemWide
            )["example:custom"],
            RegionState::Blocked
        );
        game.regions[0].endpoints[0].ports = None;
        assert_eq!(
            region_states(&[game], &report, FirewallScope::SystemWide)["example:custom"],
            RegionState::Partial
        );
    }
    #[test]
    fn unmapped_and_previous_executable_rules_are_not_replaced_with_catalogue_targets() {
        let game = game();
        let mut report = windows_snapshot(&windows()).unwrap();
        report.rules[0].source_id = Some(format!("example-{}", game.regions[0].endpoints[0].id));
        let mut old = report.rules[0].clone();
        old.key.program = Some(r"d:\games\old.exe".into());
        report.rules.push(old);
        let mut unmapped = report.rules[0].clone();
        unmapped.key.address = "203.0.113.0/24".into();
        unmapped.source_id = None;
        report.rules.push(unmapped);
        let targets = observed_targets(
            &[game],
            &report,
            FirewallScope::Executable,
            &BTreeSet::new(),
        );
        assert_eq!(targets.len(), 3);
        assert!(targets
            .iter()
            .any(|target| target.executable_path.as_deref() == Some(r"d:\games\old.exe")));
        assert!(targets
            .iter()
            .any(|target| target.game_id.is_empty()
                && target.endpoints[0].address == "203.0.113.0/24"));
    }
    #[test]
    fn malformed_readbacks_and_malformed_ports_are_never_verified() {
        let mut report = linux_snapshot(&nft()).unwrap();
        report.rules[0].key.protocol = "icmp".into();
        assert!(report.validate().is_err());
        report.rules[0].key.protocol = "udp".into();
        report.rules[0].key.ports = Some((27060, 27015));
        assert!(report.validate().is_err());
        assert!(Inspection::from_bytes(br#"{"rules":[],"extra":"unexpected"}"#).is_err());
        assert!(Inspection::from_bytes(b"permission denied").is_err());
    }
    #[test]
    fn multiple_os_rules_cover_address_and_port_ranges_only_when_no_gaps_remain() {
        let mut game = game();
        game.regions[0].endpoints[0].address = "185.25.183.0/24".into();
        let mut report = linux_snapshot(&nft()).unwrap();
        report.rules[0].key.address = "185.25.183.0/25".into();
        let mut other = report.rules[0].clone();
        other.key.address = "185.25.183.128/25".into();
        report.rules.push(other);
        assert_eq!(
            region_states(
                std::slice::from_ref(&game),
                &report,
                FirewallScope::SystemWide
            )["example:custom"],
            RegionState::Blocked
        );
        report.rules[0].key.ports = Some((27015, 27030));
        report.rules[1].key.ports = Some((27031, 27060));
        // Port and address coverage cannot be combined across different hosts.
        assert_eq!(
            region_states(
                std::slice::from_ref(&game),
                &report,
                FirewallScope::SystemWide
            )["example:custom"],
            RegionState::Partial
        );
        for rule in &mut report.rules {
            rule.key.address = "185.25.183.0/24".into();
        }
        assert_eq!(
            region_states(
                std::slice::from_ref(&game),
                &report,
                FirewallScope::SystemWide
            )["example:custom"],
            RegionState::Blocked
        );
        report.rules[1].key.ports = Some((27032, 27060));
        assert_eq!(
            region_states(&[game], &report, FirewallScope::SystemWide)["example:custom"],
            RegionState::Partial
        );
        assert!(!ranges_cover(vec![(0, u128::MAX - 1)], (0, u128::MAX)));
        assert!(ranges_cover(vec![(0, u128::MAX)], (0, u128::MAX)));
    }
    #[test]
    fn absent_owned_tables_are_distinct_from_invalid_or_denied_reads() {
        assert!(!owned_table_present(&json!({"nftables":[]})).unwrap());
        assert!(!owned_table_present(
            &json!({"nftables":[{"table":{"family":"inet","name":"other"}}]})
        )
        .unwrap());
        assert!(owned_table_present(
            &json!({"nftables":[{"table":{"family":"inet","name":TABLE}}]})
        )
        .unwrap());
        assert!(owned_table_present(&json!({"nftables":[{"error":"permission denied"}]})).is_err());
        assert!(owned_table_present(&json!({"nftables":[{"table":{"name":TABLE}}]})).is_err());
    }
    #[test]
    fn exact_owned_nft_rules_match_after_restart_and_counters_do_not_affect_verification() {
        let keys = expected_keys(&expected(None)).unwrap();
        assert_eq!(
            compare(&linux_keys(&nft()).unwrap(), &keys),
            Verification::Matched
        );
        let mut changed = nft();
        changed["nftables"][3]["rule"]["expr"][0]["match"]["right"] = json!("185.25.183.179");
        assert_eq!(
            compare(&linux_keys(&changed).unwrap(), &keys),
            Verification::Different
        );
        let mut empty = nft();
        empty["nftables"].as_array_mut().unwrap().pop();
        assert_eq!(
            compare(&linux_keys(&empty).unwrap(), &keys),
            Verification::Empty
        );
    }
    #[test]
    fn ownership_chain_shape_and_drop_action_are_not_trusted_from_names_alone() {
        let mut other_owner = nft();
        other_owner["nftables"][1]["table"]["comment"] = json!("Someone else");
        assert!(linux_keys(&other_owner).is_err());
        let mut dormant = nft();
        dormant["nftables"][1]["table"]["flags"] = json!(["dormant"]);
        assert!(linux_keys(&dormant).is_err());
        let mut wrong_hook = nft();
        wrong_hook["nftables"][2]["chain"]["hook"] = json!("input");
        assert!(linux_keys(&wrong_hook).is_err());
        let mut allowed = nft();
        allowed["nftables"][3]["rule"]["expr"][4] = json!({"accept":null});
        assert!(linux_keys(&allowed).is_err());
        let mut extra_match = nft();
        extra_match["nftables"][3]["rule"]["expr"][3] =
            json!({"match":{"op":"==","left":{"meta":{"key":"skuid"}},"right":1000}});
        assert!(linux_keys(&extra_match).is_err());
        let mut unexpected_chain = nft();
        unexpected_chain["nftables"]
            .as_array_mut()
            .unwrap()
            .push(json!({"chain":{"name":"extra"}}));
        assert!(linux_keys(&unexpected_chain).is_err());
        assert!(linux_keys(&json!({"nftables":[]})).is_err());
        assert!(linux_keys(&json!({"error":"permission denied"})).is_err());
    }
    #[test]
    fn ipv4_ipv6_prefixes_and_single_ports_are_normalized() {
        let mut json = nft();
        json["nftables"][3]["rule"]["expr"][0]["match"]["right"] =
            json!({"prefix":{"addr":"185.25.183.0","len":24}});
        json["nftables"][3]["rule"]["expr"][2]["match"]["right"] = json!(27015);
        let mut rules = expected(None);
        rules[0].endpoint.address = "185.25.183.9/24".into();
        rules[0].endpoint.ports = Some("27015".into());
        assert_eq!(linux_keys(&json).unwrap(), expected_keys(&rules).unwrap());
        json["nftables"][3]["rule"]["expr"][0]["match"]["left"]["payload"]["protocol"] =
            json!("ip6");
        json["nftables"][3]["rule"]["expr"][0]["match"]["right"] =
            json!({"prefix":{"addr":"2001:db8::","len":64}});
        rules[0].endpoint.address = "2001:db8::7/64".into();
        assert_eq!(linux_keys(&json).unwrap(), expected_keys(&rules).unwrap());
    }
    #[test]
    fn any_protocol_with_ports_requires_both_tcp_and_udp_blocks() {
        let mut rules = expected(None);
        rules[0].endpoint.protocol = Protocol::Any;
        let mut json = nft();
        let mut tcp = json["nftables"][3].clone();
        tcp["rule"]["expr"][1]["match"]["right"] = json!("tcp");
        tcp["rule"]["expr"][2]["match"]["left"]["payload"]["protocol"] = json!("tcp");
        assert_eq!(
            compare(&linux_keys(&json).unwrap(), &expected_keys(&rules).unwrap()),
            Verification::Different
        );
        json["nftables"].as_array_mut().unwrap().push(tcp);
        assert_eq!(
            compare(&linux_keys(&json).unwrap(), &expected_keys(&rules).unwrap()),
            Verification::Matched
        );
    }
    #[test]
    fn windows_checks_effective_program_scope_and_legacy_global_rules_do_not_match() {
        let keys = expected_keys(&expected(Some(r"c:\games\GAME.exe"))).unwrap();
        assert_eq!(
            compare(&windows_keys(&windows()).unwrap(), &keys),
            Verification::Matched
        );
        let mut global = windows();
        global["rules"][0]["program"] = json!("Any");
        assert_eq!(
            compare(&windows_keys(&global).unwrap(), &keys),
            Verification::Different
        );
        let mut changed_program = windows();
        changed_program["rules"][0]["program"] = json!(r"D:\Games\other.exe");
        assert_eq!(
            compare(&windows_keys(&changed_program).unwrap(), &keys),
            Verification::Different
        );
        let mut disabled = windows();
        disabled["enforced"] = json!(false);
        assert!(windows_keys(&disabled).is_err());
        let mut constrained = windows();
        constrained["supported"] = json!(false);
        assert!(windows_keys(&constrained).is_err());
        assert_eq!(
            compare(
                &windows_keys(&json!({"enforced":true,"supported":true,"rules":[]})).unwrap(),
                &keys
            ),
            Verification::Empty
        );
    }
    #[test]
    fn inspection_script_is_read_only_and_uses_active_store() {
        let script = windows_inspection_script();
        assert!(script.contains(WINDOWS_GROUP));
        assert!(script.contains("-PolicyStore ActiveStore"));
        assert!(script.contains("Get-NetFirewallApplicationFilter"));
        assert!(script.contains("Get-NetFirewallProfile"));
        assert!(script.contains("Get-Service -Name MpsSvc,BFE"));
        assert!(script.contains(WINDOWS_NETSECURITY));
        for write in [
            "New-NetFirewallRule",
            "Remove-NetFirewallRule",
            "Set-NetFirewallRule",
            "Set-NetFirewallProfile",
            "Start-Process",
        ] {
            assert!(!script.contains(write));
        }
    }
}
