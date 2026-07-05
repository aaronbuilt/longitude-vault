//! Typed extraction from a loaded vault. Unknown fields flow through
//! untouched (vault spec §3.7) — serde simply ignores them here, and this
//! crate never writes documents back.
//!
//! The engine assumes the vault has already passed the §8 validator; the
//! extraction errors here are engine-level (e.g. a projection needs a
//! spending figure), not format-level.

use serde::Deserialize;
use toml::value::Datetime;

use longitude_vault::RawVault;

use crate::project::EngineError;

#[derive(Debug, Clone, Deserialize)]
pub struct Money {
    pub amount: String,
    pub currency: String,
}

#[derive(Debug, Deserialize)]
pub struct Manifest {
    pub base_currency: String,
}

#[derive(Debug, Deserialize)]
pub struct Profile {
    pub birth_year: Option<i32>,
    pub annual_spending: Option<Money>,
    pub swr: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Account {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub secured_by: Option<String>,
    pub closed: Option<Datetime>,
}

#[derive(Debug, Deserialize)]
pub struct Balance {
    pub account: String,
    pub value: Money,
}

#[derive(Debug, Deserialize)]
pub struct Snapshot {
    pub date: Datetime,
    #[serde(default)]
    pub balance: Vec<Balance>,
}

#[derive(Debug, Default, Deserialize)]
pub struct Timeline {
    pub start: Option<Datetime>,
    pub horizon_years: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
pub struct Expenses {
    pub extra_monthly: Option<Money>,
}

#[derive(Debug, Deserialize)]
pub struct Income {
    pub id: Option<String>,
    pub amount: Option<Money>,
    pub frequency: Option<String>,
    pub from: Option<Datetime>,
    pub to: Option<Datetime>,
    pub growth: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Allocation {
    pub class: Option<String>,
    pub weight: Option<String>,
    pub expected_return: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct Portfolio {
    #[serde(default)]
    pub allocation: Vec<Allocation>,
}

#[derive(Debug, Default, Deserialize)]
pub struct Withdrawal {
    pub strategy: Option<String>,
    pub rate: Option<String>,
    /// percent-with-bounds only: annual clamp, real terms (§4.5).
    pub floor: Option<Money>,
    pub ceiling: Option<Money>,
}

#[derive(Debug, Deserialize)]
pub struct Scenario {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub targeted: bool,
    #[serde(default)]
    pub timeline: Timeline,
    #[serde(default)]
    pub expenses: Expenses,
    #[serde(default)]
    pub income: Vec<Income>,
    #[serde(default)]
    pub portfolio: Portfolio,
    #[serde(default)]
    pub withdrawal: Withdrawal,
}

#[derive(Debug)]
pub struct VaultModel {
    pub base_currency: String,
    pub profile: Profile,
    pub accounts: Vec<Account>,
    pub snapshots: Vec<Snapshot>,
    pub scenarios: Vec<Scenario>,
}

impl VaultModel {
    /// Pick the scenario to project: explicit id > the targeted one > the
    /// only one present.
    pub fn select_scenario(&self, id: Option<&str>) -> Result<&Scenario, EngineError> {
        if let Some(id) = id {
            return self.scenarios.iter().find(|s| s.id == id).ok_or_else(|| {
                EngineError::ScenarioNotFound {
                    id: id.to_string(),
                    available: self.scenario_ids(),
                }
            });
        }
        if let Some(s) = self.scenarios.iter().find(|s| s.targeted) {
            return Ok(s);
        }
        match self.scenarios.as_slice() {
            [only] => Ok(only),
            [] => Err(EngineError::NoScenarios),
            _ => Err(EngineError::NoTargetedScenario {
                available: self.scenario_ids(),
            }),
        }
    }

    fn scenario_ids(&self) -> Vec<String> {
        self.scenarios.iter().map(|s| s.id.clone()).collect()
    }
}

fn parse_doc<T: serde::de::DeserializeOwned>(path: &str, bytes: &[u8]) -> Result<T, EngineError> {
    let text = std::str::from_utf8(bytes).map_err(|_| EngineError::Document {
        doc: path.to_string(),
        message: "not valid UTF-8".into(),
    })?;
    toml::from_str(text).map_err(|e| EngineError::Document {
        doc: path.to_string(),
        message: e.to_string(),
    })
}

/// Extract the typed model the projection needs from a loaded vault.
pub fn extract(vault: &RawVault) -> Result<VaultModel, EngineError> {
    let manifest: Manifest = parse_doc(
        "manifest.toml",
        &vault
            .get("manifest.toml")
            .ok_or_else(|| EngineError::Document {
                doc: "manifest.toml".into(),
                message: "missing".into(),
            })?
            .bytes,
    )?;
    let profile: Profile = parse_doc(
        "profile.toml",
        &vault
            .get("profile.toml")
            .ok_or_else(|| EngineError::Document {
                doc: "profile.toml".into(),
                message: "missing".into(),
            })?
            .bytes,
    )?;

    let mut accounts = Vec::new();
    let mut snapshots = Vec::new();
    let mut scenarios = Vec::new();
    for doc in &vault.documents {
        if let Some(rest) = doc.path.strip_prefix("accounts/") {
            if rest.ends_with(".toml") && !rest.contains('/') {
                accounts.push(parse_doc::<Account>(&doc.path, &doc.bytes)?);
            }
        } else if let Some(rest) = doc.path.strip_prefix("snapshots/") {
            if rest.ends_with(".toml") && !rest.contains('/') {
                snapshots.push(parse_doc::<Snapshot>(&doc.path, &doc.bytes)?);
            }
        } else if let Some(rest) = doc.path.strip_prefix("scenarios/") {
            if rest.ends_with(".toml") && !rest.contains('/') {
                scenarios.push(parse_doc::<Scenario>(&doc.path, &doc.bytes)?);
            }
        }
    }

    Ok(VaultModel {
        base_currency: manifest.base_currency,
        profile,
        accounts,
        snapshots,
        scenarios,
    })
}
