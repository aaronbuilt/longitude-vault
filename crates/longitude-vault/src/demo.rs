//! The §9 reference example vault, and the minimal new-vault skeleton.
//! `vault_id` and `created` are injected so the CLI can randomize them while
//! the conformance fixtures stay byte-stable.

use crate::vault::{Document, RawVault};

fn doc(path: &str, body: String) -> Document {
    Document {
        path: path.to_string(),
        bytes: body.into_bytes(),
    }
}

fn manifest(vault_id: &str, created_rfc3339: &str) -> String {
    format!(
        r#"format = "longitude-vault"
schema = "0.1"
vault_id = "{vault_id}"
base_currency = "USD"
created = {created_rfc3339}
modified = {created_rfc3339}
generator = "longitude-cli 0.1.0"
"#
    )
}

/// A minimal valid vault: manifest + profile, ready to edit.
pub fn minimal_vault(vault_id: &str, created_rfc3339: &str) -> RawVault {
    let profile = r#"# The user, and the assumptions used as defaults platform-wide (SPEC §4.2).
passports = ["US"]          # ISO 3166-1 alpha-2, uppercase — edit to yours
tax_residency = "us"
swr = "0.040"
lifestyle = "comfortable"
"#;
    RawVault {
        documents: vec![
            doc("manifest.toml", manifest(vault_id, created_rfc3339)),
            doc("profile.toml", profile.to_string()),
        ],
    }
}

/// The complete reference example from SPEC §9.
pub fn demo_vault(vault_id: &str, created_rfc3339: &str) -> RawVault {
    let mut documents = vec![
        doc("manifest.toml", manifest(vault_id, created_rfc3339)),
        doc(
            "profile.toml",
            r#"birth_year = 1990
passports = ["US"]
tax_residency = "us"
target_retirement_age = 45
annual_spending = { amount = "60000", currency = "USD" }
annual_savings = { amount = "40000", currency = "USD" }
swr = "0.040"
lifestyle = "comfortable"
display_currency = "USD"
household = 1
"#
            .to_string(),
        ),
        doc(
            "accounts/schwab-brokerage.toml",
            r#"id = "schwab-brokerage"
name = "Schwab Brokerage"
type = "brokerage"
currency = "USD"
tax_jurisdiction = "us"
tax_wrapper = "taxable"
institution = "Charles Schwab"
opened = 2015-03-01

[[holding]]
asset = "VT"
kind = "security"
quantity = "1234.567"
cost_basis = { amount = "95000.00", currency = "USD" }
acquired = 2019-05-10
"#
            .to_string(),
        ),
        doc(
            "accounts/cold-storage.toml",
            r#"id = "cold-storage"
name = "Cold Storage"
type = "crypto"
currency = "USD"

# Watch-only, manual quantity — never private keys (SPEC §7).
[[holding]]
asset = "BTC"
kind = "crypto"
quantity = "1.50000000"
"#
            .to_string(),
        ),
        doc(
            "accounts/mortgage.toml",
            r#"id = "mortgage"
name = "Mortgage"
type = "liability"
currency = "USD"
institution = "Example Bank"
"#
            .to_string(),
        ),
        doc(
            "snapshots/2026-05-31.toml",
            r#"date = 2026-05-31

[[balance]]
account = "schwab-brokerage"
value = { amount = "405120.00", currency = "USD" }

[[balance]]
account = "cold-storage"
value = { amount = "98500.00", currency = "USD" }

[[balance]]
account = "mortgage"
value = { amount = "183200.00", currency = "USD" }
"#
            .to_string(),
        ),
        doc(
            "snapshots/2026-06-30.toml",
            r#"date = 2026-06-30
note = "mid-year check"

[[balance]]
account = "schwab-brokerage"
value = { amount = "412345.67", currency = "USD" }

[[balance]]
account = "cold-storage"
value = { amount = "101250.00", currency = "USD" }

[[balance]]
account = "mortgage"
value = { amount = "182000.00", currency = "USD" }
"#
            .to_string(),
        ),
        doc(
            "scenarios/half-life-krakow-tokyo.toml",
            r#"id = "half-life-krakow-tokyo"
name = "Half-life: Kraków + Tokyo"
targeted = true
created = 2026-07-03

[timeline]
start = 2027-01-01
horizon_years = 50

[[residency]]
place = "pl/krakow"
months_per_year = 5

[[residency]]
place = "jp/tokyo"
months_per_year = 4

[[residency]]
place = "us/detroit"
months_per_year = 3

[expenses]
lifestyle = "comfortable"
extra_monthly = { amount = "300", currency = "USD" }

[[income]]
id = "salary"
kind = "employment"
amount = { amount = "8500.00", currency = "USD" }
frequency = "monthly"
from = 2027-01-01
to = 2031-12-31
growth = "0.020"

[portfolio]
from_vault = true

[[portfolio.allocation]]
class = "equities-global"
weight = "0.70"
expected_return = "0.050"
volatility = "0.160"

[[portfolio.allocation]]
class = "bonds-global"
weight = "0.20"
expected_return = "0.015"
volatility = "0.060"

[[portfolio.allocation]]
class = "btc"
weight = "0.10"
expected_return = "0.080"
volatility = "0.600"

[withdrawal]
strategy = "fixed-percentage"
rate = "0.040"

[tax]
feie = true
treaty_positions = ["us-pl"]
"#
            .to_string(),
        ),
        doc(
            "scenarios/stay-home.toml",
            r#"id = "stay-home"
name = "Stay home: Detroit baseline"
created = 2026-07-03

[[residency]]
place = "us/detroit"
months_per_year = 12

[withdrawal]
strategy = "constant-dollar"
rate = "0.040"
"#
            .to_string(),
        ),
        doc(
            "overrides/col-krakow.toml",
            r#"[[override]]
key = "col.pl.krakow.housing.comfortable"
value = "4200"
currency = "PLN"
note = "actual rent, 2-room Kazimierz, 2026"
as_of = 2026-06-01
"#
            .to_string(),
        ),
    ];
    documents.sort_by(|a, b| a.path.cmp(&b.path));
    RawVault { documents }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validate::{validate, Mode};

    #[test]
    fn demo_vault_is_clean() {
        let vault = demo_vault(
            "1c9f0f8e-2b4a-4d6c-8e0f-1a2b3c4d5e6f",
            "2026-07-04T12:00:00Z",
        );
        let report = validate(&vault, Mode::Plaintext);
        assert!(
            report.findings.is_empty(),
            "demo vault should have no findings: {:#?}",
            report.findings
        );
    }

    #[test]
    fn minimal_vault_is_clean() {
        let vault = minimal_vault(
            "1c9f0f8e-2b4a-4d6c-8e0f-1a2b3c4d5e6f",
            "2026-07-04T12:00:00Z",
        );
        let report = validate(&vault, Mode::Plaintext);
        assert!(
            report.findings.is_empty(),
            "minimal vault should have no findings: {:#?}",
            report.findings
        );
    }
}
