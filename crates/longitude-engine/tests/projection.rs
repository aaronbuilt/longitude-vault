//! Golden and property tests for the deterministic projection, run against
//! the conformance fixture vault.

use std::path::PathBuf;
use std::str::FromStr;

use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;

use longitude_engine::model::{
    Account, Allocation, Expenses, Income, Money, Portfolio, Profile, Scenario, Timeline,
    VaultModel, Withdrawal,
};
use longitude_engine::{extract, project, Month};
use longitude_vault::RawVault;

fn demo_model() -> VaultModel {
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
    let vault = RawVault::load_dir(&fixtures.join("valid/demo.lonvault")).unwrap();
    extract(&vault).unwrap()
}

#[test]
fn demo_vault_golden_numbers() {
    let model = demo_model();
    let scenario = model.select_scenario(None).unwrap(); // targeted
    assert_eq!(scenario.id, "half-life-krakow-tokyo");

    let now = Month::from_ym(2026, 7);
    let p = project(&model, scenario, now).unwrap();

    // t₀ (§2.3): schwab 412,345.67 + cold-storage 101,250 (latest snapshot,
    // 2026-06-30) − unsecured mortgage 182,000. Real estate: none.
    assert_eq!(p.t0_investable, Decimal::from_str("331595.67").unwrap());

    // spending: profile 60,000 + 12 × 300 extra_monthly
    assert_eq!(p.annual_spending, Decimal::from(63_600));

    // FI number (§14.1): 63,600 / 0.040
    assert_eq!(p.fi_number, Some(Decimal::from(1_590_000)));

    // Score (§14.2): 331,595.67 / 1,590,000 ≈ 20.9%, uncapped, floored at 0
    let score = p.score.unwrap();
    assert!((score - 0.208551).abs() < 1e-4, "score = {score}");

    // blended return: 0.70×0.050 + 0.20×0.015 + 0.10×0.080 = 0.046
    assert!((p.blended_return - 0.046).abs() < 1e-12);

    // timeline.start = 2027-01-01, horizon 50
    assert_eq!(p.start, Month::from_ym(2027, 1));
    assert_eq!(p.horizon_years, 50);

    // The demo person: salary 2027–2031, then demand-driven withdrawals of
    // 63.6k/yr at ~10% of the portfolio — this plan fails before horizon,
    // never recovers (no later income), and never reaches FI.
    assert!(p.failed);
    let depletion = p.depletion_month.unwrap();
    assert!(
        depletion > Month::from_ym(2035, 1) && depletion < Month::from_ym(2055, 1),
        "depletion = {depletion}"
    );
    assert!(!p.recovered);
    assert_eq!(p.end_balance, 0.0);
    assert_eq!(p.fi_month, None);

    // annual table covers every calendar year of the window
    assert_eq!(p.years.len(), 50);
    assert_eq!(p.years.first().unwrap().year, 2027);

    // salary year: 12 × 8,500
    assert!((p.years.first().unwrap().income - 102_000.0).abs() < 1e-6);
}

#[test]
fn projection_is_deterministic() {
    let model = demo_model();
    let scenario = model.select_scenario(None).unwrap();
    let a = project(&model, scenario, Month::from_ym(2026, 7)).unwrap();
    let b = project(&model, scenario, Month::from_ym(2026, 7)).unwrap();
    assert_eq!(format!("{a:?}"), format!("{b:?}"));
}

// ---- hand-built models for property tests ----------------------------------

fn money(amount: &str) -> Money {
    Money {
        amount: amount.to_string(),
        currency: "USD".to_string(),
    }
}

fn tiny_model(t0: &str, annual_spending: &str) -> (VaultModel, Scenario) {
    let model = VaultModel {
        base_currency: "USD".to_string(),
        profile: Profile {
            birth_year: Some(1990),
            annual_spending: Some(money(annual_spending)),
            swr: Some("0.040".to_string()),
        },
        accounts: vec![Account {
            id: "cash".to_string(),
            kind: "cash".to_string(),
            secured_by: None,
            closed: None,
        }],
        snapshots: vec![longitude_engine::model::Snapshot {
            date: "2026-06-30".parse().unwrap(),
            balance: vec![longitude_engine::model::Balance {
                account: "cash".to_string(),
                value: money(t0),
            }],
        }],
        scenarios: vec![],
    };
    let scenario = Scenario {
        id: "flat".to_string(),
        name: "Flat".to_string(),
        targeted: true,
        timeline: Timeline {
            start: Some("2027-01-01".parse().unwrap()),
            horizon_years: Some(30),
        },
        expenses: Expenses::default(),
        income: vec![],
        portfolio: Portfolio::default(),
        withdrawal: Withdrawal::default(),
    };
    (model, scenario)
}

#[test]
fn zero_return_depletion_is_exact() {
    // 10,000 at t₀, 12,000/yr spending, 0% return: months 0–9 are funded
    // exactly; the 11th month (index 10) cannot be met.
    let (model, scenario) = tiny_model("10000", "12000");
    let p = project(&model, &scenario, Month::from_ym(2026, 7)).unwrap();
    assert!(p.failed);
    assert_eq!(
        p.depletion_month,
        Some(Month::from_ym(2027, 1).plus_months(10))
    );
    assert_eq!(p.end_balance, 0.0);
}

#[test]
fn more_assets_never_hurt() {
    let (poor_model, scenario) = tiny_model("100000", "12000");
    let (rich_model, _) = tiny_model("400000", "12000");
    let now = Month::from_ym(2026, 7);
    let poor = project(&poor_model, &scenario, now).unwrap();
    let rich = project(&rich_model, &scenario, now).unwrap();
    assert!(rich.score.unwrap() > poor.score.unwrap());
    // depletion, if both deplete, comes no earlier for the richer start
    if let (Some(p), Some(r)) = (poor.depletion_month, rich.depletion_month) {
        assert!(r >= p);
    }
    assert!(rich.end_balance >= poor.end_balance);
}

#[test]
fn income_rescue_recovers_a_failed_path() {
    // Deplete early, then a pension arrives and rebuilds the portfolio:
    // failure latches, but the path recovers (engine spec §3.4).
    let (mut model, mut scenario) = tiny_model("5000", "12000");
    model.profile.swr = Some("0.040".to_string());
    scenario.income = vec![Income {
        id: Some("pension".to_string()),
        amount: Some(money("2000")),
        frequency: Some("monthly".to_string()),
        from: Some("2030-01-01".parse().unwrap()),
        to: None,
        growth: None,
    }];
    let p = project(&model, &scenario, Month::from_ym(2026, 7)).unwrap();
    assert!(p.failed, "should deplete before the pension starts");
    assert!(p.depletion_month.unwrap() < Month::from_ym(2030, 1));
    assert!(p.recovered, "pension surplus should rebuild the portfolio");
    assert!(p.end_balance > 0.0);
}

#[test]
fn fi_date_reached_with_surplus_and_returns() {
    // Strong saver: 60k salary forever vs 12k spending, 5% real return,
    // FI number = 300k. FI arrives well within 30 years.
    let (mut model, mut scenario) = tiny_model("50000", "12000");
    model.profile.swr = Some("0.040".to_string());
    scenario.income = vec![Income {
        id: Some("salary".to_string()),
        amount: Some(money("5000")),
        frequency: Some("monthly".to_string()),
        from: None,
        to: None,
        growth: None,
    }];
    scenario.portfolio = Portfolio {
        allocation: vec![Allocation {
            class: Some("equities-global".to_string()),
            weight: Some("1.0".to_string()),
            expected_return: Some("0.050".to_string()),
        }],
    };
    let p = project(&model, &scenario, Month::from_ym(2026, 7)).unwrap();
    assert_eq!(p.fi_number, Some(Decimal::from(300_000)));
    assert!(!p.failed);
    let fi = p.fi_month.expect("FI should be reached");
    assert!(fi < Month::from_ym(2033, 1), "fi = {fi}");
    assert!(p.end_balance > p.fi_number.unwrap().to_f64().unwrap());
}

#[test]
fn secured_liability_stays_out_of_investable() {
    // A mortgage secured by a house: both out of investable math. The same
    // mortgage unsecured: subtracts.
    let (mut model, scenario) = tiny_model("100000", "12000");
    model.accounts.push(Account {
        id: "house".to_string(),
        kind: "real-estate".to_string(),
        secured_by: None,
        closed: None,
    });
    model.accounts.push(Account {
        id: "mortgage".to_string(),
        kind: "liability".to_string(),
        secured_by: Some("house".to_string()),
        closed: None,
    });
    model.snapshots[0]
        .balance
        .push(longitude_engine::model::Balance {
            account: "house".to_string(),
            value: money("400000"),
        });
    model.snapshots[0]
        .balance
        .push(longitude_engine::model::Balance {
            account: "mortgage".to_string(),
            value: money("250000"),
        });
    let now = Month::from_ym(2026, 7);
    let secured = project(&model, &scenario, now).unwrap();
    assert_eq!(secured.t0_investable, Decimal::from(100_000));

    model.accounts.last_mut().unwrap().secured_by = None;
    let unsecured = project(&model, &scenario, now).unwrap();
    assert_eq!(unsecured.t0_investable, Decimal::from(-150_000));
    assert_eq!(unsecured.score, Some(0.0), "Score floors at 0");
}
