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
use longitude_engine::{extract, project, EngineError, Month, SpendingMode};
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
    let p = project(&model, scenario, now, SpendingMode::Plan).unwrap();

    // t₀ (§2.3): schwab 412,345.67 + cold-storage 101,250 (latest snapshot,
    // 2026-06-30) − unsecured mortgage 182,000. Real estate: none.
    assert_eq!(p.t0_investable, Decimal::from_str("331595.67").unwrap());

    // spending: profile 60,000 + 12 × 300 extra_monthly
    assert_eq!(p.annual_spending, Some(Decimal::from(63_600)));

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
    let a = project(
        &model,
        scenario,
        Month::from_ym(2026, 7),
        SpendingMode::Plan,
    )
    .unwrap();
    let b = project(
        &model,
        scenario,
        Month::from_ym(2026, 7),
        SpendingMode::Plan,
    )
    .unwrap();
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
    let p = project(
        &model,
        &scenario,
        Month::from_ym(2026, 7),
        SpendingMode::Plan,
    )
    .unwrap();
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
    let poor = project(&poor_model, &scenario, now, SpendingMode::Plan).unwrap();
    let rich = project(&rich_model, &scenario, now, SpendingMode::Plan).unwrap();
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
    let p = project(
        &model,
        &scenario,
        Month::from_ym(2026, 7),
        SpendingMode::Plan,
    )
    .unwrap();
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
    let p = project(
        &model,
        &scenario,
        Month::from_ym(2026, 7),
        SpendingMode::Plan,
    )
    .unwrap();
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
    let secured = project(&model, &scenario, now, SpendingMode::Plan).unwrap();
    assert_eq!(secured.t0_investable, Decimal::from(100_000));

    model.accounts.last_mut().unwrap().secured_by = None;
    let unsecured = project(&model, &scenario, now, SpendingMode::Plan).unwrap();
    assert_eq!(unsecured.t0_investable, Decimal::from(-150_000));
    assert_eq!(unsecured.score, Some(0.0), "Score floors at 0");
}

// ---- simple mode: the §7.2 strategy registry --------------------------------

fn simple_scenario(strategy: &str, rate: Option<&str>, horizon: u32) -> Scenario {
    Scenario {
        id: "simple".to_string(),
        name: "Simple".to_string(),
        targeted: true,
        timeline: Timeline {
            start: Some("2027-01-01".parse().unwrap()),
            horizon_years: Some(horizon),
        },
        expenses: Expenses::default(),
        income: vec![],
        portfolio: Portfolio::default(),
        withdrawal: Withdrawal {
            strategy: Some(strategy.to_string()),
            rate: rate.map(|r| r.to_string()),
            ..Withdrawal::default()
        },
    }
}

#[test]
fn constant_dollar_zero_return_runs_exactly_25_years() {
    // The 4%-rule shape at 0% real return spends 1,000,000 in exactly
    // 25 years: 40,000/yr fixed in real terms (± one month of fp drift).
    let (model, _) = tiny_model("1000000", "0");
    let scenario = simple_scenario("constant-dollar", Some("0.040"), 40);
    let p = project(
        &model,
        &scenario,
        Month::from_ym(2026, 7),
        SpendingMode::Simple,
    )
    .unwrap();
    assert!(p.failed);
    let depletion = p.depletion_month.unwrap();
    let start = Month::from_ym(2027, 1);
    let months = depletion.months_since(start);
    assert!(
        (299..=301).contains(&months),
        "depleted after {months} months"
    );
    let o = p.strategy.as_ref().unwrap();
    assert_eq!(o.slug, "constant-dollar");
    assert!((o.first_year - 40_000.0).abs() < 1e-9);
    assert!(
        (o.min_year - o.max_year).abs() < 1e-9,
        "fixed in real terms"
    );
}

#[test]
fn fixed_percentage_never_fails() {
    let (model, _) = tiny_model("1000000", "0");
    let scenario = simple_scenario("fixed-percentage", Some("0.050"), 60);
    let p = project(
        &model,
        &scenario,
        Month::from_ym(2026, 7),
        SpendingMode::Simple,
    )
    .unwrap();
    assert!(!p.failed);
    assert!(p.end_balance > 0.0);
    let o = p.strategy.as_ref().unwrap();
    // 5% of a shrinking portfolio: the first year is the largest withdrawal
    assert!((o.first_year - 50_000.0).abs() < 1e-9);
    assert!((o.max_year - o.first_year).abs() < 1e-9);
    assert!(o.min_year < o.max_year, "income varies");
}

#[test]
fn percent_with_bounds_clamps_both_ways() {
    let (model, _) = tiny_model("1000000", "0");

    // rate says 20,000 but the floor lifts spending to 30,000
    let mut floored = simple_scenario("percent-with-bounds", Some("0.020"), 30);
    floored.withdrawal.floor = Some(money("30000"));
    let p = project(
        &model,
        &floored,
        Month::from_ym(2026, 7),
        SpendingMode::Simple,
    )
    .unwrap();
    assert!((p.strategy.as_ref().unwrap().first_year - 30_000.0).abs() < 1e-9);

    // rate says 100,000 but the ceiling caps spending at 50,000
    let mut capped = simple_scenario("percent-with-bounds", Some("0.100"), 30);
    capped.withdrawal.ceiling = Some(money("50000"));
    let p = project(
        &model,
        &capped,
        Month::from_ym(2026, 7),
        SpendingMode::Simple,
    )
    .unwrap();
    assert!((p.strategy.as_ref().unwrap().first_year - 50_000.0).abs() < 1e-9);

    // a floor above the ceiling is refused
    let mut bad = simple_scenario("percent-with-bounds", Some("0.040"), 30);
    bad.withdrawal.floor = Some(money("60000"));
    bad.withdrawal.ceiling = Some(money("50000"));
    let err = project(&model, &bad, Month::from_ym(2026, 7), SpendingMode::Simple).unwrap_err();
    assert!(matches!(err, EngineError::Value(_)), "{err}");
}

#[test]
fn a_binding_floor_can_fail() {
    // percent-with-bounds is "never fails" only until the floor binds hard:
    // 100,000/yr minimum spending from a 500,000 portfolio at 0% return.
    let (model, _) = tiny_model("500000", "0");
    let mut scenario = simple_scenario("percent-with-bounds", Some("0.040"), 30);
    scenario.withdrawal.floor = Some(money("100000"));
    let p = project(
        &model,
        &scenario,
        Month::from_ym(2026, 7),
        SpendingMode::Simple,
    )
    .unwrap();
    assert!(p.failed);
    let depletion = p.depletion_month.unwrap();
    let months = depletion.months_since(Month::from_ym(2027, 1));
    assert!(
        (59..=61).contains(&months),
        "depleted after {months} months"
    );
}

#[test]
fn vpw_zero_return_spends_evenly_and_depletes_at_horizon() {
    // At 0% return VPW is straight-line: 1/n of the remainder each year is
    // the same real amount every year, and the portfolio hits zero exactly
    // at the horizon — never earlier.
    let (model, _) = tiny_model("100000", "0");
    let scenario = simple_scenario("vpw", None, 10);
    let p = project(
        &model,
        &scenario,
        Month::from_ym(2026, 7),
        SpendingMode::Simple,
    )
    .unwrap();
    let o = p.strategy.as_ref().unwrap();
    assert!((o.min_year - 10_000.0).abs() < 1e-6, "min {}", o.min_year);
    assert!((o.max_year - 10_000.0).abs() < 1e-6, "max {}", o.max_year);
    assert!(p.end_balance.abs() < 1e-3, "end {}", p.end_balance);
    // fp drift may or may not trip the failure latch in the very last month;
    // anything earlier is a real bug
    if let Some(m) = p.depletion_month {
        assert!(
            m.months_since(Month::from_ym(2027, 1)) >= 119,
            "failed at {m}"
        );
    }
}

#[test]
fn vpw_first_year_matches_the_annuity_formula() {
    // 5% expected return over 30 years: rate = 0.05/(1 − 1.05⁻³⁰) ≈ 6.5051%
    let (model, _) = tiny_model("1000000", "0");
    let mut scenario = simple_scenario("vpw", None, 30);
    scenario.portfolio = Portfolio {
        allocation: vec![Allocation {
            class: Some("equities-global".to_string()),
            weight: Some("1.0".to_string()),
            expected_return: Some("0.050".to_string()),
        }],
    };
    let p = project(
        &model,
        &scenario,
        Month::from_ym(2026, 7),
        SpendingMode::Simple,
    )
    .unwrap();
    let o = p.strategy.as_ref().unwrap();
    assert!((o.first_year - 65_051.43).abs() < 1.0, "{}", o.first_year);
    assert!(!p.failed);
}

#[test]
fn unknown_strategy_is_refused_not_substituted() {
    let (model, _) = tiny_model("1000000", "0");
    let scenario = simple_scenario("guyton-klinger", Some("0.040"), 30);
    let err = project(
        &model,
        &scenario,
        Month::from_ym(2026, 7),
        SpendingMode::Simple,
    )
    .unwrap_err();
    assert!(matches!(err, EngineError::UnknownStrategy { .. }), "{err}");

    let scenario = simple_scenario("constant-dollar", None, 30);
    let err = project(
        &model,
        &scenario,
        Month::from_ym(2026, 7),
        SpendingMode::Simple,
    )
    .unwrap_err();
    assert!(matches!(err, EngineError::MissingRate { .. }), "{err}");
}

#[test]
fn simple_mode_needs_no_annual_spending() {
    // A vault with no profile.annual_spending can't run a plan-driven
    // projection, but simple mode doesn't need one (§7.2).
    let (mut model, _) = tiny_model("1000000", "0");
    model.profile.annual_spending = None;

    let scenario = simple_scenario("fixed-percentage", Some("0.040"), 30);
    let p = project(
        &model,
        &scenario,
        Month::from_ym(2026, 7),
        SpendingMode::Simple,
    )
    .unwrap();
    assert_eq!(p.annual_spending, None);
    assert_eq!(p.score, None, "the Score is a plan concept");

    let err = project(
        &model,
        &scenario,
        Month::from_ym(2026, 7),
        SpendingMode::Plan,
    )
    .unwrap_err();
    assert!(matches!(err, EngineError::MissingSpending), "{err}");
}

#[test]
fn strategy_slug_changes_nothing_in_plan_mode() {
    // §7.1: Meridian simulation is demand-driven; the slug only labels the
    // scenario's SWR. Two plan-mode runs differing only in slug are identical.
    let (model, mut scenario) = tiny_model("1000000", "40000");
    scenario.withdrawal.strategy = Some("constant-dollar".to_string());
    scenario.withdrawal.rate = Some("0.040".to_string());
    let a = project(
        &model,
        &scenario,
        Month::from_ym(2026, 7),
        SpendingMode::Plan,
    )
    .unwrap();
    scenario.withdrawal.strategy = Some("vpw".to_string());
    let b = project(
        &model,
        &scenario,
        Month::from_ym(2026, 7),
        SpendingMode::Plan,
    )
    .unwrap();
    assert_eq!(format!("{a:?}"), format!("{b:?}"));
}

// ------------------------- discretionary-guardrail -------------------------

use longitude_engine::strategy::{
    ev_multiplier, STATE_MONTHS_BEAR, STATE_MONTHS_CORRECTION, STATE_MONTHS_NORMAL,
    STATE_MONTHS_TOTAL,
};

fn guardrail_scenario(rate: &str, horizon: u32) -> Scenario {
    simple_scenario("discretionary-guardrail", Some(rate), horizon)
}

#[test]
fn state_frequencies_are_a_partition() {
    assert_eq!(
        STATE_MONTHS_NORMAL + STATE_MONTHS_CORRECTION + STATE_MONTHS_BEAR,
        STATE_MONTHS_TOTAL
    );
    assert_eq!(STATE_MONTHS_TOTAL, 97 * 12, "Jan 1926 – Dec 2022");
    // no cuts ever = the full discretionary budget on the average month
    assert!((ev_multiplier(1.0, 1.0) - 1.0).abs() < 1e-12);
    // total cuts in every down state = only normal months fund it
    assert!(
        (ev_multiplier(0.0, 0.0) - STATE_MONTHS_NORMAL as f64 / STATE_MONTHS_TOTAL as f64).abs()
            < 1e-12
    );
}

#[test]
fn guardrail_all_essential_reduces_to_constant_dollar() {
    // essential_fraction = 1 leaves nothing to flex: byte-for-byte the
    // 4%-rule shape — 1,000,000 at 0% real depletes in exactly 25 years.
    let (model, _) = tiny_model("1000000", "0");
    let mut scenario = guardrail_scenario("0.040", 40);
    scenario.withdrawal.essential_fraction = Some("1.0".to_string());
    let p = project(
        &model,
        &scenario,
        Month::from_ym(2026, 7),
        SpendingMode::Simple,
    )
    .unwrap();
    assert!(p.failed);
    let months = p
        .depletion_month
        .unwrap()
        .months_since(Month::from_ym(2027, 1));
    assert!(
        (299..=301).contains(&months),
        "depleted after {months} months"
    );
    let o = p.strategy.as_ref().unwrap();
    assert!((o.first_year - 40_000.0).abs() < 1e-9);
    assert!(
        (o.min_year - o.max_year).abs() < 1e-9,
        "fixed in real terms"
    );
}

#[test]
fn guardrail_ev_math_matches_the_worked_example() {
    // The Madfientist worked example, EV-funded: $1M @ 5.5%, half essential.
    // initial = 55,000; essential = 27,500; discretionary = 27,500 funded at
    // m = (582 + 0.5×177) / 1164, so spending = 27,500 × (1 + m), every year.
    let (model, _) = tiny_model("1000000", "0");
    let mut scenario = guardrail_scenario("0.055", 40);
    scenario.withdrawal.essential_fraction = Some("0.5".to_string());
    let p = project(
        &model,
        &scenario,
        Month::from_ym(2026, 7),
        SpendingMode::Simple,
    )
    .unwrap();
    let m = ev_multiplier(0.5, 0.0);
    let o = p.strategy.as_ref().unwrap();
    assert!((o.first_year - 27_500.0 * (1.0 + m)).abs() < 1e-6);
    assert!(
        (o.min_year - o.max_year).abs() < 1e-9,
        "EV pass is constant"
    );
    assert!((o.essential.unwrap() - 27_500.0).abs() < 1e-9);
    assert!((o.ev_multiplier.unwrap() - m).abs() < 1e-12);
    assert!(
        p.warnings.iter().any(|w| w.contains("expected value")),
        "the deterministic stand-in must announce itself: {:?}",
        p.warnings
    );
}

#[test]
fn guardrail_essential_money_form() {
    let (model, _) = tiny_model("1000000", "0");
    let mut scenario = guardrail_scenario("0.040", 40);
    scenario.withdrawal.essential = Some(money("20000"));
    let p = project(
        &model,
        &scenario,
        Month::from_ym(2026, 7),
        SpendingMode::Simple,
    )
    .unwrap();
    let m = ev_multiplier(0.5, 0.0);
    let o = p.strategy.as_ref().unwrap();
    assert!((o.first_year - (20_000.0 + 20_000.0 * m)).abs() < 1e-6);
}

#[test]
fn guardrail_never_guesses_a_split() {
    let (model, _) = tiny_model("1000000", "0");

    // neither form present: refused
    let scenario = guardrail_scenario("0.040", 30);
    let err = project(
        &model,
        &scenario,
        Month::from_ym(2026, 7),
        SpendingMode::Simple,
    )
    .unwrap_err();
    assert!(matches!(err, EngineError::MissingSplit), "{err}");

    // both forms present: also refused
    let mut scenario = guardrail_scenario("0.040", 30);
    scenario.withdrawal.essential = Some(money("20000"));
    scenario.withdrawal.essential_fraction = Some("0.5".to_string());
    let err = project(
        &model,
        &scenario,
        Month::from_ym(2026, 7),
        SpendingMode::Simple,
    )
    .unwrap_err();
    assert!(matches!(err, EngineError::MissingSplit), "{err}");
}

#[test]
fn guardrail_essential_beyond_the_rate_is_refused() {
    // 60,000 essential from a 40,000 initial withdrawal: the rate cannot
    // cover essentials — configuration error, not a projection.
    let (model, _) = tiny_model("1000000", "0");
    let mut scenario = guardrail_scenario("0.040", 30);
    scenario.withdrawal.essential = Some(money("60000"));
    let err = project(
        &model,
        &scenario,
        Month::from_ym(2026, 7),
        SpendingMode::Simple,
    )
    .unwrap_err();
    assert!(matches!(err, EngineError::Value(_)), "{err}");
}

#[test]
fn guardrail_outlasts_constant_dollar_at_the_same_rate() {
    // The whole point: flexing the discretionary half means spending less
    // than rate × t0 on the average year, so depletion arrives later than
    // the constant-dollar 25 years (0% real return, 4%, half essential).
    let (model, _) = tiny_model("1000000", "0");
    let mut scenario = guardrail_scenario("0.040", 60);
    scenario.withdrawal.essential_fraction = Some("0.5".to_string());
    let p = project(
        &model,
        &scenario,
        Month::from_ym(2026, 7),
        SpendingMode::Simple,
    )
    .unwrap();
    assert!(p.failed, "0% real still depletes eventually");
    let months = p
        .depletion_month
        .unwrap()
        .months_since(Month::from_ym(2027, 1));
    assert!(months > 301, "outlasted 25 years: {months} months");
}
