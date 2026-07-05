//! Current-state valuation and the deterministic monthly loop.

use std::str::FromStr;

use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;
use toml::value::Datetime;

use crate::model::{Money, Scenario, VaultModel};
use crate::month::Month;
use crate::strategy::{Strategy, KNOWN_STRATEGIES};

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("{doc}: {message}")]
    Document { doc: String, message: String },
    #[error("{0}")]
    Currency(String),
    #[error(
        "profile.annual_spending is required by the open projection — \
         cost-of-living-priced residency expenses need the data bundles, \
         which are engine territory outside this CLI"
    )]
    MissingSpending,
    #[error("scenario {id:?} not found; available: {}", available.join(", "))]
    ScenarioNotFound { id: String, available: Vec<String> },
    #[error("the vault has no scenarios to project")]
    NoScenarios,
    #[error(
        "unknown withdrawal strategy {slug:?} — the v0.1 registry is {}; \
         the engine refuses rather than silently substitutes (engine spec §7.2)",
        KNOWN_STRATEGIES.join(", ")
    )]
    UnknownStrategy { slug: String },
    #[error(
        "simple mode needs `strategy` in the scenario's [withdrawal] table — \
         the strategy drives spending there (engine spec §7.2); \
         the v0.1 registry is {}", KNOWN_STRATEGIES.join(", ")
    )]
    MissingStrategy,
    #[error("withdrawal strategy {slug:?} needs [withdrawal].rate")]
    MissingRate { slug: String },
    #[error(
        "no scenario selected: none is targeted and the vault has several — \
         pass --scenario <id>; available: {}", available.join(", ")
    )]
    NoTargetedScenario { available: Vec<String> },
    #[error("{0}")]
    Value(String),
}

/// How spending is determined (engine spec §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpendingMode {
    /// Demand-driven: the plan defines spending
    /// (profile.annual_spending + extra_monthly); withdrawals are
    /// expenses − income. The strategy slug changes nothing here (§7.1).
    Plan,
    /// Simple mode: the scenario's [withdrawal] strategy drives spending
    /// directly, recomputed at each simulation-year boundary (§7.2).
    Simple,
}

/// What the strategy did over the horizon (simple mode only).
#[derive(Debug, Clone)]
pub struct StrategyOutcome {
    pub slug: &'static str,
    pub rate: Option<f64>,
    pub floor: Option<f64>,
    pub ceiling: Option<f64>,
    /// Annual spending set at the first year boundary.
    pub first_year: f64,
    /// Extremes across all simulation years.
    pub min_year: f64,
    pub max_year: f64,
}

/// One projected calendar year (partial years at the edges included).
#[derive(Debug, Clone)]
pub struct YearRow {
    pub year: i32,
    pub income: f64,
    pub expenses: f64,
    pub end_balance: f64,
}

/// Deterministic single-scenario projection results. All projected money is
/// real (today's prices), in the vault's base currency, `f64` by design —
/// display it rounded.
#[derive(Debug)]
pub struct Projection {
    pub scenario_id: String,
    pub scenario_name: String,
    pub targeted: bool,
    pub start: Month,
    pub horizon_years: u32,
    /// Investable assets at t₀ (exact decimal — current state).
    pub t0_investable: Decimal,
    /// Latest snapshot date the valuation rests on, if any snapshots exist.
    pub valuation_as_of: Option<Datetime>,
    /// Annual recurring spending (profile.annual_spending + 12 × extra_monthly).
    /// `None` in simple mode, where the strategy sets spending year by year.
    pub annual_spending: Option<Decimal>,
    /// Present in simple mode: which strategy ran and what it withdrew.
    pub strategy: Option<StrategyOutcome>,
    /// Σ weight × expected_return, real, annualized.
    pub blended_return: f64,
    /// SWR used for the FI number: scenario [withdrawal].rate, else profile.swr.
    pub swr: Option<Decimal>,
    pub fi_number: Option<Decimal>,
    /// Longitude Score: investable / FI number, floored at 0, uncapped.
    pub score: Option<f64>,
    /// First month the portfolio ≥ the FI number.
    pub fi_month: Option<Month>,
    /// First month a withdrawal could not be met (failure latches; the
    /// simulation continues — later income can rebuild the portfolio).
    pub depletion_month: Option<Month>,
    pub failed: bool,
    /// Failed at some point but ended the horizon above zero.
    pub recovered: bool,
    pub end_balance: f64,
    pub years: Vec<YearRow>,
    pub warnings: Vec<String>,
}

const INVESTABLE_TYPES: &[&str] = &["cash", "brokerage", "retirement", "crypto"];

fn parse_decimal(s: &str, what: &str) -> Result<Decimal, EngineError> {
    Decimal::from_str(s).map_err(|_| EngineError::Value(format!("{what}: bad decimal {s:?}")))
}

fn money_in_base(m: &Money, base: &str, what: &str) -> Result<Decimal, EngineError> {
    if m.currency != base {
        return Err(EngineError::Currency(format!(
            "{what} is in {}, but the open projection has no FX data — \
             every amount it uses must be in the vault's base currency ({base})",
            m.currency
        )));
    }
    parse_decimal(&m.amount, what)
}

fn month_of(dt: &Datetime) -> Option<Month> {
    dt.date.map(|d| Month::from_ym(d.year as i32, d.month))
}

/// Investable assets at t₀ (engine spec §2.2/§2.3, snapshot-only — the open
/// CLI has no price feeds): latest snapshot balance per account; accounts
/// past `closed` are zero; investable = cash + brokerage + retirement +
/// crypto − unsecured liabilities. Real estate is excluded, and a liability
/// secured by a non-investable account travels with it (the house and its
/// mortgage stay together, both out).
fn value_t0(
    model: &VaultModel,
    now: Month,
    warnings: &mut Vec<String>,
) -> Result<(Decimal, Option<Datetime>), EngineError> {
    // latest observation per account
    let mut latest: std::collections::BTreeMap<&str, (Datetime, Decimal)> =
        std::collections::BTreeMap::new();
    let mut as_of: Option<Datetime> = None;
    for snap in &model.snapshots {
        let Some(snap_month) = month_of(&snap.date) else {
            continue;
        };
        for b in &snap.balance {
            let value = money_in_base(
                &b.value,
                &model.base_currency,
                &format!("snapshot balance for {:?}", b.account),
            )?;
            let newer = match latest.get(b.account.as_str()) {
                Some((prev, _)) => month_of(prev).is_none_or(|p| snap_month >= p),
                None => true,
            };
            if newer {
                latest.insert(&b.account, (snap.date, value));
            }
        }
        if as_of
            .and_then(|d| month_of(&d))
            .is_none_or(|p| snap_month >= p)
        {
            as_of = Some(snap.date);
        }
    }

    let mut total = Decimal::ZERO;
    for account in &model.accounts {
        let closed = account
            .closed
            .as_ref()
            .and_then(month_of)
            .is_some_and(|c| c < now);
        let value = if closed {
            Decimal::ZERO
        } else {
            match latest.get(account.id.as_str()) {
                Some((_, v)) => *v,
                None => {
                    if INVESTABLE_TYPES.contains(&account.kind.as_str())
                        || account.kind == "liability"
                    {
                        warnings.push(format!(
                            "account {:?} has no snapshot balance — valued at 0",
                            account.id
                        ));
                    }
                    Decimal::ZERO
                }
            }
        };

        if INVESTABLE_TYPES.contains(&account.kind.as_str()) {
            total += value;
        } else if account.kind == "liability" {
            let secured_by_excluded = account.secured_by.as_deref().is_some_and(|target| {
                model
                    .accounts
                    .iter()
                    .find(|a| a.id == target)
                    .is_some_and(|a| !INVESTABLE_TYPES.contains(&a.kind.as_str()))
            });
            if !secured_by_excluded {
                total -= value;
            }
        }
        // real-estate / other: net-worth display territory, not investable
    }
    Ok((total, as_of))
}

/// Monthly income for stream `i` at month `m` (engine spec §5): active while
/// from ≤ m ≤ to; annual amounts post at 1/12 per month; `once` posts in its
/// `from` month; growth is real, compounded annually on the anniversary.
struct Stream {
    monthly: f64,
    once: bool,
    from: Option<Month>,
    to: Option<Month>,
    growth: f64,
}

impl Stream {
    fn at(&self, m: Month, start: Month) -> f64 {
        let anchor = self.from.unwrap_or(start);
        if self.once {
            return if m == anchor { self.monthly } else { 0.0 };
        }
        if m < anchor || self.to.is_some_and(|to| m > to) {
            return 0.0;
        }
        let years = (m.months_since(anchor) / 12) as f64;
        self.monthly * (1.0 + self.growth).powf(years)
    }
}

pub fn project(
    model: &VaultModel,
    scenario: &Scenario,
    now: Month,
    mode: SpendingMode,
) -> Result<Projection, EngineError> {
    let mut warnings = Vec::new();

    // ---- t₀ (the one decimal → f64 crossing) -------------------------------
    let (t0_investable, valuation_as_of) = value_t0(model, now, &mut warnings)?;

    // ---- spending (§7): the plan's figure, or the strategy registry ---------
    let annual_spending = match mode {
        SpendingMode::Plan => {
            let base_spend = model
                .profile
                .annual_spending
                .as_ref()
                .ok_or(EngineError::MissingSpending)
                .and_then(|m| money_in_base(m, &model.base_currency, "profile.annual_spending"))?;
            let extra_monthly = scenario
                .expenses
                .extra_monthly
                .as_ref()
                .map(|m| money_in_base(m, &model.base_currency, "expenses.extra_monthly"))
                .transpose()?
                .unwrap_or(Decimal::ZERO);
            warnings.push(
                "spending comes from profile.annual_spending — pricing residency blocks \
                 from cost-of-living data is outside the open projection"
                    .to_string(),
            );
            Some(base_spend + extra_monthly * Decimal::from(12))
        }
        SpendingMode::Simple => None,
    };
    let strategy = match mode {
        SpendingMode::Simple => Some(Strategy::from_withdrawal(
            &scenario.withdrawal,
            |m, what| {
                money_in_base(m, &model.base_currency, what).map(|d| d.to_f64().unwrap_or(0.0))
            },
        )?),
        SpendingMode::Plan => None,
    };

    // ---- blended deterministic return (§6.2) --------------------------------
    let mut weight_sum = 0.0;
    let mut blended = 0.0;
    for alloc in &scenario.portfolio.allocation {
        let (Some(w), Some(r)) = (&alloc.weight, &alloc.expected_return) else {
            continue;
        };
        let w: f64 = w
            .parse()
            .map_err(|_| EngineError::Value(format!("allocation weight {w:?}")))?;
        let r: f64 = r
            .parse()
            .map_err(|_| EngineError::Value(format!("expected_return {r:?}")))?;
        weight_sum += w;
        blended += w * r;
    }
    let blended_return = if weight_sum > 0.0 {
        if (weight_sum - 1.0).abs() > 0.01 {
            warnings.push(format!(
                "allocation weights sum to {weight_sum}; normalized to 1"
            ));
        }
        blended / weight_sum
    } else {
        warnings.push(
            "no [[portfolio.allocation]] with weight + expected_return — \
             assuming a 0% real return"
                .to_string(),
        );
        0.0
    };
    let monthly_return = (1.0 + blended_return).powf(1.0 / 12.0) - 1.0;

    // ---- FI number & Score (§14.1/§14.2) — plan-driven concepts; simple
    // mode has no steady-state spend to divide by the SWR ----------------------
    let swr = match mode {
        SpendingMode::Simple => None,
        SpendingMode::Plan => match (&scenario.withdrawal.rate, &model.profile.swr) {
            (Some(r), _) => Some(parse_decimal(r, "withdrawal.rate")?),
            (None, Some(r)) => Some(parse_decimal(r, "profile.swr")?),
            (None, None) => {
                warnings.push(
                    "no [withdrawal].rate and no profile.swr — FI number and \
                     Longitude Score unavailable"
                        .to_string(),
                );
                None
            }
        },
    };
    let fi_number = annual_spending.and_then(|spend| {
        swr.and_then(|swr| {
            if swr > Decimal::ZERO {
                Some(spend / swr)
            } else {
                None
            }
        })
    });
    let score = fi_number.map(|fi| {
        (t0_investable / fi)
            .to_f64()
            .map(|s| s.max(0.0))
            .unwrap_or(0.0)
    });

    // ---- income streams (§5) -------------------------------------------------
    let mut streams = Vec::new();
    for income in &scenario.income {
        let Some(amount) = &income.amount else {
            continue;
        };
        let label = income.id.as_deref().unwrap_or("income");
        let amount = money_in_base(amount, &model.base_currency, label)?
            .to_f64()
            .unwrap_or(0.0);
        let frequency = income.frequency.as_deref().unwrap_or("monthly");
        let (monthly, once) = match frequency {
            "monthly" => (amount, false),
            "annual" => (amount / 12.0, false),
            "once" => (amount, true),
            other => {
                warnings.push(format!(
                    "income {label:?}: unknown frequency {other:?} — stream skipped"
                ));
                continue;
            }
        };
        streams.push(Stream {
            monthly,
            once,
            from: income.from.as_ref().and_then(month_of),
            to: income.to.as_ref().and_then(month_of),
            growth: income
                .growth
                .as_ref()
                .map(|g| g.parse::<f64>().unwrap_or(0.0))
                .unwrap_or(0.0),
        });
    }

    // ---- the monthly loop (§3) -----------------------------------------------
    let start = scenario
        .timeline
        .start
        .as_ref()
        .and_then(month_of)
        .unwrap_or(now);
    let horizon_years = scenario.timeline.horizon_years.unwrap_or(50).min(120);
    let months = horizon_years * 12;
    let plan_monthly_expense = annual_spending
        .map(|spend| (spend / Decimal::from(12)).to_f64().unwrap_or(0.0))
        .unwrap_or(0.0);
    let fi_target = fi_number.and_then(|d| d.to_f64());

    let t0 = t0_investable.to_f64().unwrap_or(0.0);
    let mut portfolio = t0;
    let mut failed = false;
    let mut depletion_month = None;
    let mut fi_month = None;
    let mut years: Vec<YearRow> = Vec::new();

    // Simple mode: the strategy sets annual spending at each simulation-year
    // boundary (§7.2); within a year it is spent evenly by month.
    let mut annual_spend = 0.0;
    let mut outcome = strategy.as_ref().map(|s| StrategyOutcome {
        slug: s.slug(),
        rate: match s {
            Strategy::ConstantDollar { rate }
            | Strategy::FixedPercentage { rate }
            | Strategy::PercentWithBounds { rate, .. } => Some(*rate),
            Strategy::Vpw => None,
        },
        floor: match s {
            Strategy::PercentWithBounds { floor, .. } => *floor,
            _ => None,
        },
        ceiling: match s {
            Strategy::PercentWithBounds { ceiling, .. } => *ceiling,
            _ => None,
        },
        first_year: 0.0,
        min_year: f64::INFINITY,
        max_year: 0.0,
    });

    for i in 0..months {
        let m = start.plus_months(i as i32);

        if let Some(s) = &strategy {
            if (i % 12) == 0 {
                let year = i / 12;
                annual_spend = s.annual_spend(year, portfolio, t0, horizon_years, blended_return);
                if let Some(o) = &mut outcome {
                    if year == 0 {
                        o.first_year = annual_spend;
                    }
                    o.min_year = o.min_year.min(annual_spend);
                    o.max_year = o.max_year.max(annual_spend);
                }
            }
        }
        let monthly_expense = if strategy.is_some() {
            annual_spend / 12.0
        } else {
            plan_monthly_expense
        };

        // 1. income  2. expenses  3. net cashflow
        let income: f64 = streams.iter().map(|s| s.at(m, start)).sum();
        let net = income - monthly_expense;
        if net >= 0.0 {
            portfolio += net;
        } else {
            let need = -net;
            if portfolio >= need {
                portfolio -= need;
            } else {
                // 4. failure latches; unmet spending is dropped; simulation
                //    continues — later income can rebuild the portfolio
                if !failed {
                    failed = true;
                    depletion_month = Some(m);
                }
                portfolio = 0.0;
            }
        }

        // 5. returns (flows before returns, uniformly)
        portfolio *= 1.0 + monthly_return;
        // 6. rebalance (January): a no-op under a single blended return

        if fi_month.is_none() {
            if let Some(target) = fi_target {
                if portfolio >= target {
                    fi_month = Some(m);
                }
            }
        }

        match years.last_mut() {
            Some(row) if row.year == m.year() => {
                row.income += income;
                row.expenses += monthly_expense;
                row.end_balance = portfolio;
            }
            _ => years.push(YearRow {
                year: m.year(),
                income,
                expenses: monthly_expense,
                end_balance: portfolio,
            }),
        }
    }

    let end_balance = portfolio;
    if let Some(o) = &mut outcome {
        if !o.min_year.is_finite() {
            o.min_year = 0.0; // zero-length horizon: no year boundary ran
        }
    }
    Ok(Projection {
        scenario_id: scenario.id.clone(),
        scenario_name: scenario.name.clone(),
        targeted: scenario.targeted,
        start,
        horizon_years,
        t0_investable,
        valuation_as_of,
        annual_spending,
        strategy: outcome,
        blended_return,
        swr,
        fi_number,
        score,
        fi_month,
        depletion_month,
        failed,
        recovered: failed && end_balance > 0.0,
        end_balance,
        years,
        warnings,
    })
}
