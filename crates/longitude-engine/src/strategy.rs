//! The withdrawal strategy registry (engine spec §7.2).
//!
//! Strategy-as-spending is the honest paradigm only where there is no plan
//! to be demand-driven by: **simple mode** — a portfolio plus a strategy.
//! There the registry drives spending directly, recomputed at each
//! simulation-year boundary. In a plan-driven projection the strategy slug
//! changes nothing (§7.1); `[withdrawal].rate` serves only as the SWR.
//!
//! v0.1 shipped four strategies; spec rev 7 adds `discretionary-guardrail`.
//! An unknown slug is refused, never silently substituted.

use crate::model::Withdrawal;
use crate::project::EngineError;

/// Historical frequency of US-market drawdown states, used by the
/// deterministic `discretionary-guardrail` pass. Monthly S&P Composite,
/// **nominal price index** (drawdowns as headlines report them), Shiller's
/// monthly dataset, January 1926 – December 2022, with the all-time high
/// tracked from the series start (1871). Counts, not decimals, so the
/// provenance is checkable: recompute when the window moves.
pub const STATE_MONTHS_NORMAL: u32 = 582; // < 10% below the ATH
pub const STATE_MONTHS_CORRECTION: u32 = 177; // 10–20% below
pub const STATE_MONTHS_BEAR: u32 = 405; // > 20% below
pub const STATE_MONTHS_TOTAL: u32 = 1164; // 97 years × 12

/// The share of the discretionary budget funded on an *average* month of
/// that history, given the per-state cuts — the deterministic stand-in for
/// a market path the open projection does not have.
pub fn ev_multiplier(correction_cut: f64, bear_cut: f64) -> f64 {
    (STATE_MONTHS_NORMAL as f64
        + correction_cut * STATE_MONTHS_CORRECTION as f64
        + bear_cut * STATE_MONTHS_BEAR as f64)
        / STATE_MONTHS_TOTAL as f64
}

/// How the essential slice of a `discretionary-guardrail` withdrawal was
/// specified (§4.5: exactly one form MUST be present).
#[derive(Debug, Clone, Copy)]
pub enum EssentialSpec {
    /// `essential` — annual Money, real, resolved to base currency.
    Amount(f64),
    /// `essential_fraction` — fraction of the initial withdrawal.
    Fraction(f64),
}

impl EssentialSpec {
    /// Annual essential spending given the initial withdrawal `rate × t0`.
    pub fn resolve(&self, initial_withdrawal: f64) -> f64 {
        match self {
            EssentialSpec::Amount(a) => *a,
            EssentialSpec::Fraction(f) => f * initial_withdrawal,
        }
    }
}

/// The v0.1 registry entries, parsed from a scenario's `[withdrawal]`
/// table. All amounts are annual, real, in the vault's base currency.
#[derive(Debug, Clone)]
pub enum Strategy {
    /// `rate × portfolio(start)` per year, fixed in real terms thereafter —
    /// the classic 4%-rule shape. Can fail.
    ConstantDollar { rate: f64 },
    /// `rate × current portfolio` per year — income varies, never fails.
    FixedPercentage { rate: f64 },
    /// `fixed-percentage` clamped between `floor` and `ceiling` (annual,
    /// real) — the Vanguard-style compromise. A binding floor can fail.
    PercentWithBounds {
        rate: f64,
        floor: Option<f64>,
        ceiling: Option<f64>,
    },
    /// Bogleheads Variable Percentage Withdrawal: each year, the annuity
    /// payment factor over (remaining horizon, expected return) times the
    /// current portfolio. Spends down fully by horizon, never fails.
    Vpw,
    /// Two-bucket flexibility (Madfientist/Maggiulli, 2023; "Reefing" in
    /// product vocabulary): the essential slice of `rate × t0` behaves as
    /// constant-dollar; the discretionary remainder is cut by market state
    /// (full when <10% off highs, `correction_cut` of it 10–20% off,
    /// `bear_cut` beyond). The deterministic pass has no market path, so it
    /// funds discretionary at its historical expected value
    /// ([`ev_multiplier`]). Can fail.
    DiscretionaryGuardrail {
        rate: f64,
        essential: EssentialSpec,
        correction_cut: f64,
        bear_cut: f64,
    },
}

pub const KNOWN_STRATEGIES: &[&str] = &[
    "constant-dollar",
    "fixed-percentage",
    "percent-with-bounds",
    "vpw",
    "discretionary-guardrail",
];

fn rate_of(w: &Withdrawal, slug: &str) -> Result<f64, EngineError> {
    let raw = w.rate.as_deref().ok_or_else(|| EngineError::MissingRate {
        slug: slug.to_string(),
    })?;
    let rate = raw
        .parse::<f64>()
        .map_err(|_| EngineError::Value(format!("withdrawal.rate: bad decimal {raw:?}")))?;
    if !(0.0..=1.0).contains(&rate) {
        return Err(EngineError::Value(format!(
            "withdrawal.rate {rate} is not in [0, 1] — rates are fractions, not percents"
        )));
    }
    Ok(rate)
}

/// An optional decimal-string field constrained to [0, 1].
fn fraction_of(raw: Option<&str>, field: &str, default: f64) -> Result<f64, EngineError> {
    let Some(raw) = raw else {
        return Ok(default);
    };
    let x = raw
        .parse::<f64>()
        .map_err(|_| EngineError::Value(format!("withdrawal.{field}: bad decimal {raw:?}")))?;
    if !(0.0..=1.0).contains(&x) {
        return Err(EngineError::Value(format!(
            "withdrawal.{field} {x} is not in [0, 1]"
        )));
    }
    Ok(x)
}

impl Strategy {
    /// Parse a scenario's `[withdrawal]` table into a registry entry.
    /// `bound` resolves the optional `floor`/`ceiling` Money fields
    /// (base-currency check happens in the caller's closure).
    pub fn from_withdrawal(
        w: &Withdrawal,
        mut bound: impl FnMut(&crate::model::Money, &str) -> Result<f64, EngineError>,
    ) -> Result<Strategy, EngineError> {
        let slug = w.strategy.as_deref().ok_or(EngineError::MissingStrategy)?;
        match slug {
            "constant-dollar" => Ok(Strategy::ConstantDollar {
                rate: rate_of(w, slug)?,
            }),
            "fixed-percentage" => Ok(Strategy::FixedPercentage {
                rate: rate_of(w, slug)?,
            }),
            "percent-with-bounds" => {
                let floor = w
                    .floor
                    .as_ref()
                    .map(|m| bound(m, "withdrawal.floor"))
                    .transpose()?;
                let ceiling = w
                    .ceiling
                    .as_ref()
                    .map(|m| bound(m, "withdrawal.ceiling"))
                    .transpose()?;
                if let (Some(f), Some(c)) = (floor, ceiling) {
                    if f > c {
                        return Err(EngineError::Value(format!(
                            "withdrawal.floor ({f}) exceeds withdrawal.ceiling ({c})"
                        )));
                    }
                }
                Ok(Strategy::PercentWithBounds {
                    rate: rate_of(w, slug)?,
                    floor,
                    ceiling,
                })
            }
            "vpw" => Ok(Strategy::Vpw),
            "discretionary-guardrail" => {
                let essential = match (&w.essential, &w.essential_fraction) {
                    (Some(m), None) => EssentialSpec::Amount(bound(m, "withdrawal.essential")?),
                    (None, Some(f)) => {
                        EssentialSpec::Fraction(fraction_of(Some(f), "essential_fraction", 0.0)?)
                    }
                    _ => return Err(EngineError::MissingSplit),
                };
                Ok(Strategy::DiscretionaryGuardrail {
                    rate: rate_of(w, slug)?,
                    essential,
                    correction_cut: fraction_of(
                        w.correction_cut.as_deref(),
                        "correction_cut",
                        0.5,
                    )?,
                    bear_cut: fraction_of(w.bear_cut.as_deref(), "bear_cut", 0.0)?,
                })
            }
            other => Err(EngineError::UnknownStrategy {
                slug: other.to_string(),
            }),
        }
    }

    pub fn slug(&self) -> &'static str {
        match self {
            Strategy::ConstantDollar { .. } => "constant-dollar",
            Strategy::FixedPercentage { .. } => "fixed-percentage",
            Strategy::PercentWithBounds { .. } => "percent-with-bounds",
            Strategy::Vpw => "vpw",
            Strategy::DiscretionaryGuardrail { .. } => "discretionary-guardrail",
        }
    }

    /// Annual spending for simulation year `year` (0-based), recomputed at
    /// the year boundary. `portfolio` is the balance at that boundary, `t0`
    /// the balance at the start of the simulation, `horizon_years` the total
    /// window, `expected_return` the blended annual real return.
    pub fn annual_spend(
        &self,
        year: u32,
        portfolio: f64,
        t0: f64,
        horizon_years: u32,
        expected_return: f64,
    ) -> f64 {
        match self {
            Strategy::ConstantDollar { rate } => rate * t0,
            Strategy::FixedPercentage { rate } => rate * portfolio,
            Strategy::PercentWithBounds {
                rate,
                floor,
                ceiling,
            } => {
                let mut spend = rate * portfolio;
                if let Some(f) = floor {
                    spend = spend.max(*f);
                }
                if let Some(c) = ceiling {
                    spend = spend.min(*c);
                }
                spend
            }
            Strategy::Vpw => {
                let n = horizon_years.saturating_sub(year).max(1);
                vpw_rate(expected_return, n) * portfolio
            }
            Strategy::DiscretionaryGuardrail {
                rate,
                essential,
                correction_cut,
                bear_cut,
            } => {
                let initial = rate * t0;
                let essential = essential.resolve(initial).min(initial);
                let discretionary = initial - essential;
                essential + discretionary * ev_multiplier(*correction_cut, *bear_cut)
            }
        }
    }
}

/// The VPW percentage: the annuity payment factor `r / (1 − (1+r)^−n)` over
/// `n` remaining years at real return `r` — the rate that spends a portfolio
/// growing at `r` down to exactly zero in `n` equal real payments. At `r = 0`
/// this degenerates to `1/n`. The final year (`n = 1`) withdraws everything.
pub fn vpw_rate(r: f64, n: u32) -> f64 {
    if n <= 1 {
        return 1.0;
    }
    if r.abs() < 1e-12 {
        return 1.0 / n as f64;
    }
    // r ≤ −1 is a nonsense input; treat like straight-line spend-down.
    if r <= -1.0 {
        return 1.0 / n as f64;
    }
    r / (1.0 - (1.0 + r).powi(-(n as i32)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vpw_rate_annuity_values() {
        // r=5%, n=30 → 6.5051% (hand-checked annuity factor)
        assert!((vpw_rate(0.05, 30) - 0.065_051_43).abs() < 1e-7);
        // zero return degenerates to straight-line 1/n
        assert!((vpw_rate(0.0, 25) - 0.04).abs() < 1e-12);
        // final year takes everything
        assert_eq!(vpw_rate(0.05, 1), 1.0);
    }
}
