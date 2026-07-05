//! Open engine core: the deterministic single-scenario projection.
//!
//! This is the open slice of the Longitude engine — current-state valuation,
//! the monthly loop, income streams, deterministic portfolio returns, and the
//! deterministic outputs (FI date, depletion, Longitude Score). Monte Carlo,
//! cost-of-living blending from data bundles, tax, and visa feasibility are
//! engine territory outside this crate.
//!
//! Two conventions worth knowing before reading results:
//!
//! - **Real terms first.** All math is in inflation-adjusted terms, in the
//!   vault's base currency. Expected returns are real; spending is at today's
//!   prices. "In 2040 you have $800k" means today's dollars.
//! - **Decimal / float boundary.** Current-state numbers (t₀ assets, the
//!   Score) use exact decimals. Everything projected past "now" is `f64`,
//!   and is displayed rounded — projections are estimates, never precise.

pub mod model;
pub mod month;
pub mod project;

pub use model::{extract, Scenario, VaultModel};
pub use month::Month;
pub use project::{project, EngineError, Projection, YearRow};
