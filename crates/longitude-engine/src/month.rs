//! The engine's clock is the civil month.

use std::fmt;

/// A civil month, counted continuously (year × 12 + month-index) so
/// arithmetic and ordering are trivial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Month(i32);

impl Month {
    pub fn from_ym(year: i32, month: u8) -> Month {
        debug_assert!((1..=12).contains(&month));
        Month(year * 12 + (month as i32 - 1))
    }

    pub fn year(self) -> i32 {
        self.0.div_euclid(12)
    }

    /// 1-based calendar month.
    pub fn month(self) -> u8 {
        (self.0.rem_euclid(12) + 1) as u8
    }

    pub fn is_january(self) -> bool {
        self.month() == 1
    }

    pub fn plus_months(self, n: i32) -> Month {
        Month(self.0 + n)
    }

    /// Whole months from `earlier` to `self` (negative if `self` is earlier).
    pub fn months_since(self, earlier: Month) -> i32 {
        self.0 - earlier.0
    }
}

impl fmt::Display for Month {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}", self.year(), self.month())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn month_arithmetic() {
        let m = Month::from_ym(2026, 7);
        assert_eq!(m.to_string(), "2026-07");
        assert_eq!(m.plus_months(6).to_string(), "2027-01");
        assert!(m.plus_months(6).is_january());
        assert_eq!(m.plus_months(18).months_since(m), 18);
        assert_eq!(Month::from_ym(2027, 1).months_since(m), 6);
    }
}
