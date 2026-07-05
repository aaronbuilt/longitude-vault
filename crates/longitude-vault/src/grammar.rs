//! Lexical grammars from SPEC §3: slugs, decimal strings, currency codes,
//! place strings, world-data keys, snapshot dates.

/// World-data domains defined for v0.1 (§3.6).
pub const DOMAINS: &[&str] = &[
    "col",
    "tax",
    "visa",
    "fx",
    "climate",
    "safety",
    "livability",
];

/// Entity-id / filename slug: `[a-z0-9][a-z0-9-]{0,63}` (§3.2).
pub fn is_slug(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 64 {
        return false;
    }
    if !(b[0].is_ascii_lowercase() || b[0].is_ascii_digit()) {
        return false;
    }
    b.iter()
        .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

/// Decimal-string grammar: `-?(0|[1-9][0-9]*)(\.[0-9]+)?` (§3.4).
pub fn is_decimal(s: &str) -> bool {
    let s = s.strip_prefix('-').unwrap_or(s);
    let (int, frac) = match s.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (s, None),
    };
    let int_ok = !int.is_empty()
        && int.bytes().all(|c| c.is_ascii_digit())
        && (int == "0" || int.as_bytes()[0] != b'0');
    let frac_ok = frac.is_none_or(|f| !f.is_empty() && f.bytes().all(|c| c.is_ascii_digit()));
    int_ok && frac_ok
}

/// Currency: ISO 4217 alphabetic code or an uppercase asset code (§3.4).
pub fn is_currency_code(s: &str) -> bool {
    let b = s.as_bytes();
    (2..=10).contains(&b.len())
        && b[0].is_ascii_uppercase()
        && b.iter()
            .all(|&c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

/// Passport: ISO 3166-1 alpha-2, uppercase (§4.2).
pub fn is_passport_code(s: &str) -> bool {
    s.len() == 2 && s.bytes().all(|c| c.is_ascii_uppercase())
}

/// Place string: `"<country>"` or `"<country>/<city>"`, lowercase (§3.6).
pub fn is_place(s: &str) -> bool {
    let (country, city) = match s.split_once('/') {
        Some((c, city)) => (c, Some(city)),
        None => (s, None),
    };
    let country_ok = country.len() == 2 && country.bytes().all(|c| c.is_ascii_lowercase());
    country_ok && city.is_none_or(is_slug)
}

/// World-data key: `<domain>.<country>[.<city>].<category>[.<subkey>]` (§3.6).
/// The full key registry is versioned with the data bundles, so this checks
/// shape only: a known domain, a country code, at least one more segment,
/// every segment a lowercase kebab slug.
pub fn is_world_data_key(s: &str) -> bool {
    let segs: Vec<&str> = s.split('.').collect();
    if segs.len() < 3 {
        return false;
    }
    if !DOMAINS.contains(&segs[0]) {
        return false;
    }
    if !(segs[1].len() == 2 && segs[1].bytes().all(|c| c.is_ascii_lowercase())) {
        return false;
    }
    segs[2..].iter().all(|seg| is_slug(seg))
}

/// Snapshot filename stem: `YYYY-MM-DD` with plausible month/day (§4.4).
pub fn is_date_stem(s: &str) -> bool {
    parse_date_stem(s).is_some()
}

/// Parse a `YYYY-MM-DD` stem into (year, month, day).
pub fn parse_date_stem(s: &str) -> Option<(u16, u8, u8)> {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let digits = |r: std::ops::Range<usize>| -> Option<u32> {
        if !b[r.clone()].iter().all(|c| c.is_ascii_digit()) {
            return None;
        }
        s[r].parse().ok()
    };
    let (y, m, d) = (digits(0..4)?, digits(5..7)?, digits(8..10)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some((y as u16, m as u8, d as u8))
}

/// UUID shape check for `vault_id` (§3.2): 8-4-4-4-12 hex groups.
pub fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    b.iter().enumerate().all(|(i, &c)| match i {
        8 | 13 | 18 | 23 => c == b'-',
        _ => c.is_ascii_hexdigit(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs() {
        assert!(is_slug("schwab-brokerage"));
        assert!(is_slug("a"));
        assert!(is_slug("0-day"));
        assert!(!is_slug(""));
        assert!(!is_slug("-leading-dash"));
        assert!(!is_slug("Upper"));
        assert!(!is_slug("with space"));
        assert!(!is_slug("with_underscore"));
        assert!(!is_slug(&"x".repeat(65)));
        assert!(is_slug(&"x".repeat(64)));
    }

    #[test]
    fn decimals() {
        assert!(is_decimal("0"));
        assert!(is_decimal("412345.67"));
        assert!(is_decimal("-1.5"));
        assert!(is_decimal("0.040"));
        assert!(!is_decimal(""));
        assert!(!is_decimal("+1"));
        assert!(!is_decimal("1e5"));
        assert!(!is_decimal("1,000"));
        assert!(!is_decimal("01"));
        assert!(!is_decimal(".5"));
        assert!(!is_decimal("1."));
        assert!(!is_decimal("-"));
        assert!(!is_decimal("--1"));
    }

    #[test]
    fn places() {
        assert!(is_place("pl/krakow"));
        assert!(is_place("ge"));
        assert!(is_place("us/detroit"));
        assert!(!is_place("PL/krakow"));
        assert!(!is_place("usa/detroit"));
        assert!(!is_place("us/"));
        assert!(!is_place(""));
    }

    #[test]
    fn world_data_keys() {
        assert!(is_world_data_key("col.pl.krakow.housing.comfortable"));
        assert!(is_world_data_key("tax.us.federal.ltcg"));
        assert!(is_world_data_key("visa.jp.us-passport.max-stay-days"));
        assert!(!is_world_data_key("col.pl"));
        assert!(!is_world_data_key("bogus.pl.krakow.housing"));
        assert!(!is_world_data_key("col.POL.krakow.housing"));
    }

    #[test]
    fn dates() {
        assert!(is_date_stem("2026-06-30"));
        assert!(!is_date_stem("2026-13-01"));
        assert!(!is_date_stem("2026-6-30"));
        assert!(!is_date_stem("20260630"));
    }

    #[test]
    fn uuids() {
        assert!(is_uuid("1c9f0f8e-2b4a-4d6c-8e0f-1a2b3c4d5e6f"));
        assert!(!is_uuid("1c9f0f8e-2b4a-4d6c-8e0f"));
        assert!(!is_uuid("zc9f0f8e-2b4a-4d6c-8e0f-1a2b3c4d5e6f"));
    }
}
