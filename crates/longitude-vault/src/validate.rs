//! The conforming validator (SPEC §8): errors make a vault invalid,
//! warnings don't. Works over the in-memory `RawVault`, so it applies
//! identically to both physical forms (§5).

use std::collections::{BTreeMap, BTreeSet};

use toml::value::Datetime;
use toml::Value;

use crate::grammar;
use crate::report::Report;
use crate::vault::RawVault;
use crate::{KNOWN_SCHEMA_MAJOR, RECOGNIZED_DIRS};

/// Which physical form the vault was read from — a few findings depend on it
/// (descriptor-in-plaintext, passphrase-only export mode).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Plaintext,
    Container { scrypt_only: bool },
}

const ACCOUNT_TYPES: &[&str] = &[
    "cash",
    "brokerage",
    "retirement",
    "crypto",
    "real-estate",
    "liability",
    "other",
];
const HOLDING_KINDS: &[&str] = &["security", "crypto", "cash", "custom"];
const TAX_WRAPPERS: &[&str] = &["taxable", "traditional", "roth", "pension", "isa", "other"];
const LIFESTYLES: &[&str] = &["lean", "comfortable", "luxury"];
const FREQUENCIES: &[&str] = &["monthly", "annual", "once"];
const INCOME_KINDS: &[&str] = &[
    "employment",
    "self-employment",
    "pension",
    "social-security",
    "rental",
    "one-off",
    "other",
];

#[derive(Debug, Default)]
struct AccountInfo {
    doc: String,
    is_liability: bool,
    closed: Option<(u16, u8, u8)>,
    secured_by: Option<String>,
    has_descriptor: bool,
}

pub fn validate(vault: &RawVault, mode: Mode) -> Report {
    let mut r = Report::default();

    // ---- parse every TOML document up front -------------------------------
    let mut parsed: BTreeMap<&str, Value> = BTreeMap::new();
    for doc in &vault.documents {
        if !doc.path.ends_with(".toml") {
            continue;
        }
        match std::str::from_utf8(&doc.bytes) {
            Err(_) => r.error(&doc.path, "not valid UTF-8"),
            Ok(text) => match text.parse::<Value>() {
                Ok(value) => {
                    parsed.insert(&doc.path, value);
                }
                Err(e) => r.error(&doc.path, format!("TOML syntax error: {e}")),
            },
        }
    }

    // ---- top-level structure ----------------------------------------------
    let mut unrecognized_dirs: BTreeSet<&str> = BTreeSet::new();
    for doc in &vault.documents {
        match doc.path.split_once('/') {
            None => {
                if doc.path != "manifest.toml" && doc.path != "profile.toml" {
                    r.warning(
                        &doc.path,
                        "unrecognized top-level entry (preserved per §5.1)",
                    );
                }
            }
            Some((dir, rest)) => {
                if !RECOGNIZED_DIRS.contains(&dir) {
                    unrecognized_dirs.insert(dir);
                } else if dir != "notes"
                    && dir != "transactions"
                    && (!rest.ends_with(".toml") || rest.contains('/'))
                {
                    r.warning(
                        &doc.path,
                        format!("unexpected file under {dir}/ (not validated)"),
                    );
                }
            }
        }
    }
    for dir in unrecognized_dirs {
        r.warning(
            format!("{dir}/"),
            "unrecognized top-level directory (preserved per §5.1)",
        );
    }

    // ---- manifest.toml ------------------------------------------------------
    match parsed.get("manifest.toml") {
        None => {
            if vault.get("manifest.toml").is_none() {
                r.error("manifest.toml", "missing (required — §4.1)");
            }
        }
        Some(v) => validate_manifest(v, &mut r),
    }

    // ---- profile.toml -------------------------------------------------------
    match parsed.get("profile.toml") {
        None => {
            if vault.get("profile.toml").is_none() {
                r.error("profile.toml", "missing (required — §4.2)");
            }
        }
        Some(v) => validate_profile(v, &mut r),
    }

    // ---- accounts ----------------------------------------------------------
    let mut accounts: BTreeMap<String, AccountInfo> = BTreeMap::new();
    for (path, value) in &parsed {
        if let Some(stem) = doc_stem(path, "accounts") {
            validate_account(path, stem, value, &mut accounts, &mut r);
        }
    }
    // referential checks that need the full account set
    for (id, info) in &accounts {
        if let Some(target) = &info.secured_by {
            if !accounts.contains_key(target) {
                r.error(
                    &info.doc,
                    format!("secured_by references nonexistent account id {target:?} (§4.3)"),
                );
            }
            if !info.is_liability {
                r.error(
                    &info.doc,
                    format!(
                        "secured_by is only valid on liability accounts, \
                         but {id:?} is not a liability (§4.3)"
                    ),
                );
            }
        }
    }

    // ---- snapshots ---------------------------------------------------------
    for (path, value) in &parsed {
        if let Some(stem) = doc_stem(path, "snapshots") {
            validate_snapshot(path, stem, value, &accounts, &mut r);
        }
    }

    // ---- scenarios ---------------------------------------------------------
    let mut targeted: Vec<String> = Vec::new();
    for (path, value) in &parsed {
        if let Some(stem) = doc_stem(path, "scenarios") {
            validate_scenario(path, stem, value, &mut targeted, &mut r);
        }
    }
    if targeted.len() > 1 {
        r.error(
            "(vault)",
            format!(
                "more than one scenario sets targeted = true ({}) — at most one may (§4.5)",
                targeted.join(", ")
            ),
        );
    }

    // ---- overrides ---------------------------------------------------------
    let mut override_keys: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (path, value) in &parsed {
        if doc_stem(path, "overrides").is_some() {
            validate_override_file(path, value, &mut override_keys, &mut r);
        }
    }
    for (key, files) in &override_keys {
        let distinct: BTreeSet<&String> = files.iter().collect();
        if distinct.len() > 1 {
            r.warning(
                "(vault)",
                format!(
                    "override key {key:?} appears in multiple files ({}) — \
                     last in lexical filename order wins (§4.6)",
                    files.join(", ")
                ),
            );
        } else if files.len() > 1 {
            r.warning(
                files[0].clone(),
                format!(
                    "override key {key:?} appears {} times in this file — \
                     last in document order wins (§4.6)",
                    files.len()
                ),
            );
        }
    }

    // ---- mode-dependent findings -------------------------------------------
    if mode == Mode::Plaintext {
        for info in accounts.values() {
            if info.has_descriptor {
                r.warning(
                    &info.doc,
                    "watch-only descriptor present in a plaintext-mode vault — \
                     it reveals all derived addresses to anyone who reads the file (§7)",
                );
            }
        }
    }
    if let Mode::Container { scrypt_only: true } = mode {
        r.warning(
            "(vault)",
            "passphrase-only export vault (§6.4) — no recovery key can coexist \
             with it; do not save routine changes back to it",
        );
    }

    r
}

// ============================ helpers =======================================

/// `accounts/foo.toml` → `Some("foo")` when path is a direct `.toml` child
/// of `dir`.
fn doc_stem<'a>(path: &'a str, dir: &str) -> Option<&'a str> {
    let rest = path.strip_prefix(dir)?.strip_prefix('/')?;
    if rest.contains('/') {
        return None;
    }
    rest.strip_suffix(".toml")
}

fn table(v: &Value) -> Option<&toml::map::Map<String, Value>> {
    v.as_table()
}

fn req_str<'a>(
    t: &'a toml::map::Map<String, Value>,
    key: &str,
    doc: &str,
    section: &str,
    r: &mut Report,
) -> Option<&'a str> {
    match t.get(key) {
        None => {
            r.error(doc, format!("missing required field `{key}` ({section})"));
            None
        }
        Some(Value::String(s)) => Some(s),
        Some(_) => {
            r.error(doc, format!("`{key}` must be a string ({section})"));
            None
        }
    }
}

fn opt_str<'a>(
    t: &'a toml::map::Map<String, Value>,
    key: &str,
    doc: &str,
    r: &mut Report,
) -> Option<&'a str> {
    match t.get(key) {
        None => None,
        Some(Value::String(s)) => Some(s),
        Some(_) => {
            r.error(doc, format!("`{key}` must be a string"));
            None
        }
    }
}

/// A decimal-string field (§3.4/§3.5). `required` controls the missing-field
/// error; a TOML integer/float is always the dedicated §8 error.
fn check_decimal(
    t: &toml::map::Map<String, Value>,
    key: &str,
    doc: &str,
    required: bool,
    r: &mut Report,
) {
    match t.get(key) {
        None => {
            if required {
                r.error(doc, format!("missing required field `{key}`"));
            }
        }
        Some(Value::String(s)) => {
            if !grammar::is_decimal(s) {
                r.error(
                    doc,
                    format!("`{key}` = {s:?} violates the decimal-string grammar (§3.4)"),
                );
            }
        }
        Some(Value::Integer(_)) | Some(Value::Float(_)) => {
            r.error(
                doc,
                format!(
                    "`{key}` must be a decimal string, not a TOML number — \
                     money/quantities/rates never round-trip through floats (§3.4)"
                ),
            );
        }
        Some(_) => {
            r.error(doc, format!("`{key}` must be a decimal string (§3.4)"));
        }
    }
}

/// A Money value: `{ amount = "…", currency = "…" }` (§3.4).
fn check_money_value(v: &Value, field: &str, doc: &str, r: &mut Report) {
    let Some(m) = v.as_table() else {
        r.error(
            doc,
            format!(
                "`{field}` must be an inline table {{ amount = \"…\", currency = \"…\" }} (§3.4)"
            ),
        );
        return;
    };
    match m.get("amount") {
        None => r.error(doc, format!("`{field}.amount` missing (§3.4)")),
        Some(Value::String(s)) => {
            if !grammar::is_decimal(s) {
                r.error(
                    doc,
                    format!("`{field}.amount` = {s:?} violates the decimal-string grammar (§3.4)"),
                );
            }
        }
        Some(Value::Integer(_)) | Some(Value::Float(_)) => r.error(
            doc,
            format!("`{field}.amount` must be a decimal string, not a TOML number (§3.4)"),
        ),
        Some(_) => r.error(
            doc,
            format!("`{field}.amount` must be a decimal string (§3.4)"),
        ),
    }
    match m.get("currency") {
        None => r.error(doc, format!("`{field}.currency` missing (§3.4)")),
        Some(Value::String(s)) => {
            if !grammar::is_currency_code(s) {
                r.error(
                    doc,
                    format!("`{field}.currency` = {s:?} is not a valid currency/asset code (§3.4)"),
                );
            }
        }
        Some(_) => r.error(doc, format!("`{field}.currency` must be a string (§3.4)")),
    }
}

fn check_money(
    t: &toml::map::Map<String, Value>,
    key: &str,
    doc: &str,
    required: bool,
    r: &mut Report,
) {
    match t.get(key) {
        None => {
            if required {
                r.error(doc, format!("missing required field `{key}`"));
            }
        }
        Some(v) => check_money_value(v, key, doc, r),
    }
}

fn check_place(t: &toml::map::Map<String, Value>, key: &str, doc: &str, r: &mut Report) {
    if let Some(s) = opt_str(t, key, doc, r) {
        if !grammar::is_place(s) {
            r.error(
                doc,
                format!("`{key}` = {s:?} is not a valid place string (§3.6, lowercase)"),
            );
        }
    }
}

fn date_of(dt: &Datetime) -> Option<(u16, u8, u8)> {
    dt.date.map(|d| (d.year, d.month, d.day))
}

fn check_date(
    t: &toml::map::Map<String, Value>,
    key: &str,
    doc: &str,
    r: &mut Report,
) -> Option<(u16, u8, u8)> {
    match t.get(key) {
        None => None,
        Some(Value::Datetime(dt)) => {
            let d = date_of(dt);
            if d.is_none() {
                r.error(doc, format!("`{key}` must include a calendar date (§3.3)"));
            }
            d
        }
        Some(_) => {
            r.error(
                doc,
                format!("`{key}` must be a TOML date (unquoted, e.g. 2026-06-30 — §3.3)"),
            );
            None
        }
    }
}

fn enum_warn(
    t: &toml::map::Map<String, Value>,
    key: &str,
    allowed: &[&str],
    doc: &str,
    r: &mut Report,
) {
    if let Some(Value::String(s)) = t.get(key) {
        if !allowed.contains(&s.as_str()) {
            r.warning(
                doc,
                format!("`{key}` = {s:?} is not one of {}", allowed.join(" | ")),
            );
        }
    }
}

// ============================ documents =====================================

fn validate_manifest(v: &Value, r: &mut Report) {
    let doc = "manifest.toml";
    let Some(t) = table(v) else {
        r.error(doc, "document root must be a table");
        return;
    };
    if let Some(format) = req_str(t, "format", doc, "§4.1", r) {
        if format != "longitude-vault" {
            r.error(
                doc,
                format!("`format` must be the literal \"longitude-vault\", got {format:?} (§4.1)"),
            );
        }
    }
    if let Some(schema) = req_str(t, "schema", doc, "§4.1", r) {
        match parse_schema(schema) {
            None => r.error(
                doc,
                format!("`schema` = {schema:?} is not MAJOR.MINOR (§4.1)"),
            ),
            Some((major, _)) => {
                if major > KNOWN_SCHEMA_MAJOR {
                    r.error(
                        doc,
                        format!(
                            "unknown schema MAJOR {major} — this implementation understands \
                             MAJOR {KNOWN_SCHEMA_MAJOR} and must refuse higher (§3.7)"
                        ),
                    );
                }
            }
        }
    }
    if let Some(id) = req_str(t, "vault_id", doc, "§4.1", r) {
        if !grammar::is_uuid(id) {
            r.error(doc, format!("`vault_id` = {id:?} is not a UUID (§3.2)"));
        }
    }
    if let Some(cur) = req_str(t, "base_currency", doc, "§4.1", r) {
        if !grammar::is_currency_code(cur) {
            r.error(
                doc,
                format!("`base_currency` = {cur:?} is not a valid currency code (§3.4)"),
            );
        }
    }
    for key in ["created", "modified"] {
        if let Some(v) = t.get(key) {
            if !matches!(v, Value::Datetime(_)) {
                r.error(
                    doc,
                    format!("`{key}` must be a TOML datetime (unquoted — §3.3)"),
                );
            }
        }
    }
}

fn parse_schema(s: &str) -> Option<(u64, u64)> {
    let (major, minor) = s.split_once('.')?;
    let ok = |p: &str| !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit());
    if !ok(major) || !ok(minor) {
        return None;
    }
    Some((major.parse().ok()?, minor.parse().ok()?))
}

fn validate_profile(v: &Value, r: &mut Report) {
    let doc = "profile.toml";
    let Some(t) = table(v) else {
        r.error(doc, "document root must be a table");
        return;
    };
    match t.get("passports") {
        None => r.error(doc, "missing required field `passports` (§4.2)"),
        Some(Value::Array(items)) => {
            if items.is_empty() {
                r.warning(
                    doc,
                    "`passports` is empty — visa/tax features degrade (§4.2)",
                );
            }
            for item in items {
                match item {
                    Value::String(s) if grammar::is_passport_code(s) => {}
                    Value::String(s) => r.error(
                        doc,
                        format!(
                            "passport {s:?} is not an uppercase ISO 3166-1 alpha-2 code (§4.2)"
                        ),
                    ),
                    _ => r.error(doc, "`passports` entries must be strings (§4.2)"),
                }
            }
        }
        Some(_) => r.error(doc, "`passports` must be an array (§4.2)"),
    }
    check_place(t, "tax_residency", doc, r);
    check_money(t, "annual_spending", doc, false, r);
    check_money(t, "annual_savings", doc, false, r);
    check_decimal(t, "swr", doc, false, r);
    enum_warn(t, "lifestyle", LIFESTYLES, doc, r);
    if let Some(cur) = opt_str(t, "display_currency", doc, r) {
        if !grammar::is_currency_code(cur) {
            r.error(
                doc,
                format!("`display_currency` = {cur:?} is not a valid currency code (§3.4)"),
            );
        }
    }
}

fn validate_account(
    doc: &str,
    stem: &str,
    v: &Value,
    accounts: &mut BTreeMap<String, AccountInfo>,
    r: &mut Report,
) {
    let Some(t) = table(v) else {
        r.error(doc, "document root must be a table");
        return;
    };
    let mut info = AccountInfo {
        doc: doc.to_string(),
        ..AccountInfo::default()
    };

    let id = req_str(t, "id", doc, "§4.3", r).map(str::to_string);
    if let Some(id) = &id {
        if !grammar::is_slug(id) {
            r.error(
                doc,
                format!("`id` = {id:?} violates the slug grammar (§3.2)"),
            );
        }
        if id != stem {
            r.error(
                doc,
                format!("filename stem {stem:?} ≠ id {id:?} — they must be equal (§3.2)"),
            );
        }
    }
    req_str(t, "name", doc, "§4.3", r);
    let type_ = req_str(t, "type", doc, "§4.3", r).map(str::to_string);
    if let Some(type_) = &type_ {
        if !ACCOUNT_TYPES.contains(&type_.as_str()) {
            r.error(
                doc,
                format!(
                    "`type` = {type_:?} is not one of {} (§4.3)",
                    ACCOUNT_TYPES.join(" | ")
                ),
            );
        }
        info.is_liability = type_ == "liability";
    }
    if let Some(cur) = req_str(t, "currency", doc, "§4.3", r) {
        if !grammar::is_currency_code(cur) {
            r.error(
                doc,
                format!("`currency` = {cur:?} is not a valid currency code (§3.4)"),
            );
        }
    }
    check_place(t, "tax_jurisdiction", doc, r);
    enum_warn(t, "tax_wrapper", TAX_WRAPPERS, doc, r);
    check_date(t, "opened", doc, r);
    info.closed = check_date(t, "closed", doc, r);
    if let Some(s) = opt_str(t, "secured_by", doc, r) {
        info.secured_by = Some(s.to_string());
    }

    if let Some(holdings) = t.get("holding") {
        let Some(holdings) = holdings.as_array() else {
            r.error(
                doc,
                "`holding` must be an array of tables ([[holding]] — §4.3)",
            );
            return;
        };
        if info.is_liability && !holdings.is_empty() {
            r.warning(doc, "[[holding]] is not used on liability accounts (§4.3)");
        }
        for (i, h) in holdings.iter().enumerate() {
            let ctx = format!("holding #{}", i + 1);
            let Some(h) = h.as_table() else {
                r.error(doc, format!("{ctx}: must be a table"));
                continue;
            };
            if req_str(h, "asset", doc, "§4.3", r).is_none() {
                r.error(doc, format!("{ctx}: `asset` is required (§4.3)"));
            }
            if let Some(kind) = req_str(h, "kind", doc, "§4.3", r) {
                if !HOLDING_KINDS.contains(&kind) {
                    r.error(
                        doc,
                        format!(
                            "{ctx}: `kind` = {kind:?} is not one of {} (§4.3)",
                            HOLDING_KINDS.join(" | ")
                        ),
                    );
                }
            }
            check_decimal(h, "quantity", doc, true, r);
            check_money(h, "cost_basis", doc, false, r);
            check_date(h, "acquired", doc, r);
            if let Some(source) = h.get("source").and_then(Value::as_table) {
                if source.get("descriptor").is_some() {
                    info.has_descriptor = true;
                }
            }
        }
    }

    if let Some(id) = id {
        match accounts.entry(id) {
            std::collections::btree_map::Entry::Occupied(e) => {
                r.error(doc, format!("duplicate account id {:?} (§3.2)", e.key()));
            }
            std::collections::btree_map::Entry::Vacant(e) => {
                e.insert(info);
            }
        }
    }
}

fn validate_snapshot(
    doc: &str,
    stem: &str,
    v: &Value,
    accounts: &BTreeMap<String, AccountInfo>,
    r: &mut Report,
) {
    let Some(t) = table(v) else {
        r.error(doc, "document root must be a table");
        return;
    };
    let filename_date = grammar::parse_date_stem(stem);
    if filename_date.is_none() {
        r.error(
            doc,
            format!("snapshot filename stem {stem:?} is not YYYY-MM-DD (§4.4)"),
        );
    }
    match t.get("date") {
        None => r.error(doc, "missing required field `date` (§4.4)"),
        Some(Value::Datetime(dt)) => match (date_of(dt), filename_date) {
            (Some(d), Some(f)) if d != f => r.error(
                doc,
                "`date` ≠ filename — both must be the snapshot date (§4.4)",
            ),
            (None, _) => r.error(doc, "`date` must be a calendar date (§3.3)"),
            _ => {}
        },
        Some(_) => r.error(doc, "`date` must be a TOML date (unquoted — §3.3)"),
    }

    let snap_date = filename_date;
    match t.get("balance") {
        None => r.error(doc, "at least one [[balance]] is required (§4.4)"),
        Some(Value::Array(balances)) => {
            if balances.is_empty() {
                r.error(doc, "at least one [[balance]] is required (§4.4)");
            }
            for (i, b) in balances.iter().enumerate() {
                let ctx = format!("balance #{}", i + 1);
                let Some(b) = b.as_table() else {
                    r.error(doc, format!("{ctx}: must be a table"));
                    continue;
                };
                match b.get("account") {
                    None => r.error(doc, format!("{ctx}: `account` is required (§4.4)")),
                    Some(Value::String(account)) => match accounts.get(account) {
                        None => r.error(
                            doc,
                            format!("{ctx}: references nonexistent account id {account:?} (§8)"),
                        ),
                        Some(info) => {
                            if let (Some(closed), Some(date)) = (info.closed, snap_date) {
                                if date > closed {
                                    r.warning(
                                        doc,
                                        format!(
                                            "{ctx}: dated after account {account:?} was \
                                             closed ({}-{:02}-{:02}) (§4.4)",
                                            closed.0, closed.1, closed.2
                                        ),
                                    );
                                }
                            }
                        }
                    },
                    Some(_) => r.error(doc, format!("{ctx}: `account` must be a string")),
                }
                match b.get("value") {
                    None => r.error(doc, format!("{ctx}: `value` is required (§4.4)")),
                    Some(v) => check_money_value(v, &format!("{ctx}: value"), doc, r),
                }
            }
        }
        Some(_) => r.error(
            doc,
            "`balance` must be an array of tables ([[balance]] — §4.4)",
        ),
    }
}

fn validate_scenario(doc: &str, stem: &str, v: &Value, targeted: &mut Vec<String>, r: &mut Report) {
    let Some(t) = table(v) else {
        r.error(doc, "document root must be a table");
        return;
    };
    if let Some(id) = req_str(t, "id", doc, "§4.5", r) {
        if !grammar::is_slug(id) {
            r.error(
                doc,
                format!("`id` = {id:?} violates the slug grammar (§3.2)"),
            );
        }
        if id != stem {
            r.error(
                doc,
                format!("filename stem {stem:?} ≠ id {id:?} — they must be equal (§3.2)"),
            );
        }
        if t.get("targeted") == Some(&Value::Boolean(true)) {
            targeted.push(id.to_string());
        }
    }
    req_str(t, "name", doc, "§4.5", r);
    check_date(t, "created", doc, r);

    if let Some(timeline) = t.get("timeline").and_then(Value::as_table) {
        check_date(timeline, "start", doc, r);
    }

    // residency blocks: months_per_year XOR from/to (§4.5)
    if let Some(residency) = t.get("residency") {
        let Some(blocks) = residency.as_array() else {
            r.error(
                doc,
                "`residency` must be an array of tables ([[residency]] — §4.5)",
            );
            return;
        };
        let mut recurring_months = 0.0f64;
        let mut any_recurring = false;
        for (i, block) in blocks.iter().enumerate() {
            let ctx = format!("residency #{}", i + 1);
            let Some(block) = block.as_table() else {
                r.error(doc, format!("{ctx}: must be a table"));
                continue;
            };
            match block.get("place") {
                None => r.error(doc, format!("{ctx}: `place` is required (§4.5)")),
                Some(Value::String(place)) => {
                    if !grammar::is_place(place) {
                        r.error(
                            doc,
                            format!(
                                "{ctx}: `place` = {place:?} is not a valid place string (§3.6)"
                            ),
                        );
                    }
                }
                Some(_) => r.error(doc, format!("{ctx}: `place` must be a string")),
            }
            let months = block.get("months_per_year");
            let has_range = block.contains_key("from") || block.contains_key("to");
            match (months, has_range) {
                (Some(_), true) => r.error(
                    doc,
                    format!(
                        "{ctx}: has both `months_per_year` and `from`/`to` — \
                         a block uses one form or the other, never both (§4.5)"
                    ),
                ),
                (None, false) => r.error(
                    doc,
                    format!("{ctx}: needs either `months_per_year` or `from`/`to` (§4.5)"),
                ),
                (Some(m), false) => {
                    any_recurring = true;
                    match m {
                        Value::Integer(n) => recurring_months += *n as f64,
                        Value::Float(f) => recurring_months += *f,
                        _ => r.error(doc, format!("{ctx}: `months_per_year` must be a number")),
                    }
                }
                (None, true) => {
                    for key in ["from", "to"] {
                        if !block.contains_key(key) {
                            r.error(
                                doc,
                                format!("{ctx}: `{key}` is required in the one-off form (§4.5)"),
                            );
                        } else {
                            check_date(block, key, doc, r);
                        }
                    }
                }
            }
        }
        if any_recurring {
            if recurring_months > 12.0 + 1e-9 {
                r.error(
                    doc,
                    format!(
                        "recurring residency blocks sum to {recurring_months} months/year — \
                         more than 12 is an error (§4.5)"
                    ),
                );
            } else if (recurring_months - 12.0).abs() > 1e-9 {
                r.warning(
                    doc,
                    format!(
                        "recurring residency blocks sum to {recurring_months} months/year, \
                         not 12 — fine if the partial design is deliberate (§4.5)"
                    ),
                );
            }
        }
    }

    if let Some(expenses) = t.get("expenses").and_then(Value::as_table) {
        enum_warn(expenses, "lifestyle", LIFESTYLES, doc, r);
        check_money(expenses, "extra_monthly", doc, false, r);
    }

    if let Some(incomes) = t.get("income").and_then(Value::as_array) {
        for (i, income) in incomes.iter().enumerate() {
            let ctx = format!("income #{}", i + 1);
            let Some(income) = income.as_table() else {
                r.error(doc, format!("{ctx}: must be a table"));
                continue;
            };
            check_money(income, "amount", doc, false, r);
            enum_warn(income, "kind", INCOME_KINDS, doc, r);
            enum_warn(income, "frequency", FREQUENCIES, doc, r);
            check_decimal(income, "growth", doc, false, r);
            check_date(income, "from", doc, r);
            check_date(income, "to", doc, r);
        }
    }

    if let Some(portfolio) = t.get("portfolio").and_then(Value::as_table) {
        if let Some(allocations) = portfolio.get("allocation").and_then(Value::as_array) {
            let mut weight_sum = 0.0f64;
            let mut weights_ok = !allocations.is_empty();
            for (i, alloc) in allocations.iter().enumerate() {
                let ctx = format!("allocation #{}", i + 1);
                let Some(alloc) = alloc.as_table() else {
                    r.error(doc, format!("{ctx}: must be a table"));
                    weights_ok = false;
                    continue;
                };
                check_decimal(alloc, "weight", doc, false, r);
                check_decimal(alloc, "expected_return", doc, false, r);
                check_decimal(alloc, "volatility", doc, false, r);
                match alloc.get("weight").and_then(Value::as_str) {
                    Some(w) if grammar::is_decimal(w) => {
                        weight_sum += w.parse::<f64>().unwrap_or(0.0)
                    }
                    _ => weights_ok = false,
                }
            }
            if weights_ok && (weight_sum - 1.0).abs() > 0.01 {
                r.warning(
                    doc,
                    format!("allocation weights sum to {weight_sum}, not ~1 (§4.5)"),
                );
            }
        }
    }

    if let Some(withdrawal) = t.get("withdrawal").and_then(Value::as_table) {
        check_decimal(withdrawal, "rate", doc, false, r);
        check_money(withdrawal, "floor", doc, false, r);
        check_money(withdrawal, "ceiling", doc, false, r);
    }
}

fn validate_override_file(
    doc: &str,
    v: &Value,
    keys: &mut BTreeMap<String, Vec<String>>,
    r: &mut Report,
) {
    let Some(t) = table(v) else {
        r.error(doc, "document root must be a table");
        return;
    };
    let Some(overrides) = t.get("override") else {
        return;
    };
    let Some(overrides) = overrides.as_array() else {
        r.error(
            doc,
            "`override` must be an array of tables ([[override]] — §4.6)",
        );
        return;
    };
    for (i, o) in overrides.iter().enumerate() {
        let ctx = format!("override #{}", i + 1);
        let Some(o) = o.as_table() else {
            r.error(doc, format!("{ctx}: must be a table"));
            continue;
        };
        match o.get("key") {
            None => r.error(doc, format!("{ctx}: `key` is required (§4.6)")),
            Some(Value::String(key)) => {
                if !grammar::is_world_data_key(key) {
                    r.error(
                        doc,
                        format!("{ctx}: `key` = {key:?} is not a valid world-data key (§3.6)"),
                    );
                } else {
                    keys.entry(key.clone()).or_default().push(doc.to_string());
                }
            }
            Some(_) => r.error(doc, format!("{ctx}: `key` must be a string")),
        }
        check_decimal(o, "value", doc, true, r);
        if let Some(cur) = opt_str(o, "currency", doc, r) {
            if !grammar::is_currency_code(cur) {
                r.error(
                    doc,
                    format!("{ctx}: `currency` = {cur:?} is not a valid currency code (§3.4)"),
                );
            }
        }
        check_date(o, "as_of", doc, r);
    }
}
