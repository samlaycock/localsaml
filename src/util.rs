use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use rand::Rng;
use rand::distributions::Alphanumeric;
use serde_json::Value;

pub fn b64(data: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).ok()
}

pub fn b64_std_decode(s: &str) -> Option<Vec<u8>> {
    STANDARD.decode(s.trim()).ok()
}

/// Real time in Unix seconds. Anything that should follow the simulated clock (token
/// timestamps, expiry checks) uses `AppState::now()` instead.
pub fn wall_clock() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or_default()
}

const UNITS: [(char, i64); 5] = [('w', 604_800), ('d', 86_400), ('h', 3_600), ('m', 60), ('s', 1)];

/// Parse a duration in seconds: `90`, `90s`, `15m`, `2h`, `31d`, `1w` or combinations such as
/// `1d12h`. A leading `-` makes it negative.
pub fn parse_duration(raw: &str) -> Result<i64, String> {
    let raw = raw.trim();
    let (sign, body) = match raw.strip_prefix('-') {
        Some(rest) => (-1, rest),
        None => (1, raw.strip_prefix('+').unwrap_or(raw)),
    };
    let invalid = || format!("invalid duration '{raw}' (use seconds, or e.g. 15m, 2h, 31d, 1d12h)");
    if !body.starts_with(|c: char| c.is_ascii_digit()) {
        return Err(invalid());
    }
    if let Ok(secs) = body.parse::<i64>() {
        return Ok(sign * secs);
    }
    let (mut total, mut digits) = (0i64, String::new());
    for c in body.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
            continue;
        }
        let unit = UNITS.iter().find(|(u, _)| *u == c).ok_or_else(invalid)?.1;
        let n: i64 = digits.parse().map_err(|_| invalid())?;
        total = n.checked_mul(unit).and_then(|v| total.checked_add(v)).ok_or_else(invalid)?;
        digits.clear();
    }
    if !digits.is_empty() || body.is_empty() {
        return Err(invalid());
    }
    Ok(sign * total)
}

/// Format seconds the way `parse_duration` reads them, e.g. `+1d2h`, `-15m`, `0s`.
pub fn format_duration(secs: i64) -> String {
    if secs == 0 {
        return "0s".into();
    }
    let mut rest = secs.unsigned_abs() as i64;
    let mut out = String::from(if secs < 0 { "-" } else { "+" });
    // Days are the largest unit shown: "+31d" reads better than "+4w3d".
    for (unit, size) in UNITS.into_iter().skip(1) {
        if rest >= size {
            out.push_str(&format!("{}{unit}", rest / size));
            rest %= size;
        }
    }
    out
}

pub fn random_string(len: usize) -> String {
    rand::thread_rng().sample_iter(&Alphanumeric).take(len).map(char::from).collect()
}

pub fn b64_std(data: impl AsRef<[u8]>) -> String {
    STANDARD.encode(data)
}

/// Lenient standard base64: whitespace (line-wrapped messages) and missing padding are fine.
pub fn b64_std_decode_lenient(s: &str) -> Option<Vec<u8>> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    STANDARD.decode(&cleaned).ok().or_else(|| STANDARD_NO_PAD.decode(cleaned.trim_end_matches('=')).ok())
}

/// A SAML `ID`: an xsd:ID must not start with a digit, so these always start with `prefix`.
pub fn saml_id(prefix: &str) -> String {
    let hex: String = (0..20).map(|_| format!("{:02x}", rand::random::<u8>())).collect();
    format!("{prefix}{hex}")
}

/// Unix seconds as an xsd:dateTime in UTC, e.g. `2026-10-31T13:00:00Z`.
pub fn iso8601(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Howard Hinnant's civil-from-days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// Parse an xsd:dateTime (`2026-10-31T13:00:00Z`, optional fraction and offset) to Unix seconds.
pub fn parse_iso8601(s: &str) -> Option<i64> {
    let s = s.trim();
    let (date, time) = s.split_once('T')?;
    let mut d = date.split('-');
    let (y, m, day): (i64, i64, i64) = (d.next()?.parse().ok()?, d.next()?.parse().ok()?, d.next()?.parse().ok()?);
    let (clock, offset) = if let Some(c) = time.strip_suffix('Z') {
        (c, 0)
    } else if let Some(i) = time.rfind(['+', '-']) {
        let (c, off) = time.split_at(i);
        let sign = if off.starts_with('-') { -1 } else { 1 };
        let (oh, om) = off[1..].split_once(':')?;
        (c, sign * (oh.parse::<i64>().ok()? * 3600 + om.parse::<i64>().ok()? * 60))
    } else {
        (time, 0)
    };
    let mut t = clock.split(':');
    let (h, min): (i64, i64) = (t.next()?.parse().ok()?, t.next()?.parse().ok()?);
    let sec: f64 = t.next()?.parse().ok()?;
    let (y, m) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3600 + min * 60 + sec as i64 - offset)
}

pub fn parse_form(bytes: &[u8]) -> HashMap<String, String> {
    url::form_urlencoded::parse(bytes).into_owned().collect()
}

/// Merge query string and (form-encoded) body parameters; body wins.
pub fn merged_params(query: Option<&str>, body: &[u8]) -> HashMap<String, String> {
    let mut params = parse_form(query.unwrap_or_default().as_bytes());
    params.extend(parse_form(body));
    params
}

pub fn non_empty(params: &HashMap<String, String>, key: &str) -> Option<String> {
    params.get(key).filter(|v| !v.is_empty()).cloned()
}

/// Render a JSON value as a plain string (strings unquoted).
pub fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Parse a user supplied JSON object (attributes). Accepts raw JSON or base64url-encoded JSON.
pub fn parse_json_object(raw: &str) -> Result<serde_json::Map<String, Value>, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(Default::default());
    }
    let parsed: Value = serde_json::from_str(raw).or_else(|e| {
        b64_decode(raw)
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .ok_or_else(|| format!("invalid JSON: {e}"))
    })?;
    match parsed {
        Value::Object(map) => Ok(map),
        _ => Err("must be a JSON object".into()),
    }
}

/// Merge `overrides` into `base`; a `null` override removes the entry.
pub fn merge_map(base: &mut serde_json::Map<String, Value>, overrides: &serde_json::Map<String, Value>) {
    for (k, v) in overrides {
        if v.is_null() {
            base.remove(k);
        } else {
            base.insert(k.clone(), v.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("90"), Ok(90));
        assert_eq!(parse_duration("-90"), Ok(-90));
        assert_eq!(parse_duration("15m"), Ok(900));
        assert_eq!(parse_duration("+1d12h"), Ok(129_600));
        assert_eq!(parse_duration("-31d"), Ok(-2_678_400));
        assert_eq!(parse_duration("1w"), Ok(604_800));
        for bad in ["", "d", "5x", "1d5", "--1", "1.5h"] {
            assert!(parse_duration(bad).is_err(), "{bad}");
        }
        assert_eq!(format_duration(0), "0s");
        assert_eq!(format_duration(129_600), "+1d12h");
        assert_eq!(format_duration(-61), "-1m1s");
        assert_eq!(format_duration(31 * 86_400), "+31d");
        assert_eq!(parse_duration(&format_duration(-2_678_400)), Ok(-2_678_400));
    }

    #[test]
    fn timestamps() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601(1_793_451_600), "2026-10-31T13:00:00Z");
        assert_eq!(iso8601(951_782_400), "2000-02-29T00:00:00Z");
        for t in [0, 951_782_400, 1_793_451_600, 4_102_444_799] {
            assert_eq!(parse_iso8601(&iso8601(t)), Some(t));
        }
        assert_eq!(parse_iso8601("2026-10-31T13:00:00.123Z"), Some(1_793_451_600));
        assert_eq!(parse_iso8601("2026-10-31T14:00:00+01:00"), Some(1_793_451_600));
        assert_eq!(parse_iso8601("nope"), None);
        assert!(saml_id("_").starts_with('_') && saml_id("_").len() == 41);
    }
}
