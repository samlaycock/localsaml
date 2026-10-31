//! Users declared in `localsaml.toml`: named identities shared by the login UI, the dev API
//! and automated logins.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::presets::{self, Identity, Preset};
use crate::util::merge_map;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    /// Handle used by `dev_user` and the dev API's `user`.
    pub id: String,
    /// Shown in the login UI's picker (defaults to the user's email or NameID).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Template whose attribute names are used; otherwise the issuer's default template.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preset: Option<String>,
    /// The NameID. Default: derived like the template's (e.g. from the email attribute), or a
    /// stable value unique to the user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name_id_format: Option<String>,
    /// Attributes, merged over the template defaults. Values are strings or lists of strings.
    #[serde(default)]
    pub attributes: Map<String, Value>,
    /// Merge `attributes` over the template defaults (default true).
    #[serde(default = "yes")]
    pub defaults: bool,
}

fn yes() -> bool {
    true
}

impl User {
    /// The template (an explicit one, then the user's own, then `fallback`) and identity to sign
    /// this user in with.
    pub fn resolve(&self, explicit: Option<&'static Preset>, fallback: &'static Preset) -> (&'static Preset, Identity) {
        let preset = explicit.or_else(|| self.preset.as_deref().and_then(presets::get)).unwrap_or(fallback);
        let mut attributes = if self.defaults { preset.default_attributes() } else { Map::new() };
        // Identifiers like object IDs are shared by everyone in the template, so give each user
        // their own stable one, shaped like the provider's.
        for attr in preset.attributes.iter().filter(|a| a.unique) {
            if !self.attributes.contains_key(attr.name) && attributes.contains_key(attr.name) {
                attributes.insert(attr.name.into(), stable_like(&attr.default, &self.id));
            }
        }
        merge_map(&mut attributes, &self.attributes);
        let mut identity = Identity {
            preset: preset.id.into(),
            name_id: String::new(),
            name_id_format: self.name_id_format.clone().unwrap_or_else(|| preset.name_id_format.into()),
            attributes,
        };
        identity.name_id = match &self.name_id {
            Some(n) => n.clone(),
            None => preset.derive_name_id(&identity).unwrap_or_else(|| {
                crate::util::value_to_string(&stable_like(&json!(preset.name_id_example), &self.id))
            }),
        };
        (preset, identity)
    }

    /// Does a login hint refer to this user (its id, NameID or an email attribute)?
    pub fn matches(&self, login: &str) -> bool {
        self.id == login
            || self.name_id.as_deref() == Some(login)
            || self.attributes.values().any(|v| match v {
                Value::String(s) => s.contains('@') && s.eq_ignore_ascii_case(login),
                _ => false,
            })
    }

    /// The user as shown to the login UI and `/dev/api/users`.
    pub fn to_json(&self, fallback: &'static Preset) -> Value {
        let (preset, identity) = self.resolve(None, fallback);
        json!({ "id": self.id, "label": self.label, "preset": preset.id, "identity": identity })
    }
}

pub fn validate(users: &[User]) -> anyhow::Result<()> {
    let mut seen = std::collections::HashSet::new();
    for user in users {
        if user.id.trim().is_empty() {
            anyhow::bail!("every [[users]] entry needs an id");
        }
        if !seen.insert(user.id.as_str()) {
            anyhow::bail!("duplicate user id '{}'", user.id);
        }
        if let Some(p) = &user.preset
            && presets::get(p).is_none()
        {
            anyhow::bail!("user '{}': unknown preset '{p}'", user.id);
        }
        for (name, value) in &user.attributes {
            let ok = match value {
                Value::String(_) | Value::Null => true,
                Value::Array(items) => items.iter().all(Value::is_string),
                _ => false,
            };
            if !ok {
                anyhow::bail!("user '{}': attribute '{name}' must be a string or a list of strings", user.id);
            }
        }
    }
    Ok(())
}

/// A value shaped like `template` but derived from `seed`, so it is stable across restarts and
/// distinct per seed. Numbers keep their digit count. Strings are split on `-._|:`; digit runs
/// stay digits, hex runs stay hex, long opaque runs keep each character's class, and short words
/// (`user`, `auth0`) are kept as they are.
fn stable_like(template: &Value, seed: &str) -> Value {
    let mut stream = (0u32..).flat_map(|i| Sha256::digest(format!("{seed}:{i}")));
    let mut next = move |n: u8| stream.next().unwrap_or_default() % n;
    match template {
        Value::Number(n) => {
            let len = n.to_string().len().clamp(1, 18);
            let digits: String =
                (0..len).map(|i| (b'0' + if i == 0 { 1 + next(9) } else { next(10) }) as char).collect();
            json!(digits.parse::<i64>().unwrap_or_default())
        }
        Value::String(s) => {
            let mut out = String::with_capacity(s.len());
            for segment in s.split_inclusive(['-', '.', '_', '|', ':']) {
                let (word, sep) = match segment.char_indices().last() {
                    Some((i, c)) if "-._|:".contains(c) => segment.split_at(i),
                    _ => (segment, ""),
                };
                let reshape = word.chars().all(|c| c.is_ascii_hexdigit()) || word.len() >= 16;
                for c in word.chars() {
                    out.push(match c {
                        _ if !reshape => c,
                        '0'..='9' => (b'0' + next(10)) as char,
                        _ if word.chars().all(|c| c.is_ascii_hexdigit()) => {
                            let h = b"0123456789abcdef"[next(16) as usize] as char;
                            if c.is_ascii_uppercase() { h.to_ascii_uppercase() } else { h }
                        }
                        'a'..='z' => (b'a' + next(26)) as char,
                        'A'..='Z' => (b'A' + next(26)) as char,
                        _ => c,
                    });
                }
                out.push_str(sep);
            }
            json!(out)
        }
        _ => json!(format!("user-{seed}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_like_keeps_the_shape() {
        let google = stable_like(&json!("109876543210987654321"), "alice");
        assert_eq!(google, stable_like(&json!("109876543210987654321"), "alice"));
        assert_ne!(google, stable_like(&json!("109876543210987654321"), "bob"));
        assert!(google.as_str().unwrap().chars().all(|c| c.is_ascii_digit()) && google.as_str().unwrap().len() == 21);

        let generic = stable_like(&json!("user-1234"), "alice");
        assert!(generic.as_str().unwrap().starts_with("user-"));
        assert_ne!(generic, json!("user-1234"));

        let auth0 = stable_like(&json!("auth0|64f1c0ffee0000000000abcd"), "alice");
        assert!(auth0.as_str().unwrap().starts_with("auth0|"));
        assert_eq!(auth0.as_str().unwrap().len(), 30);

        let uuid = stable_like(&json!("f3b4c2a1-1234-4cde-9abc-0123456789ab"), "alice").as_str().unwrap().to_string();
        assert_eq!(uuid.len(), 36);
        assert!(uuid.chars().all(|c| c == '-' || c.is_ascii_hexdigit()));

        let id = stable_like(&json!(1234567), "alice");
        assert_eq!(id.as_i64().unwrap().to_string().len(), 7);
    }

    #[test]
    fn users_get_their_own_identifiers() {
        let user = |id: &str| User {
            id: id.into(),
            label: None,
            preset: Some("entra".into()),
            name_id: None,
            name_id_format: None,
            attributes: serde_json::from_value(
                json!({ "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name": format!("{id}@example.com") }),
            )
            .unwrap(),
            defaults: true,
        };
        let (_, alice) = user("alice").resolve(None, presets::generic());
        let (_, bob) = user("bob").resolve(None, presets::generic());
        let oid = "http://schemas.microsoft.com/identity/claims/objectidentifier";
        assert_ne!(alice.values(oid), bob.values(oid));
        assert_eq!(alice.name_id, "alice@example.com");
        assert!(user("alice").matches("alice@example.com") && user("alice").matches("alice"));
    }
}
