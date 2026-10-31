//! The signing keyring: one current RSA key with a self-signed X.509 certificate, plus recently
//! retired keys whose certificates stay in the metadata so service providers that refresh it keep
//! trusting responses during a rotation. Persisted under the data dir as `signing-key.pem` and
//! `signing-cert.pem`, and `retired-keys/<timestamp>-<kid>.{key,cert}.pem`.

use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{OnceLock, RwLock};
use std::time::{Duration, SystemTime};

use anyhow::Context;
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, LineEnding};
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use x509_cert::Certificate;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::{Decode, DecodePem, Encode, EncodePem};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::{Time, Validity};

use crate::util::{b64_std, b64_std_decode_lenient, wall_clock};

/// How many retired keys stay in the metadata (and keep verifying) after a rotation.
pub const RETIRED_KEYS_KEPT: usize = 2;
const KEY_FILE: &str = "signing-key.pem";
const CERT_FILE: &str = "signing-cert.pem";
const RETIRED_DIR: &str = "retired-keys";
/// Certificates are valid from a day before they're made (so a clock behind real time still sees
/// them as valid) for ten years.
const CERT_BACKDATE: u64 = 86_400;
const CERT_LIFETIME: u64 = 10 * 365 * 86_400;

/// XML signature algorithms (`SignatureMethod`) and their digests (`DigestMethod`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum SigAlg {
    #[serde(rename = "rsa-sha1")]
    RsaSha1,
    #[default]
    #[serde(rename = "rsa-sha256")]
    RsaSha256,
    #[serde(rename = "rsa-sha512")]
    RsaSha512,
}

impl SigAlg {
    pub fn uri(self) -> &'static str {
        match self {
            SigAlg::RsaSha1 => "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
            SigAlg::RsaSha256 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            SigAlg::RsaSha512 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
        }
    }

    pub fn digest_uri(self) -> &'static str {
        match self {
            SigAlg::RsaSha1 => "http://www.w3.org/2000/09/xmldsig#sha1",
            SigAlg::RsaSha256 => "http://www.w3.org/2001/04/xmlenc#sha256",
            SigAlg::RsaSha512 => "http://www.w3.org/2001/04/xmlenc#sha512",
        }
    }

    pub fn from_uri(uri: &str) -> Option<Self> {
        [SigAlg::RsaSha1, SigAlg::RsaSha256, SigAlg::RsaSha512].into_iter().find(|a| a.uri() == uri)
    }

    pub fn name(self) -> &'static str {
        match self {
            SigAlg::RsaSha1 => "rsa-sha1",
            SigAlg::RsaSha256 => "rsa-sha256",
            SigAlg::RsaSha512 => "rsa-sha512",
        }
    }

    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        digest_with(self.digest_uri(), data).unwrap_or_default()
    }

    fn sign(self, key: &RsaPrivateKey, data: &[u8]) -> Vec<u8> {
        match self {
            SigAlg::RsaSha1 => SigningKey::<Sha1>::new(key.clone()).sign(data).to_vec(),
            SigAlg::RsaSha256 => SigningKey::<Sha256>::new(key.clone()).sign(data).to_vec(),
            SigAlg::RsaSha512 => SigningKey::<Sha512>::new(key.clone()).sign(data).to_vec(),
        }
    }

    pub fn verify(self, key: &RsaPublicKey, data: &[u8], signature: &[u8]) -> bool {
        let Ok(sig) = Signature::try_from(signature) else { return false };
        match self {
            SigAlg::RsaSha1 => VerifyingKey::<Sha1>::new(key.clone()).verify(data, &sig).is_ok(),
            SigAlg::RsaSha256 => VerifyingKey::<Sha256>::new(key.clone()).verify(data, &sig).is_ok(),
            SigAlg::RsaSha512 => VerifyingKey::<Sha512>::new(key.clone()).verify(data, &sig).is_ok(),
        }
    }
}

/// Hash `data` with the algorithm named by a `DigestMethod` URI.
pub fn digest_with(uri: &str, data: &[u8]) -> Option<Vec<u8>> {
    Some(match uri {
        "http://www.w3.org/2000/09/xmldsig#sha1" => Sha1::digest(data).to_vec(),
        "http://www.w3.org/2001/04/xmlenc#sha256" => Sha256::digest(data).to_vec(),
        "http://www.w3.org/2001/04/xmlenc#sha512" => Sha512::digest(data).to_vec(),
        _ => return None,
    })
}

/// An RSA key pair and its self-signed certificate.
pub struct KeyPair {
    pub private: RsaPrivateKey,
    pub public: RsaPublicKey,
    /// DER-encoded X.509 certificate.
    pub cert: Vec<u8>,
    /// Short id: the start of the certificate's SHA-256 fingerprint.
    pub kid: String,
}

impl KeyPair {
    fn new(private: RsaPrivateKey, cert: Option<Vec<u8>>) -> anyhow::Result<Self> {
        let public = private.to_public_key();
        let cert = match cert {
            Some(c) => c,
            None => self_signed_cert(&private)?,
        };
        let kid = hex(&Sha256::digest(&cert))[..16].to_string();
        Ok(Self { private, public, cert, kid })
    }

    pub fn generate() -> anyhow::Result<Self> {
        Self::new(RsaPrivateKey::new(&mut rand::thread_rng(), 2048).context("generating RSA key")?, None)
    }

    fn read(key_path: &Path, cert_path: &Path) -> anyhow::Result<Self> {
        let pem = fs::read_to_string(key_path).with_context(|| format!("reading {}", key_path.display()))?;
        let key = RsaPrivateKey::from_pkcs8_pem(&pem).with_context(|| format!("parsing {}", key_path.display()))?;
        let cert = match fs::read_to_string(cert_path) {
            Ok(pem) => Some(
                Certificate::from_pem(pem.as_bytes())
                    .with_context(|| format!("parsing {}", cert_path.display()))?
                    .to_der()?,
            ),
            Err(_) => None,
        };
        let had_cert = cert.is_some();
        let pair = Self::new(key, cert)?;
        if !had_cert {
            write_private(cert_path, &pair.cert_pem())?;
        }
        Ok(pair)
    }

    fn write(&self, key_path: &Path, cert_path: &Path) -> anyhow::Result<()> {
        write_private(key_path, &self.private.to_pkcs8_pem(LineEnding::LF)?)?;
        write_private(cert_path, &self.cert_pem())
    }

    pub fn cert_b64(&self) -> String {
        b64_std(&self.cert)
    }

    pub fn cert_pem(&self) -> String {
        Certificate::from_der(&self.cert)
            .and_then(|c| c.to_pem(x509_cert::der::pem::LineEnding::LF))
            .unwrap_or_default()
    }

    pub fn sign(&self, alg: SigAlg, data: &[u8]) -> Vec<u8> {
        alg.sign(&self.private, data)
    }

    pub fn info(&self) -> CertInfo {
        CertInfo::from_der(&self.cert)
    }
}

fn write_private(path: &Path, contents: &str) -> anyhow::Result<()> {
    fs::write(path, contents.as_bytes()).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn self_signed_cert(key: &RsaPrivateKey) -> anyhow::Result<Vec<u8>> {
    let signer = SigningKey::<Sha256>::new(key.clone());
    let spki = SubjectPublicKeyInfoOwned::from_key(key.to_public_key()).context("encoding public key")?;
    let now = SystemTime::now();
    let validity = Validity {
        not_before: Time::try_from(now - Duration::from_secs(CERT_BACKDATE))?,
        not_after: Time::try_from(now + Duration::from_secs(CERT_LIFETIME))?,
    };
    let mut serial = rand::random::<[u8; 16]>();
    serial[0] &= 0x7f; // positive
    let builder = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::new(&serial)?,
        validity,
        Name::from_str("CN=localsaml,O=localsaml (development only)")?,
        spki,
        &signer,
    )?;
    Ok(builder.build::<Signature>()?.to_der()?)
}

/// What the UI and API show about a certificate.
#[derive(Debug, Clone, Serialize)]
pub struct CertInfo {
    pub kid: String,
    pub subject: String,
    pub not_before: String,
    pub not_after: String,
    /// Colon-separated upper-case hex, as most SP settings pages expect.
    pub sha1_fingerprint: String,
    pub sha256_fingerprint: String,
    pub pem: String,
}

impl CertInfo {
    pub fn from_der(der: &[u8]) -> Self {
        let cert = Certificate::from_der(der).ok();
        let tbs = cert.as_ref().map(|c| &c.tbs_certificate);
        let colons = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":");
        Self {
            kid: hex(&Sha256::digest(der))[..16].to_string(),
            subject: tbs.map(|t| t.subject.to_string()).unwrap_or_default(),
            not_before: tbs.map(|t| t.validity.not_before.to_string()).unwrap_or_default(),
            not_after: tbs.map(|t| t.validity.not_after.to_string()).unwrap_or_default(),
            sha1_fingerprint: colons(&Sha1::digest(der)),
            sha256_fingerprint: colons(&Sha256::digest(der)),
            pem: cert.and_then(|c| c.to_pem(x509_cert::der::pem::LineEnding::LF).ok()).unwrap_or_default(),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse a certificate given as PEM, or as bare base64 DER (as in metadata `X509Certificate`).
pub fn parse_cert(text: &str) -> Result<Vec<u8>, String> {
    let text = text.trim();
    let der = if text.contains("-----BEGIN") {
        Certificate::from_pem(text.as_bytes()).map_err(|e| format!("invalid PEM certificate: {e}"))?.to_der()
    } else {
        let der = b64_std_decode_lenient(text).ok_or("certificate is neither PEM nor base64")?;
        Certificate::from_der(&der).map_err(|e| format!("invalid certificate: {e}"))?.to_der()
    };
    der.map_err(|e| format!("invalid certificate: {e}"))
}

/// The RSA public key in a DER certificate.
pub fn cert_public_key(der: &[u8]) -> Result<RsaPublicKey, String> {
    let cert = Certificate::from_der(der).map_err(|e| format!("invalid certificate: {e}"))?;
    let spki = cert.tbs_certificate.subject_public_key_info.to_der().map_err(|e| e.to_string())?;
    RsaPublicKey::from_public_key_der(&spki).map_err(|_| "the certificate's key is not an RSA key".to_string())
}

struct Ring {
    current: KeyPair,
    /// Newest first.
    retired: Vec<KeyPair>,
}

pub struct Keys {
    ring: RwLock<Ring>,
    dir: Option<PathBuf>,
}

/// Outcome of a key rotation.
pub struct Rotation {
    pub kid: String,
    pub retired_kids: Vec<String>,
}

impl Keys {
    /// An in-memory keyring with a fresh key (rotations are not persisted).
    pub fn generate() -> anyhow::Result<Self> {
        Ok(Self { ring: RwLock::new(Ring { current: KeyPair::generate()?, retired: vec![] }), dir: None })
    }

    /// Load the keyring from `dir`, creating (and persisting) a key if there is none.
    pub fn load_or_create(dir: &Path) -> anyhow::Result<Self> {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let (key_path, cert_path) = (dir.join(KEY_FILE), dir.join(CERT_FILE));
        let current = if key_path.exists() {
            KeyPair::read(&key_path, &cert_path)?
        } else {
            tracing::info!("generating new signing key at {}", key_path.display());
            let key = KeyPair::generate()?;
            key.write(&key_path, &cert_path)?;
            key
        };
        let mut files: Vec<PathBuf> = fs::read_dir(dir.join(RETIRED_DIR))
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok().map(|e| e.path()))
                    .filter(|p| p.to_string_lossy().ends_with(".key.pem"))
                    .collect()
            })
            .unwrap_or_default();
        // File names start with the retirement timestamp, so reverse order is newest first.
        files.sort();
        files.reverse();
        let retired = files
            .iter()
            .take(RETIRED_KEYS_KEPT)
            .map(|p| {
                let cert = PathBuf::from(p.to_string_lossy().replace(".key.pem", ".cert.pem"));
                KeyPair::read(p, &cert)
            })
            .collect::<anyhow::Result<_>>()?;
        Ok(Self { ring: RwLock::new(Ring { current, retired }), dir: Some(dir.to_path_buf()) })
    }

    pub fn kid(&self) -> String {
        self.ring.read().unwrap().current.kid.clone()
    }

    /// Generate a new current key; the old one is retired but stays in the metadata.
    pub fn rotate(&self) -> anyhow::Result<Rotation> {
        let next = KeyPair::generate()?;
        let mut ring = self.ring.write().unwrap();
        if let Some(dir) = &self.dir {
            let retired_dir = dir.join(RETIRED_DIR);
            fs::create_dir_all(&retired_dir).with_context(|| format!("creating {}", retired_dir.display()))?;
            let stem = format!("{:012}-{}", wall_clock(), ring.current.kid);
            ring.current
                .write(&retired_dir.join(format!("{stem}.key.pem")), &retired_dir.join(format!("{stem}.cert.pem")))?;
            // Write-then-rename so a crash never leaves a half-written current key.
            let (tmp_key, tmp_cert) = (dir.join(format!("{KEY_FILE}.tmp")), dir.join(format!("{CERT_FILE}.tmp")));
            next.write(&tmp_key, &tmp_cert)?;
            fs::rename(&tmp_cert, dir.join(CERT_FILE)).context("replacing signing certificate")?;
            fs::rename(&tmp_key, dir.join(KEY_FILE)).context("replacing signing key")?;
        }
        let old = std::mem::replace(&mut ring.current, next);
        ring.retired.insert(0, old);
        let keep = RETIRED_KEYS_KEPT.min(ring.retired.len());
        for dropped in ring.retired.drain(keep..) {
            if let Some(dir) = &self.dir
                && let Ok(entries) = fs::read_dir(dir.join(RETIRED_DIR))
            {
                let needle = format!("-{}.", dropped.kid);
                for e in entries.flatten().filter(|e| e.file_name().to_string_lossy().contains(&needle)) {
                    let _ = fs::remove_file(e.path());
                }
            }
        }
        tracing::info!("rotated signing key: {} is now current", ring.current.kid);
        Ok(Rotation {
            kid: ring.current.kid.clone(),
            retired_kids: ring.retired.iter().map(|k| k.kid.clone()).collect(),
        })
    }

    /// Run `f` with the current key pair.
    pub fn with_current<R>(&self, f: impl FnOnce(&KeyPair) -> R) -> R {
        f(&self.ring.read().unwrap().current)
    }

    pub fn current_info(&self) -> CertInfo {
        self.with_current(KeyPair::info)
    }

    /// Certificates (base64 DER) to publish: the current one first, then retired ones.
    pub fn certs_b64(&self) -> Vec<String> {
        let ring = self.ring.read().unwrap();
        std::iter::once(&ring.current).chain(&ring.retired).map(KeyPair::cert_b64).collect()
    }

    pub fn infos(&self) -> Vec<CertInfo> {
        let ring = self.ring.read().unwrap();
        std::iter::once(&ring.current).chain(&ring.retired).map(KeyPair::info).collect()
    }

    /// Public keys of the current and retired certificates.
    pub fn public_keys(&self) -> Vec<RsaPublicKey> {
        let ring = self.ring.read().unwrap();
        std::iter::once(&ring.current).chain(&ring.retired).map(|k| k.public.clone()).collect()
    }

    /// Private keys of the current and retired certificates (the built-in test SP decrypts with them).
    pub fn private_keys(&self) -> Vec<RsaPrivateKey> {
        let ring = self.ring.read().unwrap();
        std::iter::once(&ring.current).chain(&ring.retired).map(|k| k.private.clone()).collect()
    }
}

/// A key pair that isn't in any metadata, for faults that sign with an untrusted certificate.
/// Generated on first use.
pub fn untrusted() -> &'static KeyPair {
    static KEY: OnceLock<KeyPair> = OnceLock::new();
    KEY.get_or_init(|| KeyPair::generate().expect("generating the untrusted key"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificates_round_trip() {
        let key = KeyPair::generate().unwrap();
        let info = key.info();
        assert!(info.subject.contains("CN=localsaml"), "{}", info.subject);
        assert_eq!(info.sha1_fingerprint.len(), 59);
        assert_eq!(parse_cert(&key.cert_pem()).unwrap(), key.cert);
        assert_eq!(parse_cert(&key.cert_b64()).unwrap(), key.cert);
        assert_eq!(cert_public_key(&key.cert).unwrap(), key.public);
        for alg in [SigAlg::RsaSha1, SigAlg::RsaSha256, SigAlg::RsaSha512] {
            let sig = key.sign(alg, b"data");
            assert!(alg.verify(&key.public, b"data", &sig));
            assert!(!alg.verify(&key.public, b"date", &sig));
        }
    }
}
