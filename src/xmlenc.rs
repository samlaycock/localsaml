//! XML Encryption for `EncryptedAssertion`: the assertion is encrypted with a random AES key, and
//! the key with the service provider's RSA certificate (RSA-OAEP with SHA-1 MGF1, the transport
//! every SAML library supports).

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::NoPadding};
use aes_gcm::aead::{Aead, KeyInit};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};

use crate::dsig::NS_DS;
use crate::util::{b64_std, b64_std_decode_lenient};
use crate::xml::Element;

pub const NS_XENC: &str = "http://www.w3.org/2001/04/xmlenc#";
const RSA_OAEP: &str = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
const RSA_1_5: &str = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
const SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
const TYPE_ELEMENT: &str = "http://www.w3.org/2001/04/xmlenc#Element";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum EncAlg {
    #[serde(rename = "aes128-cbc")]
    Aes128Cbc,
    #[serde(rename = "aes256-cbc")]
    Aes256Cbc,
    #[serde(rename = "aes128-gcm")]
    Aes128Gcm,
    #[default]
    #[serde(rename = "aes256-gcm")]
    Aes256Gcm,
}

impl EncAlg {
    pub fn uri(self) -> &'static str {
        match self {
            EncAlg::Aes128Cbc => "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
            EncAlg::Aes256Cbc => "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
            EncAlg::Aes128Gcm => "http://www.w3.org/2009/xmlenc11#aes128-gcm",
            EncAlg::Aes256Gcm => "http://www.w3.org/2009/xmlenc11#aes256-gcm",
        }
    }

    fn from_uri(uri: &str) -> Option<Self> {
        [EncAlg::Aes128Cbc, EncAlg::Aes256Cbc, EncAlg::Aes128Gcm, EncAlg::Aes256Gcm]
            .into_iter()
            .find(|a| a.uri() == uri)
    }

    fn key_len(self) -> usize {
        match self {
            EncAlg::Aes128Cbc | EncAlg::Aes128Gcm => 16,
            EncAlg::Aes256Cbc | EncAlg::Aes256Gcm => 32,
        }
    }

    fn encrypt(self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        match self {
            EncAlg::Aes128Gcm | EncAlg::Aes256Gcm => {
                // The 96-bit IV comes first and the tag last (XML Encryption 1.1 §5.2.4).
                let iv: [u8; 12] = rand::random();
                let sealed = match self {
                    EncAlg::Aes128Gcm => aes_gcm::Aes128Gcm::new_from_slice(key)
                        .map_err(|e| e.to_string())?
                        .encrypt(&iv.into(), plaintext),
                    _ => aes_gcm::Aes256Gcm::new_from_slice(key)
                        .map_err(|e| e.to_string())?
                        .encrypt(&iv.into(), plaintext),
                }
                .map_err(|e| e.to_string())?;
                Ok([iv.as_slice(), &sealed].concat())
            }
            EncAlg::Aes128Cbc | EncAlg::Aes256Cbc => {
                // XML Encryption padding: random bytes, then the pad length (§5.2).
                let iv: [u8; 16] = rand::random();
                let pad = 16 - plaintext.len() % 16;
                let mut buf = plaintext.to_vec();
                buf.extend((1..pad).map(|_| rand::random::<u8>()));
                buf.push(pad as u8);
                let len = buf.len();
                let out = match self {
                    EncAlg::Aes128Cbc => cbc::Encryptor::<aes::Aes128>::new_from_slices(key, &iv)
                        .map_err(|e| e.to_string())?
                        .encrypt_padded_mut::<NoPadding>(&mut buf, len)
                        .map_err(|e| e.to_string())?
                        .to_vec(),
                    _ => cbc::Encryptor::<aes::Aes256>::new_from_slices(key, &iv)
                        .map_err(|e| e.to_string())?
                        .encrypt_padded_mut::<NoPadding>(&mut buf, len)
                        .map_err(|e| e.to_string())?
                        .to_vec(),
                };
                Ok([iv.as_slice(), &out].concat())
            }
        }
    }

    fn decrypt(self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
        match self {
            EncAlg::Aes128Gcm | EncAlg::Aes256Gcm => {
                if data.len() < 28 {
                    return Err("ciphertext too short".into());
                }
                let (iv, sealed) = data.split_at(12);
                let iv = aes_gcm::Nonce::from_slice(iv);
                match self {
                    EncAlg::Aes128Gcm => {
                        aes_gcm::Aes128Gcm::new_from_slice(key).map_err(|e| e.to_string())?.decrypt(iv, sealed)
                    }
                    _ => aes_gcm::Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?.decrypt(iv, sealed),
                }
                .map_err(|_| "AES-GCM decryption failed (wrong key or tampered ciphertext)".to_string())
            }
            EncAlg::Aes128Cbc | EncAlg::Aes256Cbc => {
                if data.len() < 32 || !data.len().is_multiple_of(16) {
                    return Err("ciphertext has the wrong length".into());
                }
                let (iv, ct) = data.split_at(16);
                let mut buf = ct.to_vec();
                let plain = match self {
                    EncAlg::Aes128Cbc => cbc::Decryptor::<aes::Aes128>::new_from_slices(key, iv)
                        .map_err(|e| e.to_string())?
                        .decrypt_padded_mut::<NoPadding>(&mut buf)
                        .map_err(|e| e.to_string())?
                        .to_vec(),
                    _ => cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv)
                        .map_err(|e| e.to_string())?
                        .decrypt_padded_mut::<NoPadding>(&mut buf)
                        .map_err(|e| e.to_string())?
                        .to_vec(),
                };
                let pad = *plain.last().ok_or("empty plaintext")? as usize;
                if pad == 0 || pad > 16 || pad > plain.len() {
                    return Err("invalid padding (wrong key?)".into());
                }
                Ok(plain[..plain.len() - pad].to_vec())
            }
        }
    }
}

/// Encrypt a serialized element (it must declare every namespace it uses) for `recipient`,
/// returning an `xenc:EncryptedData` element to put inside e.g. `saml:EncryptedAssertion`.
pub fn encrypt(xml: &str, recipient: &RsaPublicKey, alg: EncAlg) -> Result<Element, String> {
    let key: Vec<u8> = (0..alg.key_len()).map(|_| rand::random::<u8>()).collect();
    let ciphertext = alg.encrypt(&key, xml.as_bytes())?;
    let wrapped = recipient
        .encrypt(&mut rand::thread_rng(), Oaep::new::<sha1::Sha1>(), &key)
        .map_err(|e| format!("encrypting the key: {e}"))?;
    let x = |local: &str| Element::new(NS_XENC, "xenc", local);
    let cipher = |bytes: &[u8]| x("CipherData").child(x("CipherValue").text(b64_std(bytes)));
    let mut data = x("EncryptedData")
        .attr("Type", TYPE_ELEMENT)
        .child(x("EncryptionMethod").attr("Algorithm", alg.uri()))
        .child(
            Element::new(NS_DS, "ds", "KeyInfo").child(
                x("EncryptedKey")
                    .child(
                        x("EncryptionMethod")
                            .attr("Algorithm", RSA_OAEP)
                            .child(Element::new(NS_DS, "ds", "DigestMethod").attr("Algorithm", SHA1)),
                    )
                    .child(cipher(&wrapped)),
            ),
        )
        .child(cipher(&ciphertext));
    data.declare_namespaces();
    Ok(data)
}

/// Decrypt an `xenc:EncryptedData` element (directly or inside its parent, e.g.
/// `EncryptedAssertion`) with any of `keys`. The key may be inline or a sibling `EncryptedKey`.
pub fn decrypt(container: &Element, keys: &[RsaPrivateKey]) -> Result<String, String> {
    let data = if container.is(NS_XENC, "EncryptedData") {
        container
    } else {
        container.find(NS_XENC, "EncryptedData").ok_or("no EncryptedData")?
    };
    let alg_uri = data.find(NS_XENC, "EncryptionMethod").and_then(|e| e.get_attr("Algorithm")).unwrap_or("");
    let alg = EncAlg::from_uri(alg_uri).ok_or_else(|| format!("unsupported encryption algorithm {alg_uri}"))?;
    let encrypted_key = data
        .find(NS_DS, "KeyInfo")
        .and_then(|k| k.find(NS_XENC, "EncryptedKey"))
        .or_else(|| container.find(NS_XENC, "EncryptedKey"))
        .ok_or("no EncryptedKey")?;
    let transport = encrypted_key.find(NS_XENC, "EncryptionMethod").and_then(|e| e.get_attr("Algorithm")).unwrap_or("");
    let wrapped = cipher_value(encrypted_key)?;
    let key = keys
        .iter()
        .find_map(|k| match transport {
            RSA_OAEP => k.decrypt(Oaep::new::<sha1::Sha1>(), &wrapped).ok(),
            RSA_1_5 => k.decrypt(rsa::Pkcs1v15Encrypt, &wrapped).ok(),
            _ => None,
        })
        .ok_or_else(|| format!("couldn't decrypt the key ({transport}) with any of our keys"))?;
    let plain = alg.decrypt(&key, &cipher_value(data)?)?;
    String::from_utf8(plain).map_err(|_| "the decrypted content is not UTF-8".into())
}

fn cipher_value(el: &Element) -> Result<Vec<u8>, String> {
    el.path(&[(NS_XENC, "CipherData"), (NS_XENC, "CipherValue")])
        .and_then(|e| b64_std_decode_lenient(&e.text_content()))
        .ok_or_else(|| "missing CipherValue".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_algorithm() {
        let key = crate::keys::untrusted();
        let xml = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a">hi</saml:Assertion>"#;
        for alg in [EncAlg::Aes128Cbc, EncAlg::Aes256Cbc, EncAlg::Aes128Gcm, EncAlg::Aes256Gcm] {
            let data = encrypt(xml, &key.public, alg).unwrap();
            let parsed = crate::xml::parse(&data.to_xml()).unwrap();
            assert_eq!(decrypt(&parsed, std::slice::from_ref(&key.private)).unwrap(), xml, "{alg:?}");
        }
        let other = crate::keys::KeyPair::generate().unwrap();
        let data = encrypt(xml, &key.public, EncAlg::Aes256Gcm).unwrap();
        assert!(decrypt(&data, &[other.private]).is_err());
    }
}
