//! An implementation of the [Stateless OpenPGP Interface] using [Sequoia PGP].
//!
//! SOP is a very high-level, opinionated, and abstract interface for
//! OpenPGP implementations.  To use it, create an instance using
//! [`SQOP::default`] or [`SQOP::with_policy`], then use the trait
//! [`SOP`].
//!
//! # Examples
//!
//! This example generates a key.
//!
//! ```rust
//! # fn main() -> sop::Result<()> {
//! use sequoia_sop::{*, sop::*};
//!
//! let sop = SQOP::default();
//!
//! let alice_sec = sop.generate_key()?
//!     .userid("Alice Lovelace <alice@openpgp.example>")
//!     .generate()?
//!     .to_vec(true)?;
//! assert!(alice_sec.starts_with(b"-----BEGIN PGP PRIVATE KEY BLOCK-----"));
//! # Ok(()) }
//! ```
//!
//!   [Stateless OpenPGP Interface]: https://gitlab.com/dkg/openpgp-stateless-cli
//!   [Sequoia PGP]: https://sequoia-pgp.org

use std::{
    collections::HashMap,
    io::{self, Cursor, Write},
    time::SystemTime,
};

use sequoia_openpgp as openpgp;
use openpgp::{
    armor,
    cert::prelude::*,
    parse::{
        Parse,
        PacketParser,
        PacketParserResult,
        buffered_reader::*,
        stream::*,
    },
    packet::prelude::*,
    policy::{
        NullPolicy,
        StandardPolicy,
    },
    serialize::{
        Serialize,
        stream::*,
    },
    types::*,
};

use openpgp::{
    Cert,
    Fingerprint,
    KeyID,
};
use openpgp::crypto::{self, SessionKey};
use openpgp::packet::{key, Key, PKESK, SKESK};
use openpgp::policy::Policy;

// Public re-export for the convenience of end users.
pub use sop::{self, SOP};

use sop::{
    *,
    errors::*,
    ops::{
        ArmorLabel,
        EncryptAs,
        InlineSignAs,
        SignAs,
        SignatureMode,
        Verification,
    },
    plumbing::PasswordsAreHumanReadable,
};

/// A collection of certs.
pub struct Certs<'s> {
    sop: &'s SQOP<'s>,
    certs: Vec<openpgp::Cert>,
}

impl<'s> sop::plumbing::SopRef<'s, SQOP<'s>> for Certs<'s> {
    fn sop(&self) -> &'s SQOP<'s> {
        self.sop
    }
}

impl<'s> sop::Load<'s, SQOP<'s>> for Certs<'s> {
    fn from_reader(sop: &'s SQOP, source: &mut (dyn io::Read + Send + Sync))
                   -> Result<Self>
    where
        Self: Sized,
    {
        Ok(Certs {
            sop,
            certs: CertParser::from_reader(source).map_err(sop_error)?
                .collect::<openpgp::Result<Vec<openpgp::Cert>>>()
                .map_err(sop_error)?,
        })
    }
}

impl sop::Save for Certs<'_> {
    fn to_writer(&self, armored: bool, sink: &mut (dyn io::Write + Send + Sync))
                 -> Result<()>
    {
        if self.certs.len() == 1 {
            let cert = &self.certs[0];
            if armored {
                cert.armored().serialize(sink).map_err(sop_error)?;
            } else {
                cert.serialize(sink).map_err(sop_error)?;
            }
        } else {
            if armored {
                let mut armorer =
                    armor::Writer::new(sink, armor::Kind::PublicKey)?;
                for cert in &self.certs {
                    cert.serialize(&mut armorer).map_err(sop_error)?;
                }
                armorer.finalize()?;
            } else {
                for cert in &self.certs {
                    cert.serialize(sink).map_err(sop_error)?;
                }
            }
        }
        Ok(())
    }
}

/// A collection of keys.
pub struct Keys<'s> {
    sop: &'s SQOP<'s>,
    keys: Vec<openpgp::Cert>,
}

impl<'s> sop::plumbing::SopRef<'s, SQOP<'s>> for Keys<'s> {
    fn sop(&self) -> &'s SQOP<'s> {
        self.sop
    }
}

impl<'s> sop::Load<'s, SQOP<'s>> for Keys<'s> {
    fn from_reader(sop: &'s SQOP, source: &mut (dyn io::Read + Send + Sync))
                   -> Result<Self>
    where
        Self: Sized,
    {
        Ok(Keys {
            sop,
            keys: CertParser::from_reader(source).map_err(sop_error)?
                .collect::<openpgp::Result<Vec<openpgp::Cert>>>()
                .map_err(sop_error)?,
        })
    }
}

impl sop::Save for Keys<'_> {
    fn to_writer(&self, armored: bool, sink: &mut (dyn io::Write + Send + Sync))
                 -> Result<()>
    {
        if self.keys.len() == 1 {
            let key = &self.keys[0];
            if armored {
                key.as_tsk().armored().serialize(sink).map_err(sop_error)?;
            } else {
                key.as_tsk().serialize(sink).map_err(sop_error)?;
            }
        } else {
            if armored {
                let mut armorer =
                    armor::Writer::new(sink, armor::Kind::SecretKey)?;
                for key in &self.keys {
                    key.as_tsk().serialize(&mut armorer).map_err(sop_error)?;
                }
                armorer.finalize()?;
            } else {
                for key in &self.keys {
                    key.as_tsk().serialize(sink).map_err(sop_error)?;
                }
            }
        }
        Ok(())
    }
}

/// A collection of signatures.
pub struct Sigs<'s> {
    sop: &'s SQOP<'s>,
    data: Vec<u8>,
}

impl<'s> sop::plumbing::SopRef<'s, SQOP<'s>> for Sigs<'s> {
    fn sop(&self) -> &'s SQOP<'s> {
        self.sop
    }
}

impl<'s> sop::Load<'s, SQOP<'s>> for Sigs<'s> {
    fn from_reader(sop: &'s SQOP, source: &mut (dyn io::Read + Send + Sync))
                   -> Result<Self>
    where
        Self: Sized,
    {
        let mut data = vec![];
        source.read_to_end(&mut data)?;
        Ok(Sigs {
            sop,
            data,
        })
    }
}

impl sop::Save for Sigs<'_> {
    fn to_writer(&self, armored: bool, sink: &mut (dyn io::Write + Send + Sync))
                 -> Result<()>
    {
        // Happy path: Want armored and it already is.
        if armored && self.data.starts_with(
            b"-----BEGIN PGP PUBLIC KEY BLOCK-----")
        {
            sink.write_all(&self.data)?;
            return Ok(());
        }

        if armored {
            self.sop.armor()?
                .data(&mut Cursor::new(&self.data))?
                .to_writer(sink)?;
        } else {
            self.sop.dearmor()?
                .data(&mut Cursor::new(&self.data))?
                .to_writer(sink)?;
        }
        Ok(())
    }
}

/// [`SOP`] implementation based on [Sequoia PGP].
///
///   [Sequoia PGP]: https://sequoia-pgp.org
pub struct SQOP<'s> {
    policy: &'s dyn openpgp::policy::Policy,
}

impl Default for SQOP<'_> {
    fn default() -> Self {
        const P: &StandardPolicy = &StandardPolicy::new();
        Self::with_policy(P)
    }
}

impl<'s> SQOP<'s> {
    /// Creates a [`sop::SOP`] implementation with an explicit
    /// [`sequoia_openpgp::policy::Policy`].
    ///
    /// To use the default
    /// [`sequoia_openpgp::policy::StandardPolicy`], use
    /// [`SQOP::default`].
    pub fn with_policy(policy: &'s dyn Policy) -> Self {
        SQOP {
            policy,
        }
    }
}

impl<'s> sop::SOP<'s> for SQOP<'s> {
    type Keys = Keys<'s>;
    type Certs = Certs<'s>;
    type Sigs = Sigs<'s>;

    fn version(&'s self) -> Result<Box<dyn sop::ops::Version + 's>> {
        Ok(Box::new(Version {}))
    }
    fn sopv_version(&'s self) -> Result<&'static str> {
        Ok("1.0")
    }
    fn generate_key(&'s self)
        -> Result<Box<dyn sop::ops::GenerateKey<SQOP, Keys> + 's>>
    {
        GenerateKey::new(self)
    }
    fn change_key_password(&'s self)
        -> Result<Box<dyn sop::ops::ChangeKeyPassword<SQOP, Keys> + 's>>
    {
        ChangeKeyPassword::new(self)
    }
    fn revoke_key(&'s self)
        -> Result<Box<dyn sop::ops::RevokeKey<SQOP<'s>, Certs, Keys> + 's>>
    {
        RevokeKey::new(self)
    }
    fn extract_cert(&'s self)
        -> Result<Box<dyn sop::ops::ExtractCert<SQOP, Certs, Keys> + 's>>
    {
        ExtractCert::new(self)
    }
    fn sign(&'s self)
        -> Result<Box<dyn sop::ops::Sign<SQOP, Keys, Sigs> + 's>>
    {
        Sign::new(self)
    }
    fn verify(&'s self)
        -> Result<Box<dyn sop::ops::Verify<SQOP, Certs, Sigs> + 's>>
    {
        Verify::new(self)
    }
    fn encrypt(&'s self)
        -> Result<Box<dyn sop::ops::Encrypt<SQOP, Certs, Keys> + 's>> {
        Encrypt::new(self)
    }
    fn decrypt(&'s self)
        -> Result<Box<dyn sop::ops::Decrypt<SQOP, Certs, Keys> + 's>> {
        Decrypt::new(self)
    }
    fn armor(&'s self) -> Result<Box<dyn sop::ops::Armor + 's>> {
        Armor::new(self)
    }
    fn dearmor(&'s self) -> Result<Box<dyn sop::ops::Dearmor + 's>> {
        Dearmor::new(self)
    }
    fn inline_detach(&'s self)
        -> Result<Box<dyn sop::ops::InlineDetach<Sigs> + 's>>
    {
        InlineDetach::new(self)
    }
    fn inline_verify(&'s self)
        -> Result<Box<dyn sop::ops::InlineVerify<SQOP, Certs> + 's>>
    {
        InlineVerify::new(self)
    }
    fn inline_sign(&'s self)
        -> Result<Box<dyn sop::ops::InlineSign<SQOP, Keys> + 's>>
    {
        InlineSign::new(self)
    }
}

struct Version {}

impl sop::ops::Version<'_> for Version {
    fn frontend(&self) -> Result<sop::ops::VersionInfo> {
        Ok(sop::ops::VersionInfo {
            name: "sqop".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        })
    }

    fn backend(&self) -> Result<sop::ops::VersionInfo> {
        Ok(sop::ops::VersionInfo {
            name: "Sequoia".into(),
            version: openpgp::VERSION.into(),
        })
    }

    fn extended(&self) -> Result<String> {
        Ok(vec![
            openpgp::crypto::backend(),
            format!("Sequoia {}", openpgp::VERSION),
        ].join("\n"))
    }
}

struct GenerateKey<'s> {
    #[allow(dead_code)]
    sqop: &'s SQOP<'s>,
    profile: &'static str,
    signing_only: bool,
    with_key_password: Option<Password>,
    userids: Vec<String>,
}

impl<'s> GenerateKey<'s> {
    const PROFILE_EDDSA: &'static str = "draft-koch-eddsa-for-openpgp-00";
    const PROFILE_RFC4880: &'static str = "rfc4880";
    const PROFILES: &'static [(&'static str, &'static str)] = &[
        (Self::PROFILE_EDDSA, "use EdDSA & ECDH over Cv25519"),
        (Self::PROFILE_RFC4880, "use RSA with 3072 bit keys"),
    ];

    fn new(sqop: &'s SQOP) -> Result<Box<dyn sop::ops::GenerateKey<'s, SQOP<'s>, Keys<'s>> + 's>> {
        Ok(Box::new(GenerateKey {
            sqop,
            profile: Self::PROFILE_EDDSA,
            signing_only: false,
            with_key_password: Default::default(),
            userids: Default::default(),
        }))
    }
}

impl<'s> sop::ops::GenerateKey<'s, SQOP<'s>, Keys<'s>> for GenerateKey<'s> {
    fn list_profiles(&self) -> Vec<(String, String)> {
        Self::PROFILES.iter()
            .map(|(p, d)| (p.to_string(), d.to_string()))
            .collect()
    }

    fn profile(mut self: Box<Self>, profile: &str)
               -> Result<Box<dyn sop::ops::GenerateKey<'s, SQOP<'s>, Keys<'s>> + 's>> {
        self.profile = match profile {
            Self::PROFILE_EDDSA | "default" => Self::PROFILE_EDDSA,
            Self::PROFILE_RFC4880 => Self::PROFILE_RFC4880,
            _ => return Err(Error::UnsupportedProfile),
        };
        Ok(self)
    }

    fn signing_only(mut self: Box<Self>) -> Box<dyn sop::ops::GenerateKey<'s, SQOP<'s>, Keys<'s>> + 's> {
        self.signing_only = true;
        self
    }

    fn with_key_password(mut self: Box<Self>, password: Password)
                         -> Result<Box<dyn sop::ops::GenerateKey<'s, SQOP<'s>, Keys<'s>> + 's>> {
        self.with_key_password = Some(password);
        Ok(self)
    }

    fn userid(mut self: Box<Self>, userid: &str)
              -> Box<dyn sop::ops::GenerateKey<'s, SQOP<'s>, Keys<'s>> + 's> {
        self.userids.push(userid.into());
        self
    }

    fn generate(self: Box<Self>) -> Result<Keys<'s>> {
        let mut builder = CertBuilder::new();
        builder = builder.add_signing_subkey();
        if ! self.signing_only {
            builder = builder.add_subkey(
                KeyFlags::empty()
                    .set_storage_encryption()
                    .set_transport_encryption(),
                None,
                None);
        }

        builder = builder.set_cipher_suite(match self.profile {
            Self::PROFILE_EDDSA => CipherSuite::Cv25519,
            Self::PROFILE_RFC4880 => CipherSuite::RSA3k,
            _ => return Err(Error::UnsupportedProfile),
        });

        for u in self.userids {
            builder = builder.add_userid(u);
        }
        if let Some(p) = self.with_key_password {
            builder = builder.set_password(Some(p.normalized().into()));
        }
        let (key, _) = builder.generate().map_err(sop_error)?;

        Ok(Keys {
            sop: self.sqop,
            keys: vec![key],
        })
    }
}

struct ChangeKeyPassword<'s> {
    #[allow(dead_code)]
    sqop: &'s SQOP<'s>,
    new_password: Option<openpgp::crypto::Password>,
    old_password: Vec<openpgp::crypto::Password>,
}

impl<'s> ChangeKeyPassword<'s> {
    fn new(sqop: &'s SQOP) -> Result<Box<dyn sop::ops::ChangeKeyPassword<'s, SQOP<'s>, Keys<'s>> + 's>> {
        Ok(Box::new(ChangeKeyPassword {
            sqop,
            new_password: None,
            old_password: vec![],
        }))
    }
}

impl<'s> sop::ops::ChangeKeyPassword<'s, SQOP<'s>, Keys<'s>> for ChangeKeyPassword<'s> {
    fn new_key_password(mut self: Box<Self>, password: Password)
                        -> Result<Box<dyn sop::ops::ChangeKeyPassword<'s, SQOP<'s>, Keys<'s>> + 's>> {
        self.new_password = Some(password.normalized().into());
        Ok(self)
    }

    fn old_key_password(mut self: Box<Self>, password: Password)
                        -> Result<Box<dyn sop::ops::ChangeKeyPassword<'s, SQOP<'s>, Keys<'s>> + 's>> {
        for p in password.variants() {
            self.old_password.push(p.into());
        }
        Ok(self)
    }

    fn keys(self: Box<Self>, keys: &Keys) -> Result<Keys<'s>> {
        let mut result = vec![];

        for key in keys.keys.clone() {
            let fp = key.fingerprint();

            // Extract the key packets, starting with the unencrypted
            // ones.
            let mut key_packets =
                key.keys().unencrypted_secret()
                .map(|ka| ka.key().clone())
                .collect::<Vec<_>>();

            // Then the encrypted ones, decrypting them on the way.
            for locked_key in key.keys().secret()
                .filter(|ka| ka.secret().is_encrypted())
                .map(|ka| ka.key())
            {
                let mut unlocked = false;

                for p in &self.old_password {
                    if let Ok(k) = locked_key.clone().decrypt_secret(p) {
                        key_packets.push(k);
                        unlocked = true;
                        break;
                    }
                }

                if ! unlocked {
                    return Err(Error::KeyIsProtected);
                }
            }

            // Maybe encrypt them.
            if let Some(p) = &self.new_password {
                for k in std::mem::take(&mut key_packets) {
                    key_packets.push(k.encrypt_secret(&p).map_err(sop_error)?);
                }
            }

            // And update the key packets in the cert.
            let (key, _changed) =
                key.insert_packets2(
                    key_packets.into_iter().map(|k| -> openpgp::Packet {
                        if k.fingerprint() == fp {
                            k.role_into_primary().into()
                        } else {
                            k.role_into_subordinate().into()
                        }
                    }))
                .map_err(sop_error)?;

            result.push(key);
        }

        Ok(Keys {
            sop: self.sqop,
            keys: result,
        })
    }
}

struct RevokeKey<'s> {
    #[allow(dead_code)]
    sqop: &'s SQOP<'s>,
    key_password: Vec<openpgp::crypto::Password>,
}

impl<'s> RevokeKey<'s> {
    fn new(sqop: &'s SQOP) -> Result<Box<dyn sop::ops::RevokeKey<'s, SQOP<'s>, Certs<'s>, Keys<'s>> + 's>> {
        Ok(Box::new(RevokeKey {
            sqop,
            key_password: vec![],
        }))
    }
}

impl<'s> sop::ops::RevokeKey<'s, SQOP<'s>, Certs<'s>, Keys<'s>> for RevokeKey<'s> {
    fn with_key_password(mut self: Box<Self>, password: Password)
                         -> Result<Box<dyn sop::ops::RevokeKey<'s, SQOP<'s>, Certs<'s>, Keys<'s>> + 's>> {
        for p in password.variants() {
            self.key_password.push(p.into());
        }
        Ok(self)
    }

    fn keys(self: Box<Self>, keys: &Keys) -> Result<Certs<'s>> {
        let mut results = vec![];
        for key in &keys.keys {
            // Get the primary singer.
            let mut primary = match key.primary_key().key().parts_as_secret() {
                Ok(p) => p.clone(),
                Err(_) => return Err(Error::BadData),
            };

            // Maybe unlock the secret.
            if primary.secret().is_encrypted() {
                let mut unlocked = false;

                for p in &self.key_password {
                    if let Ok(k) = primary.clone().decrypt_secret(p) {
                        primary = k;
                        unlocked = true;
                        break;
                    }
                }

                if ! unlocked {
                    return Err(Error::KeyIsProtected);
                }
            }
            let mut signer = primary.into_keypair().map_err(sop_error)?;

            // And revoke the cert.
            let revocation = key.revoke(&mut signer,
                                        ReasonForRevocation::Unspecified,
                                        b"unspecified").map_err(sop_error)?;
            results.push(key.clone().insert_packets2(
                std::iter::once(openpgp::Packet::from(revocation)))
                         .map(|(cert, _changed)| cert)
                         .map_err(sop_error)?
                         .strip_secret_key_material());
        }

        Ok(Certs {
            sop: self.sqop,
            certs: results,
        })
    }
}

struct ExtractCert<'s> {
    #[allow(dead_code)]
    sqop: &'s SQOP<'s>,
}

impl<'s> ExtractCert<'s> {
    fn new(sqop: &'s SQOP) -> Result<Box<dyn sop::ops::ExtractCert<'s, SQOP<'s>, Certs<'s>, Keys<'s>> + 's>> {
        Ok(Box::new(ExtractCert {
            sqop,
        }))
    }
}

impl<'s> sop::ops::ExtractCert<'s, SQOP<'s>, Certs<'s>, Keys<'s>> for ExtractCert<'s> {
    fn keys(self: Box<Self>, keys: &Keys) -> Result<Certs<'s>> {
        Ok(Certs {
            sop: self.sqop,
            certs: keys.keys.iter()
                .map(|c| c.clone().strip_secret_key_material())
                .collect::<Vec<_>>(),
        })
    }
}

struct Sign<'s> {
    sqop: &'s SQOP<'s>,
    mode: SignAs,
    hash_algos: Vec<HashAlgorithm>,
    with_key_password: Vec<Password>,
    signers: Vec<openpgp::Cert>,
}

impl<'s> Sign<'s> {
    fn new(sqop: &'s SQOP) -> Result<Box<dyn sop::ops::Sign<'s, SQOP<'s>, Keys<'s>, Sigs<'s>> + 's>> {
        Ok(Box::new(Self::unboxed(sqop)))
    }

    fn unboxed(sqop: &'s SQOP) -> Sign<'s> {
        Sign {
            sqop,
            mode: Default::default(),
            hash_algos: [
                HashAlgorithm::SHA512,
                HashAlgorithm::SHA384,
                HashAlgorithm::SHA256,
                HashAlgorithm::SHA224,
            ].iter().copied().filter(|h| h.is_supported()).collect(),
            with_key_password: Default::default(),
            signers: Default::default(),
        }
    }
}

impl Sign<'_> {
    fn add_signing_keys(&mut self, keys: &Keys) -> Result<()> {
        for key in &keys.keys {
            self.add_signing_cert(key)?;
        }
        Ok(())
    }

    fn add_signing_cert(&mut self, cert: &Cert) -> Result<()> {
        let vcert =
            cert.with_policy(self.sqop.policy, None)
            .map_err(|_| Error::KeyCannotSign)?;
        if let Some(p) = vcert.preferred_hash_algorithms() {
            self.hash_algos.retain(|a| p.contains(a));
        }

        let mut one = false;
        for _key in vcert.keys()
            .supported()
            .secret()
            .alive()
            .revoked(false)
            .for_signing()
            .map(|ka| ka.key())
        {
            one = true;
            // Exactly one signature per supplied key.
            break;
        }

        self.signers.push(cert.clone());

        if one {
            Ok(())
        } else {
            Err(Error::KeyCannotSign)
        }
    }

    /// Returns the set of signers.
    fn make_signers(&self) -> Result<Vec<openpgp::crypto::KeyPair>> {
        let mut signers = Vec::with_capacity(self.signers.len());
        for cert in &self.signers {
            let vcert =
                cert.with_policy(self.sqop.policy, None)
                .map_err(|_| Error::KeyCannotSign)?;

            let mut one = false;
            for mut key in vcert.keys()
                .supported()
                .secret()
                .alive()
                .revoked(false)
                .for_signing()
                .map(|ka| ka.key().clone())
            {
                let algo = key.pk_algo();
                if key.secret().is_encrypted() {
                    for p in self.with_key_password.iter()
                        .flat_map(|p| p.variants())
                    {
                        if key.secret_mut().decrypt_in_place(algo, &p.into())
                            .is_ok()
                        {
                            break;
                        }
                    }
                }
                if ! key.secret().is_encrypted() {
                    one = true;
                    // Exactly one signature per supplied key.
                    signers.push(key.into_keypair().map_err(sop_error)?);
                    break;
                }
            }

            if ! one {
                return Err(Error::KeyIsProtected);
            }
        }

        Ok(signers)
    }
}

impl<'s> sop::ops::Sign<'s, SQOP<'s>, Keys<'s>, Sigs<'s>> for Sign<'s> {
    fn mode(mut self: Box<Self>, mode: SignAs)
            -> Box<dyn sop::ops::Sign<'s, SQOP<'s>, Keys<'s>, Sigs<'s>> + 's> {
        self.mode = mode;
        self
    }

    fn keys(mut self: Box<Self>, keys: &Keys)
            -> Result<Box<dyn sop::ops::Sign<'s, SQOP<'s>, Keys<'s>, Sigs<'s>> + 's>> {
        self.add_signing_keys(keys)?;
        Ok(self)
    }

    fn with_key_password(mut self: Box<Self>, password: Password)
                         -> Result<Box<dyn sop::ops::Sign<'s, SQOP<'s>, Keys<'s>, Sigs<'s>> + 's>> {
        self.with_key_password.push(password);
        Ok(self)
    }

    fn data(self: Box<Self>, data: &mut (dyn io::Read + Send + Sync))
            -> Result<(sop::ops::Micalg, Sigs<'s>)>
    {
        if self.signers.is_empty() {
            return Err(Error::MissingArg);
        }

        let mut buf = vec![];
        let message = Message::new(&mut buf);
        let mut signers = self.make_signers()?;
        let mut signer = Signer::with_template(
            message,
            signers.pop().expect("at least one"),
            signature::SignatureBuilder::new(into_sig_type(self.mode)))
            .hash_algo(
                self.hash_algos.get(0).cloned().unwrap_or_default()
            ).map_err(sop_error)?
            .detached();
        for s in signers {
            signer = signer.add_signer(s);
        }
        let mut message = signer.build().map_err(sop_error)?;
        io::copy(data, &mut message)?;
        message.finalize().map_err(sop_error)?;

        Ok((u8::from(HashAlgorithm::default()).into(),
            Sigs::from_bytes(self.sqop, &buf)?))
    }
}

struct Verify<'s> {
    sqop: &'s SQOP<'s>,
    verbose: bool,
    not_before: Option<SystemTime>,
    not_after: Option<SystemTime>,
    certs: Vec<Cert>,
}

impl<'s> Verify<'s> {
    fn new(sqop: &'s SQOP) -> Result<Box<dyn sop::ops::Verify<'s, SQOP<'s>, Certs<'s>, Sigs<'s>> + 's>> {
        Ok(Box::new(Self::unboxed(sqop)))
    }

    fn unboxed(sqop: &'s SQOP) -> Verify<'s>
    where
        's: 's,
    {
        Verify {
            sqop,
            verbose: Default::default(),
            not_before: Default::default(),
            not_after: Default::default(),
            certs: Default::default(),
        }
    }
}

impl<'s> sop::ops::Verify<'s, SQOP<'s>, Certs<'s>, Sigs<'s>> for Verify<'s> {
    fn not_before(mut self: Box<Self>, t: SystemTime)
                  -> Box<dyn sop::ops::Verify<'s, SQOP<'s>, Certs<'s>, Sigs<'s>> + 's> {
        self.not_before = Some(t);
        self
    }

    fn not_after(mut self: Box<Self>, t: SystemTime)
                 -> Box<dyn sop::ops::Verify<'s, SQOP<'s>, Certs<'s>, Sigs<'s>> + 's> {
        self.not_after = Some(t);
        self
    }

    fn certs(mut self: Box<Self>, cert: &Certs)
             -> Result<Box<dyn sop::ops::Verify<'s, SQOP<'s>, Certs<'s>, Sigs<'s>> + 's>> {
        for cert in &cert.certs {
            self.certs.push(cert.clone());
        }
        Ok(self)
    }

    fn signatures<'sigs>(self: Box<Self>, signatures: &'sigs Sigs)
                         -> Result<Box<dyn sop::ops::VerifySignatures<'sigs> + 'sigs>>
    where
        's: 'sigs,
    {
        Ok(Box::new(VerifySignatures {
            verify: *self,
            signatures: signatures,
        }))
    }
}

struct VerifySignatures<'s, 'sigs> {
    verify: Verify<'s>,
    signatures: &'sigs Sigs<'s>,
}

impl sop::ops::VerifySignatures<'_> for VerifySignatures<'_, '_> {
    fn data(self: Box<Self>, data: &mut (dyn io::Read + Send + Sync))
            -> Result<Vec<sop::ops::Verification>> {
        if self.verify.certs.is_empty() {
            return Err(Error::MissingArg);
        }

        let helper = VHelper::new(
            if self.verify.verbose {
                Box::new(io::stderr())
            } else {
                Box::new(io::sink())
            },
            1,
            self.verify.not_before,
            self.verify.not_after,
            self.verify.certs);
        let mut v =
            DetachedVerifierBuilder::from_bytes(&self.signatures.data)
            .map_err(sop_error)?
            .with_policy(self.verify.sqop.policy, None, helper)
            .map_err(sop_error)?;
        v.verify_reader(data).map_err(sop_error)?;
        Ok(v.into_helper().verifications)
    }
}

struct Encrypt<'s> {
    no_armor: bool,
    sign: Sign<'s>,
    profile: &'static str,
    mode: EncryptAs,
    symmetric_algos: Vec<SymmetricAlgorithm>,
    recipients: Vec<Key<key::PublicParts, key::UnspecifiedRole>>,
    passwords: Vec<Password>,
}

impl<'s> Encrypt<'s> {
    const PROFILE_RFC4880: &'static str = "rfc4880";
    const PROFILES: &'static [(&'static str, &'static str)] = &[
        (Self::PROFILE_RFC4880, "use SEIPDv1"),
    ];

    fn new(sqop: &'s SQOP) -> Result<Box<dyn sop::ops::Encrypt<'s, SQOP<'s>, Certs<'s>, Keys<'s>> + 's>> {
        Ok(Box::new(Encrypt {
            no_armor: false,
            sign: Sign::unboxed(sqop),
            profile: Self::PROFILE_RFC4880,
            mode: Default::default(),
            symmetric_algos: [
                SymmetricAlgorithm::AES256,
                SymmetricAlgorithm::AES192,
                SymmetricAlgorithm::AES128,
                SymmetricAlgorithm::Camellia256,
                SymmetricAlgorithm::Camellia192,
                SymmetricAlgorithm::Camellia128,
                SymmetricAlgorithm::Blowfish,
                SymmetricAlgorithm::Twofish,
            ].iter().copied().filter(|&a| {
                a.is_supported() && sqop.policy.symmetric_algorithm(a).is_ok()
            }).collect(),
            recipients: Default::default(),
            passwords: Default::default(),
        }))
    }

    fn add_cert(mut self: Box<Self>, cert: &Cert)
                 -> Result<Box<Self>> {
        let vcert = cert.with_policy(self.sign.sqop.policy, None)
            .map_err(|_| Error::CertCannotEncrypt)?;

        // If the recipients has preferences, compute the
        // intersection with our list.
        if let Some(p) = vcert.preferred_hash_algorithms() {
            self.sign.hash_algos.retain(|a| p.contains(a));
        }
        if let Some(p) = vcert.preferred_symmetric_algorithms() {
            self.symmetric_algos.retain(|a| p.contains(a));
        }

        let mut one = false;
        for key in vcert.keys()
            .supported()
            .alive()
            .revoked(false)
            .for_storage_encryption()
            .for_transport_encryption()
            .map(|ka| ka.key())
        {
            self.recipients.push(key.clone());
            one = true;
        }

        if one {
            Ok(self)
        } else {
            Err(Error::CertCannotEncrypt)
        }
    }
}

impl<'s> sop::ops::Encrypt<'s, SQOP<'s>, Certs<'s>, Keys<'s>> for Encrypt<'s> {
    fn no_armor(mut self: Box<Self>) -> Box<dyn sop::ops::Encrypt<'s, SQOP<'s>, Certs<'s>, Keys<'s>> + 's> {
        self.no_armor = true;
        self
    }

    fn list_profiles(&self) -> Vec<(String, String)> {
        Self::PROFILES.iter()
            .map(|(p, d)| (p.to_string(), d.to_string()))
            .collect()
    }

    fn profile(mut self: Box<Self>, profile: &str)
               -> Result<Box<dyn sop::ops::Encrypt<'s, SQOP<'s>, Certs<'s>, Keys<'s>> + 's>> {
        self.profile = match profile {
            Self::PROFILE_RFC4880 | "default" => Self::PROFILE_RFC4880,
            _ => return Err(Error::UnsupportedProfile),
        };
        Ok(self)
    }

    fn mode(mut self: Box<Self>, mode: EncryptAs) -> Box<dyn sop::ops::Encrypt<'s, SQOP<'s>, Certs<'s>, Keys<'s>> + 's> {
        self.sign.mode = mode.into();
        self.mode = mode;
        self
    }

    fn sign_with_keys(mut self: Box<Self>,
                      keys: &Keys)
                      -> Result<Box<dyn sop::ops::Encrypt<'s, SQOP<'s>, Certs<'s>, Keys<'s>> + 's>> {
        self.sign.add_signing_keys(keys)?;
        Ok(self)
    }

    fn with_key_password(mut self: Box<Self>, password: Password)
                         -> Result<Box<dyn sop::ops::Encrypt<'s, SQOP<'s>, Certs<'s>, Keys<'s>> + 's>> {
        self.sign.with_key_password.push(password);
        Ok(self)
    }

    fn with_password(mut self: Box<Self>, password: Password)
                     -> Result<Box<dyn sop::ops::Encrypt<'s, SQOP<'s>, Certs<'s>, Keys<'s>> + 's>> {
        self.passwords.push(password);
        Ok(self)
    }

    fn with_certs(mut self: Box<Self>, certs: &Certs)
                  -> Result<Box<dyn sop::ops::Encrypt<'s, SQOP<'s>, Certs<'s>, Keys<'s>> + 's>> {
        for cert in &certs.certs {
            self = self.add_cert(cert)?;
        }
        Ok(self)
    }

    fn plaintext<'d>(self: Box<Self>,
                     plaintext: &'d mut (dyn io::Read + Send + Sync))
                     -> Result<Box<dyn sop::ops::Ready<Option<sop::SessionKey>> + 'd>>
    where
        's: 'd
    {
        Ok(Box::new(EncryptReady {
            encrypt: *self,
            plaintext,
        }))
    }
}

struct EncryptReady<'s> {
    encrypt: Encrypt<'s>,
    plaintext: &'s mut (dyn io::Read + Send + Sync),
}

impl<'s> sop::ops::Ready<Option<sop::SessionKey>> for EncryptReady<'s> {
    fn to_writer(self: Box<Self>, sink: &mut (dyn io::Write + Send + Sync))
                -> Result<Option<sop::SessionKey>>
    {
        if self.encrypt.recipients.is_empty()
            && self.encrypt.passwords.is_empty()
        {
            return Err(Error::MissingArg);
        }

        let mut message = Message::new(sink);
        if ! self.encrypt.no_armor {
            message = Armorer::new(message).build().map_err(sop_error)?;
        }

        // XXX: Honor self.profile once we have more than one.

        // Encrypt the message.
        let cipher =
            self.encrypt.symmetric_algos.get(0).cloned().unwrap_or_default();
        let session_key =
            SessionKey::new(cipher.key_size().map_err(sop_error)?);
        let sop_session_key = sop::SessionKey::new(cipher, &session_key)?;
        let mut message =
            Encryptor2::with_session_key(message, cipher, session_key)
            .map_err(sop_error)?
            .add_recipients(self.encrypt.recipients.iter())
            .add_passwords(
                self.encrypt.passwords.into_iter()
                    .map(|p| crypto::Password::from(p.normalized())))
            .symmetric_algo(cipher)
            .build().map_err(sop_error)?;

        // Maybe sign the message.
        let mut signers = self.encrypt.sign.make_signers()?;
        if let Some(first) = signers.pop() {
            let mut signer = Signer::with_template(
                message, first,
                signature::SignatureBuilder::new(into_sig_type(self.encrypt.sign.mode)))
                .hash_algo(
                    self.encrypt.sign.hash_algos.get(0).cloned().unwrap_or_default())
                .map_err(sop_error)?;
            for s in signers {
                signer = signer.add_signer(s);
            }
            message = signer.build().map_err(sop_error)?;
        }

        // Literal wrapping.
        let mut message = LiteralWriter::new(message)
                .format(into_data_format(self.encrypt.mode))
                .build().map_err(sop_error)?;
        io::copy(self.plaintext, &mut message)?;
        message.finalize().map_err(sop_error)?;
        Ok(Some(sop_session_key))
    }
}

struct Decrypt<'s> {
    verify: Verify<'s>,
    session_keys: Vec<sop::SessionKey>,
    passwords: Vec<Password>,
    keys: Vec<Cert>,
    with_key_password: Vec<Password>,
}

impl<'s> Decrypt<'s> {
    fn new(sqop: &'s SQOP) -> Result<Box<dyn sop::ops::Decrypt<'s, SQOP<'s>, Certs<'s>, Keys<'s>> + 's>> {
        Ok(Box::new(Decrypt {
            verify: Verify::unboxed(sqop),
            session_keys: Default::default(),
            passwords: Default::default(),
            keys: Default::default(),
            with_key_password: Default::default(),
        }))
    }
}

impl<'s> sop::ops::Decrypt<'s, SQOP<'s>, Certs<'s>, Keys<'s>> for Decrypt<'s> {
    fn verify_not_before(mut self: Box<Self>, t: SystemTime)
                         -> Box<dyn sop::ops::Decrypt<'s, SQOP<'s>, Certs<'s>, Keys<'s>> + 's> {
        self.verify.not_before = Some(t);
        self
    }

    fn verify_not_after(mut self: Box<Self>, t: SystemTime)
                        -> Box<dyn sop::ops::Decrypt<'s, SQOP<'s>, Certs<'s>, Keys<'s>> + 's> {
        self.verify.not_after = Some(t);
        self
    }

    fn verify_with_certs(mut self: Box<Self>,
                         certs: &Certs)
                         -> Result<Box<dyn sop::ops::Decrypt<'s, SQOP<'s>, Certs<'s>, Keys<'s>> + 's>> {
        for cert in &certs.certs {
            self.verify.certs.push(cert.clone());
        }
        Ok(self)
    }

    fn with_session_key(mut self: Box<Self>, sk: sop::SessionKey)
                        -> Result<Box<dyn sop::ops::Decrypt<'s, SQOP<'s>, Certs<'s>, Keys<'s>> + 's>> {
        self.session_keys.push(sk);
        Ok(self)
    }

    fn with_password(mut self: Box<Self>, password: Password)
                     -> Result<Box<dyn sop::ops::Decrypt<'s, SQOP<'s>, Certs<'s>, Keys<'s>> + 's>> {
        self.passwords.push(password);
        Ok(self)
    }

    fn with_keys(mut self: Box<Self>, keys: &Keys)
                 -> Result<Box<dyn sop::ops::Decrypt<'s, SQOP<'s>, Certs<'s>, Keys<'s>> + 's>> {
        for key in &keys.keys {
            self.keys.push(key.clone());
        }
        Ok(self)
    }

    fn with_key_password(mut self: Box<Self>, password: Password)
                         -> Result<Box<dyn sop::ops::Decrypt<'s, SQOP<'s>, Certs<'s>, Keys<'s>> + 's>> {
        self.with_key_password.push(password);
        Ok(self)
    }

    fn ciphertext<'d>(self: Box<Self>,
                      ciphertext: &'d mut (dyn io::Read + Send + Sync))
                      -> Result<Box<dyn sop::ops::Ready<(Option<sop::SessionKey>,
                                                    Vec<sop::ops::Verification>)> + 'd>>
    where
        's: 'd
    {
        Ok(Box::new(DecryptReady {
            decrypt: *self,
            ciphertext,
        }))
    }
}

struct DecryptReady<'s> {
    decrypt: Decrypt<'s>,
    ciphertext: &'s mut (dyn io::Read + Send + Sync),
}

impl<'s> sop::ops::Ready<(Option<sop::SessionKey>, Vec<sop::ops::Verification>)>
    for DecryptReady<'s>
{
    fn to_writer(self: Box<Self>, sink: &mut (dyn io::Write + Send + Sync))
                -> Result<(Option<sop::SessionKey>, Vec<sop::ops::Verification>)> {

        let vhelper = VHelper::new(
            if self.decrypt.verify.verbose {
                Box::new(io::stderr())
            } else {
                Box::new(io::sink())
            },
            0,
            self.decrypt.verify.not_before,
            self.decrypt.verify.not_after,
            self.decrypt.verify.certs);
        let helper = Helper::new(self.decrypt.verify.sqop.policy,
                                 vhelper,
                                 self.decrypt.session_keys,
                                 self.decrypt.passwords,
                                 self.decrypt.with_key_password,
                                 self.decrypt.keys);
        let mut d = DecryptorBuilder::from_reader(self.ciphertext)
            .map_err(sop_error)?
            .with_policy(self.decrypt.verify.sqop.policy, None, helper)
            .map_err(sop_error)?;

        io::copy(&mut d, sink)?;

        let helper = d.into_helper();
        Ok((helper.session_key, helper.vhelper.verifications))
    }
}

struct Armor<'s> {
    sqop: &'s SQOP<'s>,
    label: ArmorLabel,
}

impl<'s> Armor<'s> {
    fn new(sqop: &'s SQOP) -> Result<Box<dyn sop::ops::Armor<'s> + 's>> {
        Ok(Box::new(Armor {
            sqop,
            label: Default::default(),
        }))
    }
}

impl<'s> sop::ops::Armor<'s> for Armor<'s> {
    fn label(mut self: Box<Self>, label: ArmorLabel)
             -> Box<dyn sop::ops::Armor<'s> + 's> {
        self.label = label;
        self
    }

    fn data<'d>(self: Box<Self>, data: &'d mut (dyn io::Read + Send + Sync))
                -> Result<Box<dyn sop::ops::Ready + 'd>>
    where
        's: 'd
    {
        Ok(Box::new(ArmorReady {
            armor: *self,
            data,
        }))
    }
}

struct ArmorReady<'s> {
    armor: Armor<'s>,
    data: &'s mut (dyn io::Read + Send + Sync),
}

impl<'s> sop::ops::Ready for ArmorReady<'s> {
    fn to_writer(self: Box<Self>, sink: &mut (dyn io::Write + Send + Sync))
                -> Result<()> {
        let _ = self.armor.sqop;

        let mut source = Generic::new(self.data, None).into_boxed();

        // Peek at the data to see if it is already armored.
        let armored =
            source.data(1)?.get(0).map(|b| b & 0x80 == 0).unwrap_or(false);

        // If so, dearmor, and extract the headers.
        let mut headers: Vec<(String, String)> = vec![];
        if armored {
            let mut r = armor::Reader::from_reader(
                source, armor::ReaderMode::Tolerant(None));
            headers = r.headers()?.iter().cloned().collect();
            source = Box::new(Adapter::new(r));
        }

        fn make<'s>(sink: &'s mut (dyn io::Write + Send + Sync),
                    kind: armor::Kind,
                    headers: Vec<(String, String)>)
                    -> Result<Message>
        {
            let m = Message::new(sink);
            let mut a = Armorer::new(m).kind(kind);
            for (k, v) in headers {
                a = a.add_header(k, v);
            }
            a.build().map_err(sop_error)
        }

        // We make no effort to verify the packet structure.
        let mut sink = match self.armor.label {
            ArmorLabel::Auto => {
                source = Dup::new(source).into_boxed();
                let ppr = PacketParser::from_reader(&mut source)
                    .map_err(sop_error)?;
                let kind =
                    if let PacketParserResult::Some(pp) = &ppr {
                        // Autodetect using the first packet.
                        match &pp.packet {
                        Packet::Signature(_) =>
                            armor::Kind::Signature,
                        Packet::SecretKey(_) =>
                            armor::Kind::SecretKey,
                        Packet::PublicKey(_) =>
                            armor::Kind::PublicKey,
                        Packet::PKESK(_) | Packet::SKESK(_) =>
                            armor::Kind::Message,
                            _ => return Err(Error::BadData),
                        }
                    } else {
                        return Err(Error::BadData);
                    };
                drop(ppr);
                source = source.into_inner()
                    .expect("the Dup to be popped off");
                make(sink, kind, headers)?
            },
            ArmorLabel::Sig => make(sink, armor::Kind::Signature, headers)?,
            ArmorLabel::Key => make(sink, armor::Kind::SecretKey, headers)?,
            ArmorLabel::Cert => make(sink, armor::Kind::PublicKey, headers)?,
            ArmorLabel::Message => make(sink, armor::Kind::Message, headers)?,
        };

        std::io::copy(&mut source, &mut sink)?;
        sink.finalize().map_err(sop_error)?;
        Ok(())
    }
}

struct Dearmor<'s> {
    sqop: &'s SQOP<'s>,
}

impl<'s> Dearmor<'s> {
    fn new(sqop: &'s SQOP) -> Result<Box<dyn sop::ops::Dearmor<'s> + 's>> {
        Ok(Box::new(Dearmor {
            sqop,
        }))
    }
}

impl<'s> sop::ops::Dearmor<'s> for Dearmor<'s> {
    fn data<'d>(self: Box<Self>, data: &'d mut (dyn io::Read + Send + Sync))
                -> Result<Box<dyn sop::ops::Ready + 'd>>
    where
        's: 'd
    {
        Ok(Box::new(DearmorReady {
            dearmor: *self,
            data,
        }))
    }
}

struct DearmorReady<'s> {
    dearmor: Dearmor<'s>,
    data: &'s mut (dyn io::Read + Send + Sync),
}

impl sop::ops::Ready for DearmorReady<'_> {
    fn to_writer(self: Box<Self>, sink: &mut (dyn io::Write + Send + Sync))
                -> Result<()> {
        let _ = self.dearmor.sqop;

        // Peek at the data to see if it is really armored.  We make
        // no effort to verify the packet structure.
        let mut source = Generic::new(self.data, None).into_boxed();
        let armored =
            source.data(1)?.get(0).map(|b| b & 0x80 == 0).unwrap_or(false);

        if armored {
            // XXX: Give the buffered reader to the armor::Reader once
            // that is possible.
            let mut r = openpgp::armor::Reader::from_reader(source, None);
            std::io::copy(&mut r, sink)?;
        } else {
            // Use BufferedReader::copy once available.
            std::io::copy(&mut source, sink)?;
        }
        Ok(())
    }
}

struct InlineDetach<'s> {
    sqop: &'s SQOP<'s>,
    no_armor: bool,
}

impl<'s> InlineDetach<'s> {
    fn new(sqop: &'s SQOP) -> Result<Box<dyn sop::ops::InlineDetach<'s, Sigs<'s>> + 's>> {
        Ok(Box::new(InlineDetach {
            sqop,
            no_armor: Default::default(),
        }))
    }
}

impl<'s> sop::ops::InlineDetach<'s, Sigs<'s>> for InlineDetach<'s> {
    fn message<'d>(self: Box<Self>, data: &'d mut (dyn io::Read + Send + Sync))
        -> Result<Box<dyn sop::ops::Ready<Sigs<'s>> + 'd>>
    where
        's: 'd
    {
        Ok(Box::new(InlineDetachReady {
            inline_detach: *self,
            data,
        }))
    }
}

struct InlineDetachReady<'s, 'd> {
    inline_detach: InlineDetach<'s>,
    data: &'d mut (dyn io::Read + Send + Sync),
}

impl<'s> sop::ops::Ready<Sigs<'s>> for InlineDetachReady<'s, '_> {
    fn to_writer(self: Box<Self>, sink: &mut (dyn io::Write + Send + Sync))
                -> Result<Sigs<'s>> {
        let _ = self.inline_detach.sqop;

        let np = NullPolicy::new();

        /// A nop-verification-helper to extract message and
        /// signatures.
        #[derive(Default)]
        struct NullHelper {
            sigs: Vec<Packet>,
        }

        impl VerificationHelper for NullHelper {
            fn get_certs(&mut self, _: &[openpgp::KeyHandle])
                         -> openpgp::Result<Vec<Cert>> {
                Ok(Default::default())
            }

            fn check(&mut self, structure: MessageStructure)
                     -> openpgp::Result<()> {
                for layer in structure {
                    match layer {
                        MessageLayer::SignatureGroup { results } => {
                            for result in results {
                                match result
                                    .expect_err("no certs given")
                                {
                                    VerificationError::MalformedSignature {
                                        sig, ..
                                    } =>
                                        self.sigs.push(sig.clone().into()),
                                    VerificationError::MissingKey {
                                        sig, ..
                                    } =>
                                        self.sigs.push(sig.clone().into()),
                                    _ => unreachable!("no certs given"),
                                }
                            }
                        },
                        _ => (),
                    }
                }

                Ok(())
            }
        }

        let mut verifier = VerifierBuilder::from_reader(self.data)
            .map_err(sop_error)?
            .with_policy(&np, None, NullHelper::default())
            .map_err(sop_error)?;

        io::copy(&mut verifier, sink)?;

        // Now get the signatures.
        let mut signatures = Vec::new();
        let mut signature_sink = Message::new(&mut signatures);
        if ! self.inline_detach.no_armor {
            signature_sink = Armorer::new(signature_sink)
                .kind(armor::Kind::Signature)
                .build().map_err(sop_error)?;
        }

        for sig in verifier.into_helper().sigs {
            sig.serialize(&mut signature_sink).map_err(sop_error)?;
        }
        signature_sink.finalize().map_err(sop_error)?;

        Ok(Sigs {
            sop: self.inline_detach.sqop,
            data: signatures,
        })
    }
}

struct InlineVerify<'s> {
    sqop: &'s SQOP<'s>,
    verbose: bool,
    not_before: Option<SystemTime>,
    not_after: Option<SystemTime>,
    certs: Vec<Cert>,
}

impl<'s> InlineVerify<'s> {
    fn new(sqop: &'s SQOP) -> Result<Box<dyn sop::ops::InlineVerify<'s, SQOP<'s>, Certs<'s>> + 's>> {
        Ok(Box::new(InlineVerify {
            sqop,
            verbose: Default::default(),
            not_before: Default::default(),
            not_after: Default::default(),
            certs: Default::default(),
        }))
    }
}

impl<'s> sop::ops::InlineVerify<'s, SQOP<'s>, Certs<'s>> for InlineVerify<'s> {
    fn not_before(mut self: Box<Self>, t: SystemTime)
                  -> Box<dyn sop::ops::InlineVerify<'s, SQOP<'s>, Certs<'s>> + 's> {
        self.not_before = Some(t);
        self
    }

    fn not_after(mut self: Box<Self>, t: SystemTime)
                 -> Box<dyn sop::ops::InlineVerify<'s, SQOP<'s>, Certs<'s>> + 's> {
        self.not_after = Some(t);
        self
    }

    fn certs(mut self: Box<Self>, certs: &Certs)
             -> Result<Box<dyn sop::ops::InlineVerify<'s, SQOP<'s>, Certs<'s>> + 's>> {
        for cert in &certs.certs {
            self.certs.push(cert.clone());
        }
        Ok(self)
    }

    fn message<'d>(self: Box<Self>, data: &'d mut (dyn io::Read + Send + Sync))
        -> Result<Box<dyn sop::ops::Ready<Vec<Verification>> + 'd>>
    where
        's: 'd
    {
        Ok(Box::new(InlineVerifyReady {
            inline_verify: *self,
            data,
        }))
    }
}

struct InlineVerifyReady<'s> {
    inline_verify: InlineVerify<'s>,
    data: &'s mut (dyn io::Read + Send + Sync),
}

impl<'s> sop::ops::Ready<Vec<Verification>> for InlineVerifyReady<'_> {
    fn to_writer(self: Box<Self>, sink: &mut (dyn io::Write + Send + Sync))
                -> Result<Vec<Verification>> {
        let helper = VHelper::new(
            if self.inline_verify.verbose {
                Box::new(io::stderr())
            } else {
                Box::new(io::sink())
            },
            1,
            self.inline_verify.not_before,
            self.inline_verify.not_after,
            self.inline_verify.certs);

        let mut verifier = VerifierBuilder::from_reader(self.data)
            .map_err(sop_error)?
            .with_policy(self.inline_verify.sqop.policy, None, helper)
            .map_err(sop_error)?;

        io::copy(&mut verifier, sink)?;

        Ok(verifier.into_helper().verifications)
    }
}

struct InlineSign<'s> {
    no_armor: bool,
    sign: Sign<'s>,
    mode: InlineSignAs,
}

impl<'s> InlineSign<'s> {
    fn new(sqop: &'s SQOP) -> Result<Box<dyn sop::ops::InlineSign<'s, SQOP<'s>, Keys<'s>> + 's>> {
        Ok(Box::new(InlineSign {
            no_armor: false,
            sign: Sign::unboxed(sqop),
            mode: Default::default(),
        }))
    }
}

impl<'s> sop::ops::InlineSign<'s, SQOP<'s>, Keys<'s>> for InlineSign<'s> {
    fn no_armor(mut self: Box<Self>) -> Box<dyn sop::ops::InlineSign<'s, SQOP<'s>, Keys<'s>> + 's> {
        self.no_armor = true;
        self
    }

    fn mode(mut self: Box<Self>, mode: InlineSignAs) -> Box<dyn sop::ops::InlineSign<'s, SQOP<'s>, Keys<'s>> + 's> {
        self.mode = mode;
        self
    }

    fn keys(mut self: Box<Self>, keys: &Keys)
           -> Result<Box<dyn sop::ops::InlineSign<'s, SQOP<'s>, Keys<'s>> + 's>> {
        self.sign.add_signing_keys(keys)?;
        Ok(self)
    }

    fn with_key_password(mut self: Box<Self>, password: Password)
                         -> Result<Box<dyn sop::ops::InlineSign<'s, SQOP<'s>, Keys<'s>> + 's>> {
        self.sign.with_key_password.push(password);
        Ok(self)
    }

    fn data<'d>(self: Box<Self>, data: &'d mut (dyn io::Read + Send + Sync))
        -> Result<Box<dyn sop::ops::Ready + 'd>>
    where
        's: 'd
    {
        if self.sign.signers.is_empty() {
            return Err(Error::MissingArg);
        }

        if self.no_armor && matches!(self.mode, InlineSignAs::ClearSigned)
        {
            return Err(Error::IncompatibleOptions);
        }

        Ok(Box::new(InlineSignReady {
            inline_sign: *self,
            data,
        }))
    }
}

struct InlineSignReady<'s> {
    inline_sign: InlineSign<'s>,
    data: &'s mut (dyn io::Read + Send + Sync),
}

impl<'s> sop::ops::Ready for InlineSignReady<'s> {
    fn to_writer(self: Box<Self>, sink: &mut (dyn io::Write + Send + Sync))
                -> Result<()>
    {
        let mut message = Message::new(sink);
        if ! (self.inline_sign.no_armor
              || matches!(self.inline_sign.mode, InlineSignAs::ClearSigned))
        {
            message =
                Armorer::new(message).build().map_err(sop_error)?;
        }

        let mut signers = self.inline_sign.sign.make_signers()?;
        let mut signer = Signer::with_template(
            message,
            signers.pop().expect("at least one"),
            signature::SignatureBuilder::new(
                into_isig_type(self.inline_sign.mode)))
            .hash_algo(
                self.inline_sign.sign.hash_algos.get(0).cloned()
                    .unwrap_or_default()).map_err(sop_error)?;

        for s in signers {
            signer = signer.add_signer(s);
        }

        if matches!(self.inline_sign.mode, InlineSignAs::ClearSigned) {
            signer = signer.cleartext();
        }

        let mut message = signer.build().map_err(sop_error)?;

        if ! matches!(self.inline_sign.mode, InlineSignAs::ClearSigned) {
            message = LiteralWriter::new(message).build().map_err(sop_error)?;
        }

        io::copy(self.data, &mut message)?;
        message.finalize().map_err(sop_error)?;
        Ok(())
    }
}

struct VHelper {
    verbose_out: Box<dyn io::Write>,
    verifications: Vec<Verification>,
    not_before: Option<SystemTime>,
    not_after: Option<SystemTime>,

    good: usize,
    total: usize,
    threshold: usize,

    keyring: Vec<Cert>,
}

impl VHelper {
    fn new(verbose_out: Box<dyn io::Write>,
           threshold: usize,
           not_before: Option<SystemTime>,
           not_after: Option<SystemTime>,
           keyring: Vec<Cert>)
           -> Self
    {
        VHelper {
            verbose_out,
            verifications: Default::default(),
            not_before,
            not_after,
            good: 0,
            total: 0,
            threshold,
            keyring,
        }
    }
}

impl VerificationHelper for VHelper {
    fn get_certs(&mut self, _: &[openpgp::KeyHandle])
                 -> openpgp::Result<Vec<Cert>> {
        Ok(std::mem::replace(&mut self.keyring, Default::default()))
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        use self::VerificationError::*;

        for layer in structure.into_iter() {
            match layer {
                MessageLayer::SignatureGroup { results } =>
                    for result in results {
                        self.total += 1;
                        match result {
                            Ok(GoodChecksum { sig, ka, .. }) => {
                                let t = match sig.signature_creation_time() {
                                    Some(t) => t,
                                    None => {
                                        writeln!(self.verbose_out,
                                                 "Malformed signature:")?;
                                        print_error_chain(&mut self.verbose_out, &anyhow::anyhow!(
                                            "no signature creation time"))?;
                                        continue;
                                    },
                                };

                                if let Some(not_before) = self.not_before {
                                    if t < not_before {
                                        writeln!(self.verbose_out,
                                            "Signature by {:X} was created before \
                                             the --not-before date.",
                                            ka.key().fingerprint())?;
                                        continue;
                                    }
                                }

                                if let Some(not_after) = self.not_after {
                                    if t > not_after {
                                        writeln!(self.verbose_out,
                                            "Signature by {:X} was created after \
                                             the --not-after date.",
                                            ka.key().fingerprint())?;
                                        continue;
                                    }
                                }

                                self.verifications.push(Verification::new(
                                    t,
                                    ka.fingerprint(),
                                    ka.cert().fingerprint(),
                                    match sig.typ() {
                                        SignatureType::Text =>
                                            SignatureMode::Text,
                                        _ => SignatureMode::Binary,
                                    },
                                    None)?);
                            },
                            Err(MalformedSignature { error, .. }) => {
                                writeln!(self.verbose_out,
                                         "Signature is malformed:")?;
                                print_error_chain(&mut self.verbose_out, &error)?;
                            },
                            Err(MissingKey { sig, .. }) => {
                                let issuers = sig.get_issuers();
                                writeln!(self.verbose_out,
                                         "Missing key {:X}, which is needed to \
                                           verify signature.",
                                          issuers.first().unwrap())?;
                            },
                            Err(UnboundKey { cert, error, .. }) => {
                                writeln!(self.verbose_out,
                                         "Signing key on {:X} is not bound:",
                                          cert.fingerprint())?;
                                print_error_chain(&mut self.verbose_out, &error)?;
                            },
                            Err(BadKey { ka, error, .. }) => {
                                writeln!(self.verbose_out,
                                         "Signing key on {:X} is bad:",
                                          ka.cert().fingerprint())?;
                                print_error_chain(&mut self.verbose_out, &error)?;
                            },
                            Err(BadSignature { error, .. }) => {
                                writeln!(self.verbose_out,
                                         "Verifying signature:")?;
                                print_error_chain(&mut self.verbose_out, &error)?;
                            },
                        }
                    }
                MessageLayer::Compression { .. } => (),
                MessageLayer::Encryption { .. } => (),
            }
        }

        // Dedup the keys so that it is not possible to exceed the
        // threshold by duplicating signatures or by using the same
        // key.
        self.verifications.sort();
        self.verifications.dedup();

        self.good = self.verifications.len();
        if self.good >= self.threshold {
            Ok(())
        } else {
            Err(Error::NoSignature.into())
        }
    }
}

struct Helper {
    vhelper: VHelper,
    session_keys: Vec<sop::SessionKey>,
    passwords: Vec<crypto::Password>,
    secret_keys:
        HashMap<KeyID, Key<key::SecretParts, key::UnspecifiedRole>>,
    with_key_password: Vec<Password>,
    identities: HashMap<KeyID, Fingerprint>,
    session_key: Option<sop::SessionKey>,
}

impl Helper {
    fn new(policy: &dyn Policy,
           vhelper: VHelper,
           session_keys: Vec<sop::SessionKey>,
           passwords: Vec<Password>,
           with_key_password: Vec<Password>,
           secrets: Vec<Cert>) -> Self
    {
        let mut secret_keys = HashMap::new();
        let mut identities: HashMap<KeyID, Fingerprint> = HashMap::new();
        for tsk in secrets {
            for ka in tsk.keys().secret()
                .with_policy(policy, None)
                .supported()
                .for_transport_encryption().for_storage_encryption()
            {
                let id: KeyID = ka.key().fingerprint().into();
                secret_keys.insert(id.clone(), ka.key().clone().into());
                identities.insert(id.clone(), tsk.fingerprint());
            }
        }

        Helper {
            vhelper,
            session_keys: session_keys.into_iter().map(Into::into).collect(),
            passwords: passwords.into_iter()
                .flat_map(|p| p.variants().map(crypto::Password::from)
                          .collect::<Vec<_>>()).collect(),
            secret_keys,
            with_key_password,
            identities,
            session_key: None,
        }
    }

    /// Tries to decrypt the given PKESK packet with `keypair` and try
    /// to decrypt the packet parser using `decrypt`.
    fn try_decrypt<D>(&self, pkesk: &PKESK,
                      algo: Option<SymmetricAlgorithm>,
                      keypair: &mut dyn crypto::Decryptor,
                      decrypt: &mut D)
                      -> Option<(SymmetricAlgorithm,
                                 SessionKey,
                                 Option<Fingerprint>)>
        where D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool
    {
        let keyid = keypair.public().fingerprint().into();
        let (algo, sk) = pkesk.decrypt(keypair, algo)
            .and_then(|(algo, sk)| {
                if decrypt(algo, &sk) { Some((algo, sk)) } else { None }
            })?;

        Some((algo, sk, self.identities.get(&keyid).map(|fp| fp.clone())))
    }

    /// Dumps the session key.
    fn dump_session_key(&mut self, algo: SymmetricAlgorithm, sk: &SessionKey)
                        -> Result<()> {
        self.session_key = Some(sop::SessionKey::new(algo, sk)?);
        Ok(())
    }
}

impl VerificationHelper for Helper {
    fn get_certs(&mut self, ids: &[openpgp::KeyHandle])
                 -> openpgp::Result<Vec<Cert>> {
        self.vhelper.get_certs(ids)
    }
    fn check(&mut self, structure: MessageStructure)
             -> openpgp::Result<()> {
        self.vhelper.check(structure)
    }
}

impl DecryptionHelper for Helper {
    fn decrypt<D>(&mut self, pkesks: &[PKESK], skesks: &[SKESK],
                  algo: Option<SymmetricAlgorithm>,
                  mut decrypt: D) -> openpgp::Result<Option<Fingerprint>>
        where D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool
    {
        let mut error = Error::CannotDecrypt;

        // First, try all supplied session keys.
        while let Some(sk) = self.session_keys.pop() {
            let algo = SymmetricAlgorithm::from(sk.algorithm());
            let sk = SessionKey::from(sk.key());
            if decrypt(algo, &sk) {
                self.dump_session_key(algo, &sk)?;
                return Ok(None);
            }
        }

        // Second, we try those keys that we can use.
        for pkesk in pkesks {
            let keyid = pkesk.recipient();
            if let Some(key) = self.secret_keys.get_mut(&keyid) {
                let pk_algo = key.pk_algo();

                // Try to decrypt it using any supplied password.
                if key.secret().is_encrypted() {
                    for p in self.with_key_password.iter()
                        .flat_map(|p| p.variants())
                    {
                        if key.secret_mut().decrypt_in_place(pk_algo, &p.into())
                            .is_ok()
                        {
                            break;
                        }
                    }
                }

                if ! key.secret().is_encrypted() {
                    if let Some((algo, sk, fp)) =
                        key.clone().into_keypair().ok().and_then(|mut k| {
                            self.try_decrypt(pkesk, algo, &mut k, &mut decrypt)
                        })
                    {
                        self.dump_session_key(algo, &sk)?;
                        return Ok(fp);
                    }
                } else {
                    // We could have used this key, but failed to
                    // unlock it.  Return the more useful error
                    // condition.
                    error = Error::KeyIsProtected;
                }
            }
        }

        // Third, we try to decrypt PKESK packets with wildcard
        // recipients.
        for pkesk in pkesks.iter().filter(|p| p.recipient().is_wildcard()) {
            for mut key in std::mem::take(&mut self.secret_keys).into_values() {
                let pk_algo = key.pk_algo();

                // Try to decrypt it using any supplied password.
                if key.secret().is_encrypted() {
                    for p in self.with_key_password.iter()
                        .flat_map(|p| p.variants())
                    {
                        if key.secret_mut().decrypt_in_place(pk_algo, &p.into())
                            .is_ok()
                        {
                            break;
                        }
                    }
                }

                if ! key.secret().is_encrypted() {
                    if let Some((algo, sk, fp)) =
                        key.clone().into_keypair().ok().and_then(|mut k| {
                            self.try_decrypt(pkesk, algo, &mut k, &mut decrypt)
                        })
                    {
                        self.dump_session_key(algo, &sk)?;
                        return Ok(fp);
                    }
                } else {
                    // We could plausibly have used this key, but
                    // failed to unlock it.
                    error = Error::KeyIsProtected;
                }
            }
        }

        if skesks.is_empty() {
            return Err(error.into());
        }

        // Finally, try to decrypt using the SKESKs.
        for password in self.passwords.iter() {
            for skesk in skesks {
                if let Some((algo, sk)) = skesk.decrypt(password).ok()
                    .and_then(|(algo, sk)| {
                        if decrypt(algo, &sk) {
                            Some((algo, sk))
                        } else {
                            None
                        }
                    })
                {
                    self.dump_session_key(algo, &sk)?;
                    return Ok(None);
                }
            }
        }

        Err(error.into())
    }
}

fn into_sig_type(mode: sop::ops::SignAs) -> SignatureType {
    match mode {
        SignAs::Binary => SignatureType::Binary,
        SignAs::Text => SignatureType::Text,
    }
}

fn into_isig_type(mode: sop::ops::InlineSignAs) -> SignatureType {
    match mode {
        InlineSignAs::Binary => SignatureType::Binary,
        InlineSignAs::Text => SignatureType::Text,
        InlineSignAs::ClearSigned => SignatureType::Text,
    }
}

fn into_data_format(mode: EncryptAs) -> DataFormat {
    match mode {
        EncryptAs::Binary => DataFormat::Binary,
        EncryptAs::Text => DataFormat::Text,
    }
}

/// Prints the error and causes, if any.
fn print_error_chain(sink: &mut dyn io::Write, err: &anyhow::Error)
                     -> io::Result<()>
{
    writeln!(sink, "           {}", err)?;
    for cause in err.chain().skip(1) {
        writeln!(sink, "  because: {}", cause)?;
    }
    Ok(())
}

/// Maps Sequoia errors to Errors.
///
/// XXX: This is a bit of a friction point.  We likely need to improve
/// the SOP spec a little.
fn sop_error(e: anyhow::Error) -> Error {
    let e = match e.downcast::<Error>() {
        Ok(e) => return e,
        Err(e) => e,
    };

    let e = match e.downcast::<io::Error>() {
        Ok(e) => return if e.kind() == io::ErrorKind::UnexpectedEof {
            Error::BadData
        } else {
            e.into()
        },
        Err(e) => e,
    };

    if let Some(e) = e.downcast_ref::<openpgp::Error>() {
        use openpgp::Error::*;
        return match e {
            InvalidArgument(_) => Error::BadData,
            InvalidOperation(_) => Error::BadData,
            MalformedPacket(_) => Error::BadData,
            PacketTooLarge(_, _, _) => Error::BadData,

            UnsupportedPacketType(_) => Error::BadData,

            // XXX: Those don't map cleanly, but close.
            UnsupportedHashAlgorithm(_) => Error::UnsupportedAsymmetricAlgo,
            UnsupportedPublicKeyAlgorithm(_) => Error::UnsupportedAsymmetricAlgo,
            UnsupportedEllipticCurve(_) => Error::UnsupportedAsymmetricAlgo,
            UnsupportedSymmetricAlgorithm(_) => Error::UnsupportedAsymmetricAlgo,
            UnsupportedAEADAlgorithm(_) => Error::UnsupportedAsymmetricAlgo,
            UnsupportedCompressionAlgorithm(_) => Error::UnsupportedAsymmetricAlgo,

            UnsupportedSignatureType(_) => Error::BadData,
            InvalidSessionKey(_) => Error::CannotDecrypt,
            MissingSessionKey(_) => Error::CannotDecrypt,
            MalformedMPI(_) => Error::BadData,
            BadSignature(_) => Error::BadData,
            MalformedMessage(_) => Error::BadData,
            MalformedCert(_) => Error::BadData,
            UnsupportedCert2(_, _) => Error::BadData,
            Expired(_) => Error::BadData,
            NotYetLive(_) => Error::BadData,
            NoBindingSignature(_) => Error::BadData,
            InvalidKey(_) => Error::BadData,
            PolicyViolation(_, _) => Error::BadData,
            e => {
                eprintln!("Warning: Unknown Sequoia error: {}", e);
                Error::BadData
            },
        };
    }

    eprintln!("Warning: Untranslated error: {}", e);
    Error::BadData
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use super::*;

    /// This is the example from the SOP spec:
    ///
    ///     sop generate-key "Alice Lovelace <alice@openpgp.example>" > alice.sec
    ///     sop extract-cert < alice.sec > alice.pgp
    ///
    ///     sop sign --as=text alice.sec < statement.txt > statement.txt.asc
    ///     sop verify announcement.txt.asc alice.pgp < announcement.txt
    ///
    ///     sop encrypt --sign-with=alice.sec bob.pgp < msg.eml > encrypted.asc
    ///     sop decrypt alice.sec < ciphertext.asc > cleartext.out
    #[test]
    fn sop_examples() -> Result<()> {
        let sop = SQOP::default();

        let alice_sec = sop.generate_key()?
            .userid("Alice Lovelace <alice@openpgp.example>")
            .generate()?;
        let alice_pgp = sop.extract_cert()?
            .keys(&alice_sec)?;

        let bob_sec = sop.generate_key()?
            .userid("Bob Babbage <bob@openpgp.example>")
            .generate()?;
        let bob_pgp = sop.extract_cert()?
            .keys(&bob_sec)?;

        let statement = b"Hello World :)";
        let mut data = Cursor::new(&statement);
        let (_micalg, signature) = sop.sign()?
            .mode(SignAs::Text)
            .keys(&alice_sec)?
            .data(&mut data)?;

        let verifications = sop.verify()?
            .certs(&alice_pgp)?
            .signatures(&signature)?
            .data(&mut Cursor::new(&statement))?;
        assert_eq!(verifications.len(), 1);

        let mut statement_cur = Cursor::new(&statement);
        let (_session_key, ciphertext) = sop.encrypt()?
            .sign_with_keys(&alice_sec)?
            .with_certs(&bob_pgp)?
            .plaintext(&mut statement_cur)?
            .to_vec()?;

        let mut ciphertext_cur = Cursor::new(&ciphertext);
        let (_, plaintext) = sop.decrypt()?
            .with_keys(&bob_sec)?
            .ciphertext(&mut ciphertext_cur)?
            .to_vec()?;
        assert_eq!(&plaintext, statement);

        Ok(())
    }

    #[test]
    fn issue_29() -> Result<()> {
        let sop = SQOP::default();

        let alice_sec = sop.generate_key()?
            .userid("Alice Lovelace <alice@openpgp.example>")
            .generate()?;
        let alice_pgp = sop.extract_cert()?
            .keys(&alice_sec)?;

        let no_signature = b"\n";
        assert!(matches!(sop.inline_verify()?
                         .certs(&alice_pgp)?
                         .message(&mut Cursor::new(&no_signature))
                         .and_then(|ready| ready.to_vec()),
                         Err(sop::errors::Error::BadData)));

        Ok(())
    }
}
