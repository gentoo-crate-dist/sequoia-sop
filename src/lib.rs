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
//! use sequoia_sop::*;
//!
//! let sop = SQOP::default();
//!
//! let alice_sec = sop.generate_key()?
//!     .userid("Alice Lovelace <alice@openpgp.example>")
//!     .generate()?
//!     .to_vec()?;
//! assert!(alice_sec.starts_with(b"-----BEGIN PGP PRIVATE KEY BLOCK-----"));
//! # Ok(()) }
//! ```
//!
//!   [Stateless OpenPGP Interface]: https://gitlab.com/dkg/openpgp-stateless-cli
//!   [Sequoia PGP]: https://sequoia-pgp.org

use std::{
    collections::HashMap,
    io::{self, Write},
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
        stream::*,
    },
    packet::prelude::*,
    policy::StandardPolicy,
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

use sop::*;

/// [`SOP`] implementation based on [Sequoia PGP].
///
///   [Sequoia PGP]: https://sequoia-pgp.org
pub struct SQOP<'a> {
    policy: &'a dyn openpgp::policy::Policy,
}

impl Default for SQOP<'_> {
    fn default() -> Self {
        const P: &StandardPolicy = &StandardPolicy::new();
        Self::with_policy(P)
    }
}

impl<'a> SQOP<'a> {
    /// Creates a [`sop::SOP`] implementation with an explicit
    /// [`sequoia_openpgp::policy::Policy`].
    ///
    /// To use the default
    /// [`sequoia_openpgp::policy::StandardPolicy`], use
    /// [`SQOP::default`].
    pub fn with_policy(policy: &'a dyn Policy) -> Self {
        SQOP {
            policy,
        }
    }
}

impl<'a> sop::SOP for SQOP<'a> {
    fn version<'b>(&'b self) -> Result<Box<dyn sop::Version + 'b>> {
        Ok(Box::new(self))
    }
    fn generate_key<'b>(&'b self) -> Result<Box<dyn sop::GenerateKey + 'b>> {
        GenerateKey::new(self)
    }
    fn extract_cert<'b>(&'b self) -> Result<Box<dyn sop::ExtractCert + 'b>> {
        ExtractCert::new(self)
    }
    fn sign<'b>(&'b self) -> Result<Box<dyn sop::Sign + 'b>> {
        Sign::new(self)
    }
    fn verify<'b>(&'b self) -> Result<Box<dyn sop::Verify + 'b>> {
        Verify::new(self)
    }
    fn encrypt<'b>(&'b self) -> Result<Box<dyn sop::Encrypt + 'b>> {
        Encrypt::new(self)
    }
    fn decrypt<'b>(&'b self) -> Result<Box<dyn sop::Decrypt + 'b>> {
        Decrypt::new(self)
    }
    fn armor<'b>(&'b self) -> Result<Box<dyn sop::Armor + 'b>> {
        Armor::new(self)
    }
    fn dearmor<'b>(&'b self) -> Result<Box<dyn sop::Dearmor + 'b>> {
        Dearmor::new(self)
    }
}

impl sop::Version<'_> for &SQOP<'_> {
    fn name(&self) -> String {
        "Sequoia".into()
    }

    fn version(&self) -> String {
        openpgp::VERSION.into()
    }
}

struct GenerateKey<'a> {
    #[allow(dead_code)]
    sqop: &'a SQOP<'a>,
    no_armor: bool,
    userids: Vec<String>,
}

impl<'a> GenerateKey<'a> {
    fn new(sqop: &'a SQOP) -> Result<Box<dyn sop::GenerateKey<'a> + 'a>> {
        Ok(Box::new(GenerateKey {
            sqop,
            no_armor: Default::default(),
            userids: Default::default(),
        }))
    }
}

impl<'a> sop::GenerateKey<'a> for GenerateKey<'a> {
    fn no_armor(mut self: Box<Self>) -> Box<dyn sop::GenerateKey<'a> + 'a> {
        self.no_armor = true;
        self
    }

    fn userid(mut self: Box<Self>, userid: &str)
              -> Box<dyn sop::GenerateKey<'a> + 'a> {
        self.userids.push(userid.into());
        self
    }

    fn generate(self: Box<Self>) -> Result<Box<dyn sop::Ready + 'a>> {
        Ok(Box::new(*self))
    }
}

impl sop::Ready for GenerateKey<'_> {
    fn write_to(mut self: Box<Self>, sink: &mut (dyn io::Write + Send + Sync))
                -> Result<()>
    {
        let primary_uid = self.userids.get(0).cloned();
        if primary_uid.is_some() {
            self.userids.remove(0);
        }

        let mut builder = CertBuilder::general_purpose(
            None, primary_uid);
        for u in self.userids {
            builder = builder.add_userid(u);
        }
        let (key, _) = builder.generate().map_err(sop_error)?;

        if self.no_armor {
            key.as_tsk().serialize(sink).map_err(sop_error)?;
        } else {
            key.as_tsk().armored().serialize(sink).map_err(sop_error)?;
        }
        Ok(())
    }
}

struct ExtractCert<'a> {
    #[allow(dead_code)]
    sqop: &'a SQOP<'a>,
    no_armor: bool,
}

impl<'a> ExtractCert<'a> {
    fn new(sqop: &'a SQOP) -> Result<Box<dyn sop::ExtractCert<'a> + 'a>> {
        Ok(Box::new(ExtractCert {
            sqop,
            no_armor: Default::default(),
        }))
    }
}

impl<'a> sop::ExtractCert<'a> for ExtractCert<'a> {
    /// Disables armor encoding.
    fn no_armor(mut self: Box<Self>) -> Box<dyn sop::ExtractCert<'a> + 'a> {
        self.no_armor = true;
        self
    }

    /// Extracts the cert from `key`.
    fn key(self: Box<Self>, key: &mut (dyn io::Read + Send + Sync))
           -> Result<Box<dyn Ready + 'a>> {
        Ok(Box::new(ExtractCertReady {
            extract_cert: *self,
            cert: Cert::from_reader(key).map_err(sop_error)?,
        }))
    }
}

struct ExtractCertReady<'a> {
    extract_cert: ExtractCert<'a>,
    cert: openpgp::Cert,
}

impl<'a> sop::Ready for ExtractCertReady<'a> {
    fn write_to(self: Box<Self>, sink: &mut (dyn io::Write + Send + Sync))
                -> Result<()>
    {
        if self.extract_cert.no_armor {
            self.cert.serialize(sink).map_err(sop_error)?;
        } else {
            self.cert.armored().serialize(sink).map_err(sop_error)?;
        }
        Ok(())
    }
}

struct Sign<'a> {
    sqop: &'a SQOP<'a>,
    no_armor: bool,
    mode: SignAs,
    hash_algos: Vec<HashAlgorithm>,
    signers: Vec<openpgp::crypto::KeyPair>,
}

impl<'a> Sign<'a> {
    fn new(sqop: &'a SQOP) -> Result<Box<dyn sop::Sign<'a> + 'a>> {
        Ok(Box::new(Self::unboxed(sqop)))
    }

    fn unboxed(sqop: &'a SQOP) -> Sign<'a> {
        Sign {
            sqop,
            no_armor: Default::default(),
            mode: Default::default(),
            hash_algos: [
                HashAlgorithm::SHA512,
                HashAlgorithm::SHA384,
                HashAlgorithm::SHA256,
                HashAlgorithm::SHA224,
            ].iter().copied().filter(|h| h.is_supported()).collect(),
            signers: Default::default(),
        }
    }
}

impl Sign<'_> {
    fn add_signing_key(&mut self, key: &mut (dyn io::Read + Send + Sync))
                       -> Result<()> {
        let cert = Cert::from_reader(key).map_err(sop_error)?;
        self.add_signing_cert(cert)
    }

    fn add_signing_keys(&mut self, keys: &mut (dyn io::Read + Send + Sync))
                        -> Result<()> {
        for cert in CertParser::from_reader(keys).map_err(sop_error)? {
            self.add_signing_cert(cert.map_err(sop_error)?)?;
        }
        Ok(())
    }

    fn add_signing_cert(&mut self, cert: Cert) -> Result<()> {
        let vcert =
            cert.with_policy(self.sqop.policy, None)
            .map_err(|_| Error::CertCannotSign)?;
        if let Some(p) = vcert.preferred_hash_algorithms() {
            self.hash_algos.retain(|a| p.contains(a));
        }

        let mut one = false;
        for key in vcert.keys()
            .supported()
            .secret()
            .alive()
            .revoked(false)
            .for_signing()
            .map(|ka| ka.key())
        {
            if key.secret().is_encrypted() {
                return Err(Error::KeyIsProtected);
            }
            self.signers.push(
                key.clone().into_keypair().expect("not encrypted"));
            one = true;
            // Exactly one signature per supplied key.
            break;
        }

        if one {
            Ok(())
        } else {
            Err(Error::CertCannotSign)
        }
    }
}

impl<'a> sop::Sign<'a> for Sign<'a> {
    fn no_armor(mut self: Box<Self>) -> Box<dyn sop::Sign<'a> + 'a> {
        self.no_armor = true;
        self
    }

    fn mode(mut self: Box<Self>, mode: SignAs) -> Box<dyn sop::Sign<'a> + 'a> {
        self.mode = mode;
        self
    }

    fn key(mut self: Box<Self>, key: &mut (dyn io::Read + Send + Sync))
           -> Result<Box<dyn sop::Sign<'a> + 'a>> {
        self.add_signing_key(key)?;
        Ok(self)
    }

    fn keys(mut self: Box<Self>, keys: &mut (dyn io::Read + Send + Sync))
           -> Result<Box<dyn sop::Sign<'a> + 'a>> {
        self.add_signing_keys(keys)?;
        Ok(self)
    }

    fn data(self: Box<Self>, data: &'a mut (dyn io::Read + Send + Sync))
        -> Result<Box<dyn Ready + 'a>> {
        if self.signers.is_empty() {
            return Err(Error::MissingArg);
        }

        Ok(Box::new(SignReady {
            sign: *self,
            data,
        }))
    }
}

struct SignReady<'a> {
    sign: Sign<'a>,
    data: &'a mut (dyn io::Read + Send + Sync),
}

impl<'a> sop::Ready for SignReady<'a> {
    fn write_to(mut self: Box<Self>, sink: &mut (dyn io::Write + Send + Sync))
                -> Result<()>
    {
        let mut message = Message::new(sink);
        if ! self.sign.no_armor {
            message =
                Armorer::new(message).kind(armor::Kind::Signature).build()
                .map_err(sop_error)?;
        }

        let mut signer = Signer::with_template(
            message,
            self.sign.signers.pop().expect("at least one"),
            signature::SignatureBuilder::new(into_sig_type(self.sign.mode)))
            .hash_algo(
                self.sign.hash_algos.get(0).cloned().unwrap_or_default()
            ).map_err(sop_error)?
            .detached();
        for s in self.sign.signers {
            signer = signer.add_signer(s);
        }
        let mut message = signer.build().map_err(sop_error)?;
        io::copy(self.data, &mut message)?;
        message.finalize().map_err(sop_error)?;
        Ok(())
    }
}

struct Verify<'a> {
    sqop: &'a SQOP<'a>,
    verbose: bool,
    not_before: Option<SystemTime>,
    not_after: Option<SystemTime>,
    certs: Vec<Cert>,
}

impl<'a> Verify<'a> {
    fn new(sqop: &'a SQOP) -> Result<Box<dyn sop::Verify<'a> + 'a>> {
        Ok(Box::new(Self::unboxed(sqop)))
    }

    fn unboxed(sqop: &'a SQOP) -> Verify<'a> {
        Verify {
            sqop,
            verbose: Default::default(),
            not_before: Default::default(),
            not_after: Default::default(),
            certs: Default::default(),
        }
    }
}

impl<'a> sop::Verify<'a> for Verify<'a> {
    fn not_before(mut self: Box<Self>, t: SystemTime)
                  -> Box<dyn sop::Verify<'a> + 'a> {
        self.not_before = Some(t);
        self
    }

    fn not_after(mut self: Box<Self>, t: SystemTime)
                 -> Box<dyn sop::Verify<'a> + 'a> {
        self.not_after = Some(t);
        self
    }

    fn cert(mut self: Box<Self>, cert: &mut (dyn io::Read + Send + Sync))
            -> Result<Box<dyn sop::Verify<'a> + 'a>> {
        self.certs.push(Cert::from_reader(cert).map_err(sop_error)?);
        Ok(self)
    }

    fn certs(mut self: Box<Self>, cert: &mut (dyn io::Read + Send + Sync))
             -> Result<Box<dyn sop::Verify<'a> + 'a>> {
        for cert in CertParser::from_reader(cert).map_err(sop_error)? {
            self.certs.push(cert.map_err(sop_error)?);
        }
        Ok(self)
    }

    fn signatures(self: Box<Self>,
                  signatures: &'a mut (dyn io::Read + Send + Sync))
                  -> Result<Box<dyn sop::VerifySignatures + 'a>> {
        Ok(Box::new(VerifySignatures {
            verify: *self,
            signatures: signatures,
        }))
    }
}

struct VerifySignatures<'a> {
    verify: Verify<'a>,
    signatures: &'a mut (dyn io::Read + Send + Sync),
}

impl sop::VerifySignatures for VerifySignatures<'_> {
    fn data(self: Box<Self>, data: &mut (dyn io::Read + Send + Sync))
            -> Result<Vec<sop::Verification>> {
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
            DetachedVerifierBuilder::from_reader(self.signatures)
            .map_err(sop_error)?
            .with_policy(self.verify.sqop.policy, None, helper)
            .map_err(sop_error)?;
        v.verify_reader(data).map_err(sop_error)?;
        Ok(v.into_helper().verifications)
    }
}

struct Encrypt<'a> {
    sign: Sign<'a>,
    mode: EncryptAs,
    symmetric_algos: Vec<SymmetricAlgorithm>,
    recipients: Vec<Key<key::PublicParts, key::UnspecifiedRole>>,
    passwords: Vec<Password>,
}

impl<'a> Encrypt<'a> {
    fn new(sqop: &'a SQOP) -> Result<Box<dyn sop::Encrypt<'a> + 'a>> {
        Ok(Box::new(Encrypt {
            sign: Sign::unboxed(sqop),
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
                SymmetricAlgorithm::CAST5,
                SymmetricAlgorithm::IDEA,
                SymmetricAlgorithm::TripleDES,
            ].iter().copied().filter(|h| h.is_supported()).collect(),
            recipients: Default::default(),
            passwords: Default::default(),
        }))
    }

    fn add_cert(mut self: Box<Self>, cert: Cert)
                 -> Result<Box<Self>> {
        let vcert = cert.with_policy(self.sign.sqop.policy, None)
            .map_err(|_| sop::Error::CertCannotEncrypt)?;

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

impl<'a> sop::Encrypt<'a> for Encrypt<'a> {
    /// Disables armor encoding.
    fn no_armor(mut self: Box<Self>) -> Box<dyn sop::Encrypt<'a> + 'a> {
        self.sign.no_armor = true;
        self
    }

    /// Sets encryption mode.
    fn mode(mut self: Box<Self>, mode: EncryptAs) -> Box<dyn sop::Encrypt<'a> + 'a> {
        self.sign.mode = mode.into();
        self.mode = mode;
        self
    }

    fn sign_with_key(mut self: Box<Self>,
                     key: &mut (dyn io::Read + Send + Sync))
                     -> Result<Box<dyn sop::Encrypt<'a> + 'a>> {
        self.sign.add_signing_key(key)?;
        Ok(self)
    }

    fn sign_with_keys(mut self: Box<Self>,
                      keys: &mut (dyn io::Read + Send + Sync))
                      -> Result<Box<dyn sop::Encrypt<'a> + 'a>> {
        self.sign.add_signing_keys(keys)?;
        Ok(self)
    }

    /// Encrypts with the given password.
    fn with_password(mut self: Box<Self>, password: Password)
                     -> Result<Box<dyn sop::Encrypt<'a> + 'a>> {
        self.passwords.push(password);
        Ok(self)
    }

    fn with_cert(self: Box<Self>, cert: &mut (dyn io::Read + Send + Sync))
                 -> Result<Box<dyn sop::Encrypt<'a> + 'a>> {
        let cert = Cert::from_reader(cert).map_err(sop_error)?;
        Ok(self.add_cert(cert)?)
    }

    fn with_certs(mut self: Box<Self>, certs: &mut (dyn io::Read + Send + Sync))
                  -> Result<Box<dyn sop::Encrypt<'a> + 'a>> {
        for cert in CertParser::from_reader(certs).map_err(sop_error)? {
            self = self.add_cert(cert.map_err(sop_error)?)?;
        }
        Ok(self)
    }

    /// Encrypts the given data yielding the ciphertext.
    fn plaintext(self: Box<Self>,
                 plaintext: &'a mut (dyn io::Read + Send + Sync))
                 -> Result<Box<dyn Ready + 'a>> {
        Ok(Box::new(EncryptReady {
            encrypt: *self,
            plaintext,
        }))
    }
}

struct EncryptReady<'a> {
    encrypt: Encrypt<'a>,
    plaintext: &'a mut (dyn io::Read + Send + Sync),
}

impl<'a> sop::Ready for EncryptReady<'a> {
    fn write_to(mut self: Box<Self>, sink: &mut (dyn io::Write + Send + Sync))
                -> Result<()>
    {
        let mut message = Message::new(sink);
        if ! self.encrypt.sign.no_armor {
            message = Armorer::new(message).build().map_err(sop_error)?;
        }

        // Encrypt the message.
        let mut message =
            Encryptor::for_recipients(message, self.encrypt.recipients.iter())
            .add_passwords(
                self.encrypt.passwords.into_iter().map(convert_password))
            .symmetric_algo(
                self.encrypt.symmetric_algos.get(0).cloned().unwrap_or_default())
            .build().map_err(sop_error)?;

        // Maybe sign the message.
        if let Some(first) = self.encrypt.sign.signers.pop() {
            let mut signer = Signer::with_template(
                message, first,
                signature::SignatureBuilder::new(into_sig_type(self.encrypt.sign.mode)))
                .hash_algo(
                    self.encrypt.sign.hash_algos.get(0).cloned().unwrap_or_default())
                .map_err(sop_error)?;
            for s in self.encrypt.sign.signers {
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
        Ok(())
    }
}

struct Decrypt<'a> {
    verify: Verify<'a>,
    session_keys: Vec<sop::SessionKey>,
    passwords: Vec<Password>,
    keys: Vec<Cert>,
}

impl<'a> Decrypt<'a> {
    fn new(sqop: &'a SQOP) -> Result<Box<dyn sop::Decrypt<'a> + 'a>> {
        Ok(Box::new(Decrypt {
            verify: Verify::unboxed(sqop),
            session_keys: Default::default(),
            passwords: Default::default(),
            keys: Default::default(),
        }))
    }
}

impl<'a> sop::Decrypt<'a> for Decrypt<'a> {
    /// Makes SOP consider signatures before this date invalid.
    fn verify_not_before(mut self: Box<Self>, t: SystemTime)
                         -> Box<dyn sop::Decrypt<'a> + 'a> {
        self.verify.not_before = Some(t);
        self
    }

    /// Makes SOP consider signatures after this date invalid.
    fn verify_not_after(mut self: Box<Self>, t: SystemTime)
                        -> Box<dyn sop::Decrypt<'a> + 'a> {
        self.verify.not_after = Some(t);
        self
    }

    /// Adds the verification cert.
    fn verify_with_cert(mut self: Box<Self>,
                        cert: &mut (dyn io::Read + Send + Sync))
                        -> Result<Box<dyn sop::Decrypt<'a> + 'a>> {
        self.verify.certs.push(Cert::from_reader(cert).map_err(sop_error)?);
        Ok(self)
    }

    fn verify_with_certs(mut self: Box<Self>,
                         certs: &mut (dyn io::Read + Send + Sync))
                         -> Result<Box<dyn sop::Decrypt<'a> + 'a>> {
        for cert in CertParser::from_reader(certs).map_err(sop_error)? {
            self.verify.certs.push(cert.map_err(sop_error)?);
        }
        Ok(self)
    }

    /// Tries to decrypt with the given session key.
    fn with_session_key(mut self: Box<Self>, sk: sop::SessionKey)
                        -> Result<Box<dyn sop::Decrypt<'a> + 'a>> {
        self.session_keys.push(sk);
        Ok(self)
    }

    /// Tries to decrypt with the given password.
    fn with_password(mut self: Box<Self>, password: Password)
                     -> Result<Box<dyn sop::Decrypt<'a> + 'a>> {
        self.passwords.push(password);
        Ok(self)
    }

    /// Adds the decryption key.
    fn with_key(mut self: Box<Self>, key: &mut (dyn io::Read + Send + Sync))
                -> Result<Box<dyn sop::Decrypt<'a> + 'a>> {
        self.keys.push(Cert::from_reader(key).map_err(sop_error)?);
        Ok(self)
    }

    /// Decrypts `ciphertext`, returning verification results and
    /// plaintext.
    fn ciphertext(self: Box<Self>,
                  ciphertext: &'a mut (dyn io::Read + Send + Sync))
                  -> Result<Box<dyn sop::ReadyWithResult<(Option<sop::SessionKey>,
                                                          Vec<sop::Verification>)> + 'a>>
    {
        Ok(Box::new(DecryptReady {
            decrypt: *self,
            ciphertext,
        }))
    }
}

struct DecryptReady<'a> {
    decrypt: Decrypt<'a>,
    ciphertext: &'a mut (dyn io::Read + Send + Sync),
}

impl<'a> sop::ReadyWithResult<(Option<sop::SessionKey>, Vec<sop::Verification>)>
    for DecryptReady<'a>
{
    fn write_to(self: Box<Self>, sink: &mut (dyn io::Write + Send + Sync))
                -> Result<(Option<sop::SessionKey>, Vec<sop::Verification>)> {

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

struct Armor<'a> {
    sqop: &'a SQOP<'a>,
    label: ArmorLabel,
}

impl<'a> Armor<'a> {
    fn new(sqop: &'a SQOP) -> Result<Box<dyn sop::Armor<'a> + 'a>> {
        Ok(Box::new(Armor {
            sqop,
            label: Default::default(),
        }))
    }
}

impl<'a> sop::Armor<'a> for Armor<'a> {
    fn label(mut self: Box<Self>, label: ArmorLabel)
             -> Box<dyn sop::Armor<'a> + 'a> {
        self.label = label;
        self
    }

    fn data(self: Box<Self>, data: &'a mut (dyn io::Read + Send + Sync))
        -> Result<Box<dyn sop::Ready + 'a>> {
        Ok(Box::new(ArmorReady {
            armor: *self,
            data,
        }))
    }
}

struct ArmorReady<'a> {
    armor: Armor<'a>,
    data: &'a mut (dyn io::Read + Send + Sync),
}

impl<'a> sop::Ready for ArmorReady<'a> {
    fn write_to(self: Box<Self>, sink: &mut (dyn io::Write + Send + Sync))
                -> Result<()> {
        let _ = self.armor.sqop;

        enum Labeled<'a> {
            NotYet(&'a mut (dyn io::Write + Send + Sync)),
            Labeled(Message<'a>),
        }
        use Labeled::*;

        impl<'a> Labeled<'a> {
            fn expect(self) -> Message<'a> {
                match self {
                    NotYet(_) =>
                        panic!("Labeled::expect() called on NotYet"),
                    Labeled(m) => m,
                }
            }
        }

        fn make<'a>(sink: &'a mut (dyn io::Write + Send + Sync),
                    kind: armor::Kind)
                    -> Result<Labeled<'a>>
        {
            let m = Message::new(sink);
            Armorer::new(m).kind(kind).build().map(|m| Labeled(m))
                .map_err(sop_error)
        }

        // We make no effort to verify the packet structure.
        let mut ppr = PacketParser::from_reader(self.data).map_err(sop_error)?;
        let mut sink = Some(match self.armor.label {
            ArmorLabel::Auto => NotYet(sink),
            ArmorLabel::Sig => make(sink, armor::Kind::Signature)?,
            ArmorLabel::Key => make(sink, armor::Kind::SecretKey)?,
            ArmorLabel::Cert => make(sink, armor::Kind::PublicKey)?,
            ArmorLabel::Message => make(sink, armor::Kind::Message)?,
        });

        while let PacketParserResult::Some(pp) = ppr {
            let (packet, tmp) = pp.next().map_err(sop_error)?;
            ppr = tmp;

            let s = sink.take().expect("we always put it back");
            sink = Some(match s {
                NotYet(s) => {
                    // Autodetect using the first packet.
                    match packet {
                        Packet::Signature(_) =>
                            make(s, armor::Kind::Signature)?,
                        Packet::SecretKey(_) =>
                            make(s, armor::Kind::SecretKey)?,
                        Packet::PublicKey(_) =>
                            make(s, armor::Kind::PublicKey)?,
                        Packet::PKESK(_) | Packet::SKESK(_) =>
                            make(s, armor::Kind::Message)?,
                        _ => return Err(Error::BadData),
                    }
                },
                Labeled(m) => Labeled(m),
            });

            match &mut sink {
                Some(Labeled(m)) => packet.serialize(m).map_err(sop_error)?,
                _ => unreachable!(
                    "we always put it back, detected at this point"),
            }
        }

        sink.expect("we always put it back").expect().finalize()
            .map_err(sop_error)?;
        Ok(())
    }
}

struct Dearmor<'a> {
    sqop: &'a SQOP<'a>,
}

impl<'a> Dearmor<'a> {
    fn new(sqop: &'a SQOP) -> Result<Box<dyn sop::Dearmor<'a> + 'a>> {
        Ok(Box::new(Dearmor {
            sqop,
        }))
    }
}

impl<'a> sop::Dearmor<'a> for Dearmor<'a> {
    /// Extracts the cert from `key`.
    fn data(self: Box<Self>, data: &'a mut (dyn io::Read + Send + Sync))
        -> Result<Box<dyn sop::Ready + 'a>> {
        Ok(Box::new(DearmorReady {
            dearmor: *self,
            data,
        }))
    }
}

struct DearmorReady<'a> {
    dearmor: Dearmor<'a>,
    data: &'a mut (dyn io::Read + Send + Sync),
}

impl sop::Ready for DearmorReady<'_> {
    fn write_to(self: Box<Self>, sink: &mut (dyn io::Write + Send + Sync))
                -> Result<()> {
        let _ = self.dearmor.sqop;

        // We make no effort to verify the packet structure.
        let mut ppr = PacketParser::from_reader(self.data).map_err(sop_error)?;
        while let PacketParserResult::Some(pp) = ppr {
            let (packet, tmp) = pp.next().map_err(sop_error)?;
            ppr = tmp;
            packet.serialize(sink).map_err(sop_error)?;
        }
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
    identities: HashMap<KeyID, Fingerprint>,
    session_key: Option<sop::SessionKey>,
}

impl Helper {
    fn new(policy: &dyn Policy,
           vhelper: VHelper,
           session_keys: Vec<sop::SessionKey>,
           passwords: Vec<Password>,
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
            passwords: passwords.into_iter().map(convert_password).collect(),
            secret_keys,
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
        // First, try all supplied session keys.
        while let Some(sk) = self.session_keys.pop() {
            let algo = SymmetricAlgorithm::from(sk.algorithm());
            let sk = SessionKey::from(sk.key());
            if decrypt(algo, &sk) {
                self.dump_session_key(algo, &sk)?;
                return Ok(None);
            }
        }

        // Second, we try those keys that we can use without prompting
        // for a password.
        for pkesk in pkesks {
            let keyid = pkesk.recipient();
            if let Some(key) = self.secret_keys.get(&keyid) {
                if ! key.secret().is_encrypted() {
                    if let Some((algo, sk, fp)) =
                        key.clone().into_keypair().ok().and_then(|mut k| {
                            self.try_decrypt(pkesk, algo, &mut k, &mut decrypt)
                        })
                    {
                        self.dump_session_key(algo, &sk)?;
                        return Ok(fp);
                    }
                }
            }
        }

        // Third, we try to decrypt PKESK packets with wildcard
        // recipients using those keys that we can use without
        // prompting for a password.
        for pkesk in pkesks.iter().filter(|p| p.recipient().is_wildcard()) {
            for key in self.secret_keys.values() {
                if ! key.secret().is_encrypted() {
                    if let Some((algo, sk, fp)) =
                        key.clone().into_keypair().ok().and_then(|mut k| {
                            self.try_decrypt(pkesk, algo, &mut k, &mut decrypt)
                        })
                    {
                        self.dump_session_key(algo, &sk)?;
                        return Ok(fp);
                    }
                }
            }
        }

        if skesks.is_empty() {
            return
                Err(anyhow::anyhow!("No key to decrypt message"));
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

        Err(Error::CannotDecrypt.into())
    }
}

fn into_sig_type(mode: sop::SignAs) -> SignatureType {
    match mode {
        SignAs::Binary => SignatureType::Binary,
        SignAs::Text => SignatureType::Text,
    }
}

fn into_data_format(mode: EncryptAs) -> DataFormat {
    match mode {
        EncryptAs::Binary => DataFormat::Binary,
        EncryptAs::Text => DataFormat::Text,
        EncryptAs::MIME => DataFormat::MIME,
    }
}

fn convert_password(p: Password) -> crypto::Password {
    p.as_ref().into()
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

/// Maps Sequoia errors to sop::Errors.
///
/// XXX: This is a bit of a friction point.  We likely need to improve
/// the SOP spec a little.
fn sop_error(e: anyhow::Error) -> sop::Error {
    let e = match e.downcast::<io::Error>() {
        Ok(e) => return e.into(),
        Err(e) => e,
    };

    if let Some(e) = e.downcast_ref::<openpgp::Error>() {
        use openpgp::Error::*;
        return match e {
            InvalidArgument(_) => sop::Error::BadData,
            InvalidOperation(_) => sop::Error::BadData,
            MalformedPacket(_) => sop::Error::BadData,
            PacketTooLarge(_, _, _) => sop::Error::BadData,

            UnsupportedPacketType(_) => sop::Error::BadData,

            // XXX: Those don't map cleanly, but close.
            UnsupportedHashAlgorithm(_) => sop::Error::UnsupportedAsymmetricAlgo,
            UnsupportedPublicKeyAlgorithm(_) => sop::Error::UnsupportedAsymmetricAlgo,
            UnsupportedEllipticCurve(_) => sop::Error::UnsupportedAsymmetricAlgo,
            UnsupportedSymmetricAlgorithm(_) => sop::Error::UnsupportedAsymmetricAlgo,
            UnsupportedAEADAlgorithm(_) => sop::Error::UnsupportedAsymmetricAlgo,
            UnsupportedCompressionAlgorithm(_) => sop::Error::UnsupportedAsymmetricAlgo,

            UnsupportedSignatureType(_) => sop::Error::BadData,
            InvalidSessionKey(_) => sop::Error::CannotDecrypt,
            MissingSessionKey(_) => sop::Error::CannotDecrypt,
            MalformedMPI(_) => sop::Error::BadData,
            BadSignature(_) => sop::Error::BadData,
            MalformedMessage(_) => sop::Error::BadData,
            MalformedCert(_) => sop::Error::BadData,
            UnsupportedCert(_) => sop::Error::BadData,
            Expired(_) => sop::Error::BadData,
            NotYetLive(_) => sop::Error::BadData,
            NoBindingSignature(_) => sop::Error::BadData,
            InvalidKey(_) => sop::Error::BadData,
            PolicyViolation(_, _) => sop::Error::BadData,
            e => {
                eprintln!("Warning: Unknown Sequoia error: {}", e);
                sop::Error::BadData
            },
        };
    }

    eprintln!("Warning: Untranslated error: {}", e);
    sop::Error::BadData
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
    ///     sop encrypt --sign-with=alice.sec --as=mime bob.pgp < msg.eml > encrypted.asc
    ///     sop decrypt alice.sec < ciphertext.asc > cleartext.out
    #[test]
    fn sop_examples() -> Result<()> {
        let sop = SQOP::default();

        let alice_sec = sop.generate_key()?
            .userid("Alice Lovelace <alice@openpgp.example>")
            .generate()?
            .to_vec()?;
        let alice_pgp = sop.extract_cert()?
            .key(&mut Cursor::new(&alice_sec))?.to_vec()?;

        let bob_sec = sop.generate_key()?
            .userid("Bob Babbage <bob@openpgp.example>")
            .generate()?
            .to_vec()?;
        let bob_pgp = sop.extract_cert()?
            .key(&mut Cursor::new(&bob_sec))?.to_vec()?;

        let statement = b"Hello World :)";
        let mut data = Cursor::new(&statement);
        let statement_asc = sop.sign()?
            .mode(SignAs::Text)
            .key(&mut Cursor::new(&alice_sec))?
            .data(&mut data)?
            .to_vec()?;

        let mut statement_asc_cur = Cursor::new(&statement_asc);
        let verifications = sop.verify()?
            .cert(&mut Cursor::new(&alice_pgp))?
            .signatures(&mut statement_asc_cur)?
            .data(&mut Cursor::new(&statement))?;
        assert_eq!(verifications.len(), 1);

        let mut statement_cur = Cursor::new(&statement);
        let ciphertext = sop.encrypt()?
            .sign_with_key(&mut Cursor::new(&alice_sec))?
            .mode(EncryptAs::MIME)
            .with_cert(&mut Cursor::new(&bob_pgp))?
            .plaintext(&mut statement_cur)?
            .to_vec()?;

        let mut ciphertext_cur = Cursor::new(&ciphertext);
        let (_, plaintext) = sop.decrypt()?
            .with_key(&mut Cursor::new(&bob_sec))?
            .ciphertext(&mut ciphertext_cur)?
            .to_vec()?;
        assert_eq!(&plaintext, statement);

        Ok(())
    }
}
