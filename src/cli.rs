use std::fmt;

use chrono::{DateTime, offset::Utc};
use structopt::StructOpt;

use sequoia_openpgp as openpgp;
use openpgp::{
    types::{
        SignatureType,
        DataFormat,
    },
    Result,
};

#[derive(Debug, StructOpt)]
#[structopt(about = "An implementation of the \
                     Stateless OpenPGP Command Line Interface \
                     using Sequoia")]
pub enum SOP {
    /// Prints version information.
    Version {
    },
    /// Generates a Secret Key.
    GenerateKey {
        /// Don't ASCII-armor output.
        #[structopt(long)]
        no_armor: bool,
        /// UserIDs for the generated key.
        userids: Vec<String>,
    },
    /// Extracts a Certificate from a Secret Key.
    ExtractCert {
        /// Don't ASCII-armor output.
        #[structopt(long)]
        no_armor: bool,
    },
    /// Creates Detached Signatures.
    Sign {
        /// Don't ASCII-armor output.
        #[structopt(long)]
        no_armor: bool,
        /// Sign binary data or UTF-8 text.
        #[structopt(default_value = "binary", long = "as")]
        as_: SignAs,
        /// Keys for signing.
        keys: Vec<String>,
    },
    /// Verifies Detached Signatures.
    Verify {
        /// Consider signatures before this date invalid.
        #[structopt(long, parse(try_from_str = parse_bound_round_down))]
        not_before: Option<DateTime<Utc>>,
        /// Consider signatures after this date invalid.
        #[structopt(long, parse(try_from_str = parse_bound_round_up))]
        not_after: Option<DateTime<Utc>>,
        /// Signatures to verify.
        signatures: String,
        /// Certs for verification.
        certs: Vec<String>,
    },
    /// Encrypts a Message.
    Encrypt {
        /// Don't ASCII-armor output.
        #[structopt(long)]
        no_armor: bool,
        /// Encrypt binary data, UTF-8 text, or MIME data.
        #[structopt(default_value = "binary", long = "as")]
        as_: EncryptAs,
        /// Encrypt with passwords.
        #[structopt(long, number_of_values = 1)]
        with_password: Vec<String>,
        /// Keys for signing.
        #[structopt(long, number_of_values = 1)]
        sign_with: Vec<String>,
        /// Encrypt for these certs.
        certs: Vec<String>,
    },
    /// Decrypts a Message.
    Decrypt {
        /// Write the session key here.
        #[structopt(long)]
        session_key_out: Option<String>,
        /// Try to decrypt with this session key.
        #[structopt(long, number_of_values = 1)]
        with_session_key: Vec<String>,
        /// Try to decrypt with this password.
        #[structopt(long, number_of_values = 1)]
        with_password: Vec<String>,
        /// Write verification result here.
        #[structopt(long)]
        verify_out: Option<String>,
        /// Certs for verification.
        #[structopt(long, number_of_values = 1)]
        verify_with: Vec<String>,
        /// Consider signatures before this date invalid.
        #[structopt(long, parse(try_from_str = parse_bound_round_down))]
        verify_not_before: Option<DateTime<Utc>>,
        /// Consider signatures after this date invalid.
        #[structopt(long, parse(try_from_str = parse_bound_round_up))]
        verify_not_after: Option<DateTime<Utc>>,
        /// Try to decrypt with this key.
        key: Vec<String>,
    },
    /// Converts binary OpenPGP data to ASCII
    Armor {
        /// Indicates the kind of data
        #[structopt(long, default_value = "auto")]
        label: ArmorKind,
    },
    /// Converts ASCII OpenPGP data to binary
    Dearmor {
    },
    /// Unsupported subcommand.
    #[structopt(external_subcommand)]
    Unsupported(Vec<String>),
}

#[derive(Clone, Copy, Debug)]
pub enum SignAs {
    Binary,
    Text,
}

impl std::str::FromStr for SignAs {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> openpgp::Result<Self> {
        match s {
            "binary" => Ok(SignAs::Binary),
            "text" => Ok(SignAs::Text),
            _ => Err(anyhow::anyhow!(
                "{:?}, expected one of {{binary|text}}", s)),
        }
    }
}

impl fmt::Display for SignAs {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SignAs::Binary => f.write_str("binary"),
            SignAs::Text => f.write_str("text"),
        }
    }
}

impl From<SignAs> for SignatureType {
    fn from(a: SignAs) -> Self {
        match a {
            SignAs::Binary => SignatureType::Binary,
            SignAs::Text => SignatureType::Text,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum EncryptAs {
    Binary,
    Text,
    MIME,
}

impl std::str::FromStr for EncryptAs {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> openpgp::Result<Self> {
        match s {
            "binary" => Ok(EncryptAs::Binary),
            "text" => Ok(EncryptAs::Text),
            "mime" => Ok(EncryptAs::MIME),
            _ => Err(anyhow::anyhow!(
                "{}, expected one of {{binary|text|mime}}", s)),
        }
    }
}

impl fmt::Display for EncryptAs {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            EncryptAs::Binary => f.write_str("binary"),
            EncryptAs::Text => f.write_str("text"),
            EncryptAs::MIME => f.write_str("mime"),
        }
    }
}

impl From<EncryptAs> for SignatureType {
    fn from(a: EncryptAs) -> Self {
        match a {
            EncryptAs::Binary => SignatureType::Binary,
            EncryptAs::Text => SignatureType::Text,
            // XXX: We should inspect the serialized MIME structure
            // and use Text if it is UTF-8, Binary otherwise.  But, we
            // cannot be bothered at this point.
            EncryptAs::MIME => SignatureType::Binary,
        }
    }
}

impl From<EncryptAs> for DataFormat {
    fn from(a: EncryptAs) -> Self {
        match a {
            EncryptAs::Binary => DataFormat::Binary,
            EncryptAs::Text => DataFormat::Text,
            EncryptAs::MIME => DataFormat::MIME,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ArmorKind {
    Auto,
    Sig,
    Key,
    Cert,
    Message,
}

impl std::str::FromStr for ArmorKind {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> openpgp::Result<Self> {
        match s {
            "auto" => Ok(ArmorKind::Auto),
            "sig" => Ok(ArmorKind::Sig),
            "key" => Ok(ArmorKind::Key),
            "cert" => Ok(ArmorKind::Cert),
            "message" => Ok(ArmorKind::Message),
            _ => Err(anyhow::anyhow!(
                "{:?}, expected one of \
                 {{auto|sig|key|cert|message}}", s)),
        }
    }
}

impl fmt::Display for ArmorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ArmorKind::Auto => f.write_str("auto"),
            ArmorKind::Sig => f.write_str("sig"),
            ArmorKind::Key => f.write_str("key"),
            ArmorKind::Cert => f.write_str("cert"),
            ArmorKind::Message => f.write_str("message"),
        }
    }
}

/// Parses the given string depicting a ISO 8601 timestamp, rounding down.
pub fn parse_bound_round_down(s: &str) -> Result<DateTime<Utc>> {
    match s {
        // XXX: parse "-" to None once we figure out how to do that
        // with structopt.
        "now" => Ok(Utc::now()),
        _ => parse_iso8601(s, chrono::NaiveTime::from_hms(0, 0, 0)),
    }
}

/// Parses the given string depicting a ISO 8601 timestamp, rounding up.
pub fn parse_bound_round_up(s: &str) -> Result<DateTime<Utc>> {
    match s {
        // XXX: parse "-" to None once we figure out how to do that
        // with structopt.
        "now" => Ok(Utc::now()),
        _ => parse_iso8601(s, chrono::NaiveTime::from_hms(23, 59, 59)),
    }
}

/// Parses the given string depicting a ISO 8601 timestamp.
fn parse_iso8601(s: &str, pad_date_with: chrono::NaiveTime)
                 -> Result<DateTime<Utc>>
{
    // If you modify this function this function, synchronize the
    // changes with the copy in sqv.rs!
    for f in &[
        "%Y-%m-%dT%H:%M:%S%#z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M%#z",
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%dT%H%#z",
        "%Y-%m-%dT%H",
        "%Y%m%dT%H%M%S%#z",
        "%Y%m%dT%H%M%S",
        "%Y%m%dT%H%M%#z",
        "%Y%m%dT%H%M",
        "%Y%m%dT%H%#z",
        "%Y%m%dT%H",
    ] {
        if f.ends_with("%#z") {
            if let Ok(d) = DateTime::parse_from_str(s, *f) {
                return Ok(d.into());
            }
        } else {
            if let Ok(d) = chrono::NaiveDateTime::parse_from_str(s, *f) {
                return Ok(DateTime::from_utc(d, Utc));
            }
        }
    }
    for f in &[
        "%Y-%m-%d",
        "%Y-%m",
        "%Y-%j",
        "%Y%m%d",
        "%Y%m",
        "%Y%j",
        "%Y",
    ] {
        if let Ok(d) = chrono::NaiveDate::parse_from_str(s, *f) {
            return Ok(DateTime::from_utc(d.and_time(pad_date_with), Utc));
        }
    }
    Err(anyhow::anyhow!("Malformed ISO8601 timestamp: {}", s))
}

#[test]
fn test_parse_iso8601() {
    let z = chrono::NaiveTime::from_hms(0, 0, 0);
    parse_iso8601("2017-03-04T13:25:35Z", z).unwrap();
    parse_iso8601("2017-03-04T13:25:35+08:30", z).unwrap();
    parse_iso8601("2017-03-04T13:25:35", z).unwrap();
    parse_iso8601("2017-03-04T13:25Z", z).unwrap();
    parse_iso8601("2017-03-04T13:25", z).unwrap();
    // parse_iso8601("2017-03-04T13Z", z).unwrap(); // XXX: chrono doesn't like
    // parse_iso8601("2017-03-04T13", z).unwrap(); // ditto
    parse_iso8601("2017-03-04", z).unwrap();
    // parse_iso8601("2017-03", z).unwrap(); // ditto
    parse_iso8601("2017-031", z).unwrap();
    parse_iso8601("20170304T132535Z", z).unwrap();
    parse_iso8601("20170304T132535+0830", z).unwrap();
    parse_iso8601("20170304T132535", z).unwrap();
    parse_iso8601("20170304T1325Z", z).unwrap();
    parse_iso8601("20170304T1325", z).unwrap();
    // parse_iso8601("20170304T13Z", z).unwrap(); // ditto
    // parse_iso8601("20170304T13", z).unwrap(); // ditto
    parse_iso8601("20170304", z).unwrap();
    // parse_iso8601("201703", z).unwrap(); // ditto
    parse_iso8601("2017031", z).unwrap();
    // parse_iso8601("2017", z).unwrap(); // ditto
}
