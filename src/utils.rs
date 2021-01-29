use std::path::Path;

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::{
    cert::{
        Cert,
        CertParser,
    },
    crypto::{
        Password,
    },
    parse::Parse,
};

use super::{
    Error,
    Result,
};

fn is_special_designator<S: AsRef<str>>(file: S) -> bool {
    file.as_ref().starts_with("@")
}

/// Loads the given (special) file.
pub fn load_file<S: AsRef<str>>(file: S) -> Result<std::fs::File> {
    let f = file.as_ref();

    if is_special_designator(f) {
        if Path::new(f).exists() {
            return Err(anyhow::Error::from(Error::AmbiguousInput))
                .context(format!("File {:?} exists", f));
        }

        return Err(anyhow::Error::from(Error::UnsupportedSpecialPrefix));
    }

    std::fs::File::open(f).map_err(|_| Error::MissingInput)
            .context(format!("Failed to open file {:?}", f))
}

/// Creates the given (special) file.
pub fn create_file<S: AsRef<str>>(file: S) -> Result<std::fs::File> {
    let f = file.as_ref();

    if is_special_designator(f) {
        if Path::new(f).exists() {
            return Err(anyhow::Error::from(Error::AmbiguousInput))
                .context(format!("File {:?} exists", f));
        }

        return Err(anyhow::Error::from(Error::UnsupportedSpecialPrefix));
    }

    if Path::new(f).exists() {
        return Err(anyhow::Error::from(Error::OutputExists))
            .context(format!("File {:?} exists", f));
    }

    std::fs::File::create(f).map_err(|_| Error::MissingInput) // XXX
            .context(format!("Failed to create file {:?}", f))
}

/// Loads the certs given by the (special) files.
pub fn load_certs(files: Vec<String>) -> Result<Vec<Cert>> {
    let mut certs = vec![];
    for f in files {
        let r = load_file(&f)?;
        for cert in CertParser::from_reader(r).map_err(|_| Error::BadData)
            .context(format!("Failed to load CERTS from file {:?}", f))?
        {
            certs.push(
                cert.context(format!("Malformed certificate in file {:?}", f))?
            );
        }
    }
    Ok(certs)
}

/// Loads the KEY given by the (special) files.
pub fn load_keys(files: Vec<String>) -> Result<Vec<Cert>> {
    let mut keys = vec![];
    for f in files {
        let r = load_file(&f)?;
        keys.push(Cert::from_reader(r).map_err(|_| Error::BadData)
                   .context(format!("Failed to load KEY from file {:?}", f))?);
    }
    Ok(keys)
}

/// Frobnicates the strings and converts them to passwords.
pub fn frob_passwords(p: Vec<String>) -> Result<Vec<Password>> {
    // XXX: Maybe do additional checks.
    Ok(p.iter().map(|p| p.trim_end().into()).collect())
}
