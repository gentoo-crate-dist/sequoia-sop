//! Version information.

use sop::Result;

/// Version information for SQOP.
pub struct Version {
    name: &'static str,
}

impl Default for Version {
    fn default() -> Self {
        Self::with_name("sequoia-sop")
    }
}

impl Version {
    /// Returns a version with the name set to the given value.
    pub fn with_name(name: &'static str) -> Self {
        Version {
            name,
        }
    }
}

impl sop::ops::Version<'_> for Version {
    fn frontend(&self) -> Result<sop::ops::VersionInfo> {
        Ok(sop::ops::VersionInfo {
            name: self.name.into(),
            version: env!("CARGO_PKG_VERSION").into(),
        })
    }

    fn backend(&self) -> Result<sop::ops::VersionInfo> {
        Ok(sop::ops::VersionInfo {
            name: "Sequoia".into(),
            version: sequoia_openpgp::VERSION.into(),
        })
    }

    fn extended(&self) -> Result<String> {
        Ok(vec![
            sequoia_openpgp::crypto::backend(),
            format!("Sequoia {}", sequoia_openpgp::VERSION),
        ].join("\n"))
    }
}
