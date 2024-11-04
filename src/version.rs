//! Version information.

use sop::Result;

/// Version information for SQOP.
#[derive(Default)]
pub struct Version {}

impl sop::ops::Version<'_> for Version {
    fn frontend(&self) -> Result<sop::ops::VersionInfo> {
	#[cfg(feature = "cliv")]
	let name = "sqopv";

	#[cfg(feature = "cli")]
	let name = "sqop";

        Ok(sop::ops::VersionInfo {
            name: name.into(),
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
