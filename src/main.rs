//! An implementation of the Stateless OpenPGP Command Line Interface
//! using Sequoia.
//!
//! This implements a subset of the [Stateless OpenPGP Command Line
//! Interface] using the Sequoia OpenPGP implementation.
//!
//!   [Stateless OpenPGP Command Line Interface]: https://datatracker.ietf.org/doc/draft-dkg-openpgp-stateless-cli/

use sequoia_sop::SQOP;

fn main() {
    #[cfg(feature = "cliv")]
    let variant = sop::cli::Variant::Verification;

    #[cfg(feature = "cli")]
    let variant = sop::cli::Variant::Full;

    sop::cli::main(&mut SQOP::default(), variant);
}
