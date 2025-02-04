//! An implementation of the Stateless OpenPGP Command Line Interface
//! using Sequoia.
//!
//! This implements a subset of the [Stateless OpenPGP Command Line
//! Interface] using the Sequoia OpenPGP implementation.
//!
//!   [Stateless OpenPGP Command Line Interface]: https://datatracker.ietf.org/doc/draft-dkg-openpgp-stateless-cli/

use sequoia_sop::SQOP;

fn main() {
    // Be clever and inspect argv[0].
    let argv0 = std::env::args_os().next();
    let variant = if argv0
        .map(|s| s.to_string_lossy().contains("sqopv"))
        .unwrap_or(false)
    {
        // Restrict to the verification subset.
        sop::cli::Variant::Verification
    } else {
        sop::cli::Variant::Full
    };

    sop::cli::main(&mut SQOP::default(), variant);
}
