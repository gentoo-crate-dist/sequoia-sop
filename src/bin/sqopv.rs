//! An implementation of the Stateless OpenPGP Command Line Interface
//! using Sequoia.
//!
//! This implements a subset of the [Stateless OpenPGP Command Line
//! Interface] using the Sequoia OpenPGP implementation.
//!
//!   [Stateless OpenPGP Command Line Interface]: https://datatracker.ietf.org/doc/draft-dkg-openpgp-stateless-cli/

use sequoia_policy_config::ConfiguredStandardPolicy;
use sequoia_sop::SQOP;

fn main() {
    let mut policy = ConfiguredStandardPolicy::default();
    let _ = policy.parse_default_config();
    let policy = policy.build();

    sop::cli::main(&mut SQOP::with_policy(&policy),
                   sop::cli::Variant::Verification);
}
