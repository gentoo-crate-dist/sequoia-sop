An implementation of the Stateless OpenPGP Interface using Sequoia.

This implements the [Stateless OpenPGP Command Line Interface] (SOP)
using the Sequoia OpenPGP implementation.  This crate implements the
[Rust SOP interface], as well as providing a command line frontend.

SOP implementations enjoy broad compatibility, see the [OpenPGP
interoperability test suite].

  [Stateless OpenPGP Command Line Interface]: https://datatracker.ietf.org/doc/draft-dkg-openpgp-stateless-cli/
  [Rust SOP interface]: https://docs.rs/sop
  [OpenPGP interoperability test suite]: https://tests.sequoia-pgp.org/

# SOP cli primer

To build the cli frontend, enable the "cli" feature, e.g. using `cargo
build --features=cli` or `cargo install sequoia-sop --features=cli`.

To demonstrate SOP, let's generate a key, and encrypt and decrypt a
message:

```sh
$ sqop generate-key julia@example.org > julia.secret.pgp
$ sqop extract-cert < julia.secret.pgp > julia.public.pgp
```

First, we generate a key for `julia@example.org`.  Next, we extract
the certificate, i.e. the key without the secret key material.

```sh
$ echo "a message" | sqop encrypt julia.public.pgp > message.pgp
$ sqop decrypt julia.secret.pgp < message.pgp
a message
```

Here, we encrypt a message with Julia's certificate, and decrypt it
with her key.

# Selecting different crypto backends

Sequoia PGP supports a number of [different crypto libraries].  In
order to select one for use with this crate, disable the default
features and explicitly select a backend.

  [different crypto libraries]: https://gitlab.com/sequoia-pgp/sequoia/-/tree/main/openpgp#crypto-backends

To select an alternate crypto backend when building the cli frontend,
for example the OpenSSL backend, do:

```sh
$ cargo build --no-default-features --features cli,sequoia-openpgp/compression,sequoia-openpgp/crypto-openssl
```

Or to install it from crates.io:

```sh
$ cargo install sequoia-sop --no-default-features --features cli,sequoia-openpgp/compression,sequoia-openpgp/crypto-openssl
```

In order to use it from Rust, depend sequoia-openpgp and select a
backend, like so:

```toml
[dependencies]
sop = { version = "*", default-features = false }
sequoia-openpgp = { version = "*", default-features = false, features = ["compression", "crypto-openssl"] }
```

# Shell completions

By default shell completions are put into the `cargo` target
directory, but the exact location is unpredictable.  To write the
assets to a predictable location, set the environment variable
`ASSET_OUT_DIR` to a suitable location.
