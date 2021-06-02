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
$ echo "a message" | sqop encrypt julia.public.pgp > message.pgpo
$ sqop decrypt julia.secret.pgp < message.pgp
a message
```

Here, we encrypt a message with Julia's certificate, and decrypt it
with her key.
