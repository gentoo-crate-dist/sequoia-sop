use sequoia_sop::{SQOP, Certs, Keys, Sigs};

#[macro_use]
extern crate sop;
sop::create!(SQOP<'static>, Certs, Keys, Sigs);
