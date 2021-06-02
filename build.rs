#[cfg(feature = "cli")]
fn main() {
    let outdir = std::env::var_os("CARGO_TARGET_DIR")
        .or(std::env::var_os("OUT_DIR"))
        .expect("cargo to set OUT_DIR");
    sop::cli::write_shell_completions("sqop", outdir).unwrap();
}

#[cfg(not(feature = "cli"))]
fn main() {}
