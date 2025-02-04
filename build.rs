use std::{
    env,
    error::Error,
    fs,
    path::PathBuf,
};

#[cfg(any(feature = "cli", feature = "cliv"))]
use sop::cli::Variant;

#[path = "src/version.rs"]
mod version;

fn main() {
    #[cfg(feature = "cli")]
    cli("sqop", Variant::Full).unwrap();

    #[cfg(feature = "cliv")]
    cli("sqopv", Variant::Verification).unwrap();
}

/// Writes shell completions and man pages.
#[cfg(any(feature = "cli", feature = "cliv"))]
fn cli(name: &'static str, variant: Variant) -> Result<(), Box<dyn Error>> {
    let version = version::Version::with_name(name);

    sop::cli::write_shell_completions2(
        variant, name, asset_out_dir("shell-completions")?)?;
    sop::cli::write_man_pages(
        variant, &version, "Sequoia PGP",
        asset_out_dir("man-pages")?)?;

    Ok(())
}

/// Variable name to control the asset out directory with.
const ASSET_OUT_DIR: &str = "ASSET_OUT_DIR";

/// Returns the directory to write the given assets to.
#[allow(dead_code)]
fn asset_out_dir(asset: &str) -> Result<PathBuf, Box<dyn Error>> {
    println!("cargo:rerun-if-env-changed={}", ASSET_OUT_DIR);
    let outdir: PathBuf =
        env::var_os(ASSET_OUT_DIR).unwrap_or_else(
            || env::var_os("OUT_DIR").expect("OUT_DIR not set")).into();
    if outdir.exists() && ! outdir.is_dir() {
        return Err(
            format!("{}={:?} is not a directory", ASSET_OUT_DIR, outdir).into());
    }

    let path = outdir.join(asset);
    fs::create_dir_all(&path)?;
    Ok(path)
}
