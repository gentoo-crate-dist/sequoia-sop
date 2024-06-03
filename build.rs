use std::{
    env,
    error::Error,
    fs,
    path::PathBuf,
};

#[cfg(feature = "cli")]
fn main() {
    sop::cli::write_shell_completions(
        "sqop", asset_out_dir("shell-completions").unwrap()).unwrap();
}

#[cfg(not(feature = "cli"))]
fn main() {}

/// Variable name to control the asset out directory with.
const ASSET_OUT_DIR: &str = "ASSET_OUT_DIR";

/// Returns the directory to write the given assets to.
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
