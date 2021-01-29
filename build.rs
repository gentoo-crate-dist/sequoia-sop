use std::env;
use std::fs;
use clap::Shell;
use structopt::StructOpt;

mod cli {
    include!("src/cli.rs");
}

fn main() {
    let outdir = env::var_os("CARGO_TARGET_DIR")
        .or(env::var_os("OUT_DIR"))
        .expect("cargo to set OUT_DIR");
    fs::create_dir_all(&outdir).unwrap();
    let mut clap = cli::SOP::clap();
    for shell in &[Shell::Bash, Shell::Fish, Shell::Zsh, Shell::PowerShell,
                   Shell::Elvish] {
        clap.gen_completions("sqop", *shell, &outdir);
    }
}
