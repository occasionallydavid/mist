use std::{env, path::PathBuf, process::Command};

fn c_lto_flag(rustflags: &str) -> &'static str {
    let mut plugin = false;
    let mut fat = false;
    let mut flags = rustflags.split('\x1f');
    while let Some(flag) = flags.next() {
        let option = match flag {
            "-C" | "--codegen" => flags.next(),
            _ => flag
                .strip_prefix("-C")
                .or_else(|| flag.strip_prefix("--codegen=")),
        };
        let Some(option) = option else { continue };
        let (name, value) = option.split_once('=').unwrap_or((option, ""));
        match name {
            "linker-plugin-lto" => plugin = !matches!(value, "n" | "no" | "off" | "false"),
            "lto" => fat = matches!(value, "" | "fat" | "y" | "yes" | "on" | "true"),
            _ => {}
        }
    }

    match (plugin, fat) {
        (false, _) => "",
        (true, false) => "-flto=thin",
        (true, true) => "-flto=full",
    }
}

fn main() {
    let core = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("../core");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    for path in ["Makefile", "include", "src", "third_party"] {
        println!("cargo:rerun-if-changed={}", core.join(path).display());
    }
    for key in ["CC", "AR", "CPPFLAGS", "CFLAGS", "CARGO_ENCODED_RUSTFLAGS"] {
        println!("cargo:rerun-if-env-changed={key}");
    }

    let lto = c_lto_flag(&env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default());
    let mut make = Command::new("make");
    make.current_dir(core)
        .arg(format!("BUILD={}", out.display()))
        .arg(format!("LTO={lto}"))
        .args(["-B", "all"]);
    if !lto.is_empty() && env::var_os("CC").is_none() {
        make.arg("CC=clang");
    }
    let status = make.status().expect("run make to build MIST");
    assert!(status.success(), "MIST build failed");
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=mist");
}
