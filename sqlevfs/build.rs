fn main() {
    // Dynamically link against the system libsqlite3.
    // The host process (or LD_PRELOAD environment) provides it.
    if let Ok(lib) = pkg_config::probe_library("sqlite3") {
        for path in &lib.link_paths {
            println!("cargo:rustc-link-search=native={}", path.display());
        }
    } else {
        // Fallback: assume it's on the default linker path.
        println!("cargo:rustc-link-lib=dylib=sqlite3");
    }
}