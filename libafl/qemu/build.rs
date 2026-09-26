//! Links the reference: src/guest.c and one libsecp build for the host, which
//! the Makefile archives as libdiffsecp_reference.a in DIFFSECP_REFERENCE_DIR.

fn main() {
    println!("cargo:rerun-if-env-changed=DIFFSECP_REFERENCE_DIR");
    let dir = std::env::var("DIFFSECP_REFERENCE_DIR").expect(
        "DIFFSECP_REFERENCE_DIR must hold libdiffsecp_reference.a; build with `make qemu-fuzz`",
    );
    println!("cargo:rerun-if-changed={dir}/libdiffsecp_reference.a");
    println!("cargo:rustc-link-search=native={dir}");
    println!("cargo:rustc-link-lib=static=diffsecp_reference");
}
