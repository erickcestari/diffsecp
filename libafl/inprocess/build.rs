fn main() {
    println!("cargo:rerun-if-changed=src/cmp.c");
    cc::Build::new()
        .file("src/cmp.c")
        .flag("-std=c11")
        .warnings(true)
        .compile("diffsecp_cmp");
}
