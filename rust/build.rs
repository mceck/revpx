fn main() {
    let mut lib = cc::Build::new();
    lib.file("../src/revpx-lib.c");
    #[cfg(target_os = "macos")]
    {
        let openssl_include = "/opt/homebrew/include/";
        lib.include(openssl_include);
        println!("cargo:include={}", openssl_include);
        println!("cargo:rustc-link-search=native=/opt/homebrew/lib");
    }
    lib.compile("revpx");
    println!("cargo:rustc-link-lib=crypto");
    println!("cargo:rustc-link-lib=ssl");
}
