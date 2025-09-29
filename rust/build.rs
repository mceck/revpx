fn main() {
    let mut lib = cc::Build::new();
    lib.file("../src/revpx-lib.c");

    if let Ok(openssl) = pkg_config::Config::new().probe("openssl") {
        for include in openssl.include_paths {
            lib.include(include);
        }
    } else {
        panic!("Could not find OpenSSL installation via pkg-config");
    }

    lib.compile("revpx");
}
