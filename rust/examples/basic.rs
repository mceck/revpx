fn main() {
    let revpx = revpx::RevPx::default();
    revpx.add_domains(vec![revpx::DomainConfig {
        domain: "example.localhost".to_string(),
        host: None,
        port: "8080".to_string(),
        cert: "example.localhost.pem".to_string(),
        key: "example.localhost-key.pem".to_string(),
    }]);
    revpx.run_server();
}
