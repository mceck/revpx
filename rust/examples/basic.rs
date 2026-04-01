fn main() {
    let revpx = revpx::RevPx::default();
    revpx::RevPx::use_colored_log();
    revpx.add_domains(vec![revpx::DomainConfig {
        domain: "test.localhost".to_string(),
        cert: "test.localhost.pem".to_string(),
        key: "test.localhost-key.pem".to_string(),
        backends: vec![revpx::Backend {
            port: "8080".to_string(),
            ..Default::default()
        }],
    }]);
    revpx.run_server();
}
