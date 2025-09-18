fn main() {
    let revpx = revpx::RevPx::new("80", "443");
    let domains = vec![revpx::DomainConfig {
        domain: "example.localhost".to_string(),
        host: None,
        port: "9002".to_string(),
        cert: "example.localhost.pem".to_string(),
        key: "example.localhost-key.pem".to_string(),
    }];
    for domain in domains {
        revpx.add_domain(domain);
    }
    revpx.run_server();
}
