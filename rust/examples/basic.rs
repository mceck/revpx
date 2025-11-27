fn main() {
    let revpx = revpx::RevPx::default();
    revpx.add_domains(vec![revpx::DomainConfig {
        domain: "example.localhost".to_string(),
        port: Some("8080".to_string()),
        cert: "example.localhost.pem".to_string(),
        key: "example.localhost-key.pem".to_string(),
        routes: vec![revpx::RouteConfig {
            path: "/api".to_string(),
            port: "8081".to_string(),
            rewrite: true,
            ..Default::default()
        }],
        ..Default::default()
    }]);
    revpx.run_server();
}
