use std::os::raw::c_void;

type CRevPx = c_void;

#[repr(C)]
struct CRpRule {
    match_path: *const u8,
    rewrite: *const u8,
    host: *const u8,
    port: *const u8,
}

#[repr(C)]
struct CRpRules {
    entries: *const CRpRule,
    count: i32,
}

unsafe extern "C" {
    fn revpx_set_log_level(level: i32);
    fn revpx_use_colored_log();
    fn revpx_use_simple_log();
    fn revpx_add_domain(
        revpx: *mut CRevPx,
        domain: *const u8,
        rules: *const CRpRules,
        port: *const u8,
        cert: *const u8,
        key: *const u8,
    );
    fn revpx_run_server(revpx: *mut CRevPx) -> i32;
    fn revpx_create(http_port: *const u8, https_port: *const u8) -> *mut CRevPx;
    fn revpx_free(revpx: *mut CRevPx);
}

/// A single routing rule for path-based proxying.
#[derive(Debug, Clone, Default)]
pub struct RouteRule {
    /// Path prefix to match (e.g. "/api")
    pub match_path: String,
    /// Replace matched prefix with this (None = no rewrite)
    pub rewrite: Option<String>,
    /// Backend host override (None = default "127.0.0.1")
    pub host: Option<String>,
    /// Backend port override (None = use domain default)
    pub port: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct DomainConfig {
    pub domain: String,
    pub port: String,
    pub cert: String,
    pub key: String,
    /// Optional routing rules. If empty, the entire domain is proxied.
    pub rules: Vec<RouteRule>,
}

pub struct RevPx {
    ptr: *mut CRevPx,
}

impl RevPx {
    pub fn new(http_port: &str, https_port: &str) -> Self {
        let http_port_c = std::ffi::CString::new(http_port).unwrap();
        let https_port_c = std::ffi::CString::new(https_port).unwrap();
        unsafe {
            let ptr = revpx_create(http_port_c.as_ptr().cast(), https_port_c.as_ptr().cast());
            Self { ptr }
        }
    }

    pub fn default() -> Self {
        Self::new("80", "443")
    }

    pub fn set_log_level(level: i32) {
        unsafe {
            revpx_set_log_level(level);
        }
    }

    pub fn use_colored_log() {
        unsafe {
            revpx_use_colored_log();
        }
    }

    pub fn use_simple_log() {
        unsafe {
            revpx_use_simple_log();
        }
    }

    pub fn as_ptr(&self) -> *mut CRevPx {
        self.ptr
    }

    pub fn add_domain(&self, config: DomainConfig) {
        let domain = std::ffi::CString::new(config.domain).unwrap();
        let port = std::ffi::CString::new(config.port).unwrap();
        let cert = std::ffi::CString::new(config.cert).unwrap();
        let key = std::ffi::CString::new(config.key).unwrap();

        if config.rules.is_empty() {
            unsafe {
                revpx_add_domain(
                    self.ptr,
                    domain.as_ptr().cast(),
                    std::ptr::null(),
                    port.as_ptr().cast(),
                    cert.as_ptr().cast(),
                    key.as_ptr().cast(),
                );
            }
        } else {
            // Build C rule structs. Keep CStrings alive until after the call.
            let mut c_strings: Vec<(
                std::ffi::CString,
                Option<std::ffi::CString>,
                Option<std::ffi::CString>,
                Option<std::ffi::CString>,
            )> = Vec::with_capacity(config.rules.len());

            for r in &config.rules {
                c_strings.push((
                    std::ffi::CString::new(r.match_path.as_str()).unwrap(),
                    r.rewrite.as_ref().map(|s| std::ffi::CString::new(s.as_str()).unwrap()),
                    r.host.as_ref().map(|s| std::ffi::CString::new(s.as_str()).unwrap()),
                    r.port.as_ref().map(|s| std::ffi::CString::new(s.as_str()).unwrap()),
                ));
            }

            let c_rules: Vec<CRpRule> = c_strings
                .iter()
                .map(|(m, rw, h, p)| CRpRule {
                    match_path: m.as_ptr().cast(),
                    rewrite: rw.as_ref().map_or(std::ptr::null(), |s| s.as_ptr().cast()),
                    host: h.as_ref().map_or(std::ptr::null(), |s| s.as_ptr().cast()),
                    port: p.as_ref().map_or(std::ptr::null(), |s| s.as_ptr().cast()),
                })
                .collect();

            let rules = CRpRules {
                entries: c_rules.as_ptr(),
                count: c_rules.len() as i32,
            };

            unsafe {
                revpx_add_domain(
                    self.ptr,
                    domain.as_ptr().cast(),
                    &rules,
                    port.as_ptr().cast(),
                    cert.as_ptr().cast(),
                    key.as_ptr().cast(),
                );
            }
        }
    }

    pub fn add_domains(&self, configs: Vec<DomainConfig>) {
        for config in configs {
            self.add_domain(config);
        }
    }

    pub fn run_server(&self) -> i32 {
        unsafe {
            return revpx_run_server(self.ptr);
        }
    }
}

impl Drop for RevPx {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                revpx_free(self.ptr);
            }
            self.ptr = std::ptr::null_mut();
        }
    }
}
