use std::os::raw::c_void;

type CRevPx = c_void;

unsafe extern "C" {
    fn revpx_set_log_level(level: i32);
    fn revpx_use_colored_log();
    fn revpx_use_simple_log();
    fn revpx_create(http_port: *const u8, https_port: *const u8) -> *mut CRevPx;
    fn revpx_free(revpx: *mut CRevPx);
    fn revpx_begin_domain(
        revpx: *mut CRevPx,
        domain: *const u8,
        cert: *const u8,
        key: *const u8,
    );
    fn revpx_add_backend(
        revpx: *mut CRevPx,
        host: *const u8,
        port: *const u8,
        matches: *const *const u8,
        match_count: i32,
        rewrite: *const u8,
    );
    fn revpx_end_domain(revpx: *mut CRevPx) -> bool;
    fn revpx_run_server(revpx: *mut CRevPx) -> i32;
}

/// A backend routing rule. Multiple match patterns are OR'd.
#[derive(Debug, Clone, Default)]
pub struct Backend {
    /// Backend host (None = "127.0.0.1")
    pub host: Option<String>,
    /// Backend port
    pub port: String,
    /// Glob patterns to match (empty = catch-all).
    /// Supports `*` (any non-slash) and `**` (any including slash).
    pub matches: Vec<String>,
    /// Replace matched prefix with this (None = no rewrite)
    pub rewrite: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct DomainConfig {
    pub domain: String,
    pub cert: String,
    pub key: String,
    /// Backend routing rules. If empty or single catch-all, entire domain is proxied.
    pub backends: Vec<Backend>,
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
        unsafe { revpx_set_log_level(level); }
    }

    pub fn use_colored_log() {
        unsafe { revpx_use_colored_log(); }
    }

    pub fn use_simple_log() {
        unsafe { revpx_use_simple_log(); }
    }

    pub fn as_ptr(&self) -> *mut CRevPx {
        self.ptr
    }

    pub fn add_domain(&self, config: DomainConfig) {
        let domain = std::ffi::CString::new(config.domain).unwrap();
        let cert = std::ffi::CString::new(config.cert).unwrap();
        let key = std::ffi::CString::new(config.key).unwrap();

        unsafe {
            revpx_begin_domain(
                self.ptr,
                domain.as_ptr().cast(),
                cert.as_ptr().cast(),
                key.as_ptr().cast(),
            );
        }

        for b in &config.backends {
            let host_c = b.host.as_ref()
                .map(|s| std::ffi::CString::new(s.as_str()).unwrap());
            let port_c = std::ffi::CString::new(b.port.as_str()).unwrap();
            let rewrite_c = b.rewrite.as_ref()
                .map(|s| std::ffi::CString::new(s.as_str()).unwrap());

            let match_cstrings: Vec<std::ffi::CString> = b.matches.iter()
                .map(|s| std::ffi::CString::new(s.as_str()).unwrap())
                .collect();
            let match_ptrs: Vec<*const u8> = match_cstrings.iter()
                .map(|s| s.as_ptr().cast())
                .collect();

            unsafe {
                revpx_add_backend(
                    self.ptr,
                    host_c.as_ref().map_or(std::ptr::null(), |s| s.as_ptr().cast()),
                    port_c.as_ptr().cast(),
                    if match_ptrs.is_empty() { std::ptr::null() } else { match_ptrs.as_ptr() },
                    match_ptrs.len() as i32,
                    rewrite_c.as_ref().map_or(std::ptr::null(), |s| s.as_ptr().cast()),
                );
            }
        }

        unsafe {
            revpx_end_domain(self.ptr);
        }
    }

    pub fn add_domains(&self, configs: Vec<DomainConfig>) {
        for config in configs {
            self.add_domain(config);
        }
    }

    pub fn run_server(&self) -> i32 {
        unsafe { revpx_run_server(self.ptr) }
    }
}

impl Drop for RevPx {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { revpx_free(self.ptr); }
            self.ptr = std::ptr::null_mut();
        }
    }
}
