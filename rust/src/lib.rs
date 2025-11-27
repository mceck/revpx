use std::os::raw::c_void;

type CRevPx = c_void;

unsafe extern "C" {
    fn revpx_add_domain(
        revpx: *mut CRevPx,
        domain: *const u8,
        host: *const u8,
        port: *const u8,
        cert: *const u8,
        key: *const u8,
    ) -> bool;
    fn revpx_add_domain_route(
        revpx: *mut CRevPx,
        domain: *const u8,
        path: *const u8,
        host: *const u8,
        port: *const u8,
        rewrite: bool,
    ) -> bool;
    fn revpx_run_server(revpx: *mut CRevPx) -> i32;
    fn revpx_create(http_port: *const u8, https_port: *const u8) -> *mut CRevPx;
    fn revpx_free(revpx: *mut CRevPx);
}

#[derive(Debug, Clone, Default)]
pub struct RouteConfig {
    pub path: String,
    pub host: Option<String>,
    pub port: String,
    pub rewrite: bool,
}

#[derive(Debug, Clone, Default)]
pub struct DomainConfig {
    pub domain: String,
    pub host: Option<String>,
    pub port: Option<String>,
    pub cert: String,
    pub key: String,
    pub routes: Vec<RouteConfig>,
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

    pub fn as_ptr(&self) -> *mut CRevPx {
        self.ptr
    }

    pub fn add_domain(&self, config: DomainConfig) -> bool {
        let domain = std::ffi::CString::new(config.domain).unwrap();
        let port = std::ffi::CString::new(config.port.unwrap_or_default()).unwrap();
        let cert = std::ffi::CString::new(config.cert).unwrap();
        let key = std::ffi::CString::new(config.key).unwrap();
        let host = std::ffi::CString::new(config.host.unwrap_or_default()).unwrap();

        let mut ok = unsafe {
            revpx_add_domain(
                self.ptr,
                domain.as_ptr().cast(),
                host.as_ptr().cast(),
                port.as_ptr().cast(),
                cert.as_ptr().cast(),
                key.as_ptr().cast(),
            )
        };

        for route in config.routes {
            let path = std::ffi::CString::new(route.path).unwrap();
            let rport = std::ffi::CString::new(route.port).unwrap();
            let rhost = std::ffi::CString::new(route.host.unwrap_or_default()).unwrap();
            let added_route = unsafe {
                revpx_add_domain_route(
                    self.ptr,
                    domain.as_ptr().cast(),
                    path.as_ptr().cast(),
                    rhost.as_ptr().cast(),
                    rport.as_ptr().cast(),
                    route.rewrite,
                )
            };
            ok &= added_route;
        }
        ok
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
