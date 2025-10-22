use std::os::raw::c_void;

type CRevPx = c_void;

unsafe extern "C" {
    fn revpx_add_domain(
        revpx: *mut CRevPx,
        domain: *const i8,
        host: *const i8,
        port: *const i8,
        cert: *const i8,
        key: *const i8,
    );
    fn revpx_run_server(revpx: *mut CRevPx) -> i32;
    fn revpx_create(http_port: *const i8, https_port: *const i8) -> *mut CRevPx;
    fn revpx_free(revpx: *mut CRevPx);
}

#[derive(Debug, Clone, Default)]
pub struct DomainConfig {
    pub domain: String,
    pub host: Option<String>,
    pub port: String,
    pub cert: String,
    pub key: String,
}

pub struct RevPx {
    ptr: *mut CRevPx,
}

impl RevPx {
    pub fn new(http_port: &str, https_port: &str) -> Self {
        let http_port_c = std::ffi::CString::new(http_port).unwrap();
        let https_port_c = std::ffi::CString::new(https_port).unwrap();
        unsafe {
            let ptr = revpx_create(http_port_c.as_ptr(), https_port_c.as_ptr());
            Self { ptr }
        }
    }

    pub fn default() -> Self {
        Self::new("80", "443")
    }

    pub fn as_ptr(&self) -> *mut CRevPx {
        self.ptr
    }

    pub fn add_domain(&self, config: DomainConfig) {
        let domain = std::ffi::CString::new(config.domain).unwrap();
        let port = std::ffi::CString::new(config.port).unwrap();
        let cert = std::ffi::CString::new(config.cert).unwrap();
        let key = std::ffi::CString::new(config.key).unwrap();
        let host = std::ffi::CString::new(config.host.unwrap_or_default()).unwrap();

        unsafe {
            revpx_add_domain(
                self.ptr,
                domain.as_ptr(),
                host.as_ptr(),
                port.as_ptr(),
                cert.as_ptr(),
                key.as_ptr(),
            );
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
