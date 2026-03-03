//! # C API
//!
//! C-compatible API for FFI bindings.

#![allow(unsafe_code)]

use std::ffi::CString;
use std::os::raw::c_char;

/// SDK version
#[no_mangle]
pub extern "C" fn aethelred_version() -> *const c_char {
    static VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
    VERSION.as_ptr() as *const c_char
}

/// Initialize the SDK
#[no_mangle]
pub extern "C" fn aethelred_init() -> i32 {
    0 // Success
}

/// Cleanup the SDK
#[no_mangle]
pub extern "C" fn aethelred_cleanup() {
    // Cleanup resources
}

/// Generate a keypair
#[no_mangle]
pub extern "C" fn aethelred_generate_keypair(
    public_key: *mut u8,
    public_key_len: *mut usize,
    _secret_key: *mut u8,
    _secret_key_len: *mut usize,
) -> i32 {
    let keypair = crate::crypto::HybridKeypair::generate();
    let pk_bytes = keypair.public_key().to_bytes();

    unsafe {
        if !public_key.is_null() && !public_key_len.is_null() {
            let len = std::cmp::min(*public_key_len, pk_bytes.len());
            std::ptr::copy_nonoverlapping(pk_bytes.as_ptr(), public_key, len);
            *public_key_len = pk_bytes.len();
        }
    }

    0 // Success
}

/// Free a string allocated by the SDK
#[no_mangle]
pub extern "C" fn aethelred_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            drop(CString::from_raw(s));
        }
    }
}
