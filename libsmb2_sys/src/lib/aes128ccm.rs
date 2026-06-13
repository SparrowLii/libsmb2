mod ffi {
    #![allow(
        dead_code,
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals
    )]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidMacLength,
    AuthenticationFailed,
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn encrypt(
    key: &mut [u8; 16],
    nonce: &mut [u8],
    aad: &mut [u8],
    payload: &mut [u8],
    mac_len: usize,
) -> Result<Vec<u8>> {
    if mac_len > 16 {
        return Err(Error::InvalidMacLength);
    }

    let mut mac = vec![0; mac_len];
    unsafe {
        ffi::aes128ccm_encrypt(
            key.as_mut_ptr(),
            nonce.as_mut_ptr(),
            nonce.len(),
            aad.as_mut_ptr(),
            aad.len(),
            payload.as_mut_ptr(),
            payload.len(),
            mac.as_mut_ptr(),
            mac.len(),
        );
    }
    Ok(mac)
}

pub fn decrypt(
    key: &mut [u8; 16],
    nonce: &mut [u8],
    aad: &mut [u8],
    payload: &mut [u8],
    mac: &mut [u8],
) -> Result<()> {
    let status = unsafe {
        ffi::aes128ccm_decrypt(
            key.as_mut_ptr(),
            nonce.as_mut_ptr(),
            nonce.len(),
            aad.as_mut_ptr(),
            aad.len(),
            payload.as_mut_ptr(),
            payload.len(),
            mac.as_mut_ptr(),
            mac.len(),
        )
    };

    if status == 0 {
        Ok(())
    } else {
        Err(Error::AuthenticationFailed)
    }
}
