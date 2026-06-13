// tests/translated_cases/tests/aes128ccm_test_translated.rs
// Translated from legacy test file: tests/aes128ccm-test.c
// Manifest source key is normalized to tests/aes128ccm_test.c because Rust module paths cannot contain '-'.

use libsmb2_sys::legacy::aes128ccm;

// Translated from assert-based: test_1
// Source: tests/aes128ccm_test.c:10-57
// Assertion Count: 2
#[test]
fn test_translate_aes128ccm_test_test_1() {
    // unsigned char key[16] = {0x40..0x4f}; nonce[7] = {0x10..0x16}; aad[8] = {0x00..0x07}; p[4] = {0x20..0x23}; mlen = 4.
    let mut key = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f,
    ];
    let mut nonce = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16];
    let mut aad = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let plaintext = [0x20, 0x21, 0x22, 0x23];
    let mut payload = plaintext;

    // aes128ccm_encrypt(..., buf, sizeof(p), &buf[sizeof(p)], mlen);
    let mut mac = aes128ccm::encrypt(&mut key, &mut nonce, &mut aad, &mut payload, 4).unwrap();

    // if (rc) exit(10);
    let decrypt_result = aes128ccm::decrypt(&mut key, &mut nonce, &mut aad, &mut payload, &mut mac);
    assert_eq!(decrypt_result, Ok(()));

    // if (memcmp(p, &buf[0], sizeof(p))) exit(10);
    assert_eq!(payload, plaintext);
}

// Translated from assert-based: test_2
// Source: tests/aes128ccm_test.c:59-112
// Assertion Count: 2
#[test]
fn test_translate_aes128ccm_test_test_2() {
    // unsigned char key[16] = {0x40..0x4f}; nonce[12] = {0x10..0x1b}; aad[20] = {0x00..0x13}; p[24] = {0x20..0x37}; mlen = 8.
    let mut key = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f,
    ];
    let mut nonce = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
    ];
    let mut aad = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13,
    ];
    let plaintext = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
        0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    ];
    let mut payload = plaintext;

    // aes128ccm_encrypt(..., buf, sizeof(p), &buf[sizeof(p)], mlen);
    let mut mac = aes128ccm::encrypt(&mut key, &mut nonce, &mut aad, &mut payload, 8).unwrap();

    // if (rc) exit(10);
    let decrypt_result = aes128ccm::decrypt(&mut key, &mut nonce, &mut aad, &mut payload, &mut mac);
    assert_eq!(decrypt_result, Ok(()));

    // if (memcmp(p, &buf[0], sizeof(p))) exit(10);
    assert_eq!(payload, plaintext);
}
