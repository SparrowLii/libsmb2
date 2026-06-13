use std::{env, path::PathBuf};

fn main() {
    let legacy_root = PathBuf::from("..");
    let shims = [
        PathBuf::from("shim/include/libsmb2_private_ffi.c"),
        PathBuf::from("shim/include/portable-endian_ffi.c"),
        PathBuf::from("shim/lib/unicode_ffi.c"),
    ];
    let sources = [
        PathBuf::from("../lib/aes.c"),
        PathBuf::from("../lib/aes128ccm.c"),
        PathBuf::from("../lib/aes_apple.c"),
        PathBuf::from("../lib/aes_reference.c"),
        PathBuf::from("../lib/errors.c"),
        PathBuf::from("../lib/hmac-md5.c"),
        PathBuf::from("../lib/hmac.c"),
        PathBuf::from("../lib/md4c.c"),
        PathBuf::from("../lib/md5.c"),
        PathBuf::from("../lib/sha1.c"),
        PathBuf::from("../lib/sha224-256.c"),
        PathBuf::from("../lib/sha384-512.c"),
        PathBuf::from("../lib/timestamps.c"),
        PathBuf::from("../lib/unicode.c"),
        PathBuf::from("../lib/usha.c"),
    ];
    let headers = [
        PathBuf::from("shim/include/libsmb2_private_ffi.h"),
        PathBuf::from("shim/include/portable-endian_ffi.h"),
        PathBuf::from("shim/lib/unicode_ffi.h"),
    ];

    let mut build = cc::Build::new();
    for shim in &shims {
        build.file(shim);
    }
    for source in &sources {
        build.file(source);
    }
    build.include(&legacy_root);
    build.include(legacy_root.join("include"));
    build.include(legacy_root.join("include/smb2"));
    build.include(legacy_root.join("lib"));
    build.define("HAVE_STDINT_H", Some("1"));
    build.define("HAVE_STDLIB_H", Some("1"));
    build.define("HAVE_TIME_H", Some("1"));
    build.define("USE_SHA1", Some("1"));
    build.define("USE_SHA224", Some("1"));
    build.define("USE_SHA384_SHA512", Some("1"));
    build.define("_U_", Some("__attribute__((unused))"));
    build.flag_if_supported("-std=c99");
    build.flag("-include");
    build.flag("stddef.h");

    if env::var("CARGO_LLVM_COV").is_ok() {
        build.flag("-fprofile-instr-generate");
        build.flag("-fcoverage-mapping");
    }

    build.compile("libsmb2_sys_ffi");

    let bindings = bindgen::Builder::default()
        .header(headers[0].to_string_lossy())
        .header(headers[1].to_string_lossy())
        .header(headers[2].to_string_lossy())
        .header("../lib/aes.h")
        .header("../lib/aes128ccm.h")
        .header("../lib/aes_reference.h")
        .header("../include/smb2/smb2.h")
        .header("../include/smb2/libsmb2.h")
        .header("../lib/hmac-md5.h")
        .header("../lib/md4.h")
        .header("../lib/md5.h")
        .header("../lib/sha.h")
        .clang_arg(format!("-I{}", legacy_root.display()))
        .clang_arg(format!("-I{}", legacy_root.join("include").display()))
        .clang_arg(format!("-I{}", legacy_root.join("include/smb2").display()))
        .clang_arg(format!("-I{}", legacy_root.join("lib").display()))
        .clang_arg("-DHAVE_STDINT_H=1")
        .clang_arg("-DHAVE_STDLIB_H=1")
        .clang_arg("-DHAVE_TIME_H=1")
        .clang_arg("-DUSE_SHA1=1")
        .clang_arg("-DUSE_SHA224=1")
        .clang_arg("-DUSE_SHA384_SHA512=1")
        .clang_arg("-D_U_=__attribute__((unused))")
        .clang_arg("-include")
        .clang_arg("stddef.h")
        .clang_arg("-include")
        .clang_arg("stdint.h")
        .allowlist_function("libsmb2_private_ffi_.*")
        .allowlist_function("portable_endian_ffi_.*")
        .allowlist_function("AES128_ECB_encrypt")
        .allowlist_function("AES128_ECB_.*_reference")
        .allowlist_function("aes128ccm_.*")
        .allowlist_function("nterror_to_.*")
        .allowlist_function("smb2_hmac_md5")
        .allowlist_function("MD4.*")
        .allowlist_function("MD5.*")
        .allowlist_function("SHA.*")
        .allowlist_function("USHA.*")
        .allowlist_function("hmac")
        .allowlist_function("hmac.*")
        .allowlist_function("smb2_.*timeval.*")
        .allowlist_function("smb2_utf.*")
        .allowlist_function("unicode_ffi_.*")
        .allowlist_type("libsmb2_private_ffi_.*")
        .allowlist_type("portable_endian_ffi_.*")
        .allowlist_type("MD4_CTX")
        .allowlist_type("MD5Context")
        .allowlist_type("SHA.*")
        .allowlist_type("USHA.*")
        .allowlist_type("HMACContext")
        .allowlist_type("smb2_timeval")
        .allowlist_type("smb2_utf16")
        .allowlist_var("sha.*")
        .allowlist_var("SHA.*")
        .allowlist_var("USHA.*")
        .allowlist_var("LIBSMB2_PRIVATE_FFI_.*")
        .generate()
        .expect("generate libsmb2 private FFI bindings");

    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings.write_to_file(out.join("bindings.rs")).unwrap();

    for shim in &shims {
        println!("cargo:rerun-if-changed={}", shim.display());
    }
    for source in &sources {
        println!("cargo:rerun-if-changed={}", source.display());
    }
    for header in &headers {
        println!("cargo:rerun-if-changed={}", header.display());
    }
    println!("cargo:rerun-if-changed=../include/libsmb2-private.h");
    println!("cargo:rerun-if-changed=../include/portable-endian.h");
    println!("cargo:rerun-if-changed=../include/smb2/smb2-ioctl.h");
    println!("cargo:rerun-if-changed=../lib/aes.h");
    println!("cargo:rerun-if-changed=../lib/aes128ccm.h");
    println!("cargo:rerun-if-changed=../lib/aes_reference.h");
    println!("cargo:rerun-if-changed=../include/smb2/smb2.h");
    println!("cargo:rerun-if-changed=../include/smb2/libsmb2.h");
    println!("cargo:rerun-if-changed=../lib/errors.c");
    println!("cargo:rerun-if-changed=../lib/hmac-md5.c");
    println!("cargo:rerun-if-changed=../lib/hmac-md5.h");
    println!("cargo:rerun-if-changed=../lib/hmac.c");
    println!("cargo:rerun-if-changed=../lib/md4.h");
    println!("cargo:rerun-if-changed=../lib/md4c.c");
    println!("cargo:rerun-if-changed=../lib/md5.c");
    println!("cargo:rerun-if-changed=../lib/md5.h");
    println!("cargo:rerun-if-changed=../lib/sha-private.h");
    println!("cargo:rerun-if-changed=../lib/sha.h");
    println!("cargo:rerun-if-changed=../lib/sha1.c");
    println!("cargo:rerun-if-changed=../lib/sha224-256.c");
    println!("cargo:rerun-if-changed=../lib/sha384-512.c");
    println!("cargo:rerun-if-changed=../lib/timestamps.c");
    println!("cargo:rerun-if-changed=../lib/unicode.c");
    println!("cargo:rerun-if-changed=../lib/usha.c");
}
