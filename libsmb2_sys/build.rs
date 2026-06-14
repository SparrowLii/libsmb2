use std::{env, path::PathBuf};

fn main() {
    let legacy_root = PathBuf::from("..");
    let shims = [
        PathBuf::from("shim/lib/aes_reference_header_ffi.c"),
        PathBuf::from("shim/include/asprintf_alloc_failure_ffi.c"),
        PathBuf::from("shim/include/asprintf_ffi.c"),
        PathBuf::from("shim/include/asprintf_format_failure_ffi.c"),
        PathBuf::from("shim/include/asprintf_length_failure_ffi.c"),
        PathBuf::from("shim/include/libsmb2_private_ffi.c"),
        PathBuf::from("shim/include/portable-endian_ffi.c"),
        PathBuf::from("shim/include/slist_ffi.c"),
        PathBuf::from("shim/lib/alloc_ffi.c"),
        PathBuf::from("shim/lib/compat_ffi.c"),
        PathBuf::from("shim/lib/init_ffi.c"),
        PathBuf::from("shim/lib/ntlmssp_ffi.c"),
        PathBuf::from("shim/lib/smb2_data_filesystem_info_ffi.c"),
        PathBuf::from("shim/lib/smb2_command_probe_ffi.c"),
        PathBuf::from("shim/lib/spnego_wrapper_ffi.c"),
        PathBuf::from("shim/lib/sync_ffi.c"),
        PathBuf::from("shim/lib/unicode_ffi.c"),
        PathBuf::from("shim/lib/unicode_fault_ffi.c"),
        PathBuf::from("shim/utils/smb2_cp_ffi.c"),
        PathBuf::from("shim/utils/smb2_ls_ffi.c"),
    ];
    let sources = [
        PathBuf::from("../lib/alloc.c"),
        PathBuf::from("../lib/aes.c"),
        PathBuf::from("../lib/aes128ccm.c"),
        PathBuf::from("../lib/aes_apple.c"),
        PathBuf::from("../lib/aes_reference.c"),
        PathBuf::from("../lib/asn1-ber.c"),
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
        PathBuf::from("shim/lib/aes_reference_header_ffi.h"),
        PathBuf::from("shim/lib/alloc_ffi.h"),
        PathBuf::from("shim/include/asprintf_ffi.h"),
        PathBuf::from("shim/include/libsmb2_private_ffi.h"),
        PathBuf::from("shim/include/portable-endian_ffi.h"),
        PathBuf::from("shim/include/slist_ffi.h"),
        PathBuf::from("shim/lib/compat_ffi.h"),
        PathBuf::from("shim/lib/ntlmssp_ffi.h"),
        PathBuf::from("shim/lib/smb2_data_filesystem_info_ffi.h"),
        PathBuf::from("shim/lib/smb2_command_probe_ffi.h"),
        PathBuf::from("shim/lib/spnego_wrapper_ffi.h"),
        PathBuf::from("shim/lib/sync_ffi.h"),
        PathBuf::from("shim/lib/unicode_ffi.h"),
        PathBuf::from("shim/lib/unicode_fault_ffi.h"),
        PathBuf::from("shim/utils/smb2_cp_ffi.h"),
        PathBuf::from("shim/utils/smb2_ls_ffi.h"),
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
    build.include("shim/lib");
    build.include("shim/utils");
    build.define("HAVE_STDINT_H", Some("1"));
    build.define("HAVE_STRING_H", Some("1"));
    build.define("HAVE_STDLIB_H", Some("1"));
    build.define("HAVE_SYS_TYPES_H", Some("1"));
    build.define("HAVE_TIME_H", Some("1"));
    build.define("HAVE_UNISTD_H", Some("1"));
    build.define("STDC_HEADERS", Some("1"));
    build.define("USE_SHA1", Some("1"));
    build.define("USE_SHA224", Some("1"));
    build.define("USE_SHA384_SHA512", Some("1"));
    build.define("CBC", Some("1"));
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
        .header("../include/smb2/smb2.h")
        .header("../include/smb2/libsmb2.h")
        .header("../include/smb2/libsmb2-raw.h")
        .header("../include/smb2/libsmb2-raw.h")
        .header(headers[0].to_string_lossy())
        .header(headers[1].to_string_lossy())
        .header(headers[2].to_string_lossy())
        .header(headers[3].to_string_lossy())
        .header(headers[4].to_string_lossy())
        .header(headers[5].to_string_lossy())
        .header(headers[6].to_string_lossy())
        .header(headers[7].to_string_lossy())
        .header(headers[8].to_string_lossy())
        .header(headers[9].to_string_lossy())
        .header(headers[10].to_string_lossy())
        .header(headers[11].to_string_lossy())
        .header(headers[12].to_string_lossy())
        .header(headers[13].to_string_lossy())
        .header(headers[14].to_string_lossy())
        .header(headers[15].to_string_lossy())
        .header("../lib/aes.h")
        .header("../lib/aes128ccm.h")
        .header("../lib/aes_reference.h")
        .header("../lib/asn1-ber.h")
        .header("../include/libsmb2-private.h")
        .header("../lib/hmac-md5.h")
        .header("../lib/md4.h")
        .header("../lib/md5.h")
        .header("../lib/sha.h")
        .clang_arg(format!("-I{}", legacy_root.display()))
        .clang_arg(format!("-I{}", legacy_root.join("include").display()))
        .clang_arg(format!("-I{}", legacy_root.join("include/smb2").display()))
        .clang_arg(format!("-I{}", legacy_root.join("lib").display()))
        .clang_arg("-Ishim/lib")
        .clang_arg("-Ishim/utils")
        .clang_arg("-DHAVE_STDINT_H=1")
        .clang_arg("-DHAVE_STRING_H=1")
        .clang_arg("-DHAVE_STDLIB_H=1")
        .clang_arg("-DHAVE_SYS_TYPES_H=1")
        .clang_arg("-DHAVE_TIME_H=1")
        .clang_arg("-DHAVE_UNISTD_H=1")
        .clang_arg("-DSTDC_HEADERS=1")
        .clang_arg("-DUSE_SHA1=1")
        .clang_arg("-DUSE_SHA224=1")
        .clang_arg("-DUSE_SHA384_SHA512=1")
        .clang_arg("-DCBC=1")
        .clang_arg("-D_U_=__attribute__((unused))")
        .clang_arg("-include")
        .clang_arg("stddef.h")
        .clang_arg("-include")
        .clang_arg("stdint.h")
        .clang_arg("-include")
        .clang_arg("time.h")
        .clang_arg("-include")
        .clang_arg("../include/smb2/smb2.h")
        .clang_arg("-include")
        .clang_arg("../include/smb2/libsmb2.h")
        .clang_arg("-include")
        .clang_arg("../include/smb2/libsmb2-raw.h")
        .allowlist_function("libsmb2_private_ffi_.*")
        .allowlist_function("portable_endian_ffi_.*")
        .allowlist_function("slist_ffi_.*")
        .allowlist_function("asprintf_ffi_.*")
        .allowlist_function("alloc_ffi_.*")
        .allowlist_function("aes_reference_ffi_.*")
        .allowlist_function("compat_ffi_.*")
        .allowlist_function("ntlmssp_ffi_.*")
        .allowlist_function("AES128_ECB_encrypt")
        .allowlist_function("AES128_ECB_.*_reference")
        .allowlist_function("AES128_CBC_.*_reference")
        .allowlist_function("aes128ccm_.*")
        .allowlist_function("asn1ber_.*")
        .allowlist_function("ber_.*")
        .allowlist_function("smb2_alloc_.*")
        .allowlist_function("smb2_free_data")
        .allowlist_function("nterror_to_.*")
        .allowlist_function("smb2_hmac_md5")
        .allowlist_function("MD4.*")
        .allowlist_function("MD5.*")
        .allowlist_function("SHA.*")
        .allowlist_function("USHA.*")
        .allowlist_function("hmac")
        .allowlist_function("hmac.*")
        .allowlist_function("smb2_.*timeval.*")
        .allowlist_function("smb2_data_filesystem_info_ffi_.*")
        .allowlist_function("smb2_command_probe_ffi_.*")
        .allowlist_function("spnego_ffi_.*")
        .allowlist_function("sync_ffi_.*")
        .allowlist_function("smb2_utf.*")
        .allowlist_function("unicode_ffi_.*")
        .allowlist_function("smb2_cp_ffi_.*")
        .allowlist_function("smb2_ls_ffi_.*")
        .allowlist_type("libsmb2_private_ffi_.*")
        .allowlist_type("portable_endian_ffi_.*")
        .allowlist_type("slist_ffi_.*")
        .allowlist_type("asprintf_ffi_.*")
        .allowlist_type("alloc_ffi_.*")
        .allowlist_type("compat_ffi_.*")
        .allowlist_type("auth_data")
        .allowlist_type("ntlmssp_ffi_.*")
        .allowlist_type("fs_.*_info_ffi")
        .allowlist_type("smb2_command_probe_ffi_.*")
        .allowlist_type("spnego_ffi_.*")
        .allowlist_type("sync_ffi_.*")
        .allowlist_type("MD4_CTX")
        .allowlist_type("MD5Context")
        .allowlist_type("SHA.*")
        .allowlist_type("USHA.*")
        .allowlist_type("HMACContext")
        .allowlist_type("asn1ber_.*")
        .allowlist_type("ber_type_t")
        .allowlist_type("smb2_timeval")
        .allowlist_type("smb2_utf16")
        .allowlist_type("smb2_cp_ffi_.*")
        .allowlist_type("smb2_ls_ffi_.*")
        .allowlist_var("SMB2_LS_FFI_.*")
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
    println!("cargo:rerun-if-changed=../include/slist.h");
    println!("cargo:rerun-if-changed=../include/smb2/smb2-ioctl.h");
    println!("cargo:rerun-if-changed=../lib/aes.h");
    println!("cargo:rerun-if-changed=../lib/aes128ccm.h");
    println!("cargo:rerun-if-changed=../lib/aes_reference.h");
    println!("cargo:rerun-if-changed=shim/lib/aes_reference_header_ffi.c");
    println!("cargo:rerun-if-changed=shim/lib/aes_reference_header_ffi.h");
    println!("cargo:rerun-if-changed=shim/lib/alloc_ffi.c");
    println!("cargo:rerun-if-changed=shim/lib/alloc_ffi.h");
    println!("cargo:rerun-if-changed=../lib/alloc.c");
    println!("cargo:rerun-if-changed=../lib/asn1-ber.c");
    println!("cargo:rerun-if-changed=../lib/asn1-ber.h");
    println!("cargo:rerun-if-changed=../include/smb2/smb2.h");
    println!("cargo:rerun-if-changed=../include/smb2/libsmb2.h");
    println!("cargo:rerun-if-changed=../lib/errors.c");
    println!("cargo:rerun-if-changed=../lib/hmac-md5.c");
    println!("cargo:rerun-if-changed=../lib/hmac-md5.h");
    println!("cargo:rerun-if-changed=../lib/hmac.c");
    println!("cargo:rerun-if-changed=shim/lib/init_ffi.c");
    println!("cargo:rerun-if-changed=shim/lib/init_ffi.h");
    println!("cargo:rerun-if-changed=shim/lib/ntlmssp_ffi.c");
    println!("cargo:rerun-if-changed=shim/lib/ntlmssp_ffi.h");
    println!("cargo:rerun-if-changed=../lib/ntlmssp.c");
    println!("cargo:rerun-if-changed=../lib/ntlmssp.h");
    println!("cargo:rerun-if-changed=shim/lib/spnego_wrapper_ffi.c");
    println!("cargo:rerun-if-changed=shim/lib/spnego_wrapper_ffi.h");
    println!("cargo:rerun-if-changed=shim/lib/smb2_command_probe_ffi.c");
    println!("cargo:rerun-if-changed=shim/lib/smb2_command_probe_ffi.h");
    println!("cargo:rerun-if-changed=shim/lib/sync_ffi.c");
    println!("cargo:rerun-if-changed=shim/lib/sync_ffi.h");
    println!("cargo:rerun-if-changed=../lib/md4.h");
    println!("cargo:rerun-if-changed=../lib/md4c.c");
    println!("cargo:rerun-if-changed=../lib/md5.c");
    println!("cargo:rerun-if-changed=../lib/md5.h");
    println!("cargo:rerun-if-changed=../lib/sha-private.h");
    println!("cargo:rerun-if-changed=../lib/sha.h");
    println!("cargo:rerun-if-changed=../lib/sha1.c");
    println!("cargo:rerun-if-changed=../lib/sha224-256.c");
    println!("cargo:rerun-if-changed=../lib/sha384-512.c");
    println!("cargo:rerun-if-changed=../lib/spnego-wrapper.c");
    println!("cargo:rerun-if-changed=../lib/spnego-wrapper.h");
    println!("cargo:rerun-if-changed=../lib/sync.c");
    println!("cargo:rerun-if-changed=../lib/timestamps.c");
    println!("cargo:rerun-if-changed=../lib/unicode.c");
    println!("cargo:rerun-if-changed=../utils/smb2-cp.c");
    println!("cargo:rerun-if-changed=../utils/smb2-ls.c");
    println!("cargo:rerun-if-changed=../lib/usha.c");
}
