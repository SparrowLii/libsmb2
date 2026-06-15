/* Differential ABI test: compare lsa_RPC_SID_coder encode output between the
 * original C libsmb2 and the Rust libsmb2_rust.so. Each library is driven
 * through its own create_context/allocate_pdu API so opaque struct layouts
 * never cross the boundary. We compare the encoded payload bytes + offset. */
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define DCERPC_ENCODE 1
#define NSE_BUF_SIZE 1024

struct smb2_iovec { uint8_t *buf; size_t len; void (*free)(void *); };

typedef struct RPC_SID {
    uint8_t Revision;
    uint8_t SubAuthorityCount;
    uint8_t IdentifierAuthority[6];
    uint32_t *SubAuthority;
} RPC_SID;

typedef void *(*create_ctx_fn)(void *smb2);
typedef void *(*alloc_pdu_fn)(void *dce, int direction, int payload_size);
typedef void *(*get_payload_fn)(void *pdu);
typedef void (*set_endian_fn)(void *pdu, int little_endian);
typedef int (*coder_fn)(void *dce, void *pdu, struct smb2_iovec *iov, int *offset, void *ptr);

static int run(const char *path, uint8_t *out, int *out_len)
{
    void *h = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!h) { fprintf(stderr, "dlopen %s: %s\n", path, dlerror()); return -1; }
    create_ctx_fn create_ctx = (create_ctx_fn)dlsym(h, "dcerpc_create_context");
    alloc_pdu_fn alloc_pdu = (alloc_pdu_fn)dlsym(h, "dcerpc_allocate_pdu");
    set_endian_fn set_endian = (set_endian_fn)dlsym(h, "dcerpc_set_endian");
    coder_fn coder = (coder_fn)dlsym(h, "lsa_RPC_SID_coder");
    if (!create_ctx || !alloc_pdu || !coder) {
        fprintf(stderr, "dlsym failed in %s\n", path); dlclose(h); return -1;
    }
    void *dce = create_ctx(NULL);
    void *pdu = alloc_pdu(dce, DCERPC_ENCODE, NSE_BUF_SIZE);
    /* Real usage (dcerpc_call_async) copies the little-endian drep into the PDU
     * header before the body coder runs. Model that here. */
    if (set_endian) set_endian(pdu, 1);

    uint8_t buf[NSE_BUF_SIZE];
    memset(buf, 0, sizeof(buf));
    struct smb2_iovec iov = { buf, sizeof(buf), NULL };
    int offset = 0;

    uint32_t subauth[3] = { 0x12345678u, 0x9abcdef0u, 0x00000111u };
    RPC_SID sid;
    sid.Revision = 1;
    sid.SubAuthorityCount = 3;
    uint8_t ident[6] = { 0, 0, 0, 0, 0, 5 };
    memcpy(sid.IdentifierAuthority, ident, 6);
    sid.SubAuthority = subauth;

    int rc = coder(dce, pdu, &iov, &offset, &sid);
    if (rc != 0) { fprintf(stderr, "coder rc=%d in %s\n", rc, path); dlclose(h); return -1; }
    *out_len = offset;
    memcpy(out, buf, offset > 0 ? (size_t)offset : 0);
    /* leak ctx/pdu intentionally; process is short-lived */
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) { fprintf(stderr, "usage: %s <c.so> <rust.so>\n", argv[0]); return 2; }
    uint8_t cbuf[NSE_BUF_SIZE], rbuf[NSE_BUF_SIZE];
    int clen = 0, rlen = 0;
    if (run(argv[1], cbuf, &clen)) return 1;
    if (run(argv[2], rbuf, &rlen)) return 1;
    printf("C   len=%d:", clen);
    for (int i = 0; i < clen; i++) printf(" %02x", cbuf[i]);
    printf("\nRust len=%d:", rlen);
    for (int i = 0; i < rlen; i++) printf(" %02x", rbuf[i]);
    printf("\n");
    if (clen != rlen || memcmp(cbuf, rbuf, clen) != 0) {
        printf("MISMATCH\n"); return 1;
    }
    printf("MATCH (%d bytes)\n", clen);
    return 0;
}
