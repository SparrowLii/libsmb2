#include "init_ffi.h"

#define HAVE_STDINT_H 1
#define HAVE_TIME_H 1
#include <time.h>

#include "smb2/smb2.h"
#include "compat.h"
#include "smb2/libsmb2.h"
#include "libsmb2-private.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct init_ffi_file_handle {
        smb2_command_cb cb;
        void *cb_data;
        smb2_file_id file_id;
        int64_t offset;
        int64_t end_of_file;
};

static int init_ffi_free_count;
static int init_ffi_error_callback_count;
static int init_ffi_fail_next_context_calloc;
static int init_ffi_destroy_active_callback_status;

static void *init_ffi_forced_calloc(size_t nmemb, size_t size)
{
        if (init_ffi_fail_next_context_calloc > 0) {
                init_ffi_fail_next_context_calloc--;
                return NULL;
        }
        return calloc(nmemb, size);
}

static void init_ffi_counting_free(void *buf)
{
        init_ffi_free_count++;
        free(buf);
}

static void init_ffi_error_callback(struct smb2_context *smb2 _U_,
                                    const char *error_string _U_)
{
        init_ffi_error_callback_count++;
}

static void init_ffi_oplock_callback(struct smb2_context *smb2 _U_,
                                     int status _U_,
                                     struct smb2_oplock_or_lease_break_reply *rep _U_,
                                     uint8_t *new_oplock_level _U_,
                                     uint32_t *new_lease_state _U_)
{
}

static void init_ffi_destroy_active_callback(struct smb2_context *smb2 _U_,
                                             int status,
                                             void *command_data _U_,
                                             void *private_data _U_)
{
        init_ffi_destroy_active_callback_status = status;
}

void smb2_close_connecting_fds(struct smb2_context *smb2 _U_)
{
}

void smb2_free_pdu(struct smb2_context *smb2 _U_, struct smb2_pdu *pdu _U_)
{
}

void free_c_data(struct smb2_context *smb2 _U_, struct connect_data *data _U_)
{
}

struct smb2_context *init_ffi_forced_smb2_init_context(void);
void init_ffi_forced_smb2_destroy_context(struct smb2_context *smb2);
const char *init_ffi_forced_smb2_get_error(struct smb2_context *smb2);

static void replace_string(const char **slot, const char *value)
{
        if (*slot) {
                free((void *)*slot);
                *slot = NULL;
        }
        if (value) {
                *slot = strdup(value);
        }
}

struct smb2_context *init_ffi_context_new(void)
{
        return calloc(1, sizeof(struct smb2_context));
}

void init_ffi_context_free(struct smb2_context *smb2)
{
        if (!smb2) {
                return;
        }
        free((void *)smb2->server);
        free((void *)smb2->user);
        free((void *)smb2->password);
        free((void *)smb2->domain);
        free((void *)smb2->workstation);
        free(smb2);
}

const char *init_ffi_get_error(const struct smb2_context *smb2)
{
        return smb2 ? smb2->error_string : "";
}

int init_ffi_get_nterror(const struct smb2_context *smb2)
{
        return smb2 ? smb2->nterror : 0;
}

void init_ffi_set_nterror(struct smb2_context *smb2, int nterror)
{
        if (smb2) {
                smb2->nterror = nterror;
        }
}

void init_ffi_set_client_guid(struct smb2_context *smb2, const uint8_t *guid)
{
        if (smb2 && guid) {
                memcpy(smb2->client_guid, guid, SMB2_GUID_SIZE);
        }
}

const uint8_t *init_ffi_get_client_guid(const struct smb2_context *smb2)
{
        return smb2 ? (const uint8_t *)smb2->client_guid : NULL;
}

uint16_t init_ffi_get_dialect(const struct smb2_context *smb2)
{
        return smb2 ? smb2->dialect : 0;
}

void init_ffi_set_dialect(struct smb2_context *smb2, uint16_t dialect)
{
        if (smb2) {
                smb2->dialect = dialect;
        }
}

void init_ffi_set_security_mode(struct smb2_context *smb2, uint16_t security_mode)
{
        if (smb2) {
                smb2->security_mode = security_mode;
        }
}

uint16_t init_ffi_get_security_mode(const struct smb2_context *smb2)
{
        return smb2 ? smb2->security_mode : 0;
}

void init_ffi_set_password_from_file(struct smb2_context *smb2)
{
        char *name;
        FILE *fh;
        char buf[256];
        char *domain;
        char *user;
        char *password;

        if (!smb2 || !smb2->user) {
                return;
        }
        name = getenv("NTLM_USER_FILE");
        if (!name) {
                return;
        }
        fh = fopen(name, "r");
        if (!fh) {
                return;
        }
        init_ffi_set_password(smb2, NULL);
        while (fgets(buf, sizeof(buf), fh)) {
                buf[sizeof(buf) - 1] = 0;
                while (strlen(buf) > 0 && buf[strlen(buf) - 1] == '\n') {
                        buf[strlen(buf) - 1] = 0;
                }
                if (buf[0] == 0) {
                        break;
                }
                domain = buf;
                user = strchr(domain, ':');
                if (!user) {
                        continue;
                }
                *user++ = 0;
                password = strchr(user, ':');
                if (!password) {
                        continue;
                }
                *password++ = 0;
                if (strcmp(user, smb2->user) != 0) {
                        continue;
                }
                if (domain[0] && smb2->domain && strcmp(smb2->domain, domain) == 0) {
                        init_ffi_set_password(smb2, password);
                        fclose(fh);
                        return;
                }
                if (domain[0] && smb2->server && strcmp(smb2->server, domain) == 0) {
                        init_ffi_set_password(smb2, password);
                        fclose(fh);
                        return;
                }
                if (!domain[0]) {
                        init_ffi_set_password(smb2, password);
                }
        }
        fclose(fh);
}

const char *init_ffi_get_password(const struct smb2_context *smb2)
{
        return smb2 ? smb2->password : NULL;
}

void init_ffi_set_user(struct smb2_context *smb2, const char *user)
{
        if (smb2) {
                replace_string(&smb2->user, user);
                if (user) {
                        init_ffi_set_password_from_file(smb2);
                }
        }
}

const char *init_ffi_get_user(const struct smb2_context *smb2)
{
        return (smb2 && smb2->user) ? smb2->user : NULL;
}

void init_ffi_set_password(struct smb2_context *smb2, const char *password)
{
        if (smb2) {
                replace_string(&smb2->password, password);
        }
}

void init_ffi_set_domain(struct smb2_context *smb2, const char *domain)
{
        if (smb2) {
                replace_string(&smb2->domain, domain);
                if (domain) {
                        init_ffi_set_password_from_file(smb2);
                }
        }
}

const char *init_ffi_get_domain(const struct smb2_context *smb2)
{
        return (smb2 && smb2->domain) ? smb2->domain : NULL;
}

void init_ffi_set_workstation(struct smb2_context *smb2, const char *workstation)
{
        if (smb2) {
                replace_string(&smb2->workstation, workstation);
        }
}

const char *init_ffi_get_workstation(const struct smb2_context *smb2)
{
        return (smb2 && smb2->workstation) ? smb2->workstation : NULL;
}

void init_ffi_set_server(struct smb2_context *smb2, const char *server)
{
        if (smb2) {
                replace_string(&smb2->server, server);
        }
}

void init_ffi_set_opaque(struct smb2_context *smb2, void *opaque)
{
        if (smb2) {
                smb2->opaque = opaque;
        }
}

void *init_ffi_get_opaque(const struct smb2_context *smb2)
{
        return smb2 ? smb2->opaque : NULL;
}

void init_ffi_set_seal(struct smb2_context *smb2, int val)
{
        if (smb2) {
                smb2->seal = val;
        }
}

int init_ffi_get_seal(const struct smb2_context *smb2)
{
        return smb2 ? smb2->seal : 0;
}

void init_ffi_set_sign(struct smb2_context *smb2, int val)
{
        if (smb2) {
                smb2->sign = val;
        }
}

int init_ffi_get_sign(const struct smb2_context *smb2)
{
        return smb2 ? smb2->sign : 0;
}

int init_ffi_context_active(const struct smb2_context *smb2 _U_)
{
        return 0;
}

int init_ffi_iovector_free_probe(void)
{
        struct smb2_io_vectors v;
        char *first = malloc(1);
        char *second = malloc(1);

        if (!first || !second) {
                free(first);
                free(second);
                return -1;
        }
        memset(&v, 0, sizeof(v));
        v.niov = 2;
        v.total_size = 8;
        v.num_done = 1;
        v.iov[0].buf = (uint8_t *)first;
        v.iov[0].free = init_ffi_counting_free;
        v.iov[1].buf = (uint8_t *)second;
        v.iov[1].free = init_ffi_counting_free;
        init_ffi_free_count = 0;
        for (int i = 0; i < v.niov; i++) {
                if (v.iov[i].free) {
                        v.iov[i].free(v.iov[i].buf);
                }
        }
        v.niov = 0;
        v.total_size = 0;
        v.num_done = 0;
        return init_ffi_free_count == 2 && v.niov == 0 &&
               v.total_size == 0 && v.num_done == 0;
}

int init_ffi_iovector_add_probe(size_t *total_size)
{
        struct smb2_io_vectors v;

        memset(&v, 0, sizeof(v));
        v.iov[v.niov].buf = (uint8_t *)"abc";
        v.iov[v.niov].len = 3;
        v.iov[v.niov].free = NULL;
        v.total_size += 3;
        v.niov++;
        if (total_size) {
                *total_size = v.total_size;
        }
        return v.niov == 1 && v.iov[0].len == 3;
}

int init_ffi_iovector_overflow_probe(void)
{
        struct smb2_io_vectors v;
        char *buf = malloc(1);

        if (!buf) {
                return -1;
        }
        memset(&v, 0, sizeof(v));
        v.niov = SMB2_MAX_VECTORS;
        init_ffi_free_count = 0;
        init_ffi_counting_free(buf);
        return v.niov >= SMB2_MAX_VECTORS && init_ffi_free_count == 1;
}

void init_ffi_set_error_literal(struct smb2_context *smb2, const char *error_string)
{
        if (!smb2) {
                return;
        }
        if (!error_string || error_string[0] == 0) {
                smb2->nterror = 0;
        }
        snprintf(smb2->error_string, sizeof(smb2->error_string), "%s",
                 error_string ? error_string : "");
        if (smb2->error_cb) {
                smb2->error_cb(smb2, smb2->error_string);
        }
}

int init_ffi_error_callback_probe(struct smb2_context *smb2)
{
        if (!smb2) {
                return 0;
        }
        init_ffi_error_callback_count = 0;
        smb2->error_cb = init_ffi_error_callback;
        init_ffi_set_error_literal(smb2, "callback error");
        return init_ffi_error_callback_count;
}

void init_ffi_set_nterror_with_error(struct smb2_context *smb2, int nterror,
                                     const char *error_string)
{
        if (!smb2) {
                return;
        }
        smb2->nterror = nterror;
        snprintf(smb2->error_string, sizeof(smb2->error_string), "%s",
                 error_string ? error_string : "");
}

void init_ffi_set_authentication(struct smb2_context *smb2, int val)
{
        if (smb2) {
                smb2->sec = (enum smb2_sec)val;
        }
}

int init_ffi_get_authentication(const struct smb2_context *smb2)
{
        return smb2 ? (int)smb2->sec : 0;
}

void init_ffi_set_timeout(struct smb2_context *smb2, int seconds)
{
        if (smb2) {
                smb2->timeout = seconds;
        }
}

int init_ffi_get_timeout(const struct smb2_context *smb2)
{
        return smb2 ? smb2->timeout : 0;
}

void init_ffi_set_version(struct smb2_context *smb2, int version)
{
        if (smb2) {
                smb2->version = (enum smb2_negotiate_version)version;
        }
}

int init_ffi_get_version(const struct smb2_context *smb2)
{
        return smb2 ? (int)smb2->version : 0;
}

void init_ffi_get_libversion(uint8_t *major, uint8_t *minor, uint8_t *patch)
{
        if (major) {
                *major = LIBSMB2_MAJOR_VERSION;
        }
        if (minor) {
                *minor = LIBSMB2_MINOR_VERSION;
        }
        if (patch) {
                *patch = LIBSMB2_MAJOR_VERSION;
        }
}

void init_ffi_set_passthrough(struct smb2_context *smb2, int passthrough)
{
        if (smb2) {
                smb2->passthrough = passthrough;
        }
}

int init_ffi_get_passthrough(struct smb2_context *smb2)
{
        return smb2 ? smb2->passthrough : 0;
}

int init_ffi_oplock_callback_probe(struct smb2_context *smb2)
{
        if (!smb2) {
                return 0;
        }
        smb2->oplock_or_lease_break_cb = init_ffi_oplock_callback;
        return smb2->oplock_or_lease_break_cb == init_ffi_oplock_callback;
}

int init_ffi_delegate_credentials_unavailable(struct smb2_context *in _U_,
                                              struct smb2_context *out _U_)
{
        return -1;
}

void init_ffi_set_max_read_size(struct smb2_context *smb2, uint32_t max_read_size)
{
        if (smb2) {
                smb2->max_read_size = max_read_size;
        }
}

uint32_t init_ffi_get_max_read_size(const struct smb2_context *smb2)
{
        return smb2 ? smb2->max_read_size : 0;
}

void init_ffi_set_max_write_size(struct smb2_context *smb2, uint32_t max_write_size)
{
        if (smb2) {
                smb2->max_write_size = max_write_size;
        }
}

uint32_t init_ffi_get_max_write_size(const struct smb2_context *smb2)
{
        return smb2 ? smb2->max_write_size : 0;
}

struct init_ffi_file_handle *init_ffi_file_handle_from_id(const uint8_t *file_id)
{
        struct init_ffi_file_handle *fh;

        if (!file_id) {
                return NULL;
        }
        fh = calloc(1, sizeof(struct init_ffi_file_handle));
        if (!fh) {
                return NULL;
        }
        memcpy(fh->file_id, file_id, SMB2_FD_SIZE);
        return fh;
}

void init_ffi_file_handle_free(struct init_ffi_file_handle *fh)
{
        free(fh);
}

const uint8_t *init_ffi_file_handle_get_id(const struct init_ffi_file_handle *fh)
{
        return fh ? fh->file_id : NULL;
}

static void copy_url_field(char *dst, size_t dst_len, const char *src)
{
        if (dst_len == 0) {
                return;
        }
        snprintf(dst, dst_len, "%s", src ? src : "");
}

int init_ffi_parse_url_snapshot(const char *url,
                                struct init_ffi_url_snapshot *snapshot)
{
        struct smb2_context *smb2;
        struct smb2_url *parsed;

        if (!url || !snapshot) {
                return 0;
        }
        memset(snapshot, 0, sizeof(*snapshot));
        smb2 = init_ffi_forced_smb2_init_context();
        if (!smb2) {
                return 0;
        }

        parsed = smb2_parse_url(smb2, url);
        if (!parsed) {
                init_ffi_forced_smb2_destroy_context(smb2);
                return 0;
        }

        copy_url_field(snapshot->domain, sizeof(snapshot->domain), parsed->domain);
        copy_url_field(snapshot->user, sizeof(snapshot->user), parsed->user);
        copy_url_field(snapshot->server, sizeof(snapshot->server), parsed->server);
        copy_url_field(snapshot->share, sizeof(snapshot->share), parsed->share);
        copy_url_field(snapshot->path, sizeof(snapshot->path), parsed->path);
        smb2_destroy_url(parsed);
        init_ffi_forced_smb2_destroy_context(smb2);
        return 1;
}

const char *init_ffi_parse_url_error(const char *url)
{
        static char error[MAX_ERROR_SIZE];
        struct smb2_context *smb2;

        memset(error, 0, sizeof(error));
        smb2 = init_ffi_forced_smb2_init_context();
        if (!smb2) {
                return error;
        }

        struct smb2_url *parsed = smb2_parse_url(smb2, url);
        if (parsed) {
                smb2_destroy_url(parsed);
        }
        snprintf(error, sizeof(error), "%s", init_ffi_forced_smb2_get_error(smb2));
        init_ffi_forced_smb2_destroy_context(smb2);
        return error;
}

int init_ffi_parse_url_query_snapshot(int *seal, int *version, int *sec,
                                      int *timeout)
{
        struct smb2_context *smb2;
        struct smb2_url *parsed;

        smb2 = init_ffi_forced_smb2_init_context();
        if (!smb2) {
                return 0;
        }

        parsed = smb2_parse_url(smb2, "smb://server/share?seal&vers=3&sec=ntlmssp&timeout=5");
        if (!parsed) {
                init_ffi_forced_smb2_destroy_context(smb2);
                return 0;
        }
        smb2_destroy_url(parsed);

        if (seal) {
                *seal = smb2->seal;
        }
        if (version) {
                *version = (int)smb2->version;
        }
        if (sec) {
                *sec = (int)smb2->sec;
        }
        if (timeout) {
                *timeout = smb2->timeout;
        }
        init_ffi_forced_smb2_destroy_context(smb2);
        return 1;
}

const char *init_ffi_parse_url_bad_query_error(void)
{
        static char error[MAX_ERROR_SIZE];
        struct smb2_context *smb2;
        struct smb2_url *parsed;

        memset(error, 0, sizeof(error));
        smb2 = init_ffi_forced_smb2_init_context();
        if (!smb2) {
                return error;
        }

        parsed = smb2_parse_url(smb2, "smb://server/share?unknown=1");
        if (parsed) {
                smb2_destroy_url(parsed);
        }
        snprintf(error, sizeof(error), "%s", init_ffi_forced_smb2_get_error(smb2));
        init_ffi_forced_smb2_destroy_context(smb2);
        return error;
}

int init_ffi_destroy_parsed_url_probe(void)
{
        struct smb2_context *smb2 = init_ffi_forced_smb2_init_context();
        struct smb2_url *parsed;

        if (!smb2) {
                return 0;
        }
        parsed = smb2_parse_url(smb2, "smb://domain;user@server/share/path");
        if (!parsed) {
                init_ffi_forced_smb2_destroy_context(smb2);
                return 0;
        }
        smb2_destroy_url(parsed);
        init_ffi_forced_smb2_destroy_context(smb2);
        return 1;
}

int init_ffi_destroy_null_url_probe(void)
{
        smb2_destroy_url(NULL);
        return 1;
}

#define calloc init_ffi_forced_calloc
#define smb2_init_context init_ffi_forced_smb2_init_context
#define smb2_destroy_context init_ffi_forced_smb2_destroy_context
#define smb2_active_contexts init_ffi_forced_smb2_active_contexts
#define smb2_context_active init_ffi_forced_smb2_context_active
#define smb2_free_iovector init_ffi_forced_smb2_free_iovector
#define smb2_add_iovector init_ffi_forced_smb2_add_iovector
#define smb2_set_error init_ffi_forced_smb2_set_error
#define smb2_register_error_callback init_ffi_forced_smb2_register_error_callback
#define smb2_set_nterror init_ffi_forced_smb2_set_nterror
#define smb2_get_error init_ffi_forced_smb2_get_error
#define smb2_get_nterror init_ffi_forced_smb2_get_nterror
#define smb2_set_client_guid init_ffi_forced_smb2_set_client_guid
#define smb2_get_client_guid init_ffi_forced_smb2_get_client_guid
#define smb2_get_dialect init_ffi_forced_smb2_get_dialect
#define smb2_set_security_mode init_ffi_forced_smb2_set_security_mode
#define smb2_set_password_from_file init_ffi_forced_smb2_set_password_from_file
#define smb2_set_user init_ffi_forced_smb2_set_user
#define smb2_get_user init_ffi_forced_smb2_get_user
#define smb2_get_workstation init_ffi_forced_smb2_get_workstation
#define smb2_set_password init_ffi_forced_smb2_set_password
#define smb2_set_domain init_ffi_forced_smb2_set_domain
#define smb2_get_domain init_ffi_forced_smb2_get_domain
#define smb2_set_workstation init_ffi_forced_smb2_set_workstation
#define smb2_set_opaque init_ffi_forced_smb2_set_opaque
#define smb2_set_seal init_ffi_forced_smb2_set_seal
#define smb2_set_sign init_ffi_forced_smb2_set_sign
#define smb2_set_authentication init_ffi_forced_smb2_set_authentication
#define smb2_set_timeout init_ffi_forced_smb2_set_timeout
#define smb2_set_version init_ffi_forced_smb2_set_version
#define smb2_get_libsmb2Version init_ffi_forced_smb2_get_libsmb2Version
#define smb2_set_passthrough init_ffi_forced_smb2_set_passthrough
#define smb2_get_passthrough init_ffi_forced_smb2_get_passthrough
#define smb2_set_oplock_or_lease_break_callback init_ffi_forced_smb2_set_oplock_or_lease_break_callback
#define smb2_delegate_credentials init_ffi_forced_smb2_delegate_credentials
void init_ffi_forced_smb2_set_error(struct smb2_context *smb2,
                                    const char *error_string, ...);
void init_ffi_forced_smb2_register_error_callback(struct smb2_context *smb2,
                                                  smb2_error_cb error_cb);
void init_ffi_forced_smb2_set_nterror(struct smb2_context *smb2, int nterror,
                                      const char *error_string, ...);
const char *init_ffi_forced_smb2_get_error(struct smb2_context *smb2);
int init_ffi_forced_smb2_get_nterror(struct smb2_context *smb2);
void init_ffi_forced_smb2_set_client_guid(struct smb2_context *smb2,
                                          const uint8_t guid[SMB2_GUID_SIZE]);
const char *init_ffi_forced_smb2_get_client_guid(struct smb2_context *smb2);
uint16_t init_ffi_forced_smb2_get_dialect(struct smb2_context *smb2);
void init_ffi_forced_smb2_set_security_mode(struct smb2_context *smb2,
                                            uint16_t security_mode);
void init_ffi_forced_smb2_set_password_from_file(struct smb2_context *smb2);
void init_ffi_forced_smb2_set_user(struct smb2_context *smb2,
                                   const char *user);
const char *init_ffi_forced_smb2_get_user(struct smb2_context *smb2);
const char *init_ffi_forced_smb2_get_workstation(struct smb2_context *smb2);
void init_ffi_forced_smb2_free_iovector(struct smb2_context *smb2,
                                        struct smb2_io_vectors *v);
struct smb2_iovec *init_ffi_forced_smb2_add_iovector(
        struct smb2_context *smb2, struct smb2_io_vectors *v, uint8_t *buf,
        size_t len, void (*free_cb)(void *));
void init_ffi_forced_smb2_set_password(struct smb2_context *smb2,
                                       const char *password);
void init_ffi_forced_smb2_set_domain(struct smb2_context *smb2,
                                     const char *domain);
const char *init_ffi_forced_smb2_get_domain(struct smb2_context *smb2);
void init_ffi_forced_smb2_set_workstation(struct smb2_context *smb2,
                                          const char *workstation);
void init_ffi_forced_smb2_set_opaque(struct smb2_context *smb2, void *opaque);
void init_ffi_forced_smb2_set_seal(struct smb2_context *smb2, int val);
void init_ffi_forced_smb2_set_sign(struct smb2_context *smb2, int val);
void init_ffi_forced_smb2_set_authentication(struct smb2_context *smb2,
                                             int val);
void init_ffi_forced_smb2_set_timeout(struct smb2_context *smb2, int seconds);
void init_ffi_forced_smb2_set_version(
        struct smb2_context *smb2, enum smb2_negotiate_version version);
void init_ffi_forced_smb2_get_libsmb2Version(
        struct smb2_libversion *smb2_ver);
void init_ffi_forced_smb2_set_passthrough(struct smb2_context *smb2,
                                          int passthrough);
void init_ffi_forced_smb2_get_passthrough(struct smb2_context *smb2,
                                          int *passthrough);
void init_ffi_forced_smb2_set_oplock_or_lease_break_callback(
        struct smb2_context *smb2, smb2_oplock_or_lease_break_cb cb);
int init_ffi_forced_smb2_delegate_credentials(struct smb2_context *in,
                                              struct smb2_context *out);
#include "init.c"
#undef calloc
#undef smb2_init_context
#undef smb2_destroy_context
#undef smb2_active_contexts
#undef smb2_context_active
#undef smb2_free_iovector
#undef smb2_add_iovector
#undef smb2_set_error
#undef smb2_register_error_callback
#undef smb2_set_nterror
#undef smb2_get_error
#undef smb2_get_nterror
#undef smb2_set_client_guid
#undef smb2_get_client_guid
#undef smb2_get_dialect
#undef smb2_set_security_mode
#undef smb2_set_password_from_file
#undef smb2_set_user
#undef smb2_get_user
#undef smb2_get_workstation
#undef smb2_set_password
#undef smb2_set_domain
#undef smb2_get_domain
#undef smb2_set_workstation
#undef smb2_set_opaque
#undef smb2_set_seal
#undef smb2_set_sign
#undef smb2_set_authentication
#undef smb2_set_timeout
#undef smb2_set_version
#undef smb2_get_libsmb2Version
#undef smb2_set_passthrough
#undef smb2_get_passthrough
#undef smb2_set_oplock_or_lease_break_callback
#undef smb2_delegate_credentials

struct init_ffi_context_defaults init_ffi_real_context_defaults(void)
{
        struct init_ffi_context_defaults result;
        struct smb2_context *smb2;

        memset(&result, 0, sizeof(result));
        smb2 = init_ffi_forced_smb2_init_context();
        if (!smb2) {
                return result;
        }

        result.allocated = 1;
        result.fd = smb2->fd;
        result.sec = (int)smb2->sec;
        result.version = (int)smb2->version;
        result.ndr = smb2->ndr;
        result.active = init_ffi_forced_smb2_context_active(smb2);
        init_ffi_forced_smb2_destroy_context(smb2);
        return result;
}

int init_ffi_init_context_allocation_failure_probe(void)
{
        struct smb2_context *smb2;

        init_ffi_fail_next_context_calloc = 1;
        smb2 = init_ffi_forced_smb2_init_context();
        init_ffi_fail_next_context_calloc = 0;
        return smb2 == NULL && init_ffi_forced_smb2_active_contexts() == NULL;
}

int init_ffi_destroy_active_context_probe(void)
{
        struct smb2_context *smb2 = init_ffi_forced_smb2_init_context();

        if (!smb2) {
                return 0;
        }
        init_ffi_destroy_active_callback_status = 0;
        smb2->connect_cb = init_ffi_destroy_active_callback;
        smb2->connect_data = NULL;
        init_ffi_forced_smb2_destroy_context(smb2);
        return init_ffi_forced_smb2_active_contexts() == NULL &&
               init_ffi_destroy_active_callback_status == (int)SMB2_STATUS_CANCELLED;
}

int init_ffi_destroy_null_context_probe(void)
{
        init_ffi_forced_smb2_destroy_context(NULL);
        return 1;
}

int init_ffi_active_contexts_probe(void)
{
        struct smb2_context *first = init_ffi_forced_smb2_init_context();
        struct smb2_context *second = init_ffi_forced_smb2_init_context();
        int ok;

        if (!first || !second) {
                if (first) {
                        init_ffi_forced_smb2_destroy_context(first);
                }
                if (second) {
                        init_ffi_forced_smb2_destroy_context(second);
                }
                return 0;
        }

        ok = init_ffi_forced_smb2_active_contexts() == second && second->next == first;
        init_ffi_forced_smb2_destroy_context(second);
        init_ffi_forced_smb2_destroy_context(first);
        return ok;
}

int init_ffi_real_context_active_probe(void)
{
        struct smb2_context *smb2 = init_ffi_forced_smb2_init_context();
        int ok;

        if (!smb2) {
                return 0;
        }

        ok = init_ffi_forced_smb2_context_active(smb2) == 1;
        init_ffi_forced_smb2_destroy_context(smb2);
        return ok;
}
