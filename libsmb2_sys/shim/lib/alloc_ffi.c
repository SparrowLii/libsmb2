#include <stdarg.h>

struct smb2_context;

void smb2_set_error(struct smb2_context *smb2, const char *error_string, ...)
{
    (void)smb2;
    (void)error_string;

    va_list ap;
    va_start(ap, error_string);
    va_end(ap);
}
