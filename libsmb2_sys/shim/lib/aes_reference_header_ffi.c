#ifdef CBC
#undef CBC
#endif
#ifdef ECB
#undef ECB
#endif

#include "aes_reference.h"

int aes_reference_ffi_default_cbc_value(void)
{
    return CBC;
}

int aes_reference_ffi_default_cbc_declarations_enabled(void)
{
#if defined(CBC) && CBC
    return 1;
#else
    return 0;
#endif
}

#undef _AES_REFERENCE_H_
#undef CBC
#undef ECB
#define ECB 0

#include "aes_reference.h"

int aes_reference_ffi_external_ecb_value(void)
{
    return ECB;
}

int aes_reference_ffi_external_ecb_declarations_enabled(void)
{
#if defined(ECB) && ECB
    return 1;
#else
    return 0;
#endif
}
