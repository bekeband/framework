
#include "crypto/block_cipher_modes.h"
#include "block_cipher_mode_private.h"
#include <stdint.h>
#include <string.h>

void BLOCK_CIPHER_PaddingInsert (uint8_t * block, uint8_t blockLen, uint8_t paddingLength, uint32_t options)
{
    uint8_t i;

    i = blockLen - paddingLength;

    if((options & BLOCK_CIPHER_OPTION_PAD_NULLS) == BLOCK_CIPHER_OPTION_PAD_NULLS)
    {
        memset(&block[i], 0, paddingLength);
    }
    else if((options & BLOCK_CIPHER_OPTION_PAD_8000) == BLOCK_CIPHER_OPTION_PAD_8000)
    {
        block[i++] = 0x80;
        memset(&block[i], 0, paddingLength - 1);
    }
    else if((options & BLOCK_CIPHER_OPTION_PAD_NUMBER) == BLOCK_CIPHER_OPTION_PAD_NUMBER)
    {
        memset(&block[i], paddingLength, paddingLength);
    }
}


