
#include "crypto/block_cipher_modes.h"
#include "crypto/src/block_cipher_modes/block_cipher_mode_private.h"
#include "system_config.h"
#include <string.h>

void BLOCK_CIPHER_CFB_Initialize (BLOCK_CIPHER_CFB_CONTEXT * context, BLOCK_CIPHER_FunctionEncrypt encryptFunction, BLOCK_CIPHER_FunctionDecrypt decryptFunction, uint32_t blockSize, uint8_t * initializationVector)
{
    context->encrypt = encryptFunction;
    context->decrypt = decryptFunction;
    context->blockSize = blockSize;
    memcpy (context->initializationVector, initializationVector, blockSize);
}

void BLOCK_CIPHER_CFB_Encrypt (DRV_HANDLE handle, uint8_t * cipherText, uint8_t * plainText, uint32_t numBytes, void * key, BLOCK_CIPHER_CFB_CONTEXT * context, uint32_t options)
{
    if((options & BLOCK_CIPHER_OPTION_USE_CFB1) == BLOCK_CIPHER_OPTION_USE_CFB1)
    {
        uint8_t i, plainText_temp = 0;
        uint8_t __attribute__((aligned)) buffer[CRYPTO_CONFIG_BLOCK_MAX_SIZE];
        uint32_t j;

        j=0;

        while(numBytes--)
        {
            if(j==8)
            {
                cipherText++;
                j = 0;
            }
            
            if(j++==0)
            {
                plainText_temp = *plainText++;
                *cipherText = 0;
            }

            (*context->encrypt)(handle, buffer, context->initializationVector, key);
            
            *cipherText >>= 1;

            if((plainText_temp & 0x01) != 0)
            {
                if((buffer[0] & 0x80) == 0)
                {
                    *cipherText |= 0x80;
                }
            }
            else
            {
                if((buffer[0] & 0x80) != 0)
                {
                    *cipherText |= 0x80;
                }
            }

            plainText_temp >>= 1;

            for(i=0;i<(context->blockSize - 1);i++)
            {
                context->initializationVector[i] <<= 1;
                if((context->initializationVector[i+1] & 0x80) == 0x80)
                {
                    context->initializationVector[i] |= 0x01;
                }
            }

            context->initializationVector[context->blockSize - 1] <<=1;

            if((*cipherText & (0x80)) == 0x80)
            {
                context->initializationVector[context->blockSize - 1] |= 0x01;
            }
        }
        while(j++ != 8)
        {
            *cipherText >>= 1;
        }

    }
    else if ((options & BLOCK_CIPHER_OPTION_USE_CFB8) == BLOCK_CIPHER_OPTION_USE_CFB8)
    {
        uint8_t i;
        uint8_t __attribute__((aligned)) buffer[CRYPTO_CONFIG_BLOCK_MAX_SIZE];

        while(numBytes--)
        {
            (*context->encrypt)(handle, buffer, context->initializationVector, key);

            *cipherText = *plainText++ ^ buffer[0];

            for(i=0;i<(context->blockSize - 1);i++)
            {
                context->initializationVector[i] = context->initializationVector[i+1];
            }

            context->initializationVector[context->blockSize-1] = *cipherText++;
        }
    }
    else
    {
        if((options & BLOCK_CIPHER_OPTION_STREAM_START) == BLOCK_CIPHER_OPTION_STREAM_START)
        {
            context->bytesRemaining = context->blockSize;
        }

        while(numBytes--)
        {
            if(context->bytesRemaining == context->blockSize)
            {
                (*context->encrypt)(handle, context->initializationVector, context->initializationVector, key);
                context->bytesRemaining = 0;
            }

            *cipherText = *plainText++ ^ context->initializationVector[context->bytesRemaining];
            context->initializationVector[context->bytesRemaining++] = *cipherText++;
        }
    }
}

void BLOCK_CIPHER_CFB_Decrypt (DRV_HANDLE handle, uint8_t * plainText, uint8_t * cipherText, uint32_t numBytes, void * key, BLOCK_CIPHER_CFB_CONTEXT * context, uint32_t options)
{
    if((options & BLOCK_CIPHER_OPTION_USE_CFB1) == BLOCK_CIPHER_OPTION_USE_CFB1)
    {
        uint8_t i,cipherText_temp = 0;
        uint8_t __attribute__((aligned)) buffer[context->blockSize];

        uint32_t j;

        j=0;

        while(numBytes--)
        {
            if(j==8)
            {
                plainText++;
                j = 0;
            }
            
            if(j++==0)
            {
                *plainText = 0;
                cipherText_temp = *cipherText++;
            }

            (*context->encrypt)(handle, buffer, context->initializationVector, key);

            *plainText >>= 1;

            if((cipherText_temp & 0x01) != 0)
            {
                if((buffer[0] & 0x80) == 0)
                {
                    *plainText |= 0x80;
                }
            }
            else
            {
                if((buffer[0] & 0x80) != 0)
                {
                    *plainText |= 0x80;
                }
            }

            for(i=0;i<(context->blockSize - 1);i++)
            {
                context->initializationVector[i] <<= 1;
                if((context->initializationVector[i+1] & 0x80) == 0x80)
                {
                    context->initializationVector[i] |= 0x01;
                }
            }

            context->initializationVector[context->blockSize-1] <<=1;
            if((cipherText_temp & (0x01)) == 0x01)
            {
                context->initializationVector[context->blockSize-1] |= 0x01;
            }

            cipherText_temp >>= 1;
        }
        while(j++ != 8)
        {
            *plainText >>= 1;
        }
    }
    else if ((options & BLOCK_CIPHER_OPTION_USE_CFB8) == BLOCK_CIPHER_OPTION_USE_CFB8)
    {
        uint8_t i;
        uint8_t __attribute__((aligned)) buffer[context->blockSize];

        while(numBytes--)
        {
            (*context->encrypt)(handle, buffer, context->initializationVector, key);

            *plainText++ = *cipherText ^ buffer[0];

            for(i=0;i<(context->blockSize - 1);i++)
            {
                context->initializationVector[i] = context->initializationVector[i+1];
            }

            context->initializationVector[context->blockSize-1] = *cipherText++;
        }
    }
    else
    {
        if((options & BLOCK_CIPHER_OPTION_STREAM_START) == BLOCK_CIPHER_OPTION_STREAM_START)
        {
            context->bytesRemaining = context->blockSize;
        }

        while(numBytes--)
        {
            if(context->bytesRemaining == context->blockSize)
            {
                (*context->encrypt)(handle, context->initializationVector, context->initializationVector, key);
                context->bytesRemaining = 0;
            }

            *plainText++ = *cipherText ^ context->initializationVector[context->bytesRemaining];
            context->initializationVector[context->bytesRemaining++] = *cipherText++;
        }
    }
}


