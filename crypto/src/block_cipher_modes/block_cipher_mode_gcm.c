
#include "crypto/block_cipher_modes.h"
#include "crypto/src/block_cipher_modes/block_cipher_mode_private.h"
#include "system_config.h"
#include <string.h>

void BLOCK_CIPHER_GCM_GaloisMultiply (uint8_t * result, uint8_t * a, uint8_t * b);
void BLOCK_CIPHER_GCM_GHash (BLOCK_CIPHER_GCM_CONTEXT * context);

typedef union {
  uint32_t ui32;
  uint8_t  ui8_arr[4];
} ff_int32_t;

void BLOCK_CIPHER_GCM_Initialize (DRV_HANDLE handle, BLOCK_CIPHER_GCM_CONTEXT * context, BLOCK_CIPHER_FunctionEncrypt encryptFunction, BLOCK_CIPHER_FunctionDecrypt decryptFunction, uint32_t blockSize, uint8_t * initializationVector, uint32_t initializationVectorLen, void * keyStream, uint32_t keyStreamSize, void * key)
{
    context->encrypt = encryptFunction;
    context->decrypt = decryptFunction;
    context->blockSize = blockSize;
    context->keyStream = keyStream;
    context->keyStreamSize = keyStreamSize;
    context->flags.authCompleted = false;
    context->authDataLen = 0;
    context->cipherTextLen = 0;

    // Zero the hash subkey field
    memset (context->hashSubKey, 0x00, blockSize);
    // Zero the initial authentication tag
    memset (context->authTag, 0x00, blockSize);

    // Initialize the hash sub-key
    (*context->encrypt)(handle, context->hashSubKey, context->hashSubKey, key);

    if (initializationVectorLen == 12)
    {
        // Set up the initialization vector from the vector passed in by the user
        memcpy (context->initializationVector, initializationVector, blockSize - 4);
        memset (context->initializationVector + blockSize - 4, 0x00, 3);
        *(context->initializationVector + blockSize - 1) = 0x01;
    }
    else
    {
        // Calculate an initialization vector from the user-specified value
        uint32_t tempIVLen = initializationVectorLen;
        while (tempIVLen > blockSize)
        {
            memcpy (context->authBuffer, initializationVector, blockSize);
            context->authBufferLen = blockSize;
            initializationVector += blockSize;
            tempIVLen -= blockSize;
            BLOCK_CIPHER_GCM_GHash (context);
        }
        context->authBufferLen = blockSize;
        // If the IV isn't an even multiple of the block size, pad it with zeros and hash the rest of it
        if (tempIVLen != 0)
        {
            memcpy (context->authBuffer, initializationVector, tempIVLen);
            memset (context->authBuffer + tempIVLen, 0x00, 16 - tempIVLen);
            BLOCK_CIPHER_GCM_GHash(context);
            context->authBufferLen = blockSize;
            tempIVLen = 0;
        }
        // Hash the length of the IV to create the final initialization vector
        while (tempIVLen < 11)
        {
            context->authBuffer[tempIVLen++] = 0;
        }
        context->authBuffer[15] = (uint8_t)((initializationVectorLen << 3) & 0xFF);
        context->authBuffer[14] = (uint8_t)((initializationVectorLen >> 5) & 0xFF);
        context->authBuffer[13] = (uint8_t)((initializationVectorLen >> 13) & 0xFF);
        context->authBuffer[12] = (uint8_t)((initializationVectorLen >> 21) & 0xFF);
        context->authBuffer[11] = (uint8_t)((initializationVectorLen >> 29) & 0xFF);

        BLOCK_CIPHER_GCM_GHash (context);

        memcpy (context->initializationVector, context->authTag, blockSize);
    }

    // Zero the initial authentication tag
    memset (context->authTag, 0x00, blockSize);

    context->authBufferLen = 0;
    
    memcpy (context->counter, context->initializationVector, blockSize);
    // Increment block size.  The initial counter vector will be used for authentication at the end of
    // this encryption; any actual encryption will start with counter value 0x00000002.
    *(context->counter + blockSize - 1) = *(context->counter + blockSize - 1) + 1;
    // Reset the key stream pointer
    context->keyStreamCurrentPosition = context->keyStream;
    context->bytesRemainingInKeyStream = 0;
}

BLOCK_CIPHER_ERRORS BLOCK_CIPHER_GCM_Encrypt (DRV_HANDLE handle, uint8_t * cipherText, uint8_t * plainText, uint32_t numBytes, uint8_t * authenticationTag, uint8_t tagLen, void * key, BLOCK_CIPHER_GCM_CONTEXT * context, uint32_t options)
{
    BLOCK_CIPHER_ERRORS status;
    uint8_t i;
    
    // If authenticate of data that has not been encrypted has not been completed, continue
    if (!context->flags.authCompleted)
    {
        if ((options & BLOCK_CIPHER_OPTION_AUTHENTICATE_ONLY) != BLOCK_CIPHER_OPTION_AUTHENTICATE_ONLY)
        {
            // Note: The GHash function will zero-pad the authentication data if authBufferLen is not at the buffer size
            BLOCK_CIPHER_GCM_GHash (context);
            context->flags.authCompleted = true;
        }
    }

    if (context->flags.authCompleted)
    {
        // Add the number of bytes being encrypted to the total cipher text length
        context->cipherTextLen += numBytes;
        while(numBytes--)
        {
            if(context->bytesRemainingInKeyStream == 0)
            {
                status = BLOCK_CIPHER_GCM_KeyStreamGenerate   (handle, 1, key, context, BLOCK_CIPHER_OPTION_STREAM_CONTINUE);
                if(status != BLOCK_CIPHER_ERROR_NONE)
                {
                    return status;
                }
            }

            context->bytesRemainingInKeyStream--;
            *cipherText = *plainText++ ^ *(uint8_t*)context->keyStreamCurrentPosition++;
            // Store the calculated ciphertext in the auth buffer
            *(context->authBuffer + context->authBufferLen) = *cipherText++;
            context->authBufferLen++;
            // If we have a whole block of ciphertext stored, hash it.
            if (context->authBufferLen == context->blockSize)
            {
                BLOCK_CIPHER_GCM_GHash (context);
            }

            if(context->keyStreamCurrentPosition == ((uint8_t*)context->keyStream + context->keyStreamSize))
            {
                context->keyStreamCurrentPosition = context->keyStream;
            }
        }
    }
    else
    {
        // Add the number of bytes being authenticated but not encrypted to the authDataLen parameter.
        context->authDataLen += numBytes;
        // Only authenticate this data
        while (numBytes)
        {
            if (context->blockSize - context->authBufferLen < numBytes)
            {
                i = context->blockSize - context->authBufferLen;
            }
            else
            {
                i = numBytes;
            }
            memcpy (context->authBuffer + context->authBufferLen, plainText, i);
            context->authBufferLen += i;
            if (context->authBufferLen == context->blockSize)
            {
                BLOCK_CIPHER_GCM_GHash (context);
                // Note: The GHash function will clear authBufferLen
            }
            numBytes -= i;
            plainText += i;
        }
    }

    // When the encryption stream is complete, pad the buffer and hash it.
    if ((options & BLOCK_CIPHER_OPTION_STREAM_COMPLETE) == BLOCK_CIPHER_OPTION_STREAM_COMPLETE)
    {
        // Pad the existing data with zeros and hash.
        BLOCK_CIPHER_GCM_GHash (context);
        // Copy the 64-bit lengths on the authenticated-but-not-encrypted data and the cipherText into 
        // the authBuffer and hash it
        context->authBuffer[15] = (uint8_t)((context->cipherTextLen << 3) & 0xFF);
        context->authBuffer[14] = (uint8_t)((context->cipherTextLen >> 5) & 0xFF);
        context->authBuffer[13] = (uint8_t)((context->cipherTextLen >> 13) & 0xFF);
        context->authBuffer[12] = (uint8_t)((context->cipherTextLen >> 21) & 0xFF);
        context->authBuffer[11] = (uint8_t)((context->cipherTextLen >> 29) & 0xFF);
        context->authBuffer[10] = 0;
        context->authBuffer[9] = 0;
        context->authBuffer[8] = 0;
        context->authBuffer[7] = (uint8_t)((context->authDataLen << 3) & 0xFF);
        context->authBuffer[6] = (uint8_t)((context->authDataLen >> 5) & 0xFF);
        context->authBuffer[5] = (uint8_t)((context->authDataLen >> 13) & 0xFF);
        context->authBuffer[4] = (uint8_t)((context->authDataLen >> 21) & 0xFF);
        context->authBuffer[3] = (uint8_t)((context->authDataLen >> 29) & 0xFF);
        context->authBuffer[2] = 0;
        context->authBuffer[1] = 0;
        context->authBuffer[0] = 0;
        context->authBufferLen = 16;
        BLOCK_CIPHER_GCM_GHash (context);
        
        // Compute digest
        (*context->encrypt)(handle, context->authBuffer, context->initializationVector, key);
        for (i = 0; i < context->blockSize; i++)
        {
            context->authTag[i] ^= context->authBuffer[i];
        }

        memcpy (authenticationTag, context->authTag, tagLen);
    }

    return BLOCK_CIPHER_ERROR_NONE;
}

BLOCK_CIPHER_ERRORS BLOCK_CIPHER_GCM_Decrypt (DRV_HANDLE handle, uint8_t * plainText, uint8_t * cipherText, uint32_t numBytes, uint8_t * authenticationTag, uint8_t tagLen, void * key, BLOCK_CIPHER_GCM_CONTEXT * context, uint32_t options)
{
    BLOCK_CIPHER_ERRORS status;
    uint8_t i;

    // If authenticate of data that has not been encrypted has not been completed, continue
    if (!context->flags.authCompleted)
    {
        if ((options & BLOCK_CIPHER_OPTION_AUTHENTICATE_ONLY) != BLOCK_CIPHER_OPTION_AUTHENTICATE_ONLY)
        {
            // Note: The GHash function will zero-pad the authentication data if authBufferLen is not at the buffer size
            BLOCK_CIPHER_GCM_GHash (context);
            context->flags.authCompleted = true;
        }
    }

    if (context->flags.authCompleted)
    {
        // Add the number of bytes being encrypted to the total cipher text length
        context->cipherTextLen += numBytes;
        while(numBytes--)
        {
            if(context->bytesRemainingInKeyStream == 0)
            {
                status = BLOCK_CIPHER_GCM_KeyStreamGenerate   (handle, 1, key, context, BLOCK_CIPHER_OPTION_STREAM_CONTINUE);
                if(status != BLOCK_CIPHER_ERROR_NONE)
                {
                    return status;
                }
            }

            context->bytesRemainingInKeyStream--;
            *(context->authBuffer + context->authBufferLen) = *cipherText;
            *plainText++ = *cipherText++ ^ *(uint8_t*)context->keyStreamCurrentPosition++;
            // Store the calculated ciphertext in the auth buffer
            context->authBufferLen++;
            // If we have a whole block of ciphertext stored, hash it.
            if (context->authBufferLen == context->blockSize)
            {
                BLOCK_CIPHER_GCM_GHash (context);
            }

            if(context->keyStreamCurrentPosition == ((uint8_t*)context->keyStream + context->keyStreamSize))
            {
                context->keyStreamCurrentPosition = context->keyStream;
            }
        }
    }
    else
    {
        // Add the number of bytes being authenticated but not encrypted to the authDataLen parameter.
        context->authDataLen += numBytes;
        // Only authenticate this data
        while (numBytes)
        {
            if (context->blockSize - context->authBufferLen < numBytes)
            {
                i = context->blockSize - context->authBufferLen;
            }
            else
            {
                i = numBytes;
            }
            memcpy (context->authBuffer + context->authBufferLen, cipherText, i);
            context->authBufferLen += i;
            if (context->authBufferLen == context->blockSize)
            {
                BLOCK_CIPHER_GCM_GHash (context);
                // Note: The GHash function will clear authBufferLen
            }
            numBytes -= i;
            cipherText += i;
        }
    }

    // When the encryption stream is complete, pad the buffer and hash it.
    if ((options & BLOCK_CIPHER_OPTION_STREAM_COMPLETE) == BLOCK_CIPHER_OPTION_STREAM_COMPLETE)
    {
        // Pad the existing data with zeros and hash.
        BLOCK_CIPHER_GCM_GHash (context);
        // Copy the 64-bit lengths on the authenticated-but-not-encrypted data and the cipherText into
        // the authBuffer and hash it
        context->authBuffer[15] = (uint8_t)((context->cipherTextLen << 3) & 0xFF);
        context->authBuffer[14] = (uint8_t)((context->cipherTextLen >> 5) & 0xFF);
        context->authBuffer[13] = (uint8_t)((context->cipherTextLen >> 13) & 0xFF);
        context->authBuffer[12] = (uint8_t)((context->cipherTextLen >> 21) & 0xFF);
        context->authBuffer[11] = (uint8_t)((context->cipherTextLen >> 29) & 0xFF);
        context->authBuffer[10] = 0;
        context->authBuffer[9] = 0;
        context->authBuffer[8] = 0;
        context->authBuffer[7] = (uint8_t)((context->authDataLen << 3) & 0xFF);
        context->authBuffer[6] = (uint8_t)((context->authDataLen >> 5) & 0xFF);
        context->authBuffer[5] = (uint8_t)((context->authDataLen >> 13) & 0xFF);
        context->authBuffer[4] = (uint8_t)((context->authDataLen >> 21) & 0xFF);
        context->authBuffer[3] = (uint8_t)((context->authDataLen >> 29) & 0xFF);
        context->authBuffer[2] = 0;
        context->authBuffer[1] = 0;
        context->authBuffer[0] = 0;
        context->authBufferLen = 16;
        BLOCK_CIPHER_GCM_GHash (context);

        // Compute digest
        (*context->encrypt)(handle, context->authBuffer, context->initializationVector, key);
        for (i = 0; i < context->blockSize; i++)
        {
            context->authTag[i] ^= context->authBuffer[i];
        }

        if (memcmp (authenticationTag, context->authTag, tagLen) != 0)
        {
            return BLOCK_CIPHER_ERROR_INVALID_AUTHENTICATION;
        }
    }

    return BLOCK_CIPHER_ERROR_NONE;
}

BLOCK_CIPHER_ERRORS BLOCK_CIPHER_GCM_KeyStreamGenerate (DRV_HANDLE handle, uint32_t numBlocks, void * key, BLOCK_CIPHER_GCM_CONTEXT * context, uint32_t options)
{
    uint8_t i;
    uint8_t* ptr;
    uint8_t __attribute__((aligned)) buffer[CRYPTO_CONFIG_BLOCK_MAX_SIZE];

    if(memcmp(context->counter,context->initializationVector,context->blockSize) == 0)
    {
        return BLOCK_CIPHER_ERROR_CTR_COUNTER_EXPIRED;
    }

    ptr = context->keyStreamCurrentPosition + context->bytesRemainingInKeyStream;

    while(numBlocks--)
    {
        //If there is enough room in the buffer for one more block of key
        //  data, then let's generate another block of key stream
        if((context->keyStreamSize - context->bytesRemainingInKeyStream) >= context->blockSize)
        {
            (*context->encrypt)(handle, buffer, context->counter, key);

            for(i=0;i<context->blockSize;i++)
            {
                if(ptr >= ((uint8_t*)context->keyStream + context->keyStreamSize))
                {
                    ptr = context->keyStream;
                }

                *ptr++ = buffer[i];
            }

            context->bytesRemainingInKeyStream += context->blockSize;

            i = 15;
            do
            {
                if(++context->counter[i] != 0)
                {
                    break;
                }
            }while(--i > 11);
        }
        else
        {
            return BLOCK_CIPHER_ERROR_KEY_STREAM_GEN_OUT_OF_SPACE;
        }
    }

    return BLOCK_CIPHER_ERROR_NONE;
}

void BLOCK_CIPHER_GCM_GHash (BLOCK_CIPHER_GCM_CONTEXT * context)
{
    uint8_t * buffer = context->authBuffer;
    uint8_t * result = context->authTag;
    uint8_t i, j;

    j = context->blockSize;

    if (context->authBufferLen == 0)
    {
        return;
    }
    else if (context->authBufferLen < j)
    {
        // Pad the data with zeros
        memset (buffer + context->authBufferLen, 0x00, j - context->authBufferLen);
    }

    // XOR the current auth tag with the data in the auth buffer
    for (i = 0; i < j; i++)
    {
        *(result + i) ^= *(buffer + i);
    }

    // Compute the finite field multiplication of that XOR and the hash subkey
    BLOCK_CIPHER_GCM_GaloisMultiply (context->authTag, context->authTag, context->hashSubKey);

    context->authBufferLen = 0;
}

void BLOCK_CIPHER_GCM_GaloisMultiply (uint8_t * result, uint8_t * a, uint8_t * b)
{
    uint8_t bitCount;
    ff_int32_t v[4];
    ff_int32_t product[4];
    uint8_t mask = 0x80;
    bool msbSet;

    // Initialize product to zero
    memset (product, 0x00, 16);

    // Copy b to v (taking endianness into account)
    v[0].ui8_arr[3] = *b++;
    v[0].ui8_arr[2] = *b++;
    v[0].ui8_arr[1] = *b++;
    v[0].ui8_arr[0] = *b++;
    v[1].ui8_arr[3] = *b++;
    v[1].ui8_arr[2] = *b++;
    v[1].ui8_arr[1] = *b++;
    v[1].ui8_arr[0] = *b++;
    v[2].ui8_arr[3] = *b++;
    v[2].ui8_arr[2] = *b++;
    v[2].ui8_arr[1] = *b++;
    v[2].ui8_arr[0] = *b++;
    v[3].ui8_arr[3] = *b++;
    v[3].ui8_arr[2] = *b++;
    v[3].ui8_arr[1] = *b++;
    v[3].ui8_arr[0] = *b++;

    for (bitCount = 0; bitCount < 128; bitCount++)
    {
        if ((*a & mask) != 0)
        {
            product[0].ui32 ^= v[0].ui32;
            product[1].ui32 ^= v[1].ui32;
            product[2].ui32 ^= v[2].ui32;
            product[3].ui32 ^= v[3].ui32;
        }

        // Store the MSb of the 128-bit var
        msbSet = (v[3].ui32 & 0x01) != 0;
        // Shift the other bytes in the 128-bit var
        v[3].ui32 = (v[3].ui32 >> 1) | (v[2].ui32 << 31);
        v[2].ui32 = (v[2].ui32 >> 1) | (v[1].ui32 << 31);
        v[1].ui32 = (v[1].ui32 >> 1) | (v[0].ui32 << 31);
        v[0].ui32 = (v[0].ui32 >> 1);

        // If the MSb of the 128-bit var was set, xor the var with the reducing polynomial
        if (msbSet)
        {
            v[0].ui32 ^= 0xE1000000;
        }
        // Adjust the mask value and move a if necessary
        mask >>= 1;
        if (mask == 0)
        {
            a++;
            mask = 0x80;
        }
    }

    // Copy the product to the output variable
    for (mask = 0; mask < 4; mask++)
    {
        *result++ = product[mask].ui8_arr[3];
        *result++ = product[mask].ui8_arr[2];
        *result++ = product[mask].ui8_arr[1];
        *result++ = product[mask].ui8_arr[0];
    }
}




