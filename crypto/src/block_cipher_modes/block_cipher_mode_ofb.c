
#include "crypto/block_cipher_modes.h"
#include "crypto/src/block_cipher_modes/block_cipher_mode_private.h"
#include "system_config.h"
#include <string.h>

void BLOCK_CIPHER_OFB_Initialize (BLOCK_CIPHER_OFB_CONTEXT * context, BLOCK_CIPHER_FunctionEncrypt encryptFunction, BLOCK_CIPHER_FunctionDecrypt decryptFunction, uint32_t blockSize, uint8_t * initializationVector, void * keyStream, uint32_t keyStreamSize)
{
    context->encrypt = encryptFunction;
    context->decrypt = decryptFunction;
    context->blockSize = blockSize;
    memcpy (context->initializationVector, initializationVector, blockSize);
    context->keyStream = keyStream;
    context->keyStreamSize = keyStreamSize;
}

BLOCK_CIPHER_ERRORS BLOCK_CIPHER_OFB_Encrypt (DRV_HANDLE handle, uint8_t * cipherText, uint8_t * plainText, uint32_t numBytes, void * key, BLOCK_CIPHER_OFB_CONTEXT * context, uint32_t options)
{
    BLOCK_CIPHER_ERRORS status;

    //If the user has specified that they want to create a new stream,
    //  then create the stream for them
    if((options & BLOCK_CIPHER_OPTION_STREAM_START) == BLOCK_CIPHER_OPTION_STREAM_START)
    {
        status = BLOCK_CIPHER_OFB_KeyStreamGenerate (handle, 1, key, context, options);
        if(status != BLOCK_CIPHER_ERROR_NONE)
        {
            return status;
        }
    }

    while(numBytes--)
    {
        if(context->bytesRemainingInKeyStream == 0)
        {
            status = BLOCK_CIPHER_OFB_KeyStreamGenerate   (handle, 1, key, context, BLOCK_CIPHER_OPTION_STREAM_CONTINUE);
            if(status != BLOCK_CIPHER_ERROR_NONE)
            {
                return status;
            }
        }

        context->bytesRemainingInKeyStream--;
        *cipherText++ = *plainText++ ^ *(uint8_t*)context->keyStreamCurrentPosition++;

        if(context->keyStreamCurrentPosition == ((uint8_t*)context->keyStream + context->keyStreamSize))
        {
            context->keyStreamCurrentPosition = context->keyStream;
        }
    }

    return BLOCK_CIPHER_ERROR_NONE;
}

BLOCK_CIPHER_ERRORS BLOCK_CIPHER_OFB_KeyStreamGenerate (DRV_HANDLE handle, uint32_t numBlocks, void * key, BLOCK_CIPHER_OFB_CONTEXT * context, uint32_t options)
{
    uint8_t i;
    uint8_t* ptr;

    if((options & BLOCK_CIPHER_OPTION_STREAM_START) == BLOCK_CIPHER_OPTION_STREAM_START)
    {
        context->keyStreamCurrentPosition = context->keyStream;
        context->bytesRemainingInKeyStream = 0;
    }

    ptr = context->keyStreamCurrentPosition + context->bytesRemainingInKeyStream;

    while(numBlocks--)
    {
        //If there is enough room in the buffer for one more block of key
        //  data, then let's generate another block of key stream
        if((context->keyStreamSize - context->bytesRemainingInKeyStream) >= context->blockSize)
        {
            (*context->encrypt)(handle, context->initializationVector, context->initializationVector, key);

            for(i=0;i<context->blockSize;i++)
            {
                if(ptr >= ((uint8_t*)context->keyStream + context->keyStreamSize))
                {
                    ptr = context->keyStream;
                }

                *ptr++ = context->initializationVector[i];
            }

            context->bytesRemainingInKeyStream += context->blockSize;
        }
        else
        {
            return BLOCK_CIPHER_ERROR_KEY_STREAM_GEN_OUT_OF_SPACE;
        }
    }

    return BLOCK_CIPHER_ERROR_NONE;
}

