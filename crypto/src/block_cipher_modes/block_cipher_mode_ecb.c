
#include "crypto/block_cipher_modes.h"
#include "crypto/src/block_cipher_modes/block_cipher_mode_private.h"
#include "system_config.h"
#include <string.h>

void BLOCK_CIPHER_ECB_Initialize (BLOCK_CIPHER_ECB_CONTEXT * context, BLOCK_CIPHER_FunctionEncrypt encryptFunction, BLOCK_CIPHER_FunctionDecrypt decryptFunction, uint32_t blockSize)
{
    context->encrypt = encryptFunction;
    context->decrypt = decryptFunction;
    context->blockSize = blockSize;
}

void BLOCK_CIPHER_ECB_Encrypt (DRV_HANDLE handle, uint8_t * cipherText, uint32_t * numCipherBytes, uint8_t * plainText, uint32_t numPlainBytes, void * key, BLOCK_CIPHER_ECB_CONTEXT * context, uint32_t options)
{
    uint8_t i;
    uint8_t __attribute__((aligned)) buffer[CRYPTO_CONFIG_BLOCK_MAX_SIZE];
    
    *numCipherBytes = 0;
    
    if ((options & BLOCK_CIPHER_OPTION_STREAM_START) == BLOCK_CIPHER_OPTION_STREAM_START)
    {
        context->bytesRemaining = 0;
    }
    
    if ((context->bytesRemaining + numPlainBytes) < context->blockSize)
    {
        for (i = context->bytesRemaining; i < context->bytesRemaining + numPlainBytes; i++)
        {
            context->remainingData[i] = *plainText++;
        }
        
        context->bytesRemaining += numPlainBytes;
        
        return;
    }
    
    for (i = context->bytesRemaining; i < context->blockSize; i++)
    {
        context->remainingData[i] = *plainText++;
    }
    
    numPlainBytes += context->bytesRemaining;
    
    while (1)
    {
        (*context->encrypt)(handle, buffer, context->remainingData, key);

        memcpy(cipherText,buffer,context->blockSize);

        numPlainBytes -= context->blockSize;
        *numCipherBytes += context->blockSize;

        cipherText += context->blockSize;

        //Continue with the remaining data left to process
        if(numPlainBytes >= context->blockSize)
        {
            //Get the next input block ready
            memcpy( context->remainingData,
                    plainText,
                    context->blockSize
                  );
            plainText += context->blockSize;
        }
        else
        {
            if((options & BLOCK_CIPHER_OPTION_PAD_MASK) != BLOCK_CIPHER_OPTION_PAD_NONE)
            {
                // Add padding to the block
                BLOCK_CIPHER_PaddingInsert(context->remainingData, context->blockSize, context->blockSize - context->bytesRemaining, options);
    
                // Since we have added padding, there is a full block of data.
                numPlainBytes = context->blockSize;

                // Clear the padding option so we don't come back to this section
                //   of code again.
                options &= ~BLOCK_CIPHER_OPTION_PAD_MASK;
            }
            else
            {
                //If there isn't a complete block worth of data left then exit the 
                //  loop.
                break;
            }
        }
    }

    //save the number of plain text bytes remaining in the buffer
    context->bytesRemaining = numPlainBytes;

    //Copy any remaining bytes to the buffer.
    for(i=0; i < numPlainBytes; i++)
    {
        context->remainingData[i] = *plainText++;
    }

}

void BLOCK_CIPHER_ECB_Decrypt (DRV_HANDLE handle, uint8_t * plainText, uint32_t * numPlainBytes, uint8_t * cipherText, uint32_t numCipherBytes, void * key, BLOCK_CIPHER_ECB_CONTEXT * context, uint32_t options)
{
    uint8_t i;

    *numPlainBytes = 0;

    if((options & BLOCK_CIPHER_OPTION_STREAM_START) == BLOCK_CIPHER_OPTION_STREAM_START)
    {
        context->bytesRemaining = 0;
    }

    if((context->bytesRemaining + numCipherBytes) < context->blockSize)
    {
        //Append the new data to the end of the old data
        memcpy(&context->remainingData[context->bytesRemaining], cipherText, numCipherBytes);                

        //increase the size of the number of bytes with the number of bytes
        //  that were remaining in the buffer before the function was called.
        context->bytesRemaining += numCipherBytes;

        //exit since there is not a complete block;
        return;
    }

    //Append the new data to the end of the old data
    for(i=context->bytesRemaining; i < context->blockSize; i++)
    {
        context->remainingData[i] = *cipherText++;
    }

    //increase the size of the number of bytes with the number of bytes
    //  that were remaining in the buffer before the function was called.
    numCipherBytes += context->bytesRemaining;

    while(1)
    {
        (*context->decrypt)(handle, plainText, context->remainingData, key);
        
        numCipherBytes -= context->blockSize;
        *numPlainBytes += context->blockSize;

        plainText += context->blockSize;

        if(numCipherBytes >= context->blockSize)
        {
            //Get the next input block ready
            memcpy(context->remainingData, cipherText, context->blockSize);
            cipherText += context->blockSize;
        }
        else
        {
            //If there isn't a complete block worth of data left then exit the 
            //  loop.
            break;
        }
    }

    //save the number of plain text bytes remaining in the buffer
    context->bytesRemaining = numCipherBytes;

    //Copy any remaining bytes to the buffer.
    memcpy(context->remainingData, cipherText, numCipherBytes);
}


