/*********************************************************************
 *
 *                  Block Cipher Mode of Operation header
 *                  Cipher Feedback Mode
 *
 *********************************************************************
 * FileName:        block_cipher_mode_cfb.h
 * Dependencies:    None
 * Processor:       PIC18, PIC24F, PIC24H, dsPIC30F, dsPIC33F
 * Company:         Microchip Technology, Inc.
 *
 * Software License Agreement
 *
 * Copyright (C) 2002-2012 Microchip Technology Inc.  All rights
 * reserved.
 *
 * Microchip licenses to you the right to use, modify, copy, and
 * distribute:
 * (i)  the Software when embedded on a Microchip microcontroller or
 *      digital signal controller product ("Device") which is
 *      integrated into Licensee's product; or
 * (ii) ONLY the Software driver source files ENC28J60.c, ENC28J60.h,
 *        ENCX24J600.c and ENCX24J600.h ported to a non-Microchip device
 *        used in conjunction with a Microchip ethernet controller for
 *        the sole purpose of interfacing with the ethernet controller.
 *
 * You should refer to the license agreement accompanying this
 * Software for additional information regarding your rights and
 * obligations.
 *
 * THE SOFTWARE AND DOCUMENTATION ARE PROVIDED "AS IS" WITHOUT
 * WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
 * LIMITATION, ANY WARRANTY OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO EVENT SHALL
 * MICROCHIP BE LIABLE FOR ANY INCIDENTAL, SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES, LOST PROFITS OR LOST DATA, COST OF
 * PROCUREMENT OF SUBSTITUTE GOODS, TECHNOLOGY OR SERVICES, ANY CLAIMS
 * BY THIRD PARTIES (INCLUDING BUT NOT LIMITED TO ANY DEFENSE
 * THEREOF), ANY CLAIMS FOR INDEMNITY OR CONTRIBUTION, OR OTHER
 * SIMILAR COSTS, WHETHER ASSERTED ON THE BASIS OF CONTRACT, TORT
 * (INCLUDING NEGLIGENCE), BREACH OF WARRANTY, OR OTHERWISE.
 *
 * IMPORTANT:  The implementation and use of third party algorithms,
 * specifications and/or other technology may require a license from
 * various third parties.  It is your responsibility to obtain
 * information regarding any applicable licensing obligations.
 *
 ********************************************************************/

#include <stdint.h>
#include "system_config.h"

// Context structure for a cipher feedback operation
typedef struct
{
    uint8_t __attribute__((aligned)) initializationVector[CRYPTO_CONFIG_BLOCK_MAX_SIZE];      // Initialization vector for the CFB operation
    uint32_t blockSize;                                                         // Block size of the cipher algorithm being used with the block cipher mode module
    BLOCK_CIPHER_FunctionEncrypt encrypt;                                       // Encrypt function for the algorithm being used with the block cipher mode module
    BLOCK_CIPHER_FunctionDecrypt decrypt;                                       // Decrypt function for the algorithm being used with the block cipher mode module
    uint8_t bytesRemaining;                                                     // Number of bytes remaining in the remainingData buffer
} BLOCK_CIPHER_CFB_CONTEXT;

// *****************************************************************************
/* Function:
    void BLOCK_CIPHER_CFB_Initialize (BLOCK_CIPHER_CFB_CONTEXT * context, 
        BLOCK_CIPHER_FunctionEncrypt encryptFunction, 
        BLOCK_CIPHER_FunctionDecrypt decryptFunction, uint32_t blockSize,
        uint8_t * initialization_vector)

  Summary:
    Initializes a CFB context for encryption/decryption.
  
  Description:
    Initializes a CFB context for encryption/decryption.  The user will specify 
    details about the algorithm being used in CFB mode.
  
  Precondition:
    Any required initialization needed by the block cipher algorithm must
    have been performed.

  Parameters:
    context - The CFB context to initialize.
    encryptFunction - Pointer to the encryption function for the block cipher
        algorithm being used in CFB mode.
    decryptFunction - Pointer to the decryption function for the block cipher
        algorithm being used in CFB mode.
    blockSize - The block size of the block cipher algorithm being used in CFB mode.
    initializationVector - The initialization vector for this operation.  The length
        of this vector must be equal to the block size of your block cipher.

  Returns:
    None.
    
  Example:
    <code>
    // Initialize the CFB block cipher module for use with AES.
    SYS_MODULE_OBJ sysObject;
    DRV_HANDLE handle;
    BLOCK_CIPHER_CFB_CONTEXT context;
    // Initialization vector for CFB mode
    static uint8_t initialization_vector[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    sysObject = DRV_AES_Initialize (DRV_AES_INDEX, NULL);
    if (sysObject != SYS_MODULE_OBJ_STATIC)
    {
        // error
    }

    handle = DRV_AES_Open (DRV_AES_INDEX, 0);
    if (handle != DRV_AES_HANDLE)
    {
        // error
    }

    // Initialize the block cipher module
    BLOCK_CIPHER_CFB_Initialize (&context, AES_Encrypt, AES_Decrypt, AES_BLOCK_SIZE, initialization_vector);
    </code>
*/
void BLOCK_CIPHER_CFB_Initialize (BLOCK_CIPHER_CFB_CONTEXT * context, BLOCK_CIPHER_FunctionEncrypt encryptFunction, BLOCK_CIPHER_FunctionDecrypt decryptFunction, uint32_t blockSize, uint8_t * initializationVector);

/*********************************************************************************************************************************************************************************************************************
  Function:
       void BLOCK_CIPHER_CFB_Encrypt (DRV_HANDLE handle, uint8_t * cipherText,
           uint32_t * numCipherBytes, uint8_t * plainText, uint32_t numPlainBytes,
           void * key, BLOCK_CIPHER_CFB_CONTEXT * context, uint32_t options);
    
  Summary:
    Encrypts plain text using cipher feedback mode.
  Description:
    Encrypts plain text using cipher feedback mode.
  Conditions:
    The CFB context must be initialized with the block cipher
    encrypt/decrypt functions and the block cipher algorithm's block size.
    The block cipher module must be initialized, if necessary.
  Input:
    handle -          A handle that is passed to the block cipher's
                      encrypt/decrypt functions to specify which instance of
                      the block cipher module to use. This parameter can be
                      specified as NULL if the block cipher does not have
                      multiple instances.
    cipherText -      The cipher text produced by the encryption. This
                      buffer must be a multiple of the block size, even if
                      the plain text buffer size is not. This buffer should
                      always be larger than the plain text buffer.
    numCipherBytes -  Pointer to a uint32_t; the number of bytes encrypted
                      will be returned in this parameter.
    plainText -       The plain test to encrypt.
    numPlainBytes -   The number of plain text bytes that must be encrypted.
                      If the number of plain text bytes encrypted is not
                      evenly divisible by the block size, the remaining
                      bytes will be cached in the CFB context structure
                      until additional data is provided.
    key -             The key to use when encrypting/decrypting the data.
                      The format of this key will depend on the block cipher
                      you are using.
    context -         Pointer to a context structure for this encryption.
                      The first call of this function should have the
                      context->initializationVector set to the
                      initializationVector. The same context structure
                      instance should be used for every call used for the
                      same data stream. The contents of this structure
                      should not be changed by the user once the
                      encryption/decryption has started.
    options -         Block cipher encryption options that the user can
                      specify, or'd together. Valid options for this
                      function are
                      * BLOCK_CIPHER_OPTION_STREAM_START
                      * BLOCK_CIPHER_OPTION_STREAM_CONTINUE
                      * BLOCK_CIPHER_OPTION_STREAM_COMPLETE
                      * BLOCK_CIPHER_OPTION_CIPHER_TEXT_POINTER_ALIGNED
                      * BLOCK_CIPHER_OPTION_PLAIN_TEXT_POINTER_ALIGNED
                      * BLOCK_CIPHER_OPTION_USE_CFB1
                      * BLOCK_CIPHER_OPTION_USE_CFB8
                      * BLOCK_CIPHER_OPTION_USE_CFB_BLOCK_SIZE
  Return:
    None
    
  Example:
    <code>
    // ***************************************************************
    // Encrypt data in CFB mode with the AES algorithm.
    // ***************************************************************
    
    // System module object variable (for initializing AES)
    SYS_MODULE_OBJ sysObject;
    
    // Drive handle variable, to describe which AES module to use
    DRV_HANDLE handle;
    
    // CFB mode context
    BLOCK_CIPHER_CFB_CONTEXT context;

    // Initialization vector for CFB mode
    static uint8_t initialization_vector[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    // Plain text to encrypt
    static uint8_t plain_text[] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, \
                                    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, \
                                    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, \
                                    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
    // The encryption key
    static uint8_t AESKey128[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    // Structure to contain the created AES round keys
    AES_ROUND_KEYS_128_BIT round_keys;
    // Buffer to contain encrypted plaintext
    uint8_t cipher_text[sizeof(plain_text)];
    // The number of bytes that were encrypted
    uint32_t num_bytes_encrypted;
    
    // Initialization call for the AES module
    sysObject = DRV_AES_Initialize (DRV_AES_INDEX, NULL);
    if (sysObject != SYS_MODULE_OBJ_STATIC)
    {
        // error
    }

    // Driver open call for the AES module
    handle = DRV_AES_Open (DRV_AES_INDEX, 0);
    if (handle != DRV_AES_HANDLE)
    {
        // error
    }

    //Create the AES round keys.  This only needs to be done once for each AES key.
    AES_RoundKeysCreate (&round_keys, (uint8_t*)AESKey128, AES_KEY_SIZE_128_BIT);

    // Initialize the Block Cipher context with the AES module encryption/decryption functions and the AES block size
    BLOCK_CIPHER_CFB_Initialize (&context, AES_Encrypt, AES_Decrypt, AES_BLOCK_SIZE, initialization_vector);

    //Encrypt the data
    BLOCK_CIPHER_CFB_Encrypt (handle, cipher_text, &num_bytes_encrypted, (void *) plain_text, sizeof(plain_text), &round_keys, &context, BLOCK_CIPHER_OPTION_STREAM_START | BLOCK_CIPHER_OPTION_USE_CFB1);
    </code>
                                                                                                                                                                                                                      
  *********************************************************************************************************************************************************************************************************************/
void BLOCK_CIPHER_CFB_Encrypt (DRV_HANDLE handle, uint8_t * cipherText, uint8_t * plainText, uint32_t numBytes, void * key, BLOCK_CIPHER_CFB_CONTEXT * context, uint32_t options);

// *****************************************************************************
/* Function:
    void BLOCK_CIPHER_CFB_Decrypt (DRV_HANDLE handle, uint8_t * plainText, 
        uint32_t * numPlainBytes, uint8_t * cipherText, uint32_t numCipherBytes, 
        void * key, BLOCK_CIPHER_CFB_CONTEXT * context, uint32_t options)

    Summary:
    Decrypts cipher text using cipher-block chaining mode.
  Description:
    Decrypts cipher text using cipher-block chaining mode.
  Conditions:
    The CFB context must be initialized with the block cipher
    encrypt/decrypt functions and the block cipher algorithm's block size.
    The block cipher module must be initialized, if necessary.
  Input:
    handle -          A handle that is passed to the block cipher's
                      encrypt/decrypt functions to specify which instance of
                      the block cipher module to use. This parameter can be
                      specified as NULL if the block cipher does not have
                      multiple instances.
    plainText -       The plain test produced by the decryption. This buffer
                      must be a multiple of the block cipher's block size,
                      even if the cipher text passed in is not.
    numPlainBytes -   Pointer to a uint32_t; the number of bytes decrypted
                      will be returned in this parameter.
    cipherText -      The cipher text that will be decrypted. This buffer
                      must be a multiple of the block size, unless this is
                      the end of the stream (the
                      BLOCK_CIPHER_OPTION_STREAM_COMPLETE option must be set
                      in this case).
    numCipherBytes -  The number of cipher text bytes to decrypt.
    key -             The key to use when encrypting/decrypting the data.
                      The format of this key will depend on the block cipher
                      you are using.
    context -         Pointer to a context structure for this decryption.
                      The first call of this function should have the
                      context->initializationVector set to the
                      initializationVector. The same context structure
                      instance should be used for every call used for the
                      same data stream. The contents of this structure
                      should not be changed by the user once the
                      encryption/decryption has started.
    options -         Block cipher encryption options that the user can
                      specify, or'd together. Valid options for this
                      function are
                      * BLOCK_CIPHER_OPTION_STREAM_START
                      * BLOCK_CIPHER_OPTION_STREAM_COMPLETE
                      * BLOCK_CIPHER_OPTION_CIPHER_TEXT_POINTER_ALIGNED
                      * BLOCK_CIPHER_OPTION_PLAIN_TEXT_POINTER_ALIGNED
                      * BLOCK_CIPHER_OPTION_USE_CFB1
                      * BLOCK_CIPHER_OPTION_USE_CFB8
                      * BLOCK_CIPHER_OPTION_USE_CFB_BLOCK_SIZE
  Return:
    None
    
  Example:
    <code>
    // ***************************************************************
    // Decrypt data in CFB mode with the AES algorithm.
    // ***************************************************************
    
    // System module object variable (for initializing AES)
    SYS_MODULE_OBJ sysObject;
    
    // Drive handle variable, to describe which AES module to use
    DRV_HANDLE handle;
    
    // CFB mode context
    BLOCK_CIPHER_CFB_CONTEXT context;

    // Initialization vector for CFB mode
    static uint8_t initialization_vector[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    // Cipher text to decrypt
    static uint8_t cipher_text[] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, \
                                     0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, \
                                     0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, \
                                     0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
    // The encryption key
    static uint8_t AESKey128[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    // Structure to contain the created AES round keys
    AES_ROUND_KEYS_128_BIT round_keys;
    // Buffer to contain encrypted plaintext
    uint8_t plain_text[sizeof(cipher_text)];
    // The number of bytes that were decrypted
    uint32_t num_bytes_decrypted;
    
    // Initialization call for the AES module
    sysObject = DRV_AES_Initialize (DRV_AES_INDEX, NULL);
    if (sysObject != SYS_MODULE_OBJ_STATIC)
    {
        // error
    }

    // Driver open call for the AES module
    handle = DRV_AES_Open (DRV_AES_INDEX, 0);
    if (handle != DRV_AES_HANDLE)
    {
        // error
    }

    //Create the AES round keys.  This only needs to be done once for each AES key.
    AES_RoundKeysCreate (&round_keys, (uint8_t*)AESKey128, AES_KEY_SIZE_128_BIT);
    
    // Initialize the Block Cipher context with the AES module encryption/decryption functions and the AES block size
    BLOCK_CIPHER_CFB_Initialize (&context, AES_Encrypt, AES_Decrypt, AES_BLOCK_SIZE, initialization_vector);

    // Decrypt the data
    BLOCK_CIPHER_CFB_Decrypt (handle, plain_text, &num_bytes_decrypted, (void *) cipher_text, sizeof(cipher_text), &round_keys, &context, BLOCK_CIPHER_OPTION_STREAM_START | BLOCK_CIPHER_USE_CFB1);
    </code>
*/
void BLOCK_CIPHER_CFB_Decrypt (DRV_HANDLE handle, uint8_t * plainText, uint8_t * cipherText, uint32_t numBytes, void * key, BLOCK_CIPHER_CFB_CONTEXT * context, uint32_t options);



