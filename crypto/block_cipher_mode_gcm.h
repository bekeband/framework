/*********************************************************************
 *
 *                  Block Cipher Mode of Operation header
 *                  Galois Message Authentication Code Mode
 *
 *********************************************************************
 * FileName:        block_cipher_mode_gmac.h
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
#include <stdbool.h>
#include "system_config.h"

// Context structure for the Galois counter operation
typedef struct
{
    uint8_t __attribute__((aligned)) initializationVector[CRYPTO_CONFIG_BLOCK_MAX_SIZE];  // Buffer containing the initialization vector and initial counter.
    uint8_t __attribute__((aligned)) counter[CRYPTO_CONFIG_BLOCK_MAX_SIZE];               // Buffer containing the current counter value.
    uint8_t __attribute__((aligned)) hashSubKey[CRYPTO_CONFIG_BLOCK_MAX_SIZE];            // Buffer containing the calculated hash subkey
    uint8_t __attribute__((aligned)) authTag[CRYPTO_CONFIG_BLOCK_MAX_SIZE];               // Buffer containing the current authentication tag
    uint8_t __attribute__((aligned)) authBuffer[CRYPTO_CONFIG_BLOCK_MAX_SIZE];            // Buffer containing data that has been encrypted but has not been authenticated
    BLOCK_CIPHER_FunctionEncrypt encrypt;                                   // Encrypt function for the algorithm being used with the block cipher mode module
    BLOCK_CIPHER_FunctionDecrypt decrypt;                                   // Decrypt function for the algorithm being used with the block cipher mode module
    void * keyStream;                                                       // Pointer to the key stream.  Must be a multiple of the cipher's block size, but smaller than 2^25 bytes.
    void * keyStreamCurrentPosition;                                        // Pointer to the current position in the key stream.
    uint32_t keyStreamSize;                                                 // Size of the key stream.
    uint32_t bytesRemainingInKeyStream;                                     // Number of bytes remaining in the key stream
    uint32_t blockSize;                                                     // Block size of the cipher algorithm being used with the block cipher mode module
    uint32_t cipherTextLen;                                                 // Current number of ciphertext bytes computed
    uint32_t authDataLen;                                                   // Current number of non-ciphertext bytes authenticated
    uint8_t authBufferLen;                                                  // Number of bytes in the auth Buffer
    struct
    {
        uint8_t authCompleted : 1;                                          // Determines if authentication of non-encrypted data has been completed for this device.
        uint8_t filler : 7;
    } flags;
} BLOCK_CIPHER_GCM_CONTEXT;


// *****************************************************************************
/* Function:
    void BLOCK_CIPHER_GCM_Initialize (BLOCK_CIPHER_GCM_CONTEXT * context,
        BLOCK_CIPHER_FunctionEncrypt encryptFunction,
        BLOCK_CIPHER_FunctionDecrypt decryptFunction, uint32_t blockSize,
        uint8_t * initializationVector, void * keyStream, uint32_t keyStreamSize)

  Summary:
    Initializes a GCM context for encryption/decryption.
  
  Description:
    Initializes a GCM context for encryption/decryption.  The user will specify
    details about the algorithm being used in GCM mode.
  
  Precondition:
    Any required initialization needed by the block cipher algorithm must
    have been performed.

  Parameters:
    handle - A handle that is passed to the block cipher's encrypt/decrypt
        functions to specify which instance of the block cipher module to use.
        This parameter can be specified as NULL if the block cipher does not
        have multiple instances.
    context - The GCM context to initialize.
    encryptFunction - Pointer to the encryption function for the block cipher
        algorithm being used in GCM mode.
    decryptFunction - Pointer to the decryption function for the block cipher
        algorithm being used in GCM mode.
    blockSize - The block size of the block cipher algorithm being used in GCM mode.
    initializationVector - A security nonce.  See the GCM specification, section 8.2
        for information about constructing initialization vectors.
    initializationVectorLen - Length of the initialization vector, in bytes
    keyStream - Pointer to a buffer to contain a calculated keyStream.
    keyStreamSize - The size of the keystream buffer, in bytes.
    key - The key to use when encrypting/decrypting the data.  The format of
        this key will depend on the block cipher you are using.  The key is
        used by the Initialize function to calculate the hash subkey.

  Returns:
    None.
    
  Example:
    <code>
    // Initialize the GCM block cipher module for use with AES.
    SYS_MODULE_OBJ sysObject;
    DRV_HANDLE handle;
    BLOCK_CIPHER_GCM_CONTEXT context;
    // Initialization vector for GCM mode
    static uint8_t ivValue[12] = {0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,0xde,0xca,0xf8,0x88};
    //keyStream could also be allocated memory instead of fixed memory
    uint8_t keyStream[AES_BLOCK_SIZE*4];
    // The encryption key
    static uint8_t AESKey128[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    // Structure to contain the created AES round keys
    AES_ROUND_KEYS_128_BIT round_keys;

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

    //Create the AES round keys.  This only needs to be done once for each AES key.
    AES_RoundKeysCreate (&round_keys, (uint8_t*)AESKey128, AES_KEY_SIZE_128_BIT);

    // Initialize the Block Cipher context
    BLOCK_CIPHER_GCM_Initialize (handle, &context, AES_Encrypt, AES_Decrypt, AES_BLOCK_SIZE, (uint8_t *)ivValue, 12, (void *)&keyStream, sizeof(keyStream), &round_keys);
    </code>
*/
void BLOCK_CIPHER_GCM_Initialize (DRV_HANDLE handle, BLOCK_CIPHER_GCM_CONTEXT * context, BLOCK_CIPHER_FunctionEncrypt encryptFunction, BLOCK_CIPHER_FunctionDecrypt decryptFunction, uint32_t blockSize, uint8_t * initializationVector, uint32_t initializationVectorLen, void * keyStream, uint32_t keyStreamSize, void * key);

/***********************************************************************************************************************************************************************************************
  Function:
       BLOCK_CIPHER_ERRORS BLOCK_CIPHER_GCM_Encrypt (DRV_HANDLE handle,
           uint8_t * cipherText, uint8_t * plainText, uint32_t numBytes,
           uint8_t * authenticationTag, uint8_t tagLen, void * key,
           BLOCK_CIPHER_GCM_CONTEXT * context, uint32_t options)
    
  Summary:
    Encrypts/authenticates plain text using Galois/counter mode.
  Description:
    Encrypts/authenticates plain text using Galois/counter mode. This
    function accepts a combination of data that must be authenticated but
    not encrypted, and data that must be authenticated and encrypted. The
    user should initialize a GCM context using BLOCK_CIPHER_GCM_Initialize,
    then pass all authenticated-but-not-encrypted data into this function
    with the BLOCK_CIPHER_OPTION_AUTHENTICATE_ONLY option, and then pass
    any authenticated-and-encrypted data in using the
    BLOCK_CIPHER_OPTION_STREAM_CONTINUE option. When calling this function
    for the final time, the user must use the
    BLOCK_CIPHER_OPTION_STREAM_COMPLETE option to generate padding required
    to compute the authentication tag successfully. Note that
    BLOCK_CIPHER_OPTION_STREAM_COMPLETE must always be specified at the end
    of a stream, even if no encryption is being done.
    
    The GMAC (Galois Message Authentication Code) mode can be used by using
    GCM without providing any data to encrypt (e.g. by only using
    BLOCK_CIPHER_OPTION_AUTHENTICATE_ONLY and
    BLOCK_CIPHER_OPTION_STREAM_COMPLETE options).
  Conditions:
    The GCM context must be initialized with the block cipher
    encrypt/decrypt functions and the block cipher algorithm's block size.
    The block cipher module must be initialized, if necessary.
    
    The initializationVector parameter in the BLOCK_CIPHER_GCM_CONTEXT
    structure should be initialized. See section 8.2 of the GCM
    specification for more information.
  Input:
    handle -             A handle that is passed to the block cipher's
                         encrypt/decrypt functions to specify which instance
                         of the block cipher module to use. This parameter
                         can be specified as NULL if the block cipher does
                         not have multiple instances.
    cipherText -         The cipher text produced by the encryption. This
                         buffer must be at least numBytes long.
    plainText -          The plain test to encrypt. Must be at least
                         numBytes long.
    numBytes -           The number of plain text bytes that must be
                         encrypted.
    authenticationTag -  Pointer to a structure to contain the
                         authentication tag generated by a series of
                         authentications. The tag will be written to this
                         buffer when the user specifies the
                         BLOCK_CIPHER_OPTION_STREAM_COMPLETE option.
    tagLen -             The length of the authentication tag, in bytes. 16
                         bytes is standard. Shorter byte lengths can be
                         used, but they provide less reliable
                         authentication.
    key -                The key to use when encrypting/decrypting the data.
                         The format of this key will depend on the block
                         cipher you are using.
    context -            Pointer to a context structure for this encryption.
                         The first call of this function should have the
                         context->initializationVector set to the
                         initializationVector. The same context structure
                         instance should be used for every call used for the
                         same data stream. The contents of this structure
                         should not be changed by the user once the
                         encryption/decryption has started.
    options -            Block cipher encryption options that the user can
                         specify, or'd together. If no option is specified
                         then BLOCK_CIPHER_OPTION_STREAM_CONTINUE is
                         assumed. Valid options for this function are
                         * BLOCK_CIPHER_OPTION_AUTHENTICATE_ONLY
                         * BLOCK_CIPHER_OPTION_STREAM_CONTINUE
                         * BLOCK_CIPHER_OPTION_STREAM_COMPLETE
  Return:
    Returns a member of the BLOCK_CIPHER_ERRORS enumeration:
      * BLOCK_CIPHER_ERROR_NONE - no error.
      * BLOCK_CIPHER_ERROR_KEY_STREAM_GEN_OUT_OF_SPACE - There was not
        enough room remaining in the context->keyStream buffer to fit the
        key data requested by the numBlocks parameter.
      * BLOCK_CIPHER_ERROR_GCM_COUNTER_EXPIRED - The requesting call
        has caused the counter number to run out of unique combinations.
  Example:
    <code>
    // ***************************************************************
    // Encrypt data in GCM mode with the AES algorithm.
    // ***************************************************************
    
    // System module object variable (for initializing AES)
    SYS_MODULE_OBJ sysObject;
    
    // Drive handle variable, to describe which AES module to use
    DRV_HANDLE handle;
    
    // GCM mode context
    BLOCK_CIPHER_GCM_CONTEXT context;

    // Initialization vector for GCM mode
    static uint8_t ivValue[12] = {0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,0xde,0xca,0xf8,0x88};

    // Data that will be authenticated, but not encrypted.
    uint8_t authData[20] = {0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,0xab,0xad,0xda,0xd2,};

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
    //keyStream could also be allocated memory instead of fixed memory
    uint8_t keyStream[AES_BLOCK_SIZE*4];
    // Structure to contain the calculated authentication tag
    uint8_t tag[16];
    
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

    // Initialize the Block Cipher context
    BLOCK_CIPHER_GCM_Initialize (handle, &context, AES_Encrypt, AES_Decrypt, AES_BLOCK_SIZE, (uint8_t *)ivValue, 12, (void *)&keyStream, sizeof(keyStream), &round_keys);

    //Generate 4 blocks of key stream
    BLOCK_CIPHER_GCM_KeyStreamGenerate(handle, 4, &round_keys, &context, 0);

    // Authenticate the non-encrypted data
    if (BLOCK_CIPHER_GCM_Encrypt (handle, NULL, (uint8_t *)authData, 20, NULL, 0, &round_keys, &context, BLOCK_CIPHER_OPTION_AUTHENTICATE_ONLY) != BLOCK_CIPHER_ERROR_NONE)
    {
        // An error occured
        while(1);
    }

    // As an example, this data will be encrypted in two blocks, to demonstrate how to use the options.
    // Encrypt the first forty bytes of data.
    // Note that at this point, you don't really need to specify the tag pointer or its length.  This parameter only
    // needs to be specified when the BLOCK_CIPHER_OPTION_STREAM_COMPLETE option is used.
    if (BLOCK_CIPHER_GCM_Encrypt (handle, cipherText, (uint8_t *)ptShort, 40, tag, 16, &round_keys, &context, BLOCK_CIPHER_OPTION_STREAM_CONTINUE) != BLOCK_CIPHER_ERROR_NONE)
    {
        // An error occured
        while(1);
    }

    //Encrypt the final twenty bytes of data.
    // Since we are using BLOCK_CIPHER_OPTION_STREAM_COMPLETE, we must specify a pointer to and length of the tag array, to store the auth tag.
    if (BLOCK_CIPHER_GCM_Encrypt (handle, cipherText + 40, (uint8_t *)ptShort + 40, 20, tag, 16, &round_keys, &context, BLOCK_CIPHER_OPTION_STREAM_COMPLETE) != BLOCK_CIPHER_ERROR_NONE)
    {
        // An error occured
        while(1);
    }
    </code>
                                                                                                                                                                                                
  ***********************************************************************************************************************************************************************************************/
BLOCK_CIPHER_ERRORS BLOCK_CIPHER_GCM_Encrypt (DRV_HANDLE handle, uint8_t * cipherText, uint8_t * plainText, uint32_t numBytes, uint8_t * authenticationTag, uint8_t tagLen, void * key, BLOCK_CIPHER_GCM_CONTEXT * context, uint32_t options);

// *****************************************************************************
/* Function:
    BLOCK_CIPHER_ERRORS BLOCK_CIPHER_GCM_Decrypt (DRV_HANDLE handle,
        uint8_t * plainText, uint8_t * cipherText, uint32_t numBytes,
        uint8_t * authenticationTag, uint8_t tagLen, void * key,
        BLOCK_CIPHER_GCM_CONTEXT * context, uint32_t options)

  Summary:
    Decrypts/authenticates plain text using Galois/counter mode.
  Description:
    Decrypts/authenticates plain text using Galois/counter mode. This
    function accepts a combination of data that must be authenticated but
    not decrypted, and data that must be authenticated and decrypted. The
    user should initialize a GCM context using BLOCK_CIPHER_GCM_Initialize,
    then pass all authenticated-but-not-decrypted data into this function
    with the BLOCK_CIPHER_OPTION_AUTHENTICATE_ONLY option, and then pass
    any authenticated-and-decrypted data in using the
    BLOCK_CIPHER_OPTION_STREAM_CONTINUE option. When calling this function
    for the final time, the user must use the
    BLOCK_CIPHER_OPTION_STREAM_COMPLETE option to generate padding required
    to compute the authentication tag successfully. Note that
    BLOCK_CIPHER_OPTION_STREAM_COMPLETE must always be specified at the end
    of a stream, even if no encryption is being done.
    
    The GMAC (Galois Message Authentication Code) mode can be used by using
    GCM without providing any data to decrypt (e.g. by only using
    BLOCK_CIPHER_OPTION_AUTHENTICATE_ONLY and
    BLOCK_CIPHER_OPTION_STREAM_COMPLETE options).
  Conditions:
    The GCM context must be initialized with the block cipher
    encrypt/decrypt functions and the block cipher algorithm's block size.
    The block cipher module must be initialized, if necessary.
    
    The initializationVector parameter in the BLOCK_CIPHER_GCM_CONTEXT
    structure should be initialized. See section 8.2 of the GCM
    specification for more information.
  Input:
    handle -             A handle that is passed to the block cipher's
                         encrypt/decrypt functions to specify which instance
                         of the block cipher module to use. This parameter
                         can be specified as NULL if the block cipher does
                         not have multiple instances.
    plainText -          The cipher text produced by the decryption. This
                         buffer must be at least numBytes long.
    cipherText -         The cipher test to decrypt. Must be at least
                         numBytes long.
    numBytes -           The number of cipher text bytes that must be
                         decrypted.
    authenticationTag -  Pointer to a structure containing the
                         authentication tag generated by an
                         encrypt/authenticate operation. The tag calculated
                         during decryption will be checked against this
                         buffer when the user specifies the
                         BLOCK_CIPHER_OPTION_STREAM_COMPLETE option.
    tagLen -             The length of the authentication tag, in bytes.
    key -                The key to use when encrypting/decrypting the data.
                         The format of this key will depend on the block
                         cipher you are using.
    context -            Pointer to a context structure for this decryption.
                         The first call of this function should have the
                         context->initializationVector set to the
                         initializationVector. The same context structure
                         instance should be used for every call used for the
                         same data stream. The contents of this structure
                         should not be changed by the user once the
                         encryption/decryption has started.
    options -            Block cipher decryption options that the user can
                         specify, or'd together. If no option is specified
                         then BLOCK_CIPHER_OPTION_STREAM_CONTINUE is
                         assumed. Valid options for this function are
                         * BLOCK_CIPHER_OPTION_AUTHENTICATE_ONLY
                         * BLOCK_CIPHER_OPTION_STREAM_CONTINUE
                         * BLOCK_CIPHER_OPTION_STREAM_COMPLETE
  Return:
    Returns a member of the BLOCK_CIPHER_ERRORS enumeration:
      * BLOCK_CIPHER_ERROR_NONE - no error.
      * BLOCK_CIPHER_ERROR_KEY_STREAM_GEN_OUT_OF_SPACE - There was not
        enough room remaining in the context->keyStream buffer to fit the
        key data requested by the numBlocks parameter.
      * BLOCK_CIPHER_ERROR_GCM_COUNTER_EXPIRED - The requesting call
        has caused the counter number to run out of unique combinations.
      * BLOCK_CIPHER_ERROR_INVALID_AUTHENTICATION - The calculated
        authentication tag did not match the one provided by the user.
  Example:
    <code>
    // ***************************************************************
    // Decrypt data in GCM mode with the AES algorithm.
    // ***************************************************************

    // System module object variable (for initializing AES)
    SYS_MODULE_OBJ sysObject;

    // Drive handle variable, to describe which AES module to use
    DRV_HANDLE handle;

    // GCM mode context
    BLOCK_CIPHER_GCM_CONTEXT context;

    // Initialization vector for GCM mode
    static uint8_t ivValue[12] = {0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,0xde,0xca,0xf8,0x88};

    // Data that will be authenticated, but not decrypted.
    uint8_t authData[20] = {0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,0xab,0xad,0xda,0xd2,};

   // Cipher text to decrypt
    static uint8_t cipher_text[] = { 0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c, \
                                    0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e, \
                                    0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05, \
                                    0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97, 0x3d, 0x58, 0xe0, 0x91,};


    // The decryption key
    static uint8_t AESKey128[] = {0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08};
    // Structure to contain the created AES round keys
    AES_ROUND_KEYS_128_BIT round_keys;
    // Buffer to contain decrypted ciphertext
    uint8_t plain_text[sizeof(cipher_text)];
    //keyStream could also be allocated memory instead of fixed memory
    uint8_t keyStream[AES_BLOCK_SIZE*4];
    // The authentication tag for our ciphertext and our authData.
    uint8_t tag[]  = {0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb, 0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12, 0x1a, 0x47,};

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

    // Initialize the Block Cipher context
    BLOCK_CIPHER_GCM_Initialize (handle, &context, AES_Encrypt, AES_Decrypt, AES_BLOCK_SIZE, (uint8_t *)ivValue, 12, (void *)&keyStream, sizeof(keyStream), &round_keys);

    //Generate 4 blocks of key stream
    BLOCK_CIPHER_GCM_KeyStreamGenerate(handle, 4, &round_keys, &context, 0);

    // Authenticate the non-encrypted data
    if (BLOCK_CIPHER_GCM_Decrypt (handle, NULL, (uint8_t *)authData, 20, NULL, 0, &round_keys, &context, BLOCK_CIPHER_OPTION_AUTHENTICATE_ONLY) != BLOCK_CIPHER_ERROR_NONE)
    {
        // An error occured
        while(1);
    }

    // As an example, this data will be decrypted in two blocks, to demonstrate how to use the options.
    // Decrypt the first forty bytes of data.
    // Note that at this point, you don't really need to specify the tag pointer or its length.  This parameter only
    // needs to be specified when the BLOCK_CIPHER_OPTION_STREAM_COMPLETE option is used.
    if (BLOCK_CIPHER_GCM_Decrypt (handle, plain_text, (uint8_t *)cipher_text, 40, tag, 16, &round_keys, &context, BLOCK_CIPHER_OPTION_STREAM_CONTINUE) != BLOCK_CIPHER_ERROR_NONE)
    {
        // An error occured
        while(1);
    }

    // Decrypt the final twenty bytes of data.
    // Since we are using BLOCK_CIPHER_OPTION_STREAM_COMPLETE, we must specify the authentication tag and its length.  If it does not match
    // the tag we obtain by decrypting the data, the Decrypt function will return BLOCK_CIPHER_ERROR_INVALID_AUTHENTICATION.
    if (BLOCK_CIPHER_GCM_Decrypt (handle, plain_text + 40, (uint8_t *)cipher_text + 40, 20, tag, 16, &round_keys, &context, BLOCK_CIPHER_OPTION_STREAM_COMPLETE) != BLOCK_CIPHER_ERROR_NONE)
    {
        // An error occured
        while(1);
    }
    </code>
*/
BLOCK_CIPHER_ERRORS BLOCK_CIPHER_GCM_Decrypt (DRV_HANDLE handle, uint8_t * plainText, uint8_t * cipherText, uint32_t numBytes, uint8_t * authenticationTag, uint8_t tagLen, void * key, BLOCK_CIPHER_GCM_CONTEXT * context, uint32_t options);

// *****************************************************************************
/* Function:
    BLOCK_CIPHER_ERRORS BLOCK_CIPHER_GCM_KeyStreamGenerate (DRV_HANDLE handle,
        uint32_t numBlocks, void * key, BLOCK_CIPHER_GCM_CONTEXT * context,
        uint32_t options)

  Summary:
    Generates a key stream for use with the Galois/counter mode.

  Description:
    Generates a key stream for use with the Galois/counter mode.
  
  Precondition:
    The GCM context must be initialized with the block cipher encrypt/decrypt
    functions and the block cipher algorithm's block size.  The block cipher 
    module must be initialized, if necessary.

    The initializationVector parameter in the BLOCK_CIPHER_GCM_CONTEXT structure
    should be initialized.  The size of this vector is the same as the block size 
    of the cipher you are using.
    
  Parameters:
    handle - A handle that is passed to the block cipher's encrypt/decrypt 
        functions to specify which instance of the block cipher module to use.
        This parameter can be specified as NULL if the block cipher does not 
        have multiple instances.
    numBlocks - The number of blocks of key stream that should be created. 
        context->keyStream should have enough space remaining to handle this request.
    key - The key to use when generating this key stream.  The format of 
        this key will depend on the block cipher you are using.
    context - Pointer to a context structure for this operation.  The first call of 
        this function should have the context->initializationVector set.  This value will
        be incremented for each block request.
    options - Block cipher encryption options that the user can specify, or'd together.  This
        function currently does not support any options.
  
  Returns:
    Returns a member of the BLOCK_CIPHER_ERRORS enumeration:
        * BLOCK_CIPHER_ERROR_NONE - no error.
        * BLOCK_CIPHER_ERROR_KEY_STREAM_GEN_OUT_OF_SPACE - There was not enough room 
            remaining in the context->keyStream buffer to fit the key data requested by the 
            numBlocks parameter.
        * BLOCK_CIPHER_ERROR_GCM_COUNTER_EXPIRED - The requesting call has caused the counter
            number to run out of unique combinations.
    
  Example:
    <code>
    // ***************************************************************
    // Encrypt data in GCM mode with the AES algorithm.
    // ***************************************************************
    
    // System module object variable (for initializing AES)
    SYS_MODULE_OBJ sysObject;
    
    // Drive handle variable, to describe which AES module to use
    DRV_HANDLE handle;
    
    // GCM mode context
    BLOCK_CIPHER_GCM_CONTEXT context;

    // Initialization vector for GCM mode
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
    //keyStream could also be allocated memory instead of fixed memory
    uint8_t keyStream[AES_BLOCK_SIZE*4];

    
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
    BLOCK_CIPHER_GCM_Initialize (handle, &context, AES_Encrypt, AES_Decrypt, AES_BLOCK_SIZE, initialization_vector, 12, (void *)&keyStream, sizeof (keyStream), &round_keys);

    //Generate 4 blocks of key stream
    BLOCK_CIPHER_GCM_KeyStreamGenerate(handle, 4, &round_keys, &context, BLOCK_CIPHER_OPTION_STREAM_START);

    //Encrypt the data
    BLOCK_CIPHER_GCM_Encrypt (handle, cipher_text,(void *) plain_text, sizeof(plain_text), &round_keys, &context, BLOCK_CIPHER_OPTION_STREAM_CONTINUE);
        <code>
    // ***************************************************************
    // Encrypt data in GCM mode with the AES algorithm.
    // ***************************************************************

    // System module object variable (for initializing AES)
    SYS_MODULE_OBJ sysObject;

    // Drive handle variable, to describe which AES module to use
    DRV_HANDLE handle;

    // GCM mode context
    BLOCK_CIPHER_GCM_CONTEXT context;

    // Initialization vector for GCM mode
    static uint8_t ivValue[12] = {0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,0xde,0xca,0xf8,0x88};

    // Data that will be authenticated, but not encrypted.
    uint8_t authData[20] = {0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,0xab,0xad,0xda,0xd2,};

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
    //keyStream could also be allocated memory instead of fixed memory
    uint8_t keyStream[AES_BLOCK_SIZE*4];
    // Structure to contain the calculated authentication tag
    uint8_t tag[16];

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

    // Initialize the Block Cipher context
    BLOCK_CIPHER_GCM_Initialize (handle, &context, AES_Encrypt, AES_Decrypt, AES_BLOCK_SIZE, (uint8_t *)ivValue, 12, (void *)&keyStream, sizeof(keyStream), &round_keys);

    //Generate 4 blocks of key stream
    BLOCK_CIPHER_GCM_KeyStreamGenerate(handle, 4, &round_keys, &context, 0);
    </code>
*/
BLOCK_CIPHER_ERRORS BLOCK_CIPHER_GCM_KeyStreamGenerate (DRV_HANDLE handle, uint32_t numBlocks, void * key, BLOCK_CIPHER_GCM_CONTEXT * context, uint32_t options);

