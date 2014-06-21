/*****************************************************************************

 Advanced Encryption Standard (AES) Include Header
   128 bit key, 128 bit data block
   For more information see, AN1044

****************************************************************************
 FileName:		aes.h
 Dependencies:	aes.s
 Processor:		PIC24F, PIC24H, dsPIC30F, or dsPIC33F
 Compiler:		MPLAB C30 2.02 or later
 Linker:			MPLAB LINK30 2.02 or later
 Company:		Microchip Technology Incorporated

 Software License Agreement

 The software supplied herewith by Microchip Technology Incorporated
 (the “Company”) for its PICmicro® Microcontroller is intended and
 supplied to you, the Company’s customer, for use solely and
 exclusively on Microchip PICmicro Microcontroller products. The
 software is owned by the Company and/or its supplier, and is
 protected under applicable copyright laws. All rights are reserved.
 Any use in violation of the foregoing restrictions may subject the
 user to criminal sanctions under applicable laws, as well as to
 civil liability for the breach of the terms and conditions of this
 license.

 Microchip Technology Inc. (“Microchip”) licenses this software to 
 you solely for use with Microchip products.  The software is owned 
 by Microchip and is protected under applicable copyright laws.  
 All rights reserved.

 You may not export or re-export Software, technical data, direct 
 products thereof or any other items which would violate any applicable
 export control laws and regulations including, but not limited to, 
 those of the United States or United Kingdom.  You agree that it is
 your responsibility to obtain copies of and to familiarize yourself
 fully with these laws and regulations to avoid violation.

 SOFTWARE IS PROVIDED “AS IS.”  MICROCHIP EXPRESSLY DISCLAIM ANY 
 WARRANTY OF ANY KIND, WHETHER EXPRESS OR IMPLIED, INCLUDING BUT NOT 
 LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 PARTICULAR PURPOSE, OR NON-INFRINGEMENT. IN NO EVENT SHALL MICROCHIP
 BE LIABLE FOR ANY INCIDENTAL, SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES,
 LOST PROFITS OR LOST DATA, HARM TO YOUR EQUIPMENT, COST OF PROCUREMENT
 OF SUBSTITUTE GOODS, TECHNOLOGY OR SERVICES, ANY CLAIMS BY THIRD PARTIES
 (INCLUDING BUT NOT LIMITED TO ANY DEFENSE THEREOF), ANY CLAIMS FOR 
 INDEMNITY OR CONTRIBUTION, OR OTHER SIMILAR COSTS. 

****************************************************************************/
#ifndef AES_H
#define AES_H

// *****************************************************************************
// *****************************************************************************
// Section: Includes
// *****************************************************************************
// *****************************************************************************

#include <stdint.h>
#include "crypto/src/drv_common.h"
#include "crypto/src/sys_common.h"
#include "crypto/src/sys_module.h"

// *****************************************************************************
// *****************************************************************************
// Section: Constants & Data Types
// *****************************************************************************
// *****************************************************************************

// Definition for a single drive index for the software-only AES module
#define DRV_AES_INDEX_0 0
// Map of the default drive index to drive index 0
#define DRV_AES_INDEX DRV_AES_INDEX_0
// Number of drive indicies for this module
#define DRV_AES_INDEX_COUNT 1
// Definition for a single drive handle for the software-only AES module
#define DRV_AES_HANDLE ((DRV_HANDLE) 0)

// Use an AES key length of 128-bits / 16 bytes.
#define AES_KEY_SIZE_128_BIT    16 
// Use an AES key length of 192-bits / 24 bytes.
#define AES_KEY_SIZE_192_BIT    24 
// Use an AES key length of 256-bits / 32 bytes.
#define AES_KEY_SIZE_256_BIT    32 

// Definition of a 128-bit key to simplify the creation of a round key buffer for the 
// AES_RoundKeysCreate() function.
typedef struct
{
    uint32_t key_length;                    // Length of the key
    uint32_t data[44];                  /*Round keys*/
} AES_ROUND_KEYS_128_BIT;

// Definition of a 192-bit key to simplify the creation of a round key buffer for the 
// AES_RoundKeysCreate() function.
typedef struct
{
    uint32_t key_length;                    // Length of the key
    uint32_t data[52];                  // Round keys
} AES_ROUND_KEYS_192_BIT;

// Definition of a 256-bit key to simplify the creation of a round key buffer for the 
// AES_RoundKeysCreate() function.
typedef struct
{
    uint32_t key_length;                    // Length of the key
    uint32_t data[60];                  // Round keys
} AES_ROUND_KEYS_256_BIT;

#if defined(CRYPTO_CONFIG_AES_KEY_128_ENABLE)
    #define AES_ROUND_KEYS AES_ROUND_KEYS_128_BIT
#elif defined(CRYPTO_CONFIG_AES_KEY_192_ENABLE)
    #define AES_ROUND_KEYS AES_ROUND_KEYS_192_BIT
#else
    /**********************************************************************
      Definition for the AES module's Round Key structure. Depending on the
      configuration of the library, this could be defined as
      AES_ROUND_KEYS_128_BIT, AES_ROUND_KEYS_192_BIT, or
      AES_ROUND_KEYS_256_BIT.                                              
      **********************************************************************/
    #define AES_ROUND_KEYS AES_ROUND_KEYS_256_BIT
#endif

// The AES block size (16 bytes)
#define AES_BLOCK_SIZE  16

// *****************************************************************************
// *****************************************************************************
// Section: AES Interface Routines
// *****************************************************************************
// *****************************************************************************

// *****************************************************************************
/* Function:
    SYS_MODULE_OBJ DRV_AES_Initialize(const SYS_MODULE_INDEX index,
            const SYS_MODULE_INIT * const init)

  Summary:
    Initializes the data for the instance of the AES module.

  Description:
    This routine initializes data for the instance of the AES module.  For pure 
    software implementations, the function has no effect.

  Precondition:
    None

  Parameters:
    index       - Identifier for the instance to be initialized

    init        - Pointer to the data structure containing any data
                  necessary to initialize the hardware. This pointer may
                  be null if no data is required and default
                  initialization is to be used

  Returns:
    If successful, returns a valid handle to a driver instance object.
    Otherwise, it returns SYS_MODULE_OBJ_INVALID
    
  Example:
    <code>
    SYS_MODULE_OBJ sysObject;
    
    sysObject = DRV_AES_Initialize (DRV_AES_INDEX, NULL);
    if (sysObject != SYS_MODULE_OBJ_STATIC)
    {
        // error
    }
    </code>
*/
SYS_MODULE_OBJ DRV_AES_Initialize( const SYS_MODULE_INDEX index, const SYS_MODULE_INIT * const init);

// *****************************************************************************
/* Function:
    void DRV_AES_Deinitialize(SYS_MODULE_OBJ object)

  Summary:
    Deinitializes the instance of the AES module

  Description:
    Deinitializes the specific module instance disabling its operation.  For 
    pure software implementations, this function has no effect.

  Precondition:
    None

  Parameters:
    object           - Identifier for the instance to be de-initialized

  Returns:
    None
    
  Example:
    <code>
    SYS_MODULE_OBJ sysObject;
    
    sysObject = DRV_AES_Initialize (DRV_AES_INDEX, NULL);
    if (sysObject != SYS_MODULE_OBJ_STATIC)
    {
        // error
    }

    DRV_AES_Deinitialize (sysObject);
    </code>
*/
void DRV_AES_Deinitialize( SYS_MODULE_OBJ object);

// *****************************************************************************
/* Function:
    DRV_HANDLE DRV_AES_Open(const SYS_MODULE_INDEX index,
        const DRV_IO_INTENT ioIntent)

  Summary:
    Opens a new client for the device instance.

  Description:
    Returns a handle of the opened client instance. All client operation APIs
    will require this handle as an argument.

  Precondition:
    The driver must have been previously initialized and in the
    initialized state.

  Parameters:
    index           - Identifier for the instance to opened
    ioIntent        - Possible values from the enumeration DRV_IO_INTENT
                      There are currently no applicable values for this module.

  Returns:
    None
    
  Example:
    <code>
    SYS_MODULE_OBJ sysObject;
    DRV_HANDLE handle;
    
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
    </code>
*/
DRV_HANDLE DRV_AES_Open( const SYS_MODULE_INDEX index, const DRV_IO_INTENT ioIntent);

// *****************************************************************************
/* Function:
    void DRV_AES_Close (DRV_HANDLE handle)

  Summary:
    Closes an opened client

  Description:
    Closes an opened client, resets the data structure and removes the client
    from the driver.

  Precondition:
    None.

  Parameters:
    handle          - The handle of the opened client instance returned by
                      DRV_AES_Open().

  Returns:
    None
    
  Example:
    <code>  
    handle = DRV_AES_Open (DRV_AES_INDEX, 0);
    if (handle != DRV_AES_HANDLE)
    {
        // error
    }
    
    DRV_AES_Close (handle);
    </code>
*/
void DRV_AES_Close (DRV_HANDLE handle);


/*******************************************************************************
  Function:
    void AES_RoundKeysCreate(    void* round_keys,
                                uint8_t* key, 
                                uint8_t key_size
                            )

  Summary:
    Creates a set of round keys from an AES key to be used in AES encryption and decryption of data blocks.

  Description:
    This routine takes an AES key and performs a key schedule to expand the key into a number of separate
    set of round keys.  These keys are commonly know as the Rijindael key schedule or a session key.

  Precondition:
    None.

  Parameters:
    round_keys - Pointer to the output buffer that will contain the expanded short key (Rijindael) schedule/ session key.  This is to be used in the 
                    encryption and decryption routines.  The round_keys buffer must be word aligned for the target processor.
    key        - The input key which can be 128, 192, or 256 bits in length.
    key_size   - Specifies the key length in bytes.  Valid options are\: 
                    * AES_KEY_SIZE_128_BIT
                    * AES_KEY_SIZE_192_BIT
                    * AES_KEY_SIZE_256_BIT
                    The values 16, 24, and 32 may also be used instead of the above definitions.

  Returns:
    None

  Example:
    <code>
    static const uint8_t AESKey128[] = {  0x95, 0xA8, 0xEE, 0x8E, 
                                        0x89, 0x97, 0x9B, 0x9E, 
                                        0xFD, 0xCB, 0xC6, 0xEB, 
                                        0x97, 0x97, 0x52, 0x8D 
                                     };
    AES_ROUND_KEYS_128_BIT round_keys;

    AES_RoundKeysCreate(    &round_keys, 
                            AESKey128, 
                            AES_KEY_SIZE_128_BIT
                       );
    </code>

  *****************************************************************************/
void AES_RoundKeysCreate(void* round_keys, uint8_t* key, uint8_t key_size);

// *****************************************************************************
/* Function:
    void AES_Encrypt (DRV_HANDLE handle, void * cipherText, void * plainText, void * key)

  Summary:
    Encrypts a 128-bit block of data using the AES algorithm.

  Description:
    Encrypts a 128-bit block of data using the AES algorithm.
  
  Precondition:
    The AES module must be configured and initialized, if necessary.

  Parameters:
    handle - Pointer to the driver handle for the instance of the AES module you 
        are using to encrypt the plainText.  No function for pure software 
        implementation.
    cipherText - Buffer for the 128-bit output block of cipherText produced by 
        encrypting the plainText.
    plainText - The 128-bit block of plainText to encrypt.
    key - Pointer to a set of round keys created by the AES_RoundKeysCreate function.
  
  Returns:
    None
    
  Remarks:
    AES should be used the a block cipher mode of operation.  See 
    block_cipher_modes.h for more information.
*/
void AES_Encrypt (DRV_HANDLE handle, void * cipherText, void * plainText, void * key);

// *****************************************************************************
/* Function:
    void AES_Decrypt (DRV_HANDLE handle, void * plainText, void * cipherText, void * key)

  Summary:
    Decrypts a 128-bit block of data using the AES algorithm.

  Description:
    Decrypts a 128-bit block of data using the AES algorithm.
  
  Precondition:
    The AES module must be configured and initialized, if necessary.

  Parameters:
    handle - Pointer to the driver handle for the instance of the AES module you 
        are using to decrypt the cipherText.  No function for pure software 
        implementation.
    plainText - Buffer for the 128-bit output block of plainText produced by 
        decrypting the cipherText.
    cipherText - The 128-bit block of cipherText to decrypt.
    key - Pointer to a set of round keys created by the AES_RoundKeysCreate function.
  
  Returns:
    None.
    
  Remarks:
    AES should be used the a block cipher mode of operation.  See 
    block_cipher_modes.h for more information.
*/
void AES_Decrypt (DRV_HANDLE handle, void * plainText, void * cipherText, void * key);

#endif //AES_H
