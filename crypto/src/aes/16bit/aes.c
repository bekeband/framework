/********************************************************************
 FileName:      AES_helper.c
 Dependencies:  See INCLUDES section
 Compiler:      Microchip C30/C32
 Company:       Microchip Technology, Inc.

 Software License Agreement:

 The software supplied herewith by Microchip Technology Incorporated
 (the “Company”) for its PIC® Microcontroller is intended and
 supplied to you, the Company’s customer, for use solely and
 exclusively on Microchip PIC Microcontroller products. The
 software is owned by the Company and/or its supplier, and is
 protected under applicable copyright laws. All rights are reserved.
 Any use in violation of the foregoing restrictions may subject the
 user to criminal sanctions under applicable laws, as well as to
 civil liability for the breach of the terms and conditions of this
 license.

 THIS SOFTWARE IS PROVIDED IN AN “AS IS” CONDITION. NO WARRANTIES,
 WHETHER EXPRESS, IMPLIED OR STATUTORY, INCLUDING, BUT NOT LIMITED
 TO, IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 PARTICULAR PURPOSE APPLY TO THIS SOFTWARE. THE COMPANY SHALL NOT,
 IN ANY CIRCUMSTANCES, BE LIABLE FOR SPECIAL, INCIDENTAL OR
 CONSEQUENTIAL DAMAGES, FOR ANY REASON WHATSOEVER.

********************************************************************
 File Description:

 Change History:
  Rev   Description
  ----  ----------------------------------------------
  2.0   Initial Revision
********************************************************************/
#include <system_config.h>
#include <crypto/aes.h>

#if defined(__PIC32MX__)
    #include <crypto/src/aes/pic32/aes_ecb_pic32.h>
#endif

#include <stdio.h>
#include <string.h>

#if defined(__C30__)
SYS_MODULE_OBJ DRV_AES_Initialize(const SYS_MODULE_INDEX index, const SYS_MODULE_INIT * const init)
{
    if (index != DRV_AES_INDEX)
    {
        return SYS_MODULE_OBJ_INVALID;
    }

    return SYS_MODULE_OBJ_STATIC;
}

void DRV_AES_Deinitialize(SYS_MODULE_OBJ object)
{
    return;
}

DRV_HANDLE DRV_AES_Open(const SYS_MODULE_INDEX index, const DRV_IO_INTENT ioIntent)
{
    if (index != DRV_AES_INDEX)
    {
        return DRV_HANDLE_INVALID;
    }

    return DRV_AES_HANDLE;
}

void DRV_AES_Close (DRV_HANDLE handle)
{
    return;
}


/*******************************************************************************
  Function:
    void AES_RoundKeysCreate(    void* round_keys,
                                uint8_t* key, 
                                uint8_t key_size
                            )

  Summary:
    Creates a set of round keys from an AES key to be used in AES encryption 
       and decryption of data blocks.

  Description:
    This routine takes an AES key and performs a key schedule to expand the key
       into a number of separate set of round keys.  These keys are commonly 
       know as the Rijindael key schedule or a session key.

  Precondition:
    None.

  Parameters:
    round_keys - [out] Pointer to the output buffer that will contain the expanded short key (Rijindael) schedule/ session key.  This is to be used in the 
                       encryption and decryption routines.  The round_keys buffer must be
                       word aligned for the target processor.
    key        - [in]  The input key which can be 128, 192, or 256 bits in length.
    key_size   - [in]  Specifies the key length in bytes.  Valid options are\: 
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
void AES_RoundKeysCreate128(void* round_keys, uint8_t* key);
void AES_RoundKeysCreate192(void* round_keys, uint8_t* key);
void AES_RoundKeysCreate256(void* round_keys, uint8_t* key);

void AES_RoundKeysCreate(void* round_keys, uint8_t* key, uint8_t key_size)
{
    #if defined(CRYPTO_CONFIG_AES_KEY_128_ENABLE)
        AES_RoundKeysCreate128(round_keys,key);
    #elif defined(CRYPTO_CONFIG_AES_KEY_192_ENABLE)
        AES_RoundKeysCreate192(round_keys,key);
    #elif defined(CRYPTO_CONFIG_AES_KEY_256_ENABLE)
        AES_RoundKeysCreate256(round_keys,key);
    #else
        //Dynamic
        switch(key_size)
        {
            case AES_KEY_SIZE_128_BIT:
                AES_RoundKeysCreate128(round_keys,key);
                break;
            case AES_KEY_SIZE_192_BIT:
                AES_RoundKeysCreate192(round_keys,key);
                break;
            case AES_KEY_SIZE_256_BIT:
                AES_RoundKeysCreate256(round_keys,key);
                break;
        }
    #endif        
}
#endif

