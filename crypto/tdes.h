;/*****************************************************************************
; *
; * Triple Data Encryption Standard (TDES) Include Header
; *   168 bit key, 64 bit data block
; *   For more information see, AN1044
; *
; *****************************************************************************
; * FileName:        TDES.h
; * Dependencies:    DES_asm.s, TDES_asm.s
; * Processor:        PIC24F, PIC24H, dsPIC30F, or dsPIC33F
; * Compiler:        MPLAB C30 2.03 or later
; * Linker:            MPLAB LINK30 2.03 or later
; * Company:        Microchip Technology Incorporated
; *
; * Software License Agreement
; *
; * The software supplied herewith by Microchip Technology Incorporated
; * (the “Company”) for its PICmicro® Microcontroller is intended and
; * supplied to you, the Company’s customer, for use solely and
; * exclusively on Microchip PICmicro Microcontroller products. The
; * software is owned by the Company and/or its supplier, and is
; * protected under applicable copyright laws. All rights are reserved.
; * Any use in violation of the foregoing restrictions may subject the
; * user to criminal sanctions under applicable laws, as well as to
; * civil liability for the breach of the terms and conditions of this
; * license.
; *
; * Microchip Technology Inc. (“Microchip”) licenses this software to 
; * you solely for use with Microchip products.  The software is owned 
; * by Microchip and is protected under applicable copyright laws.  
; * All rights reserved.
; *
; * You may not export or re-export Software, technical data, direct 
; * products thereof or any other items which would violate any applicable
; * export control laws and regulations including, but not limited to, 
; * those of the United States or United Kingdom.  You agree that it is
; * your responsibility to obtain copies of and to familiarize yourself
; * fully with these laws and regulations to avoid violation.
; *
; * SOFTWARE IS PROVIDED “AS IS.”  MICROCHIP EXPRESSLY DISCLAIM ANY 
; * WARRANTY OF ANY KIND, WHETHER EXPRESS OR IMPLIED, INCLUDING BUT NOT 
; * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
; * PARTICULAR PURPOSE, OR NON-INFRINGEMENT. IN NO EVENT SHALL MICROCHIP
; * BE LIABLE FOR ANY INCIDENTAL, SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES,
; * LOST PROFITS OR LOST DATA, HARM TO YOUR EQUIPMENT, COST OF PROCUREMENT
; * OF SUBSTITUTE GOODS, TECHNOLOGY OR SERVICES, ANY CLAIMS BY THIRD PARTIES
; * (INCLUDING BUT NOT LIMITED TO ANY DEFENSE THEREOF), ANY CLAIMS FOR 
; * INDEMNITY OR CONTRIBUTION, OR OTHER SIMILAR COSTS. 
; *
; *****************************************************************************/
#ifndef __TDES_H_
#define __TDES_H_

#include <stdint.h>

// *****************************************************************************
// *****************************************************************************
// Section: Constants & Data Types
// *****************************************************************************
// *****************************************************************************

// Defines the TDES key size in bytes
#define TDES_KEY_SIZE    8 

//Definition to simplify the creation of a round key buffer for the 
//  TDES_RoundKeysCreate() function.
typedef struct
{
    uint32_t data[96];
} TDES_ROUND_KEYS;

/* Defines the data block size for the TDES algorithm. The TDES algorithm uses
   a fixed 8 byte data block so this is defined as a constant that can be used
   to define or measure against the TDES data block size. */
#define TDES_BLOCK_SIZE  8


// *****************************************************************************
// *****************************************************************************
// Section: TDES Interface Routines
// *****************************************************************************
// *****************************************************************************

/***************************************************************************
  Function:
        void TDES_RoundKeysCreate(void* roundKeys,
                                    uint8_t* key,
                                )
    
  Summary:
    Creates a set of round keys from an TDES key to be used in TDES
    encryption and decryption of data blocks.
  Description:
    This routine takes an TDES key and performs a key expansion to expand
    the key into a number of separate set of round keys. These keys are
    commonly know as a Key Schedule, or subkeys.
  Conditions:
    None.
  Input:
    roundKeys  -  [out] Pointer to the output buffer that will contain the
                  expanded subkeys. This is to be used in the encryption and
                  decryption routines. The round_keys buffer must be word
                  aligned for the target processor.
    key -         [in] The input key which can be 192 bits in length. This
                  key should be formed from three concatenated DES keys.
  Return:
    None
  Example:
    <code>
    static unsigned char __attribute__((aligned)) TDESKey[]  =   {
                                            0x25, 0x9d, 0xf1, 0x6e, 0x7a, 0xf8, 0x04, 0xfe,
                                            0x83, 0xb9, 0x0e, 0x9b, 0xf7, 0xc7, 0xe5, 0x57,
                                            0x25, 0x9d, 0xf1, 0x6e, 0x7a, 0xf8, 0x04, 0xfe
                                        };
    TDES_ROUND_KEYS round_keys;
    
    TDES_RoundKeysCreate(    &round_keys,
                            TDESKey
                       );
    </code>
                                                                            
  ***************************************************************************/
void TDES_RoundKeysCreate(void* roundKeys, uint8_t* key);

// *****************************************************************************
/* Function:
    void TDES_Encrypt(DRV_HANDLE handle, void* cipherText, void* plainText, 
        void* key)

  Summary:
    Encrypts a 64-byte block of data using the Triple-DES algorithm.

  Description:
    Encrypts a 64-byte block of data using the Triple-DES algorithm.
  
  Precondition:
    None

  Parameters:
    handle - Pointer to the driver handle for an instance of a TDES module 
        being used to encrypt the plaintext.  This should be specified as 
        NULL for the pure software implementation of TDES.
    cipherText - Buffer for the 64-bit output block of cipherText produced by 
        encrypting the plainText.
    plainText - The 64-bit block of plainText to encrypt.
    key - Pointer to a set of round keys created with the TDES_RoundKeysCreate 
        function.
  
  Returns:
    None.
    
  Remarks:
    TDES should be used with a block cipher mode of operation.  See 
    block_cipher_modes.h for more information.
*/
void TDES_Encrypt(DRV_HANDLE handle, void* cipherText, void* plainText, void* key);

// *****************************************************************************
/* Function:
    void TDES_Decrypt(DRV_HANDLE handle, void* cipherText, void* plainText, 
        void* key)

  Summary:
    Decrypts a 64-byte block of data using the Triple-DES algorithm.

  Description:
    Decrypts a 64-byte block of data using the Triple-DES algorithm.
  
  Precondition:
    None

  Parameters:
    handle - Pointer to the driver handle for an instance of a TDES module 
        being used to decrypt the ciphertext.  This should be specified as 
        NULL for the pure software implementation of TDES.
    plainText - Buffer for the 64-bit output block of plainText produced by 
        decrypting the cipherText.
    cipherText - The 64-bit block of cipherText to decrypt.
    key - Pointer to a set of round keys created with the TDES_RoundKeysCreate 
        function.
  
  Returns:
    None.
    
  Remarks:
    TDES should be used with a block cipher mode of operation.  See 
    block_cipher_modes.h for more information.
*/
void TDES_Decrypt(DRV_HANDLE handle, void* plain_text, void* cipher_text, void* key);

#endif
