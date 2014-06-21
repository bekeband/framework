/*********************************************************************
 *
 *                 XTEA Function Library Header
 *
 *********************************************************************
 * FileName:        xtea.h
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
#include "crypto/src/drv_common.h"

// The XTEA algorithm block size
#define XTEA_BLOCK_SIZE             8ul

/*********************************************************************
 * Function:        void XTEA_Configure (uint8_t iterations)
 *
 * Description:     Configures the XTEA module.
 *
 * PreCondition:    None
 *
 * Input:           iterations - The number of iterations of the 
 *                      XTEA algorithm that the encrypt/decrypt 
 *                      functions should perform for each block
 *                      encryption/decryption.
 *
 * Output:          None
 *
 * Side Effects:    None
 *
 * Overview:        None
 *
 * Remarks:         This implementation is not thread-safe.  If you 
 *                  are using XTEA for multiple applications in an 
 *                  preemptive operating system you must use the 
 *                  same number of iterations for all applications
 *                  to avoid error.
 ********************************************************************/
void XTEA_Configure (uint8_t iterations);

/*********************************************************************
 * Function:        void XTEA_Encrypt(DRV_HANDLE handle, uint32_t* data,
 *                      unsigned int dataLength, uint32_t * key)
 *
 * Description:     Encrypts a 64-bit block of data using the XTEA algorithm.
 *
 * PreCondition:    None
 *
 * Input:           handle - Provided for compatibility with the block 
 *                      cipher modes of operations module.
 *                  cipherText - Pointer to the 64-bit output buffer for the 
 *                      encrypted plainText.
 *                  plainText - Pointer to one 64-bit block of data to 
 *                      encrypt.
 *                  key - Pointer to the 128-bit key.
 *
 * Output:          None
 *
 * Side Effects:    None
 *
 * Overview:        None
 *
 * Remarks:         None
 ********************************************************************/
void XTEA_Encrypt (DRV_HANDLE handle, uint32_t * cipherText, uint32_t * plainText, uint32_t * key);

/*********************************************************************
 * Function:        void XTEA_Decrypt(DRV_HANDLE handle, uint32_t* data,
 *                      unsigned int dataLength, uint32_t * key)
 *
 * Description:     Decrypts a 64-bit block of data using the XTEA algorithm.
 *
 * PreCondition:    None
 *
 * Input:           handle - Provided for compatibility with the block
 *                      cipher modes of operations module.
 *                  plainText - Pointer to the 64-bit output buffer for the 
 *                      decrypted plainText.
 *                  cipherText - Pointer to a 64-bit block of cipherText to 
 *                      decrypt.
 *                  key - Pointer to the 128-bit key.
 *
 * Output:          None
 *
 * Side Effects:    None
 *
 * Overview:        None
 *
 * Note:            None
 ********************************************************************/
void XTEA_Decrypt (DRV_HANDLE handle, uint32_t * plainText, uint32_t * cipherText, uint32_t * key);
