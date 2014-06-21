/*********************************************************************
 *
 *                Crypto Configuration Header
 *
 *********************************************************************
 * FileName:        crypto_config.h
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

 
/****************************************************************************************************************************/
/* Block Cipher Configuration options (AES, TDES, XTEA)                                                                     */
/****************************************************************************************************************************/
// Defines the largest block size used by the ciphers you are using with the block cipher modes of operation
#define CRYPTO_CONFIG_BLOCK_MAX_SIZE      16ul

 
/****************************************************************************************************************************/
/* AES Configuration options                                                                                                */
/****************************************************************************************************************************/

// Supported key lengths.  Select one of these four key length options for your application.
 
#define CRYPTO_CONFIG_AES_KEY_DYNAMIC_ENABLE            // Define this macro to dynamically determine key length at runtime
#define CRYPTO_CONFIG_AES_KEY_128_ENABLE                // Define this macro to only use 128-bit key lengths
#define CRYPTO_CONFIG_AES_KEY_192_ENABLE                // Define this macro to only use 192-bit key lengths
#define CRYPTO_CONFIG_AES_KEY_256_ENABLE                // Define this macro to use 256-bit key lengths.  Enabling this will actually enable CRYPTO_CONFIG_AES_KEY_DYNAMIC







