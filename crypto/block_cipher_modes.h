/*********************************************************************
 *
 *                  Block Cipher Mode of Operation header
 *
 *********************************************************************
 * FileName:        block_cipher_mode.h
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
#include "crypto/src/drv_common.h"
#include "system_config.h"

#ifndef CRYPTO_CONFIG_BLOCK_MAX_SIZE
    #define CRYPTO_CONFIG_BLOCK_MAX_SIZE        32u
#endif

// Enumeration defining available block cipher modes of operation
typedef enum
{
    BLOCK_CIPHER_MODE_ECB = 0,      // Electronic Codebook mode
    BLOCK_CIPHER_MODE_CBC,          // Cipher-block Chaining mode
    BLOCK_CIPHER_MODE_CFB,          // Cipher Feedback mode
    BLOCK_CIPHER_MODE_OFB,          // Output Feedback mode
    BLOCK_CIPHER_MODE_CTR           // Counter mode
} BLOCK_CIPHER_MODES;

// Enumeration defining potential errors the can occur when using a block cipher mode 
// of operation.  Modes that do not use keystreams will not generate errors.
typedef enum
{
    /* No errors. */
    BLOCK_CIPHER_ERROR_NONE = (0x00000000u),

    /* The calling function has requested that more bits be added to the
       key stream then are available in the buffer allotted for the key stream.
       Since there was not enough room to complete the request, the request
       was not processed. */
    BLOCK_CIPHER_ERROR_KEY_STREAM_GEN_OUT_OF_SPACE,

    /* The requesting call has caused the counter number to run out of unique
       combinations.  In CTR mode it is not safe to use the same counter
       value for a given key.  */
    BLOCK_CIPHER_ERROR_CTR_COUNTER_EXPIRED,

    /* Authentication of the specified data failed.  */
    BLOCK_CIPHER_ERROR_INVALID_AUTHENTICATION
} BLOCK_CIPHER_ERRORS;


// This option is used to pass data that will be authenticated but not encrypted into an authenticating block cipher mode function.
#define BLOCK_CIPHER_OPTION_AUTHENTICATE_ONLY           /*DOM-IGNORE-BEGIN*/ (0x00002000u)    /*DOM-IGNORE-END*/

// The stream is still in progress.
#define BLOCK_CIPHER_OPTION_STREAM_CONTINUE             /*DOM-IGNORE-BEGIN*/ (0x00000000u)    /*DOM-IGNORE-END*/

// The stream is complete.  Padding will be applied if required.
#define BLOCK_CIPHER_OPTION_STREAM_COMPLETE             /*DOM-IGNORE-BEGIN*/ (0x00004000u)    /*DOM-IGNORE-END*/

// This should be passed when a new stream is starting
#define BLOCK_CIPHER_OPTION_STREAM_START                /*DOM-IGNORE-BEGIN*/ (0x00008000u)    /*DOM-IGNORE-END*/

// The cipher text pointer is pointing to data that is aligned to the target machine's word size (16-bit aligned for PIC24/dsPIC30/dsPIC33, and 8-bit aligned for PIC18).  Enabling this feature may improve throughput.
#define BLOCK_CIPHER_OPTION_CIPHER_TEXT_POINTER_ALIGNED /*DOM-IGNORE-BEGIN*/ (0x00000040u)    /*DOM-IGNORE-END*/

// The plain text pointer is pointing to data that is aligned to the target machine's word size (16-bit aligned for PIC24/dsPIC30/dsPIC33, and 8-bit aligned for PIC18).  Enabling this feature may improve throughput.
#define BLOCK_CIPHER_OPTION_PLAIN_TEXT_POINTER_ALIGNED  /*DOM-IGNORE-BEGIN*/ (0x00000080u)    /*DOM-IGNORE-END*/

// Pad with whatever data is already in the RAM.  This flag is normally set only for the last block of data.
#define BLOCK_CIPHER_OPTION_PAD_NONE                    /*DOM-IGNORE-BEGIN*/ (0x00000000u)    /*DOM-IGNORE-END*/

// Pad with 0x00 bytes if the current and previous data lengths do not end on a block boundary (multiple of 16 bytes).  This flag is normally set only for the last block of data.
#define BLOCK_CIPHER_OPTION_PAD_NULLS                   /*DOM-IGNORE-BEGIN*/ (0x00000100u)    /*DOM-IGNORE-END*/

// Pad with 0x80 followed by 0x00 bytes (a 1 bit followed by several 0 bits) if the current and previous data lengths do not end on a block boundary (multiple of 16 bytes).  This flag is normally set only for the last block of data.
#define BLOCK_CIPHER_OPTION_PAD_8000                    /*DOM-IGNORE-BEGIN*/ (0x00000200u)    /*DOM-IGNORE-END*/

// Pad with three 0x03's, four 0x04's, five 0x05's, six 0x06's, etc. set by the number of padding bytes needed if the current and previous data lengths do not end on a block boundary (multiple of 16 bytes).  This flag is normally set only for the last block of data.
#define BLOCK_CIPHER_OPTION_PAD_NUMBER                  /*DOM-IGNORE-BEGIN*/ (0x00000400u)    /*DOM-IGNORE-END*/

// Mask to determine the padding option that is selected.
#define BLOCK_CIPHER_OPTION_PAD_MASK                    /*DOM-IGNORE-BEGIN*/ (0x00000700u)    /*DOM-IGNORE-END*/

// Mask to determine the size of the counter in bytes.
#define BLOCK_CIPHER_OPTION_CTR_SIZE_MASK               /*DOM-IGNORE-BEGIN*/ (0x0000000Fu)    /*DOM-IGNORE-END*/

// Treat the counter as a 32-bit counter.  Leave the remaining section of the counter unchanged
#define BLOCK_CIPHER_OPTION_CTR_32BIT                   /*DOM-IGNORE-BEGIN*/ (0x00000004u)    /*DOM-IGNORE-END*/

// Treat the counter as a 64-bit counter.  Leave the remaining section of the counter unchanged
#define BLOCK_CIPHER_OPTION_CTR_64BIT                   /*DOM-IGNORE-BEGIN*/ (0x00000008u)    /*DOM-IGNORE-END*/

// Treat the counter as a full 128-bit counter.  This is the default option.
#define BLOCK_CIPHER_OPTION_CTR_128BIT                  /*DOM-IGNORE-BEGIN*/ (0x00000000u)    /*DOM-IGNORE-END*/

// Calculate the key stream for CFB1 mode
#define BLOCK_CIPHER_OPTION_USE_CFB1                    /*DOM-IGNORE-BEGIN*/ (0x00800000u)    /*DOM-IGNORE-END*/

// Calculate the key stream for CFB8 mode
#define BLOCK_CIPHER_OPTION_USE_CFB8                    /*DOM-IGNORE-BEGIN*/ (0x00400000u)    /*DOM-IGNORE-END*/

// Calculate the key stream for CFB(block size) mode
#define BLOCK_CIPHER_OPTION_USE_CFB_BLOCK_SIZE          /*DOM-IGNORE-BEGIN*/ (0x00000000u)    /*DOM-IGNORE-END*/

// A definition to specify the default set of options.
#define BLOCK_CIPHER_OPTION_OPTIONS_DEFAULT             /*DOM-IGNORE-BEGIN*/ (0x00000000u)    /*DOM-IGNORE-END*/


/***************************************************************************
  Function:
            void BLOCK_CIPHER_FunctionEncrypt (
                         DRV_HANDLE handle, void * cipherText,
                         void * plainText, void * key)
    
  Conditions:
    None
  Input:
    handle -      A driver handle. If the encryption module you are using
                  has multiple instances, this handle will be used to
                  differentiate them. For single instance encryption modules
                  (software\-only modules) this parameter can be specified
                  as NULL.
    cipherText -  The resultant cipherText produced by the encryption. The
                  type of pointer used for this parameter will be dependent
                  on the block cipher module you are using.
    plainText -   The plainText that will be encrypted. The type of pointer
                  used for this parameter will be dependent on the block
                  cipher module you are using.
    key -         Pointer to the key. The format and length of the key
                  depends on the block cipher module you are using.
  Return:
    None
  Side Effects:
    None
  Description:
    \Function pointer for a block cipher's encryption function. When using
    the block cipher modes of operation module, you will configure it to
    use the encrypt function of the block cipher module that you are using
    with a pointer to that block cipher's encrypt function.
    
    None
  Remarks:
    None                                                                    
  ***************************************************************************/
typedef void (*BLOCK_CIPHER_FunctionEncrypt)(DRV_HANDLE handle, void * cipherText, void * plainText, void * key);

/***************************************************************************
  Function:
            void BLOCK_CIPHER_FunctionDecrypt (
                         DRV_HANDLE handle, void * cipherText,
                         void * plainText, void * key)
    
  Conditions:
    None
  Input:
    handle -      A driver handle. If the decryption module you are using
                  has multiple instances, this handle will be used to
                  differentiate them. For single instance decryption modules
                  (software\-only modules) this parameter can be specified
                  as NULL.
    plainText -   The resultant plainText that was decrypted. The type of
                  pointer used for this parameter will be dependent on the
                  block cipher module you are using.
    cipherText -  The cipherText that will be decrypted. The type of pointer
                  used for this parameter will be dependent on the block
                  cipher module you are using.
    key -         Pointer to the key. The format and length of the key
                  depends on the block cipher module you are using.
  Return:
    None
  Side Effects:
    None
  Description:
    \Function pointer for a block cipher's decryption function. When using
    the block cipher modes of operation module, you will configure it to
    use the decrypt function of the block cipher module that you are using
    with a pointer to that block cipher's encrypt function.
    
    None
  Remarks:
    None                                                                    
  ***************************************************************************/
typedef void (*BLOCK_CIPHER_FunctionDecrypt)(DRV_HANDLE handle, void * plainText, void * cipherText, void * key);

// Includes for each mode's header file
#include "crypto/block_cipher_mode_ecb.h"
#include "crypto/block_cipher_mode_cbc.h"
#include "crypto/block_cipher_mode_ofb.h"
#include "crypto/block_cipher_mode_cfb.h"
#include "crypto/block_cipher_mode_ctr.h"
#include "crypto/block_cipher_mode_gcm.h"

