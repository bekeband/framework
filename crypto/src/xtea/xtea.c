/*********************************************************************
 *
 *                 XTEA Function Library Implementation
 *
 *********************************************************************
 * FileName:        xtea.c
 * Dependencies:    None
 * Processor:       PIC18, PIC24F, PIC24H, dsPIC30F, dsPIC33F, PIC32
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

/****************************** Headers *****************************/
#include <stdint.h>
#include "crypto/xtea.h"
#include "crypto/src/xtea/xtea_private.h"
#include <string.h>

/****************************** Constants ***************************/
const uint32_t DELTA = 0x9E3779B9;

/***************************** Config values ************************/
uint8_t gIterations;

/****************************** Functions ***************************/

void XTEA_Configure (uint8_t iterations)
{
    gIterations = iterations;
}

void XTEA_Encrypt (DRV_HANDLE handle, uint32_t * cipherText, uint32_t * plainText, uint32_t * key)
{
    uint8_t i=0;
    uint32_t x1;
    uint32_t x2;
    uint32_t sum;
    uint8_t iterationCount = gIterations;
    
    memcpy (cipherText, plainText, XTEA_BLOCK_SIZE);
    
    sum = 0;
    x1= *cipherText;
    x2= *(cipherText+1);

    while(iterationCount > 0)
    {
        x1 += ((x2<<4 ^ x2>>5) + x2) ^ (sum + *(key+(sum&0x03)));
        sum+=DELTA;
        x2 += ((x1<<4 ^ x1>>5) + x1) ^ (sum + *(key+(sum>>11&0x03)));

        iterationCount--;
    }
    *(cipherText++) = x1;
    *(cipherText++) = x2;
    i++;
}


void XTEA_Decrypt (DRV_HANDLE handle, uint32_t * plainText, uint32_t * cipherText, uint32_t * key)
{
    uint8_t i=0;
    uint32_t x1;
    uint32_t x2;
    uint32_t sum;
    
    memcpy (plainText, cipherText, XTEA_BLOCK_SIZE);

    sum = DELTA * gIterations;
    x1 = *plainText;
    x2 = *(plainText+1);

    while(sum != 0)
    {
        x2 -= ((x1<<4 ^ x1>>5) + x1) ^ (sum + *(key+(sum>>11&0x03)));
        sum -= DELTA;
        x1 -= ((x2<<4 ^ x2>>5) + x2) ^ (sum + *(key+(sum&0x03)));
    }
    *(plainText++) = x1;
    *(plainText++) = x2;
    i++;
}
