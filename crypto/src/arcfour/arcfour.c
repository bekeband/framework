/*********************************************************************
 *
 *	ARCFOUR Cryptography Library
 *  Library for Microchip TCP/IP Stack
 *	 - Provides encryption and decryption capabilities for the ARCFOUR
 *     algorithm, typically used as a bulk cipher for SSL
 *   - Reference: http://tools.ietf.org/html/draft-kaukonen-cipher-arcfour-01
 *
 *********************************************************************
 * FileName:        arcfour.c
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
 *		ENCX24J600.c and ENCX24J600.h ported to a non-Microchip device
 *		used in conjunction with a Microchip ethernet controller for
 *		the sole purpose of interfacing with the ethernet controller.
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
#define __ARCFOUR_C

#include "crypto/arcfour.h"

/*****************************************************************************
  Function:
    void ARCFOUR_CreateSBox(ARCFOUR_CONTEXT* context, uint8_t * sBox, 
    uint8_t* key, uint16_t key_length)

  Summary:
    Initializes an ARCFOUR encryption stream.

  Description:
    This function initializes an ARCFOUR encryption stream.  Call this 
    function to set up the initial state of the encryption context and the
    S-box.  The S-box will be initialized to its zero state with the 
    supplied key.
    
    This function can be used to initialize for encryption and decryption.

  Precondition:
    None.

  Parameters:
    context - A pointer to the allocated encryption context structure
    sBox - A pointer to a 256-byte buffer that will be used for the S-box.
    key - A pointer to the key to be used
    key_length - The length of the data in key

  Returns:
    None

  Remarks:
    For security, the key should be destroyed after this call.
  ***************************************************************************/
void ARCFOUR_CreateSBox(ARCFOUR_CONTEXT* context, uint8_t * sBox, uint8_t* key, uint16_t key_length)
{
	uint8_t temp, i, j, *Sbox;

	// Initialize the context indicies
	i = 0;
	j = 0;
    context->sBox = sBox;
	Sbox = sBox;
	
	// Initialize each S-box element with its index
	do
	{
		Sbox[i] = i;
		i++;
	} while(i != 0u);

	// Fill in the S-box
	do
	{
		j = j + Sbox[i] + key[i % key_length];
		temp = Sbox[i];
		Sbox[i] = Sbox[j];
		Sbox[j] = temp;
		i++;
	} while(i != 0u);

	// Reset the context indicies
	context->iterator = 0;
	context->coiterator = 0;

}

/*****************************************************************************
  Function:
    void ARCFOUR_Encrypt(uint8_t* data, uint32_t data_length, 
        ARCFOUR_CONTEXT* context)

  Summary:
    Encrypts an array of data with the ARCFOUR algorithm.

  Description:
    This function uses the current ARCFOUR context to encrypt data in place.

  Precondition:
    The encryption context ctx has been initialized with ARCFOUR_CreateSBox.

  Parameters:
    data - The data to be encrypted (in place)
    data_length - The length of data
    context - A pointer to the initialized encryption context structure

  Returns:
    None
  ***************************************************************************/
void ARCFOUR_Encrypt(uint8_t* data, uint32_t data_length, ARCFOUR_CONTEXT* context)
{
	uint8_t temp, temp2, i, j, *Sbox;

	// Buffer context variables in local RAM for faster access
	i = context->iterator;
	j = context->coiterator;
	Sbox = context->sBox;

	// Loop over each byte.  Extract its key and XOR
	while(data_length--)
	{		
		i++;
		temp = Sbox[i];		
		j += temp;
		temp2 = Sbox[j];
		Sbox[i] = temp2;
		Sbox[j] = temp;
		temp += temp2;
		temp2 = Sbox[temp];

		*data++ ^= temp2;
	}
	
	// Save the new context
	context->iterator = i;
	context->coiterator = j;

}



