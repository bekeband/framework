/*********************************************************************
 *
 *					ARCFOUR Cryptography Headers
 *
 *********************************************************************
 * FileName:        arcfour.h
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

#include <stdint.h>

#ifndef __ARCFOUR_H
#define __ARCFOUR_H

// Encryption Context for ARCFOUR module.
// The program need not access any of these values directly, but rather
// only store the structure and use ARCFOUR_CreateSBox to set it up.
typedef struct
{
	uint8_t *sBox;              // A pointer to a 256 byte S-box array
	uint8_t iterator;           // The iterator variable
	uint8_t coiterator;         // The co-iterator
} ARCFOUR_CONTEXT;

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
	key_length - The length of the key, in bytes.

  Returns:
	None

  Remarks:
	For security, the key should be destroyed after this call.
  ***************************************************************************/
void ARCFOUR_CreateSBox(ARCFOUR_CONTEXT* context, uint8_t * sBox, uint8_t* key, uint16_t key_length);

/*****************************************************************************
  Function:
	void ARCFOUR_Encrypt(uint8_t* data, uint32_t data_length, 
        ARCFOUR_CONTEXT* context)

  Summary:
	Encrypts an array of data with the ARCFOUR algorithm.

  Description:
	This function uses the current ARCFOUR context to encrypt data in place.

  Precondition:
	The encryption context has been initialized with ARCFOUR_CreateSBox.

  Parameters:
	data - The data to be encrypted (in place)
	data_length - The length of data
	context - A pointer to the initialized encryption context structure

  Returns:
	None
  ***************************************************************************/
void ARCFOUR_Encrypt(uint8_t* data, uint32_t data_length, ARCFOUR_CONTEXT* context);


/*****************************************************************************
  Function:
	void ARCFOUR_Decrypt(uint8_t* data, uint32_t data_length, 
        ARCFOUR_CONTEXT* context

  Summary:
	Decrypts an array of data with the ARCFOUR algorithm.

  Description:
	This function uses the current ARCFOUR context to decrypt data in place.

  Precondition:
	The encryption context has been initialized with ARCFOUR_CreateSBox.

  Parameters:
	data - The data to be encrypted (in place)
	data_length - The length of data
	context - A pointer to the initialized encryption context structure

  Returns:
	None
  ***************************************************************************/
#define ARCFOUR_Decrypt     ARCFOUR_Encrypt

#endif

