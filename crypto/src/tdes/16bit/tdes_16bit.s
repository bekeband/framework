;/*****************************************************************************
; *
; * Triple Data Encryption Standard (TDES) Encrypt/Decrypt Routines
; *   168 bit key, 64 bit data block
; *   For more information see, AN1044
; *
; *****************************************************************************
; * FileName:        TDES_asm.s
; * Dependencies:    DES_asm.s
; * Processor:        PIC24F, PIC24H, dsPIC30F, or dsPIC33F
; * Compiler:        MPLAB ASM30 2.03 or later
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
.equ VALID_ID,0
    .ifdecl __dsPIC33E
        .include "p33Exxxx.inc"
    .endif

    .ifdecl __dsPIC33F
        .include "p33Fxxxx.inc"
    .endif

    .ifdecl __dsPIC30F
        .include "p30Fxxxx.inc"
    .endif

    .ifdecl __PIC24E
        .include "p24Exxxx.inc"
    .endif

    .ifdecl __PIC24H
        .include "p24Hxxxx.inc"
    .endif

    .ifdecl __PIC24F
        .include "p24Fxxxx.inc"
    .endif

    .ifdecl __PIC24FK
        .include "p24Fxxxx.inc"
    .endif

.if VALID_ID <> 1
    .error "Processor ID not specified in generic include files.  New ASM30 assembler needs to be downloaded?"
.endif

.ifdecl __HAS_EDS
    .equ    PSVPAG,DSRPAG    
.endif

.global _TDES_Encrypt
.global _TDES_Decrypt
.global _TDES
.global _TDES_RoundKeysCreate

.bss
_SubkeyPointer: .space 2
W14_save_var: .space 2

.text
;*****************************************************************************************************
; void TDES_Encrypt(void* cipher_text, void* plain_text, void* round_keys);
;*****************************************************************************************************
; -- Working register usage --------------------------------------------------------------------------
; W0  - (param) Pointer to buffer for the output cipher text 
; W1  - (param) Pointer to input plain text
; W2  - (param) Pointer to the round keys
; W3  - (local) Encryption/Decryption selection bit (bit 0 = 1 for encryption, and = 0 for decryption)
; W4  -
; W5  - 
; W6  - 
; W7  - 
; W8  - 
; W9  - 
; W10 - 
; W11 - 
; W12 - 
; W13 - 
; W14 - 
;
; Note: don't need to save/restore W0 or W1 locally since 
;  these are used for the parameters of this function and their values
;  should not be needed outside of this function.  
;----------------------------------------------------------------------------------------------------
_TDES_Encrypt:
    mov W1, W0
    mov W2, W1
    mov W3, W2
    mov #0x01,W3
    call _TDES
    return

;*****************************************************************************************************
; void TDES_Decrypt(void* plain_text, void* cipher_text, void* round_keys);
;*****************************************************************************************************
; -- Working register usage --------------------------------------------------------------------------
; W0  - (param) Pointer to buffer for the output plain text 
; W1  - (param) Pointer to input cipher text
; W2  - (param) Pointer to the round keys
; W3  - (local) Encryption/Decryption selection bit (bit 0 = 1 for encryption, and = 0 for decryption)
; W4  -
; W5  - 
; W6  - 
; W7  - 
; W8  - 
; W9  - 
; W10 - 
; W11 - 
; W12 - 
; W13 - 
; W14 - 
;
; Note: don't need to save/restore W0 or W1 locally since 
;  these are used for the parameters of this function and their values
;  should not be needed outside of this function.  
;----------------------------------------------------------------------------------------------------
_TDES_Decrypt:
    mov W1, W0
    mov W2, W1
    mov W3, W2
    mov #0x0, W3
    add #0x178,W2
    call _TDES
    return


;*****************************************************************************************************
; void TDES(void* output_buffer, void* input_buffer, void* round_keys, unsigned char mode);
;*****************************************************************************************************
; -- Working register usage --------------------------------------------------------------------------
; W0  - (param) Pointer to buffer for the output text 
; W1  - (param) Pointer to input text
; W2  - (param) Pointer to the round keys
; W3  - (param) Encryption/Decryption selection bit (bit 0 = 1 for encryption, and = 0 for decryption)
; W4  -
; W5  - 
; W6  - 
; W7  - 
; W8  - 
; W9  - 
; W10 - 
; W11 - 
; W12 - 
; W13 - 
; W14 - 
;
; Note: don't need to save/restore W0, W1, W2, or W3 locally since 
;  these are used for the parameters of this function and their values
;  should not be needed outside of this function.  
;----------------------------------------------------------------------------------------------------
_TDES:
    call _des

    ;if it was encrypt then now do a decryption and visa versa
    btg W3,#0x0

    ;move the round key pointer
    btss W3,#0x0
    add #0xF8,W2
    btsc W3,#0x0
    sub #0xF8,W2
;    mov WREG,_subKeyBlock
    ;The input for the second cycle is the output of the first cycle
    mov W0,W1
    call _des

    ;if it was encrypt then now do a decryption and visa versa
    btg W3,#0x0
    btsc W3,#0x0
    add #0x8,W2
    btss W3,#0x0
    sub #0x8,W2
;    mov WREG,_subKeyBlock
    call _des

    return

;*********************************** New Functions ********************************
; -- Working register usage --------------------------------------------------------------------------
; W0 - Pointer to where to write the resulting round keys
; W1 - Pointer to the key
; W2  - 
; W3  - 
; W4  -
; W5  - 
; W6  - 
; W7  - 
; W8  - 
; W9  - 
; W10 - 
; W11 - 
; W12 - 
; W13 - 
; W14 - 
;
; Note: don't need to save/restore W0 or W1 locally since 
;  these are used for the parameters of this function and their values
;  should not be needed outside of this function.  
;----------------------------------------------------------------------------------------------------
_TDES_RoundKeysCreate:
    ;calculate the round keys for the first DES key
    call _calcSubKeys2

    ;move to the pointer to point to the location for the second round keys
    add #0x80,W0
    ;point to the second DES key
    add #0x08,W1
    ;and calculate the round keys
    call _calcSubKeys2

    ;move to the pointer to point to the location for the third round keys
    add #0x80,W0
    ;point to the third DES key
    add #0x08,W1
    ;and calculate the round keys
    call _calcSubKeys2
    return

.end
