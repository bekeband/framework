/**********************************************************************
* © 2012 Microchip Technology Inc.
*
* FileName:        ret_codes.h
* Processor:       dsPIC30F/dsPIC33F/dsPIC33E
*
* SOFTWARE LICENSE AGREEMENT:
* Microchip Technology Incorporated ("Microchip") retains all ownership and 
* intellectual property rights in the code accompanying this message and in all 
* derivatives hereto.  You may use this code, and any derivatives created by 
* any person or entity by or on your behalf, exclusively with Microchip's
* proprietary products.  Your acceptance and/or use of this code constitutes 
* agreement to the terms and conditions of this notice.
*
* CODE ACCOMPANYING THIS MESSAGE IS SUPPLIED BY MICROCHIP "AS IS".  NO 
* WARRANTIES, WHETHER EXPRESS, IMPLIED OR STATUTORY, INCLUDING, BUT NOT LIMITED 
* TO, IMPLIED WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY AND FITNESS FOR A 
* PARTICULAR PURPOSE APPLY TO THIS CODE, ITS INTERACTION WITH MICROCHIP'S 
* PRODUCTS, COMBINATION WITH ANY OTHER PRODUCTS, OR USE IN ANY APPLICATION. 
*
* YOU ACKNOWLEDGE AND AGREE THAT, IN NO EVENT, SHALL MICROCHIP BE LIABLE, WHETHER 
* IN CONTRACT, WARRANTY, TORT (INCLUDING NEGLIGENCE OR BREACH OF STATUTORY DUTY), 
* STRICT LIABILITY, INDEMNITY, CONTRIBUTION, OR OTHERWISE, FOR ANY INDIRECT, SPECIAL, 
* PUNITIVE, EXEMPLARY, INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, FOR COST OR EXPENSE OF 
* ANY KIND WHATSOEVER RELATED TO THE CODE, HOWSOEVER CAUSED, EVEN IF MICROCHIP HAS BEEN 
* ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE FORESEEABLE.  TO THE FULLEST EXTENT 
* ALLOWABLE BY LAW, MICROCHIP'S TOTAL LIABILITY ON ALL CLAIMS IN ANY WAY RELATED TO 
* THIS CODE, SHALL NOT EXCEED THE PRICE YOU PAID DIRECTLY TO MICROCHIP SPECIFICALLY TO 
* HAVE THIS CODE DEVELOPED.
*
* You agree that you are solely responsible for testing the code and 
* determining its suitability.  Microchip has no obligation to modify, test, 
* certify, or support the code.
*
* ADDITIONAL NOTES:
*
*
**********************************************************************/
/****************************************************************************/
/* FILE         ret_codes.h
 *
 * DESCRIPTION  This file contains the C return codes for the
 *              routines in the dsPIC Cryptographic Library.
 *
 * AUTHOR       M. H. Etzel, NTRU Cryptosystems, Inc.
 *
 * DATE         6/20/2003
 *
 * NOTES
 *              - THIS FILE MUST BE IN SYNC WITH ret_codes.inc FOR ASM.
 *
 * CHANGES
 *
 */

#ifndef RET_CODES_H
#define RET_CODES_H

/* return code definitions */

#define MCL_SUCCESS                 0       /* successful completion */
#define MCL_DRBG_NOT_INITIALIZED    1       /* DRBG not initialized */
#define MCL_ILLEGAL_SIZE            2       /* illegal size parameter */
#define MCL_ILLEGAL_PADDING         3       /* illegal padding */
#define MCL_ILLEGAL_PARAMETER       4       /* illegal parameter */
#define MCL_INVALID_MAC             5       /* invalid MAC */
#define MCL_INVALID_SIGNATURE       6       /* invalid signature */
#define MCL_INVALID_CIPHERTEXT      7       /* invalid ciphertext */


#endif /* RET_CODES_H */
