/**********************************************************************
* © 2012 Microchip Technology Inc.
*
* FileName:        rsa_enc_dec.h
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
/* FILE         rsa_enc_dec.h
 *
 * DESCRIPTION  This file contains the C function declarations for
 *              RSA encryption and decryption routines in the dsPIC
 *              Cryptographic Library.
 *
 * AUTHOR       N. A. Howgrave-Graham, NTRU Cryptosystems, Inc.
 *
 * DATE         11/20/2003
 *
 * NOTES
 *
 * CHANGES
 *              - 08/25/2009 mhe
 *                  - added rsa_encrypt_raw() and rsa_decrypt_raw() 
 *
 */

#ifndef RSA_ENC_DEC_H
#define RSA_ENC_DEC_H

/* function declarations */

/****************************************************************************/
extern unsigned short int               /* return code:
                                            MCL_SUCCESS
                                            MCL_ILLEGAL_PARAMETER
                                            MCL_ILLEGAL_SIZE */
rsa_encrypt(
    unsigned char *c,                   /* address for the ciphertext,
                                           k bytes */
    unsigned char *m,                   /* a pointer to the plaintext message */
    unsigned short int m_byte_len,      /* 0 <= no. of m bytes <= k-11 */
    unsigned char *n,                   /* a pointer to the RSA public modulus,
                                           most significant byte first */
    unsigned short int n_byte_len,      /* k, the number of bytes in n,
                                           must be 128 or 256 */
    unsigned char *e,                   /* a pointer to the RSA public exponent,
                                           most significant byte first */
    unsigned short int e_byte_len,      /* 0 < number of bytes in e <= k */
    unsigned char *xbuf,                /* pointer to a working buffer
                                           (xdata, length 2*k bytes,
                                           aligned (64)) */
    unsigned char *ybuf,                /* pointer to working buffer,
                                           (ydata, length 3*k bytes,
                                           aligned (2)) */
    uint32_t(*randFunc) (void) 
);

/* NOTE: the c buffer may not overlap the high half of xbuf addresses */

/* NOTE: THE WORKING BUFFER, xbuf, MUST BE ALIGNED AND LOCATED AS FOLLOWS:
 unsigned char __attribute__ ((aligned (64), space(xmemory))) xbuf[2*k];
 */

/* NOTE: THE WORKING BUFFER, ybuf, MUST BE ALIGNED AND LOCATED AS FOLLOWS:
 unsigned char __attribute__ ((aligned (2), space(ymemory), eds)) ybuf[3*k];
 */

  
/****************************************************************************/
extern unsigned short int               /* return code
                                            MCL_SUCCESS
                                            MCL_ILLEGAL_PARAMETER
                                            MCL_ILLEGAL_SIZE
                                            MCL_INVALID_CIPHERTEXT */
rsa_decrypt(
    unsigned char *m,                   /* address for the plaintext message */
    unsigned short int *m_byte_len,     /* address for the length of the
                                           plaintext message,
                                           0 <= m_byte_len <= k-11 */
    unsigned char *c,                   /* a pointer to the ciphertext buffer */
    unsigned short int c_byte_len,      /* number of bytes in c, must be 128
                                           or 256 */
    unsigned char *privkey,             /* a pointer to the private key,
                                           length 5*k/2 aligned(2) bytes */
    unsigned char *xbuf,                /* a pointer to a working buf,
                                           (xdata, length 3*(k/2) bytes,
                                           aligned (2)) */
    unsigned char *ybuf                 /* a pointer to a working buf,
                                           (ydata, length 3*(k/2) bytes,
                                           aligned (2)) */
);

/* NOTE: the m buffer may not overlap the low k-11 bytes of xbuf addresses */

/* NOTE: THE PRIVATE KEY BUFFER, privkey, MUST BE ALIGNED AS FOLLOWS:
 *       unsigned char __attribute__ ((aligned (2))) sk[5*k/2] */

/* NOTE: THE WORKING BUFFER, xbuf, MUST BE ALIGNED AND LOCATED AS FOLLOWS:
 unsigned char __attribute__ ((aligned (2), space(xmemory))) xbuf[3*k/2];
 */

/* NOTE: THE WORKING BUFFER, ybuf, MUST BE ALIGNED AND LOCATED AS FOLLOWS:
 unsigned char __attribute__ ((aligned (2), space(ymemory), eds)) ybuf[3*k/2];
 */


/****************************************************************************/
extern unsigned short int               /* return code:
                                            MCL_SUCCESS
                                            MCL_ILLEGAL_PARAMETER
                                            MCL_ILLEGAL_SIZE */
rsa_encrypt_raw(
    unsigned char *c,                   /* address for the ciphertext,
                                           k bytes */
    unsigned char *m,                   /* a pointer to the plaintext message,
                                           m < k */
    unsigned short int m_byte_len,      /* 0 <= no. of m bytes <= k */
    unsigned char *n,                   /* a pointer to the RSA public modulus,
                                           most significant byte first */
    unsigned short int n_byte_len,      /* k, the number of bytes in n,
                                           must be 128 or 144 */
    unsigned char *e,                   /* a pointer to the RSA public exponent,
                                           most significant byte first */
    unsigned short int e_byte_len,      /* 0 < number of bytes in e <= k */
    unsigned char *xbuf,                /* pointer to a working buffer
                                           (xdata, length 2*k bytes,
                                           aligned (64)) */
    unsigned char *ybuf                 /* pointer to working buffer,
                                           (ydata, length 3*k bytes,
                                           aligned (2)) */
);

/* NOTE: the c buffer may not overlap the high half of xbuf addresses */

/* NOTE: THE WORKING BUFFER, xbuf, MUST BE ALIGNED AND LOCATED AS FOLLOWS:
 unsigned char __attribute__ ((aligned (64), __section__(".xbss") )) xbuf[2*k];
 */

/* NOTE: THE WORKING BUFFER, ybuf, MUST BE ALIGNED AND LOCATED AS FOLLOWS:
 unsigned char __attribute__ ((aligned (2), __section__(".ybss") )) ybuf[3*k];
 */

  
/****************************************************************************/
extern unsigned short int               /* return code
                                            MCL_SUCCESS
                                            MCL_ILLEGAL_PARAMETER
                                            MCL_ILLEGAL_SIZE */
rsa_decrypt_raw(
    unsigned char *m,                   /* address for the plaintext message */
    unsigned short int *m_byte_len,     /* address for the length of the
                                           plaintext message,
                                           0 <= m_byte_len <= k */
    unsigned char *c,                   /* a pointer to the ciphertext buffer */
    unsigned short int c_byte_len,      /* number of bytes in c, must be 128
                                           or 144 */
    unsigned char *privkey,             /* a pointer to the private key,
                                           length 5*k/2 aligned(2) bytes */
    unsigned char *xbuf,                /* a pointer to a working buf,
                                           (xdata, length 3*(k/2) bytes,
                                           aligned (2)) */
    unsigned char *ybuf                 /* a pointer to a working buf,
                                           (ydata, length 3*(k/2) bytes,
                                           aligned (2)) */
);

/* NOTE: the m buffer may not overlap the low k bytes of xbuf addresses */

/* NOTE: THE PRIVATE KEY BUFFER, privkey, MUST BE ALIGNED AS FOLLOWS:
 *       unsigned char __attribute__ ((aligned (2))) sk[5*k/2] */

/* NOTE: THE WORKING BUFFER, xbuf, MUST BE ALIGNED AND LOCATED AS FOLLOWS:
 unsigned char __attribute__ ((aligned (2), space(xmemory))) xbuf[3*k/2];
 */

/* NOTE: THE WORKING BUFFER, ybuf, MUST BE ALIGNED AND LOCATED AS FOLLOWS:
 unsigned char __attribute__ ((aligned (2), space(ymemory), eds)) ybuf[3*k/2];
 */


#endif /* RSA_ENC_DEC_H */
