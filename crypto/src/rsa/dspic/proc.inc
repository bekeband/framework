;/**********************************************************************
;* © 2012 Microchip Technology Inc.
;*
;* FileName:        proc.inc
;* Processor:       dsPIC30F/dsPIC33F/dsPIC33E
;*
;* SOFTWARE LICENSE AGREEMENT:
;* Microchip Technology Incorporated ("Microchip") retains all ownership and 
;* intellectual property rights in the code accompanying this message and in all 
;* derivatives hereto.  You may use this code, and any derivatives created by 
;* any person or entity by or on your behalf, exclusively with Microchip's
;* proprietary products.  Your acceptance and/or use of this code constitutes 
;* agreement to the terms and conditions of this notice.
;*
;* CODE ACCOMPANYING THIS MESSAGE IS SUPPLIED BY MICROCHIP "AS IS".  NO 
;* WARRANTIES, WHETHER EXPRESS, IMPLIED OR STATUTORY, INCLUDING, BUT NOT LIMITED 
;* TO, IMPLIED WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY AND FITNESS FOR A 
;* PARTICULAR PURPOSE APPLY TO THIS CODE, ITS INTERACTION WITH MICROCHIP'S 
;* PRODUCTS, COMBINATION WITH ANY OTHER PRODUCTS, OR USE IN ANY APPLICATION. 
;*
;* YOU ACKNOWLEDGE AND AGREE THAT, IN NO EVENT, SHALL MICROCHIP BE LIABLE, WHETHER 
;* IN CONTRACT, WARRANTY, TORT (INCLUDING NEGLIGENCE OR BREACH OF STATUTORY DUTY), 
;* STRICT LIABILITY, INDEMNITY, CONTRIBUTION, OR OTHERWISE, FOR ANY INDIRECT, SPECIAL, 
;* PUNITIVE, EXEMPLARY, INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, FOR COST OR EXPENSE OF 
;* ANY KIND WHATSOEVER RELATED TO THE CODE, HOWSOEVER CAUSED, EVEN IF MICROCHIP HAS BEEN 
;* ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE FORESEEABLE.  TO THE FULLEST EXTENT 
;* ALLOWABLE BY LAW, MICROCHIP'S TOTAL LIABILITY ON ALL CLAIMS IN ANY WAY RELATED TO 
;* THIS CODE, SHALL NOT EXCEED THE PRICE YOU PAID DIRECTLY TO MICROCHIP SPECIFICALLY TO 
;* HAVE THIS CODE DEVELOPED.
;*
;* You agree that you are solely responsible for testing the code and 
;* determining its suitability.  Microchip has no obligation to modify, test, 
;* certify, or support the code.
;*
;* ADDITIONAL NOTES:
;*
;*
;**********************************************************************/
;***************************************************************************
; FILE          proc.inc
;
; DESCRIPTION   This file includes the proper SFR and bit definitions
;				depending on the device family.
;               all dsPIC30F devices.
;
; AUTHOR        M. H. Etzel, Security Innovation, Inc.
;
; DATE          09/05/2011
;
; NOTES
;
; CHANGES
;

;.ifdef __dsPIC30F
;.include "p30Fxxxx.inc"
;.equiv PROC_INC_SET,1
;.endif

.ifdef __dsPIC33F
.include "p33Fxxxx.inc"
.equiv PROC_INC_SET,1
.endif

.ifdef __MCHP16EP
.include "p33Exxxx.inc"
.equiv PROC_INC_SET,1
.endif

.ifndef PROC_INC_SET
.error "cannot include processor definitions for unknown device family"
.endif
