/*******************************************************************************
 Module for Microchip Graphics Library - Primitive Layer

  Company:
    Microchip Technology Inc.

  File Name:
    gfx_palette.c

  Summary:
    This implements the palette routines of the Primitive Layer.
*******************************************************************************/

// DOM-IGNORE-BEGIN
/*******************************************************************************
Copyright (c) 2013 released Microchip Technology Inc.  All rights reserved.

Microchip licenses to you the right to use, modify, copy and distribute
Software only when embedded on a Microchip microcontroller or digital signal
controller that is integrated into your product or third party product
(pursuant to the sublicense terms in the accompanying license agreement).

You should refer to the license agreement accompanying this Software for
additional information regarding your rights and obligations.

SOFTWARE AND DOCUMENTATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION, ANY WARRANTY OF
MERCHANTABILITY, TITLE, NON-INFRINGEMENT AND FITNESS FOR A PARTICULAR PURPOSE.
IN NO EVENT SHALL MICROCHIP OR ITS LICENSORS BE LIABLE OR OBLIGATED UNDER
CONTRACT, NEGLIGENCE, STRICT LIABILITY, CONTRIBUTION, BREACH OF WARRANTY, OR
OTHER LEGAL EQUITABLE THEORY ANY DIRECT OR INDIRECT DAMAGES OR EXPENSES
INCLUDING BUT NOT LIMITED TO ANY INCIDENTAL, SPECIAL, INDIRECT, PUNITIVE OR
CONSEQUENTIAL DAMAGES, LOST PROFITS OR LOST DATA, COST OF PROCUREMENT OF
SUBSTITUTE GOODS, TECHNOLOGY, SERVICES, OR ANY CLAIMS BY THIRD PARTIES
(INCLUDING BUT NOT LIMITED TO ANY DEFENSE THEREOF), OR OTHER SIMILAR COSTS.
*******************************************************************************/
// DOM-IGNORE-END

#include <stdint.h>
#include "gfx/gfx_palette.h"

#if defined(GFX_LIB_CFG_USE_PALETTE)

extern void StartVBlankInterrupt(void);
uint8_t             PaletteBpp;
uint8_t             blPaletteChangeError;
GFX_RESOURCE_HDR    *pPendingPalette;
uint16_t            PendingStartEntry;
uint16_t            PendingLength;

/*********************************************************************
* Function: void RequestPaletteChange(GFX_RESOURCE_HDR *pPalette, uint16_t startEntry, uint16_t length)
*
* Overview: Loads the palettes from the flash during vertical blanking period
*           if possible, otherwise loads immediately.
*
* PreCondition: PaletteInit() must be called before.
*
* Input: pPalette   - Pointer to the palette resource
*        startEntry - Start entry to load (inclusive)
*        length     - Number of entries
*
* Output: none
*
* Side Effects: There may be a slight flicker when the Palette entries
*               are getting loaded one by one.
*
********************************************************************/
void RequestPaletteChange(GFX_RESOURCE_HDR *pPalette, uint16_t startEntry, uint16_t length)
{
    pPendingPalette = pPalette;
    PendingStartEntry = startEntry;
    PendingLength = length;
    StartVBlankInterrupt();
}

/*********************************************************************
* Function: uint8_t SetPalette(GFX_RESOURCE_HDR *pPalette, uint16_t startEntry, uint16_t length)
*
* Overview: Loads the palettes from the flash immediately.
*
* PreCondition: PaletteInit() must be called before.
*
* Input: pPalette   - Pointer to the palette resource
*        startEntry - Start entry to load (inclusive)
*        length     - Number of entries
*
* Output: Status: Zero -> Success, Non-zero -> Error.
*                 - 3 - GFX_RESOURCE_HDR type is not a valid type palette
*                 - 2 - pPalette is NULL
*                 - 1 - startingEntry + length > max entries
*                 - 0 - palette is set with no errors.
*
* Side Effects: There may be a slight flicker when the Palette entries
*               are getting loaded one by one.
*
********************************************************************/
uint8_t SetPalette(GFX_RESOURCE_HDR *pPalette, uint16_t startEntry, uint16_t length)
{
    uint8_t         status = 3;
#if defined(GFX_LIB_CFG_USE_PALETTE_EXTERNAL)
    GFX_PALETTE_ENTRY   paletteEntry[256];
#endif

    switch(pPalette->type)
    {
    
        case GFX_RESOURCE_PALETTE_FLASH_NONE:

            if (pPalette->resource.palette.numberOfEntries < length)
            {
                length = pPalette->resource.palette.numberOfEntries;
            }

            status = SetPaletteFlash(pPalette->resource.palette.location.constByteAddress, startEntry, length);
            break;

        case GFX_RESOURCE_PALETTE_RAM_NONE :

            if (pPalette->resource.palette.numberOfEntries < length)
            {
                length = pPalette->resource.palette.numberOfEntries;
            }

            status = SetPaletteFlash(pPalette->resource.palette.location.ramAddress, startEntry, length);
            break;

    #if defined(GFX_LIB_CFG_USE_PALETTE_EXTERNAL)
        case GFX_RESOURCE_PALETTE_EXTERNAL_NONE:
            // NOTE:
            // When SetPalette() is called in an interrupt sub-routine (ISR) and the palette is sourced from
            // external memory, make sure that the resource sharing is managed properly.
            // Problems can occur when the main routine is performing access to the same memory
            // and the interrupt occurs. The ExternalMemoryCallback() may use that same driver to the
            // external memory and may break currently ongoing accesses.
            // Therefore, for cases where the SetPalette() is launched in an ISR and
            // the palette is from external memory. It will be safer to copy the palette to RAM
            // first and call SetPalette() in the ISR with the palette coming from the copy in RAM.
            ExternalMemoryCallback(pPalette, (startEntry * sizeof(GFX_PALETTE_ENTRY)), sizeof(GFX_PALETTE_ENTRY)*length, (void*)paletteEntry);

            status = SetPaletteFlash(paletteEntry, startEntry, length);
            break;
    #endif
        default:
            status = 3;
            break;

    }

    return (status);
}

/*********************************************************************
* Function: uint8_t GetPaletteChangeError(void)
*
* Overview: Returns the Palette change error status
*
* PreCondition: none
*
* Input: none
*
* Output: NoError -> Zero; Error -> Non Zero
*
* Side Effects: none
*
********************************************************************/
uint8_t GetPaletteChangeError(void)
{
    return (blPaletteChangeError);
}

/*********************************************************************
* Function: void ClearPaletteChangeError(void)
*
* Overview: Clears the Palette change error status
*
* PreCondition: none
*
* Input: none
*
* Output: none
*
* Side Effects: none
*
********************************************************************/
void ClearPaletteChangeError(void)
{
    blPaletteChangeError = 0;
}

#endif // GFX_LIB_CFG_USE_PALETTE
