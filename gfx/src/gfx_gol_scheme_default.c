/********************************************************************
 Software License Agreement:

 The software supplied herewith by Microchip Technology Incorporated
 (the "Company") for its PIC(R) Microcontroller is intended and
 supplied to you, the Company's customer, for use solely and
 exclusively on Microchip PIC Microcontroller products. The
 software is owned by the Company and/or its supplier, and is
 protected under applicable copyright laws. All rights are reserved.
 Any use in violation of the foregoing restrictions may subject the
 user to criminal sanctions under applicable laws, as well as to
 civil liability for the breach of the terms and conditions of this
 license.

 THIS SOFTWARE IS PROVIDED IN AN "AS IS" CONDITION. NO WARRANTIES,
 WHETHER EXPRESS, IMPLIED OR STATUTORY, INCLUDING, BUT NOT LIMITED
 TO, IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 PARTICULAR PURPOSE APPLY TO THIS SOFTWARE. THE COMPANY SHALL NOT,
 IN ANY CIRCUMSTANCES, BE LIABLE FOR SPECIAL, INCIDENTAL OR
 CONSEQUENTIAL DAMAGES, FOR ANY REASON WHATSOEVER.
 *******************************************************************/

/*****************************************************************************
 * Section: Includes
 *****************************************************************************/
#include "system_config.h"
#ifndef GFX_LIB_CFG_SCHEME_DEFAULT

#include "gfx/gfx_gol.h"

//#if defined(GFX_LIB_CFG_USE_GOL)
/*****************************************************************************
 * Overview: This defines a default GOL scheme that gets populated when an 
 *           application calls the GOLCreateScheme().  The application can 
 *           override this definition by defining the macro GFX_LIB_CFG_SCHEME_DEFAULT 
 *           in the GraphicsConfig.h header file and defining GOLSchemeDefault 
 *           structure in the application code. It is important to use the same
 *           structure name since the library assumes that this object exists 
 *           and assigns the default style scheme pointer to this object.
 *****************************************************************************/
const GFX_GOL_OBJ_SCHEME GOLSchemeDefault =
{
#if (GFX_CONFIG_COLOR_DEPTH == 1)
    .EmbossDkColor          = BLACK,                        // Emboss dark color used for 3d effect.
    .EmbossLtColor          = WHITE,                        // Emboss light color used for 3d effect.
    .TextColor0             = WHITE,                        // Character color 0 used for objects that supports text.
    .TextColor1             = BLACK,                        // Character color 1 used for objects that supports text.
    .TextColorDisabled      = WHITE,                        // Character color used when object is in a disabled state.
    .Color0                 = BLACK,                        // Color 0 usually assigned to an Object state.
    .Color1                 = WHITE,                        // Color 1 usually assigned to an Object state.
    .ColorDisabled          = BLACK,                        // Color used when an Object is in a disabled state.
    .CommonBkColor          = BLACK,                        // Background color used to hide Objects.
    .BackGroundInfo.color   = BLACK,                        // set the default of the color used for background

#ifndef GFX_CONFIG_ALPHABLEND_DISABLE
    #error "Alpha Blending is not supported for color depths less than 16 BPP."
#endif

#ifndef GFX_CONFIG_GRADIENT_DISABLE
    #error "Gradient feature is not supported for color depths less than 16 BPP."
#endif

#elif (GFX_CONFIG_COLOR_DEPTH == 4)
    .EmbossDkColor          = GRAY006,                      // Emboss dark color used for 3d effect.
    .EmbossLtColor          = GRAY010,                      // Emboss light color used for 3d effect.
    .TextColor0             = WHITE,                        // Character color 0 used for objects that supports text.
    .TextColor1             = BLACK,                        // Character color 1 used for objects that supports text.
    .TextColorDisabled      = GRAY012,                      // Character color used when object is in a disabled state.
    .Color0                 = GRAY008,                      // Color 0 usually assigned to an Object state.
    .Color1                 = GRAY004,                      // Color 1 usually assigned to an Object state.
    .ColorDisabled          = GRAY014,                      // Color used when an Object is in a disabled state.
    .CommonBkColor          = BLACK,                        // Background color used to hide Objects.
    .BackGroundInfo.color   = BLACK,                        // set the default of the color used for background

#ifndef GFX_CONFIG_ALPHABLEND_DISABLE
    #error "Alpha Blending is not supported for color depths less than 16 BPP."
#endif

#ifndef GFX_CONFIG_GRADIENT_DISABLE
    #error "Gradient feature is not supported for color depths less than 16 BPP."
#endif

#else    
    .EmbossDkColor          = GFX_RGBConvert(0x2B, 0x55, 0x87), // Emboss dark color used for 3d effect.
    .EmbossLtColor          = GFX_RGBConvert(0xD4, 0xE4, 0xF7), // Emboss light color used for 3d effect.
    .TextColor0             = GFX_RGBConvert(0x07, 0x1E, 0x48), // Character color 0 used for objects that supports text.
    .TextColor1             = GFX_RGBConvert(0xFF, 0xFF, 0xFF), // Character color 1 used for objects that supports text.
    .TextColorDisabled      = GFX_RGBConvert( 245,  245,  220), // Character color used when object is in a disabled state.
    .Color0                 = GFX_RGBConvert(0xA9, 0xDB, 0xEF), // Color 0 usually assigned to an Object state.
    .Color1                 = GFX_RGBConvert(0x26, 0xC7, 0xF2), // Color 1 usually assigned to an Object state.
    .ColorDisabled          = GFX_RGBConvert(0xB6, 0xD2, 0xFB), // Color used when an Object is in a disabled state.
    .CommonBkColor          = GFX_RGBConvert(0xD4, 0xED, 0xF7), // Background color used to hide Objects.
#endif

    .CommonBkLeft           = 0,                            // Horizontal starting position of the background.
    .CommonBkTop            = 0,                            // Horizontal starting position of the background.
    .CommonBkType           = GFX_BACKGROUND_COLOR,         // Background type color since widgets uses the
                                                            // common background color as default hide setting.
    .pCommonBkImage         = NULL,                         // pointer to the background image used

    .pFont                  = NULL,                         // Font for the scheme.

    .fillStyle              = GFX_FILL_STYLE_COLOR,         // fill style

#ifndef GFX_CONFIG_ALPHABLEND_DISABLE
    .AlphaValue             = 100,                          // Alpha value used (percent based)
#endif

#ifndef GFX_CONFIG_GRADIENT_DISABLE
#ifndef GFX_CONFIG_PALETTE_DISABLE
    #error "Gradient feature is not currently supported when palette is enabled. Declare the macro GFX_CONFIG_PALETTE_DISABLE to disable the palette mode"
#endif

    .gradientStartColor = GFX_RGBConvert(0xA9, 0xDB, 0xEF), // Starting color
    .gradientEndColor   = GFX_RGBConvert(0x26, 0xC7, 0xF2), // Ending color

#endif

    .EmbossSize         = 3       // Emboss size of the panel for 3-D effect default to macro defined.

};

//#endif
#endif
