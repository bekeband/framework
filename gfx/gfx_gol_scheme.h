/*******************************************************************************
 Module for Microchip Graphics Library - Graphic Object Layer Scheme

  Company:
    Microchip Technology Inc.

  File Name:
    gfx_gol_scheme.h

  Summary:
    Graphics Object Layer Scheme routines/macros of the Microchip Graphics Library.

  Description:
    This module implements the common routines for the Graphics Object Layer
    of the Microchip Graphics Library. The routines are independent of the
    Display Driver Layer and should be compatible with any Display Driver
    that is compliant with the requirements of the Display Driver
    Layer of the Graphics Library.
    The module utilizes the Graphics Primitive Layer to render the objects.
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

#ifndef _GFX_GOL_SCHEME_H
// DOM-IGNORE-BEGIN
      #define _GFX_GOL_SCHEME_H
// DOM-IGNORE-END
/*********************************************************************
 * Section: Includes
 *********************************************************************/
#include <stdbool.h>
#include <stdint.h>
#include "system_config.h"
#include "gfx/gfx_colors.h"

// *****************************************************************************
/*
  <GROUP gol_types>

   Typedef:
        GFX_GOL_OBJ_SCHEME

    Summary:
        This structure specifies the style scheme components of an object.

    Description:
        This structure specifies the style scheme components of an object.
        All objects will use the style scheme when rendering. Refer to
        specific object documentation on how the style scheme colors are
        utilized by the object.

        The style scheme allows objects to show 3D effects as well as
        feedback to users. For example, in Button objects, a press and
        release effect on the Buttons are easily shown by manipulating
        the colors when the object is drawn with a pressed state and
        released state. The style scheme also allows effects such as
        gradients and alpha blending. When using alpha blending, the
        style scheme requires objects to be associated with background
        information.

        A background can be a flat color background or an image. The usage
        of a background requires the background dimension to be larger than
        the object. In other words, the object should be drawn within the
        background dimension. Multiple objects can share a common background.
        As long as all the objects are drawn within the dimension of the
        background they can share a common background.

        The supported background types are (See GFX_BACKGROUND_TYPE):
        - GFX_BACKGROUND_COLOR - this type will set the common background
                                 to be a flat color. The color used is
                                 specified by CommonBkType.
        - GFX_BACKGROUND_IMAGE - this tyoe will set the common background to
                                 be an image. The image used is specified
                                 by pCommonBkImage.

        When an object is associated with a background, it can be easily
        hidden or redrawn with some effects (for example alpha blending
        with the background). The background information allows the redrawing
        of the background with the object without the need to manually
        refreshing the background using primitive calls by the application.

    Remarks:
        None.
 */
// *****************************************************************************
typedef struct
{
    GFX_COLOR           EmbossDkColor;              // Emboss dark color used for 3d effect.
    GFX_COLOR           EmbossLtColor;              // Emboss light color used for 3d effect.
    GFX_COLOR           TextColor0;                 // Character color 0 used for objects that supports text.
    GFX_COLOR           TextColor1;                 // Character color 1 used for objects that supports text.
    GFX_COLOR           TextColorDisabled;          // Character color used when object is in a disabled state.
    GFX_COLOR           Color0;                     // Color 0 usually assigned to an Object state.
    GFX_COLOR           Color1;                     // Color 1 usually assigned to an Object state.
    GFX_COLOR           ColorDisabled;              // Color used when an Object is in a disabled state.
    GFX_RESOURCE_HDR    *pFont;                     // Font selected for the scheme.

    GFX_FILL_STYLE      fillStyle;                  // must be set to a gradient type when using gradient

    GFX_COLOR           CommonBkColor;              // Background color used to hide Objects.
    uint16_t            CommonBkLeft;               // Horizontal starting position of the background.
    uint16_t            CommonBkTop;                // Vertical starting position of the background.
    GFX_BACKGROUND_TYPE CommonBkType;               // Specifies the type of background to use.
    GFX_RESOURCE_HDR    *pCommonBkImage;            // Pointer to the background image used. Set this

#ifndef GFX_CONFIG_ALPHABLEND_DISABLE
    uint16_t            AlphaValue;                 // Alpha value used for alpha blending
#endif
     
#ifndef GFX_CONFIG_GRADIENT_DISABLE
    GFX_COLOR           gradientStartColor;         // start color of the gradient fill
    GFX_COLOR           gradientEndColor;           // end color of the gradient fill
#endif

    uint16_t            EmbossSize;                 // Emboss size of the panel for 3-D effect. Set to zero
                                                    // if not used.

} GFX_GOL_OBJ_SCHEME;

extern inline void __attribute__((always_inline)) GFX_GOL_SchemeEmbossDarkColorSet(GFX_GOL_OBJ_SCHEME *pScheme, GFX_COLOR darkColor)
{
    pScheme->EmbossDkColor = darkColor;
}

extern inline GFX_COLOR __attribute__((always_inline)) GFX_GOL_SchemeEmbossDarkColorGet(GFX_GOL_OBJ_SCHEME *pScheme)
{
    return (pScheme->EmbossDkColor);
}

extern inline void __attribute__((always_inline)) GFX_GOL_SchemeEmbossLightColorSet(GFX_GOL_OBJ_SCHEME *pScheme, GFX_COLOR lightColor)
{
    pScheme->EmbossLtColor = lightColor;
}

extern inline GFX_COLOR __attribute__((always_inline)) GFX_GOL_SchemeEmbossLightColorGet(GFX_GOL_OBJ_SCHEME *pScheme)
{
    return (pScheme->EmbossLtColor);
}

extern inline void __attribute__((always_inline)) GFX_GOL_SchemeEmbossSizeSet(GFX_GOL_OBJ_SCHEME *pScheme, uint16_t size)
{
    pScheme->EmbossSize = size;
}

extern inline uint16_t __attribute__((always_inline)) GFX_GOL_SchemeEmbossSizeGet(GFX_GOL_OBJ_SCHEME *pScheme)
{
    return (pScheme->EmbossSize);
}


extern inline void __attribute__((always_inline)) GFX_GOL_SchemeEmbossSet(GFX_GOL_OBJ_SCHEME *pScheme, GFX_COLOR darkColor, GFX_COLOR lightColor, uint16_t size)
{
    pScheme->EmbossDkColor = darkColor;
    pScheme->EmbossLtColor = lightColor;
    pScheme->EmbossSize = size;
}

extern inline void __attribute__((always_inline)) GFX_GOL_SchemeTextColor0Set(GFX_GOL_OBJ_SCHEME *pScheme, GFX_COLOR textColor)
{
    pScheme->TextColor0 = textColor;
}

extern inline GFX_COLOR __attribute__((always_inline)) GFX_GOL_SchemeTextColor0Get(GFX_GOL_OBJ_SCHEME *pScheme)
{
    return (pScheme->TextColor0);
}

extern inline void __attribute__((always_inline)) GFX_GOL_SchemeTextColor1Set(GFX_GOL_OBJ_SCHEME *pScheme, GFX_COLOR textColor)
{
    pScheme->TextColor1 = textColor;
}

extern inline GFX_COLOR __attribute__((always_inline)) GFX_GOL_SchemeTextColor1Get(GFX_GOL_OBJ_SCHEME *pScheme)
{
    return (pScheme->TextColor1);
}

extern inline void __attribute__((always_inline)) GFX_GOL_SchemeTextColorDisableSet(GFX_GOL_OBJ_SCHEME *pScheme, GFX_COLOR disableColor)
{
    pScheme->TextColorDisabled = disableColor;
}

extern inline GFX_COLOR __attribute__((always_inline)) GFX_GOL_SchemeTextColorDisableGet(GFX_GOL_OBJ_SCHEME *pScheme)
{
    return (pScheme->TextColorDisabled);
}


extern inline void __attribute__((always_inline)) GFX_GOL_SchemeTextColorSet(GFX_GOL_OBJ_SCHEME *pScheme, GFX_COLOR textColor0, GFX_COLOR textColor1, GFX_COLOR disableColor)
{
    pScheme->TextColor0 = textColor0;
    pScheme->TextColor1 = textColor1;
    pScheme->TextColorDisabled = disableColor;
}

extern inline void __attribute__((always_inline)) GFX_GOL_SchemeColor0Set(GFX_GOL_OBJ_SCHEME *pScheme, GFX_COLOR color)
{
    pScheme->Color0 = color;
}

extern inline GFX_COLOR __attribute__((always_inline)) GFX_GOL_SchemeColor0Get(GFX_GOL_OBJ_SCHEME *pScheme)
{
    return (pScheme->Color0);
}

extern inline void __attribute__((always_inline)) GFX_GOL_SchemeColor1Set(GFX_GOL_OBJ_SCHEME *pScheme, GFX_COLOR color)
{
    pScheme->Color1 = color;
}

extern inline GFX_COLOR __attribute__((always_inline)) GFX_GOL_SchemeColor1Get(GFX_GOL_OBJ_SCHEME *pScheme)
{
    return (pScheme->Color1);
}

extern inline void __attribute__((always_inline)) GFX_GOL_SchemeColorDisabledSet(GFX_GOL_OBJ_SCHEME *pScheme, GFX_COLOR disableColor)
{
    pScheme->ColorDisabled = disableColor;
}

extern inline GFX_COLOR __attribute__((always_inline)) GFX_GOL_SchemeColorDisabledGet(GFX_GOL_OBJ_SCHEME *pScheme)
{
    return (pScheme->ColorDisabled);
}

extern inline void __attribute__((always_inline)) GFX_GOL_SchemeColorSet(GFX_GOL_OBJ_SCHEME *pScheme, GFX_COLOR color0, GFX_COLOR color1, GFX_COLOR disableColor)
{
    pScheme->Color0 = color0;
    pScheme->Color1 = color1;
    pScheme->ColorDisabled = disableColor;

}

extern inline void __attribute__((always_inline)) GFX_GOL_SchemeFontSet(GFX_GOL_OBJ_SCHEME *pScheme, GFX_RESOURCE_HDR *font)
{
    pScheme->pFont = font;
}

extern inline GFX_RESOURCE_HDR*__attribute__((always_inline)) GFX_GOL_SchemeFontGet(GFX_GOL_OBJ_SCHEME *pScheme)
{
    return (pScheme->pFont);
}

extern inline void __attribute__((always_inline)) GFX_GOL_SchemeFillStyleSet(GFX_GOL_OBJ_SCHEME *pScheme, GFX_FILL_STYLE style)
{
    pScheme->fillStyle = style;
}

extern inline GFX_FILL_STYLE __attribute__((always_inline)) GFX_GOL_SchemeFillStyleGet(GFX_GOL_OBJ_SCHEME *pScheme)
{
    return (pScheme->fillStyle);
}


extern inline void __attribute__((always_inline)) GFX_GOL_SchemeBackgroundColorSet(GFX_GOL_OBJ_SCHEME *pScheme, GFX_COLOR color)
{
    pScheme->CommonBkColor = color;
}

extern inline GFX_COLOR __attribute__((always_inline)) GFX_GOL_SchemeBackgroundColorGet(GFX_GOL_OBJ_SCHEME *pScheme)
{
    return (pScheme->CommonBkColor);
}


extern inline void __attribute__((always_inline)) GFX_GOL_SchemeBackgroundImageSet(GFX_GOL_OBJ_SCHEME *pScheme, uint16_t left, uint16_t top, GFX_RESOURCE_HDR *image)
{
    pScheme->CommonBkLeft = left;
    pScheme->CommonBkTop = top;
    pScheme->pCommonBkImage = image;
}

extern inline void __attribute__((always_inline)) GFX_GOL_SchemeBackgroundTypeSet(GFX_GOL_OBJ_SCHEME *pScheme, GFX_BACKGROUND_TYPE type)
{
    pScheme->CommonBkType = type;
}

extern inline GFX_BACKGROUND_TYPE __attribute__((always_inline)) GFX_GOL_SchemeBackgroundTypeGet(GFX_GOL_OBJ_SCHEME *pScheme)
{
    return (pScheme->CommonBkType);
}
#if !defined(GFX_CONFIG_ALPHABLEND_DISABLE)
extern inline void __attribute__((always_inline)) GFX_GOL_SchemeAlphaPrecentSet(GFX_GOL_OBJ_SCHEME *pScheme, uint16_t percent)
{
    pScheme->AlphaValue = percent;
}
#endif

#if !defined (GFX_CONFIG_GRADIENT_DISABLE)
extern inline void __attribute__((always_inline)) GFX_GOL_SchemeGradientStartColorSet(GFX_GOL_OBJ_SCHEME *pScheme, GFX_COLOR startColor)
{
    pScheme->gradientStartColor = startColor;
}

extern inline GFX_COLOR __attribute__((always_inline)) GFX_GOL_SchemeGradientStartColorGet(GFX_GOL_OBJ_SCHEME *pScheme)
{
    return (pScheme->gradientStartColor);
}

extern inline void __attribute__((always_inline)) GFX_GOL_SchemeGradientEndColorSet(GFX_GOL_OBJ_SCHEME *pScheme, GFX_COLOR endColor)
{
    pScheme->gradientEndColor = endColor;
}

extern inline GFX_COLOR __attribute__((always_inline)) GFX_GOL_SchemeGradientEndColorGet(GFX_GOL_OBJ_SCHEME *pScheme)
{
    return (pScheme->gradientEndColor);
}

extern inline void __attribute__((always_inline)) GFX_GOL_SchemeGradientColorSet(GFX_GOL_OBJ_SCHEME *pScheme, GFX_COLOR startColor, GFX_COLOR endColor)
{
    pScheme->gradientStartColor = startColor;
    pScheme->gradientEndColor = endColor;
}
#endif

#endif 
