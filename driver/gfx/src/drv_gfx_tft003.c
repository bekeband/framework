/*******************************************************************************
 Display Driver for Microchip Graphics Library - Display Driver Layer

  Company:
    Microchip Technology Inc.

  File Name:
    drv_gfx_tft003.c

  Summary:
    Display Driver for use with the Microchip Graphics Library.

  Description:
    This module implements the display driver for the following controllers:
    *  Ilitek ILI9341
    This module implements the basic Display Driver Layer API required by the 
    Microchip Graphics Library to enable, initialize and render pixels 
    to the display controller. 
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

// *****************************************************************************
// *****************************************************************************
// Section: Included Files
// *****************************************************************************
// *****************************************************************************

// *****************************************************************************
// *****************************************************************************
// Section: Included Files
// *****************************************************************************
// *****************************************************************************
#include "system.h"
#include <stdint.h>

#if defined (GFX_USE_DISPLAY_CONTROLLER_ILI9341)

#if defined (__XC16__)
  #include <libpic30.h>
#endif
                       
#include "driver/gfx/drv_gfx_display.h"      
#include "driver/gfx/drv_gfx_tft003.h"
#include "gfx/gfx_primitive.h"

#if defined (USE_GFX_PMP)
    #include "driver/gfx/drv_gfx_pmp.h"
#elif defined (USE_GFX_EPMP)
    #include "driver/gfx/drv_gfx_epmp.h"
#endif

// *****************************************************************************
// *****************************************************************************
// Section: Helper Macros and Functions
// *****************************************************************************
// *****************************************************************************

/*********************************************************************
* Macro:  DRV_GFX_PixelWrite(color)
*
* PreCondition: none
*
* Input: color
*
* Output: none
*
* Side Effects: none
*
* Overview: writes pixel at the current address
*
* Note: chip select should be enabled
*
********************************************************************/
#ifdef USE_16BIT_PMP
    #define DRV_GFX_PixelWrite(color)	DRV_GFX_PMPWrite(color)
#else
    inline void __attribute__((always_inline)) DRV_GFX_PixelWrite(uint16_t color)
    {
        DRV_GFX_PMPWrite(((DRIVER_UINT16_UNION)color).uint168BitValue[1]);
        DRV_GFX_PMPWrite(((DRIVER_UINT16_UNION)color).uint168BitValue[0]);
    }
#endif

/*********************************************************************
* Macros:  DRV_GFX_AddressSet(addr)
*
* Overview: Writes address pointer.
*
* PreCondition: none
*
* Input: add0 -  32-bit address.
*
* Output: none
*
* Side Effects: none
*
********************************************************************/
void DRV_GFX_AddressSet(uint16_t x, uint16_t y)
{
    DisplaySetCommand();
    // set column address
    DRV_GFX_PMPWrite(0x2A);
    DisplaySetData();
    DRV_GFX_PMPWrite(((DRIVER_UINT16_UNION)x).uint168BitValue[1]);
    DRV_GFX_PMPWrite(((DRIVER_UINT16_UNION)x).uint168BitValue[0]);

    DisplaySetCommand();
    // set page address
    DRV_GFX_PMPWrite(0x2B);
    DisplaySetData();
    DRV_GFX_PMPWrite(((DRIVER_UINT16_UNION)y).uint168BitValue[1]);
    DRV_GFX_PMPWrite(((DRIVER_UINT16_UNION)y).uint168BitValue[0]);

    DisplaySetCommand();
//    // set to memory write command
//    DRV_GFX_PMPWrite(0x2C);
//    DisplaySetData();
}

void DRV_GFX_CommandWrite(uint8_t cmd)
{
    DisplayEnable();
    DisplaySetCommand();
    DRV_GFX_PMPWrite(cmd);
    DisplayDisable();
}

inline void __attribute__((always_inline)) DRV_GFX_DataWrite(uint8_t data)
{
    DisplayEnable();
    DisplaySetData();
    DRV_GFX_PMPWrite(data);
    DisplayDisable();
}

// *****************************************************************************
/*  Function:
    void DRV_GFX_DisplayBrightness(uint16_t level)

    Summary:
        This function sets the display brightness.

    Description:
        This function sets the display brightness. The levels are
        0-100 where 0 means that the display is turned off and 100
        means that the display is at its brightest mode.
        This usually controls the backlight of the display.

        In cases where the backlight is hooked up to a PWM signal
        the level will determine the frequency and period of the PWM signal.
        In cases there control is only on or off, 0 means off and
        level greater than 0 means on.


*/
// *****************************************************************************
void DRV_GFX_DisplayBrightness(uint16_t level)
{
    // If the brightness can be controlled (for example through PWM)
    // add code that will control the PWM here.

    if (level > 0)
    {
        DisplayBacklightOn();           
    }    
    else if (level == 0)
    {
        DisplayBacklightOff();
    }    
        
}    

/*********************************************************************
* Function:  void DRV_GFX_Initialize()
*
* PreCondition: none
*
* Input: none
*
* Output: none
*
* Side Effects: none
*
* Overview: resets LCD, initializes PMP
*
* Note: none
*
********************************************************************/
void DRV_GFX_Initialize(void)
{
    // Set FLASH CS pin as output
    DisplayFlashConfig();

    // Initialize the device
    DRV_GFX_PMPInitialize();

    __delay_ms(5);

    // Power on LCD
    DisplayPowerOn();
    DisplayPowerConfig();

    __delay_ms(2);
  
    DisplayResetDisable();  // remove reset
    __delay_ms(1);          // Delay 1ms
    DisplayResetEnable();   // set reset
    __delay_ms(10);         // Delay 10ms - This delay time is necessary
    DisplayResetDisable();  // remove reset
    __delay_ms(10);         // Delay 120 ms

    //Start initial Sequence
    DRV_GFX_CommandWrite(0x01); // software reset
    __delay_ms(500);            // delay(5);
    DRV_GFX_CommandWrite(0x28); // display off
//------------power control------------------------------
    DRV_GFX_CommandWrite(0xC0); // power control
    DRV_GFX_DataWrite(26);      //
    DRV_GFX_CommandWrite(0xC1); // power control
    DRV_GFX_DataWrite(0x11);    //
    DRV_GFX_CommandWrite(0xC5); // vcom control
    DRV_GFX_DataWrite(0x5C);    //
    DRV_GFX_DataWrite(0x4C);    //
    DRV_GFX_CommandWrite(0xC7); // vcom control
    DRV_GFX_DataWrite(0x94);    //
//------------memory access control------------------------
    DRV_GFX_CommandWrite(0x36); // memory access control
//    DRV_GFX_DataWrite(0x48);    // 48 my,mx,mv,ml,BGR,mh,0.0

#if defined (DISP_ORIENTATION_0)
    DRV_GFX_DataWrite(0x08);  //  my,mx,mv,ml,BGR,mh,0.0
#else
    DRV_GFX_DataWrite(0x38);  //  my,mx,mv,ml,BGR,mh,0.0
#endif

    DRV_GFX_CommandWrite(0x3A); // pixel format set
    DRV_GFX_DataWrite(0x55);    // 16bit /pixel
//----------------- frame rate------------------------------
    DRV_GFX_CommandWrite(0xB1); // frame rate
    DRV_GFX_DataWrite(0x00);    //
    DRV_GFX_DataWrite(0x1B);    // 70
//----------------Gamma---------------------------------
    DRV_GFX_CommandWrite(0xF2); // 3Gamma Function Disable
    DRV_GFX_DataWrite(0x08);    //
    DRV_GFX_CommandWrite(0x26); //
    DRV_GFX_DataWrite(0x01);    // gamma set 4 gamma curve 01/02/04/08
    DRV_GFX_CommandWrite(0xE0); // positive gamma correction
    DRV_GFX_DataWrite(0x1F);    //
    DRV_GFX_DataWrite(0x1A);    //
    DRV_GFX_DataWrite(0x18);    //
    DRV_GFX_DataWrite(0x0A);    //
    DRV_GFX_DataWrite(0x0F);    //
    DRV_GFX_DataWrite(0x06);    //
    DRV_GFX_DataWrite(0x45);    //
    DRV_GFX_DataWrite(0x87);    //
    DRV_GFX_DataWrite(0x32);    //
    DRV_GFX_DataWrite(0x0A);    //
    DRV_GFX_DataWrite(0x07);    //
    DRV_GFX_DataWrite(0x02);    //
    DRV_GFX_DataWrite(0x07);    //
    DRV_GFX_DataWrite(0x05);    //
    DRV_GFX_DataWrite(0x00);    //
    DRV_GFX_CommandWrite(0xE1); // negative gamma correction
    DRV_GFX_DataWrite(0x00);    //
    DRV_GFX_DataWrite(0x25);    //
    DRV_GFX_DataWrite(0x27);    //
    DRV_GFX_DataWrite(0x05);    //
    DRV_GFX_DataWrite(0x10);    //
    DRV_GFX_DataWrite(0x09);    //
    DRV_GFX_DataWrite(0x3A);    //
    DRV_GFX_DataWrite(0x78);    //
    DRV_GFX_DataWrite(0x4D);    //
    DRV_GFX_DataWrite(0x05);    //
    DRV_GFX_DataWrite(0x18);    //
    DRV_GFX_DataWrite(0x0D);    //
    DRV_GFX_DataWrite(0x38);    //
    DRV_GFX_DataWrite(0x3A);    //
    DRV_GFX_DataWrite(0x1F);    //
//--------------ddram ---------------------
    DRV_GFX_CommandWrite(0x2A); // column address set
    DRV_GFX_DataWrite(0x00);    //
    DRV_GFX_DataWrite(0x00);    //
#if defined (DISP_ORIENTATION_0)
    DRV_GFX_DataWrite(0x00);
    DRV_GFX_DataWrite(0xEF);    // X Max  = 240
#else
    DRV_GFX_DataWrite(0x01);
    DRV_GFX_DataWrite(0x3F);    // X Max = 320
#endif
    DRV_GFX_DataWrite(0x00);    //
    DRV_GFX_DataWrite(0xEF);    //
    DRV_GFX_CommandWrite(0x2B); // page address set
    DRV_GFX_DataWrite(0x00);    //
    DRV_GFX_DataWrite(0x00);    //
#if defined (DISP_ORIENTATION_0)
    DRV_GFX_DataWrite(0x01);
    DRV_GFX_DataWrite(0x3F);    // Y Max = 320
#else
    DRV_GFX_DataWrite(0x01);
    DRV_GFX_DataWrite(0x3F);    // Y Max = 240
#endif
    //DRV_GFX_CommandWrite(0x34); // tearing effect off
    //DRV_GFX_CommandWrite(0x35); // tearing effect on
    //DRV_GFX_CommandWrite(0xB4); // display inversion
    //DRV_GFX_DataWrite(0x00);    //

    DRV_GFX_CommandWrite(0xB7);  // entry mode set
    DRV_GFX_DataWrite(0x07);     //
//-----------------display---------------------
    DRV_GFX_CommandWrite(0xB6);  // display function control
    DRV_GFX_DataWrite(0x0A);     //
    DRV_GFX_DataWrite(0x82);     //
    DRV_GFX_DataWrite(0x27);     //
    DRV_GFX_DataWrite(0x00);     //
    DRV_GFX_CommandWrite(0x11);  // sleep out
    DRV_GFX_CommandWrite(0x29);  // display on
    __delay_ms(200);             // delay(200);

}

// *****************************************************************************
/*  Function:
    GFX_STATUS GFX_PixelPut(
                    uint16_t    x,
                    uint16_t    y)

    Summary:
        Draw the pixel on the given position.

    Description:
        This routine draws the pixel on the given position.
        The color used is the color set by the last call to
        GFX_ColorSet().

        If position is not on the frame buffer, then the behavior
        is undefined. If color is not set, before this function
        is called, the output is undefined.

*/
// *****************************************************************************
GFX_STATUS GFX_PixelPut(uint16_t x, uint16_t y)
{
    DisplayEnable();
    DRV_GFX_AddressSet(x, y);

    // set to memory write command
    DRV_GFX_PMPWrite(0x2C);
    DisplaySetData();
    
    DRV_GFX_PixelWrite(GFX_ColorGet());

    DisplayDisable();

    return (GFX_STATUS_SUCCESS);
    
}

// *****************************************************************************
/*  Function:
    GFX_COLOR GFX_PixelGet(
                    uint16_t    x,
                    uint16_t    y)

    Summary:
        Gets color of the pixel on the given position.

    Description:
        This routine gets the pixel on the given position.

        If position is not on the frame buffer, then the behavior
        is undefined.

*/
// *****************************************************************************
GFX_COLOR GFX_PixelGet(uint16_t x, uint16_t y)
{
    GFX_COLOR result;
    uint8_t red, green, blue;

    DisplayEnable();
    DRV_GFX_AddressSet(x, y);

    // set to memory read command
    DRV_GFX_PMPWrite(0x2E);
    DisplaySetData();

#ifdef USE_8BIT_PMP

    // this first two reads are a dummy reads
    DRV_GFX_PMPSingleRead();
    DRV_GFX_PMPSingleRead();

    // these are the reads that will get the actual pixel data
    // read RED
    red = DRV_GFX_PMPSingleRead();
    // read GREEN
    green = DRV_GFX_PMPSingleRead();
    // read BLUE
    blue = DRV_GFX_PMPSingleRead();

    DisplayDisable();

    result = (GFX_COLOR)(
                            ((((GFX_COLOR)(red)   & 0xF8) >> 3) << 11)  |
                            ((((GFX_COLOR)(green) & 0xFC) >> 2) << 5)   |
                            (( (GFX_COLOR)(blue)  & 0xF8) >> 3)
                        );

#else
#warning 16bit PMP is not yet supported in this driver
#endif
    // Disable LCD
    DisplayDisable();

    return (result);
}

// *****************************************************************************
/*  Function:
    uint16_t GFX_PixelArrayPut(
                                uint16_t x,
                                uint16_t y,
                                GFX_COLOR *pPixel,
                                uint16_t numPixels)

    Summary:
        Renders an array of pixels to the frame buffer.

    Description:
        This renders an array of pixels starting from the
        location defined by x and y with the length
        defined by numPixels. The rendering will be performed
        in the increasing x direction. If the length is more
        than 1 line of the screen, the rendering may continue
        to the next line depending on the way the memory of
        the display controller is arranged.
        For example, in some display controller, if the parameters are
           GFX_PixelArrayPut(0, 0, ptrToArray, (320*240));
        The array is rendered on all the pixels of a QVGA screen.

        This function also supports transparent color feature.
        When the feature is enabled the pixel with the transparent
        color will not be rendered and will be skipped.
        x and y must define a location within the display
        buffer.

*/
// *****************************************************************************
uint16_t GFX_PixelArrayPut(
                                uint16_t x,
                                uint16_t y,
                                GFX_COLOR *pPixel,
                                uint16_t numPixels)
{
    uint16_t    z;

    DisplayEnable();      
    DRV_GFX_AddressSet(x, y);

    // set to memory write command
    DRV_GFX_PMPWrite(0x2C);
    DisplaySetData();

#ifndef GFX_CONFIG_TRANSPARENT_COLOR_DISABLE
    if (GFX_TransparentColorStatusGet() == GFX_FEATURE_ENABLED)
    {
        for(z = 0; z < numPixels; z++)
        {
            // Write pixel to screen
            if (GFX_TransparentColorGet() == *pPixel)
            {
                // do a look ahead to predict the next one, if the next one is
                // not transparent, set the address to the new address so we
                // start the rendering on the right address
                // we do this because DRV_GFX_AddressSet() is time consuming
                if (((z+1) < numPixels) && ((*(pPixel + 1)) != GFX_TransparentColorGet()))
                {
                    DRV_GFX_AddressSet(x+z, y);
                    // set to memory write command
                    DRV_GFX_PMPWrite(0x2C);
                    DisplaySetData();
                }
            }
            else
            {
                DRV_GFX_PixelWrite(*pPixel);
            }
            pPixel++;
        }
    }
    else
#endif
    {
        for(z = 0; z < numPixels; z++)
        {
            // Write pixel to screen
            DRV_GFX_PixelWrite(*pPixel);
            pPixel++;
        }
    }
    DisplayDisable();
    return 1;
}

// *****************************************************************************
/*  Function:
    uint16_t GFX_PixelArrayGet(
                                uint16_t x,
                                uint16_t y,
                                GFX_COLOR *pPixel,
                                uint16_t numPixels)

    Summary:
        Renders an array of pixels to the frame buffer.

    Description:
        This retrieves an array of pixels from the display buffer
        starting from the location defined by x and y with
        the length defined by numPixels. All the retrieved pixels
        must be inside the display buffer.

        The function behavoir will be undefined is one of the
        following is true:
        1. x and y location is outside the frame buffer.
        2. x + numPixels exceeds the frame buffer.
        3. Depending on how the frame buffer memory is arranged
           x + numPixels exceeds the width of the frame buffer.

*/
// *****************************************************************************
uint16_t GFX_PixelArrayGet(
                                uint16_t x,
                                uint16_t y,
                                GFX_COLOR *pPixel,
                                uint16_t numPixels)
{

    uint16_t            z;
    uint8_t             red, blue, green;

    DisplayEnable();
    DRV_GFX_AddressSet(x, y);

    // set to memory read command
    DRV_GFX_PMPWrite(0x2E);
    DisplaySetData();

    // dummy reads
#if defined(USE_GFX_PMP)
#ifdef USE_8BIT_PMP
        // this first two reads are a dummy reads
        DRV_GFX_PMPSingleRead();
        DRV_GFX_PMPSingleRead();
#else
#warning 16bit PMP is not yet supported in this driver
#endif
#endif

    for(z = 0; z < numPixels; z++)
    {
#if defined(USE_GFX_PMP)

        // these are the reads that will get the actual pixel data
        // read RED
        red = DRV_GFX_PMPSingleRead();
        // read GREEN
        green = DRV_GFX_PMPSingleRead();
        // read BLUE
        blue = DRV_GFX_PMPSingleRead();

        DisplayDisable();

        *pPixel = (GFX_COLOR)(
                                ((((GFX_COLOR)(red)   & 0xF8) >> 3) << 11) |
                                ((((GFX_COLOR)(green) & 0xFC) >> 2) << 5)  |
                                (( (GFX_COLOR)(blue)  & 0xF8) >> 3)
                             );

#endif
        pPixel++;
    }
    DisplayDisable();
    return (z);

}

// *****************************************************************************
/*  Function:
    GFX_STATUS GFX_BarDraw(
                                uint16_t left,
                                uint16_t top,
                                uint16_t right,
                                uint16_t bottom)

    Summary:
        This function renders a bar shape using the currently set fill
        style and color.

    Description:
        This function renders a bar shape with the currently set
        fill style (See GFX_FillStyleGet() and GFX_FillStyleSet() for
        details of fill style):
        - solid color - when the fill style is set to
                        GFX_FILL_STYLE_COLOR
        - alpha blended fill - when the fill style is set to
                        GFX_FILL_STYLE_ALPHA_COLOR.

        Any other selected fill style will be ignored and will assume
        a solid color fill will be used. The parameters left, top, right
        bottom will define the shape dimension.

        When fill style is set to GFX_FILL_STYLE_ALPHA_COLOR, the bar
        can also be rendered with an option to select the type of
        background.
        GFX_BACKGROUND_NONE - the bar will be rendered with no alpha blending.
        GFX_BACKGROUND_COLOR - the bar will be alpha blended with the
                               currently set background color.
        GFX_BACKGROUND_IMAGE - the bar will be alpha blended with the
                               currently set background image.
        GFX_BACKGROUND_DISPLAY_BUFFER - the bar will be alpha blended
                               with the current contents of the frame buffer.

        The background type is set by the GFX_BackgroundTypeSet().

        The rendering of this shape becomes undefined when any one of the
        following is true:
        - Any of the following pixel locations left,top or right,bottom
          falls outside the frame buffer.
        - Colors are not set before this function is called.
        - When right < left
        - When bottom < top
        - When pixel locations defined by left, top and/or right, bottom
          are not on the frame buffer.

*/
// *****************************************************************************
GFX_STATUS GFX_BarDraw(         uint16_t left,
                                uint16_t top,
                                uint16_t right,
                                uint16_t bottom)
{
    register uint16_t x, y;

#if !defined(GFX_LIB_CFG_USE_NONBLOCKING)
    while (GFX_RenderStatusGet() != GFX_STATUS_READY_BIT);

    /* Ready */
#else
    if (GFX_RenderStatusGet() != GFX_STATUS_READY_BIT)
        return (0);
#endif

#ifndef GFX_CONFIG_ALPHABLEND_DISABLE
    if (GFX_FillStyleGet() == GFX_FILL_STYLE_ALPHA_COLOR)
    {
        if(GFX_AlphaBlendingValueGet() != 100)
        {
            if (GFX_BarAlphaDraw(left,top,right,bottom))
                return (GFX_STATUS_SUCCESS);
            else
                return (GFX_STATUS_FAILURE);
        }
    }
#endif

    DisplayEnable();
    for(y = top; y < bottom + 1; y++)
    {
        DRV_GFX_AddressSet(left, y);
        // set to memory write command
        DRV_GFX_PMPWrite(0x2C);
        DisplaySetData();

        for(x = left; x < right + 1; x++)
        {
            DRV_GFX_PixelWrite(GFX_ColorGet());
        }
    }

    DisplayDisable();
    return (GFX_STATUS_SUCCESS);
}

// *****************************************************************************
/*  Function:
    GFX_STATUS GFX_ScreenClear(void)

    Summary:
        Clears the screen to the currently set color (GFX_ColorSet()).

    Description:
        This function clears the screen with the current color and sets
        the line cursor position to (0, 0).

        If color is not set, before this function is called, the output
        is undefined.

        If the function returns GFX_STATUS_FAILURE, clearing is not
        yet finished. Application must call the function again to continue
        the clearing.

*/
// *****************************************************************************
GFX_STATUS GFX_ScreenClear(void)
{
    uint32_t   counter;

    DisplayEnable();
    DRV_GFX_AddressSet(0, 0);

    // set to memory write command
    DRV_GFX_PMPWrite(0x2C);
    DisplaySetData();

    for(counter = 0; counter < (uint32_t) (GFX_MaxXGet() + 1) * (GFX_MaxYGet() + 1); counter++)
    {
        DRV_GFX_PixelWrite(GFX_ColorGet());
    }

    DisplayDisable();

    GFX_LinePositionSet(0, 0);

    return (GFX_STATUS_SUCCESS);
}

// *****************************************************************************
/*  Function:
    GFX_STATUS GFX_RenderStatusGet()

    Summary:
        This function returns the driver's status on rendering.

    Description:
        This function returns the driver's rendering status. Valid values
        returned are GFX_STATUS_BUSY_BIT or GFX_STATUS_READY_BIT

*/
// *****************************************************************************
GFX_STATUS_BIT GFX_RenderStatusGet(void)
{  
    return (GFX_STATUS_READY_BIT);
}

#endif 

