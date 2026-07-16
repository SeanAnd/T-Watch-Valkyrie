#pragma once

#include <GpioLogic.h>
#include <OLEDDisplay.h>

/**
 * An adapter class that allows using the LovyanGFX library as if it was an OLEDDisplay implementation.
 *
 * Remaining TODO:
 * optimize display() to only draw changed pixels (see other OLED subclasses for examples)
 * Use the fast NRF52 SPI API rather than the slow standard arduino version
 *
 * turn radio back on - currently with both on spi bus is fucked? or are we leaving chip select asserted?
 */
class TFTDisplay : public OLEDDisplay
{
  public:
    /* constructor
    FIXME - the parameters are not used, just a temporary hack to keep working like the old displays
    */
    TFTDisplay(uint8_t, int, int, OLEDDISPLAY_GEOMETRY, HW_I2C);

    // Destructor to clean up allocated memory
    ~TFTDisplay();

    // Write the buffer to the display memory
    virtual void display() override { display(false); };
    virtual void display(bool fromBlank);
    void sdlLoop();

    // Turn the display upside down
    virtual void flipScreenVertically();

    // Touch screen (static handlers)
    static bool hasTouch(void);
    static bool getTouch(int16_t *x, int16_t *y);

    // Functions for changing display brightness
    void setDisplayBrightness(uint8_t);

    /**
     * shim to make the abstraction happy
     *
     */
    void setDetected(uint8_t detected);

#if defined(VALKYRIE_TFT_RGB565)
    /// Registers the single Valkyrie RGB565 layer for the next display flush.
    /// RGB565 value zero is transparent; a later registration replaces the pending layer.
    void drawRGB565Sprite(int16_t x, int16_t y, const uint16_t *pixels, uint16_t sourceWidth, uint16_t sourceHeight,
                          uint16_t destWidth, uint16_t destHeight);

    /// Redraws a monochrome UI rectangle after RGB sprites, providing a foreground overlay layer.
    void drawMonochromeOverlay(int16_t x, int16_t y, uint16_t width, uint16_t height);
#endif

    /**
     * This is normally managed entirely by TFTDisplay, but some rare applications (heltec tracker) might need to replace the
     * default GPIO behavior with something a bit more complex.
     *
     * We (cruftily) make it static so that variant.cpp can access it without needing a ptr to the TFTDisplay instance.
     */
    static GpioPin *backlightEnable;

  protected:
    // the header size of the buffer used, e.g. for the SPI command header
    virtual int getBufferOffset(void) override { return 0; }

    // Send a command to the display (low level function)
    virtual void sendCommand(uint8_t com) override;

    // Connect to the display
    virtual bool connect() override;

    uint16_t *linePixelBuffer = nullptr;

#if defined(VALKYRIE_TFT_RGB565)
    struct RGB565Sprite {
        int16_t x = 0;
        int16_t y = 0;
        const uint16_t *pixels = nullptr;
        uint16_t sourceWidth = 0;
        uint16_t sourceHeight = 0;
        uint16_t destWidth = 0;
        uint16_t destHeight = 0;
        bool valid = false;
    };

    RGB565Sprite pendingSprite;
    RGB565Sprite displayedSprite;

    struct OverlayRect {
        int16_t x = 0;
        int16_t y = 0;
        uint16_t width = 0;
        uint16_t height = 0;
        bool valid = false;
    } pendingOverlay;
#endif
};
