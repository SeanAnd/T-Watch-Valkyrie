#include "ValkyrieWardriveInput.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "graphics/Screen.h"
#include "input/InputBroker.h"

namespace valkyrie
{

namespace
{
bool s_alertUiActive = false;
bool s_exitTapPending = false;
/// Same nav-suppression trick as ValkyrieHeartbeatInput to prevent a queued tap/swipe
/// from changing the main frame the instant we close.
uint32_t s_suppressNavigationUntilMs = 0;

static bool isMainFrameNavEvent(input_broker_event ev)
{
    switch (ev) {
    case INPUT_BROKER_LEFT:
    case INPUT_BROKER_RIGHT:
    case INPUT_BROKER_USER_PRESS:
    case INPUT_BROKER_ALT_PRESS:
    case INPUT_BROKER_UP_LONG:
    case INPUT_BROKER_DOWN_LONG:
        return true;
    default:
        return false;
    }
}
} // namespace

void setWardriveAlertUiActive(bool active)
{
    if (s_alertUiActive && !active)
        s_suppressNavigationUntilMs = millis() + 600;
    if (active)
        s_suppressNavigationUntilMs = 0;
    s_alertUiActive = active;
    if (!active)
        s_exitTapPending = false;
}

void requestWardriveUiExit()
{
    if (s_alertUiActive)
        s_exitTapPending = true;
}

bool consumeWardriveUiExitTap()
{
    if (!s_exitTapPending)
        return false;
    s_exitTapPending = false;
    return true;
}

bool handleWardriveScreenInput(const InputEvent *event)
{
    if (!event)
        return false;

    const uint32_t now = millis();
    if (s_suppressNavigationUntilMs != 0 && (int32_t)(now - s_suppressNavigationUntilMs) < 0 &&
        isMainFrameNavEvent(event->inputEvent))
        return true;

    if (!s_alertUiActive)
        return false;

    if (event->inputEvent == INPUT_BROKER_USER_PRESS) {
        requestWardriveUiExit();
        if (screen)
            screen->runNow();
        return true;
    }
    if (event->inputEvent == INPUT_BROKER_LEFT || event->inputEvent == INPUT_BROKER_RIGHT ||
        event->inputEvent == INPUT_BROKER_ALT_PRESS || event->inputEvent == INPUT_BROKER_UP_LONG ||
        event->inputEvent == INPUT_BROKER_DOWN_LONG)
        return true;

    return false;
}

} // namespace valkyrie

#endif
