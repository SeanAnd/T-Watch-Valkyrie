#pragma once

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

namespace valkyrie
{
void showSettingsMenu();
void showNotificationsMenu();
void showConstantScanEnableConfirmMenu();
} // namespace valkyrie

#endif
