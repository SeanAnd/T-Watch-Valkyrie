#pragma once

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

namespace valkyrie
{
void showSettingsMenu();
void showNotificationsMenu();
void showConstantScanEnableConfirmMenu();
/// Sub-menu reached from "Wardrive…" in the main settings page. Houses the three wardrive prefs
/// (wd_req_fix, wd_per_ms, wd_phn). Defined in ValkyrieWardriveMenu.cpp.
void showWardriveSettingsMenu();
} // namespace valkyrie

#endif
