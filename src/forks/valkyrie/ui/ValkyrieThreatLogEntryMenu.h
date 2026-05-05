#pragma once

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

namespace valkyrie
{

void threatLogEntryMenuOpen(size_t pageIndex, size_t lineOnPage);
void showThreatLogEntryMenu();

} // namespace valkyrie

#endif
