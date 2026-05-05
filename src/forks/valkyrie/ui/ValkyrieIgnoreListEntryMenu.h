#pragma once

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

namespace valkyrie
{

void ignoreListEntryMenuOpen(size_t storageIndex);
void showIgnoreListEntryMenu();

} // namespace valkyrie

#endif
