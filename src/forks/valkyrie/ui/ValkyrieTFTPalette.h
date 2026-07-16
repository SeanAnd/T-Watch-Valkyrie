#pragma once

#include <stdint.h>

namespace valkyrie
{

inline uint16_t tftForegroundForRow(uint32_t row, uint32_t displayHeight)
{
    constexpr uint16_t accentBlue = 0x1BD9;
    constexpr uint16_t bodyPearl = 0xF77E;
    return (row <= 22 || row + 12 >= displayHeight) ? accentBlue : bodyPearl;
}

} // namespace valkyrie
