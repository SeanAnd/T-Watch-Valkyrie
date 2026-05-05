#pragma once

#include "modules/BleClassifier.h"

namespace valkyrie
{

// Wire / CSV token (must match log file and protobuf naming expectations).
const char *threatTypeWireName(ThreatType t);

// Short label for on-device menus (alerts toggles).
const char *threatTypeMenuLabel(ThreatType t);

} // namespace valkyrie
