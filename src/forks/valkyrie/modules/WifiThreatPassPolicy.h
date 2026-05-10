#pragma once

// Cold/hot bring-up split for STA + promiscuous passes (duty + heartbeat hunt).
// Keep Wi‑Fi STA driver initialised once; prefer esp_wifi_stop() over cycling
// through WIFI_OFF to avoid Arduino-ESP32 init/deinit heap churn.

namespace wifi_threat_pass_policy
{

enum class Phase : uint8_t {
    InitDisconnectWait,
    InitModeStaWait,
};

struct BeginDecision {
    bool needWifiDisconnect;
    Phase nextPhase;
};

inline BeginDecision decideBegin(bool staDriverAlreadyInitialised)
{
    if (!staDriverAlreadyInitialised)
        return {true, Phase::InitDisconnectWait};
    return {false, Phase::InitModeStaWait};
}

} // namespace wifi_threat_pass_policy
