#include "ValkyrieHeartbeatFeedback.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "../HeartbeatSignalTier.h"
#include "../modules/BleThreatDetectorModule.h"
#include "ValkyrieFork.h"
#include "concurrency/OSThread.h"
#include "configuration.h"
#include "main.h"
#include "mesh/Throttle.h"
#include "modules/ExternalNotificationModule.h"
#include "PowerFSM.h"

#include <cstring>

namespace valkyrie
{

namespace
{

class HeartbeatFeedbackThread : public concurrency::OSThread
{
  public:
    HeartbeatFeedbackThread() : concurrency::OSThread("ValkyrieHBFB") { disable(); }

  protected:
    int32_t runOnce() override;
};

HeartbeatFeedbackThread *g_feedback = nullptr;
uint32_t g_lastWakePokeMs = 0;
uint32_t g_lastPulseMs = 0;

static void pulseHaptic(HeartbeatSignalTier tier)
{
#if defined(HAS_DRV2605) && defined(T_WATCH_S3)
    if (externalNotificationModule && externalNotificationModule->nagging())
        return;
    uint8_t effect = 1;
    if (tier == HeartbeatSignalTier::VeryWeak)
        effect = 3;
    else if (tier == HeartbeatSignalTier::Weak)
        effect = 2;
    drv.setWaveform(0, effect);
    drv.setWaveform(1, 0);
    drv.go();
#else
    (void)tier;
#endif
}

static void maybeBeep()
{
#if defined(HAS_I2S)
    if (!audioThread)
        return;
    if (audioThread->isPlaying())
        return;
    static const char kRttl[] = "d=8,o=6,b=1200:16";
    audioThread->beginRttl(kRttl, (uint32_t)strlen(kRttl));
#endif
}

int32_t HeartbeatFeedbackThread::runOnce()
{
    if (!bleThreatDetector || !bleThreatDetector->isHeartbeatActive()) {
        return 60 * 1000;
    }

    if (g_lastWakePokeMs == 0 || !Throttle::isWithinTimespanMs(g_lastWakePokeMs, 8000)) {
        powerFSM.trigger(EVENT_INPUT);
        g_lastWakePokeMs = millis();
    }

    HeartbeatSignalTier tier = bleThreatDetector->getHeartbeatSignalTier();
    if (tier == HeartbeatSignalTier::None) {
        return 200;
    }

    const uint32_t periodMs = heartbeatTierPulsePeriodMs(tier);
    if (periodMs == 0)
        return 200;

    if (g_lastPulseMs != 0 && Throttle::isWithinTimespanMs(g_lastPulseMs, periodMs)) {
        return 50;
    }
    g_lastPulseMs = millis();

    pulseHaptic(tier);
    maybeBeep();
    return 50;
}

} // namespace

void startHeartbeatFeedback()
{
    if (!g_feedback) {
        g_feedback = new HeartbeatFeedbackThread();
    }
    g_lastWakePokeMs = millis();
    g_lastPulseMs = 0;
    // ctor calls disable(); Thread::tillRun() never runs until enabled is true again.
    g_feedback->enabled = true;
    g_feedback->setIntervalFromNow(0);
}

void stopHeartbeatFeedback()
{
    if (g_feedback) {
        g_feedback->disable();
    }
    g_lastPulseMs = 0;
}

} // namespace valkyrie

#endif
