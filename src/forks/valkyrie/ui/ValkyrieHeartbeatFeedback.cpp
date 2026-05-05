#include "ValkyrieHeartbeatFeedback.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include "../HeartbeatSignalTier.h"
#include "../modules/BleThreatDetectorModule.h"
#include "ValkyrieFork.h"
#include "concurrency/OSThread.h"
#include "configuration.h"
#include "main.h"
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

static void pulseHaptic()
{
#if defined(HAS_DRV2605) && defined(T_WATCH_S3)
    if (externalNotificationModule && externalNotificationModule->nagging())
        return;
    drv.setWaveform(0, 16);
    drv.setWaveform(1, 0);
    drv.setWaveform(2, 16);
    drv.setWaveform(3, 0);
    drv.setWaveform(4, 16);
    drv.setWaveform(5, 0);
    drv.setWaveform(6, 16);
    drv.setWaveform(7, 0);
    drv.go();
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

    const uint32_t now = millis();
    if (now - g_lastWakePokeMs >= 8000) {
        powerFSM.trigger(EVENT_INPUT);
        g_lastWakePokeMs = now;
    }

    HeartbeatSignalTier tier = bleThreatDetector->getHeartbeatSignalTier();
    if (tier == HeartbeatSignalTier::None) {
        return 200;
    }

    // Slower cadence on weaker tiers so haptic is not frantic (Strong stays quickest).
    uint32_t periodMs = 1200;
    if (tier == HeartbeatSignalTier::Medium)
        periodMs = 900;
    else if (tier == HeartbeatSignalTier::Strong)
        periodMs = 380;

    if (g_lastPulseMs != 0 && (now - g_lastPulseMs) < periodMs) {
        return 50;
    }
    g_lastPulseMs = now;

    pulseHaptic();
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
