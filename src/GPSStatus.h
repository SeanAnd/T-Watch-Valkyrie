#pragma once
#include "NodeDB.h"
#include "Status.h"
#include "configuration.h"
#include <Arduino.h>

namespace meshtastic
{

/// Describes the state of the GPS system.
class GPSStatus : public Status
{

  private:
    CallbackObserver<GPSStatus, const GPSStatus *> statusObserver =
        CallbackObserver<GPSStatus, const GPSStatus *>(this, &GPSStatus::updateStatus);

    bool hasLock = false;     // default to false, until we complete our first read
    bool isConnected = false; // Do we have a GPS we are talking to

    bool isPowerSaving = false; // Are we in power saving state

    meshtastic_Position p = meshtastic_Position_init_default;

    /// Time of last valid GPS fix (millis since boot)
    uint32_t lastFixMillis = 0;

  public:
    GPSStatus() { statusType = STATUS_TYPE_GPS; }

    // preferred method
    GPSStatus(bool hasLock, bool isConnected, bool isPowerSaving, const meshtastic_Position &pos) : Status()
    {
        this->hasLock = hasLock;
        this->isConnected = isConnected;
        this->isPowerSaving = isPowerSaving;

        // all-in-one struct copy
        this->p = pos;
    }

    GPSStatus(const GPSStatus &);
    GPSStatus &operator=(const GPSStatus &);

    void observe(Observable<const GPSStatus *> *source) { statusObserver.observe(source); }

    bool getHasLock() const { return hasLock; }

    bool getIsConnected() const { return isConnected; }

    bool getIsPowerSaving() const { return isPowerSaving; }

    /// Staleness window for phone-supplied position before getHasUsablePosition() stops trusting it.
    /// The Meshtastic phone app pushes position every few seconds; 30 s lets a couple of misses slip
    /// without falsely claiming a fix.
    static constexpr uint32_t kPhonePositionFreshMs = 30000;

    /// True when SOMETHING usable can be returned by getLatitude/getLongitude/getAltitude:
    ///   - on-device GPS lock (hasLock is true), OR
    ///   - config.position.fixed_position is set and localPosition is non-zero, OR
    ///   - localPosition is non-zero and was updated within kPhonePositionFreshMs (live phone GPS).
    /// Narrow getHasLock() is intentionally left alone for callers that specifically want
    /// "on-device chip happy" (e.g. MeshService::onGPSChanged copies gps->p on that signal).
    bool getHasUsablePosition() const
    {
        if (hasLock)
            return true;
        const bool localNonZero = (localPosition.latitude_i != 0 || localPosition.longitude_i != 0);
        if (!localNonZero)
            return false;
        if (config.position.fixed_position)
            return true;
        if (!nodeDB)
            return false;
        const uint32_t last = nodeDB->getLastLocalPositionUpdateMs();
        if (last == 0)
            return false;
        return (millis() - last) <= kPhonePositionFreshMs;
    }

    int32_t getLatitude() const
    {
        if (config.position.fixed_position) {
            return localPosition.latitude_i;
        }
        if (hasLock) {
            return p.latitude_i;
        }
        // No on-device fix and not in fixed-position mode. Fall back to a fresh phone-supplied
        // localPosition if we have one; otherwise return whatever p has (typically zero).
        if (getHasUsablePosition()) {
            return localPosition.latitude_i;
        }
        return p.latitude_i;
    }

    int32_t getLongitude() const
    {
        if (config.position.fixed_position) {
            return localPosition.longitude_i;
        }
        if (hasLock) {
            return p.longitude_i;
        }
        if (getHasUsablePosition()) {
            return localPosition.longitude_i;
        }
        return p.longitude_i;
    }

    int32_t getAltitude() const
    {
        if (config.position.fixed_position) {
            return localPosition.altitude;
        }
        if (hasLock) {
            return p.altitude;
        }
        if (getHasUsablePosition()) {
            return localPosition.altitude;
        }
        return p.altitude;
    }

    uint32_t getDOP() const { return p.PDOP; }

    uint32_t getHeading() const { return p.ground_track; }

    uint32_t getNumSatellites() const { return p.sats_in_view; }

    /// Return millis() when the last GPS fix occurred (0 = never)
    uint32_t getLastFixMillis() const { return lastFixMillis; }

    bool matches(const GPSStatus *newStatus) const
    {
#ifdef GPS_DEBUG
        LOG_DEBUG("GPSStatus.match() new pos@%x to old pos@%x", newStatus->p.timestamp, p.timestamp);
#endif
        return (newStatus->hasLock != hasLock || newStatus->isConnected != isConnected ||
                newStatus->isPowerSaving != isPowerSaving || newStatus->p.latitude_i != p.latitude_i ||
                newStatus->p.longitude_i != p.longitude_i || newStatus->p.altitude != p.altitude ||
                newStatus->p.altitude_hae != p.altitude_hae || newStatus->p.PDOP != p.PDOP ||
                newStatus->p.ground_track != p.ground_track || newStatus->p.ground_speed != p.ground_speed ||
                newStatus->p.sats_in_view != p.sats_in_view);
    }

    int updateStatus(const GPSStatus *newStatus)
    {
        // Only update the status if values have actually changed
        bool isDirty = matches(newStatus);

        if (isDirty && p.timestamp && (newStatus->p.timestamp == p.timestamp)) {
            // We can NEVER be in two locations at the same time! (also PR #886)
            LOG_ERROR("BUG: Positional timestamp unchanged from prev solution");
        }

        initialized = true;
        hasLock = newStatus->hasLock;
        isConnected = newStatus->isConnected;

        p = newStatus->p;

        if (isDirty) {
            if (hasLock) {
                // Record time of last valid GPS fix
                lastFixMillis = millis();

                // In debug logs, identify position by @timestamp:stage (stage 3 = notify)
                LOG_DEBUG("New GPS pos@%x:3 lat=%f lon=%f alt=%d pdop=%.2f track=%.2f speed=%.2f sats=%d", p.timestamp,
                          p.latitude_i * 1e-7, p.longitude_i * 1e-7, p.altitude, p.PDOP * 1e-2, p.ground_track * 1e-5,
                          p.ground_speed * 1e-2, p.sats_in_view);
            } else {
                LOG_DEBUG("No GPS lock");
            }
            onNewStatus.notifyObservers(this);
        }
        return 0;
    }
};

} // namespace meshtastic

extern meshtastic::GPSStatus *gpsStatus;
