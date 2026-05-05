#include "ThreatIgnoreList.h"
#include "configuration.h"

#if defined(ARCH_ESP32) && defined(VALKYRIE_FORK)

#include <Preferences.h>
#include <cstring>
#include <mutex>

namespace valkyrie
{

namespace
{

static constexpr const char *kNvsNamespace = "valkyrie";
static constexpr const char *kBlobKey = "ign_blob";

// Blob: [version u8][count u8][count * (type u8 + mac 6)]
static constexpr uint8_t kBlobVersion = 1;

struct Entry {
    uint8_t type;
    uint8_t mac[6];
};

static std::mutex s_mu;
static Entry s_entries[ThreatIgnoreList::kMaxEntries];
static size_t s_count = 0;

static bool validType(uint8_t v)
{
    return v >= 1 && v <= 6;
}

static bool entryMatches(const Entry &e, ThreatType t, const uint8_t mac[6])
{
    return e.type == static_cast<uint8_t>(t) && memcmp(e.mac, mac, 6) == 0;
}

} // namespace

void ThreatIgnoreList::reloadCache()
{
    std::lock_guard<std::mutex> lock(s_mu);
    s_count = 0;
    Preferences prefs;
    if (!prefs.begin(kNvsNamespace, true)) {
        return;
    }
    size_t blobLen = prefs.getBytesLength(kBlobKey);
    if (blobLen < 2) {
        prefs.end();
        return;
    }
    uint8_t buf[2 + kMaxEntries * 7];
    if (blobLen > sizeof(buf))
        blobLen = sizeof(buf);
    size_t rd = prefs.getBytes(kBlobKey, buf, blobLen);
    prefs.end();
    if (rd < 2 || buf[0] != kBlobVersion)
        return;
    size_t n = buf[1];
    if (n > kMaxEntries)
        n = kMaxEntries;
    if (rd < 2 + n * 7)
        return;
    for (size_t i = 0; i < n; ++i) {
        const uint8_t *p = buf + 2 + i * 7;
        if (!validType(p[0]))
            continue;
        s_entries[s_count].type = p[0];
        memcpy(s_entries[s_count].mac, p + 1, 6);
        s_count++;
    }
}

bool ThreatIgnoreList::isIgnored(ThreatType t, const uint8_t mac[6])
{
    if (t == ThreatType::None)
        return false;
    std::lock_guard<std::mutex> lock(s_mu);
    for (size_t i = 0; i < s_count; ++i) {
        if (entryMatches(s_entries[i], t, mac))
            return true;
    }
    return false;
}

size_t ThreatIgnoreList::count()
{
    std::lock_guard<std::mutex> lock(s_mu);
    return s_count;
}

bool ThreatIgnoreList::getEntry(size_t index, ThreatType *typeOut, uint8_t macOut[6])
{
    if (!typeOut || !macOut)
        return false;
    std::lock_guard<std::mutex> lock(s_mu);
    if (index >= s_count)
        return false;
    *typeOut = static_cast<ThreatType>(s_entries[index].type);
    memcpy(macOut, s_entries[index].mac, 6);
    return true;
}

bool ThreatIgnoreList::persistLocked()
{
    uint8_t buf[2 + kMaxEntries * 7];
    buf[0] = kBlobVersion;
    buf[1] = (uint8_t)s_count;
    for (size_t i = 0; i < s_count; ++i) {
        uint8_t *p = buf + 2 + i * 7;
        p[0] = s_entries[i].type;
        memcpy(p + 1, s_entries[i].mac, 6);
    }
    size_t blobLen = 2 + s_count * 7;

    Preferences prefs;
    if (!prefs.begin(kNvsNamespace, false)) {
        LOG_WARN("ThreatIgnoreList: NVS open failed on save");
        return false;
    }
    size_t wr = prefs.putBytes(kBlobKey, buf, blobLen);
    prefs.end();
    if (wr != blobLen) {
        LOG_WARN("ThreatIgnoreList: putBytes failed (%u != %u)", (unsigned)wr, (unsigned)blobLen);
        return false;
    }
    return true;
}

bool ThreatIgnoreList::add(ThreatType t, const uint8_t mac[6])
{
    if (t == ThreatType::None)
        return false;
    std::lock_guard<std::mutex> lock(s_mu);
    for (size_t i = 0; i < s_count; ++i) {
        if (entryMatches(s_entries[i], t, mac))
            return true;
    }
    if (s_count >= kMaxEntries)
        return false;
    s_entries[s_count].type = static_cast<uint8_t>(t);
    memcpy(s_entries[s_count].mac, mac, 6);
    s_count++;
    if (!persistLocked()) {
        s_count--;
        return false;
    }
    return true;
}

void ThreatIgnoreList::removeAt(size_t index)
{
    std::lock_guard<std::mutex> lock(s_mu);
    if (index >= s_count)
        return;
    for (size_t j = index + 1; j < s_count; ++j)
        s_entries[j - 1] = s_entries[j];
    s_count--;
    persistLocked();
}

} // namespace valkyrie

#else

#include <cstddef>
#include <cstdint>

namespace valkyrie
{
void ThreatIgnoreList::reloadCache() {}
bool ThreatIgnoreList::isIgnored(ThreatType, const uint8_t *) { return false; }
size_t ThreatIgnoreList::count() { return 0; }
bool ThreatIgnoreList::getEntry(size_t, ThreatType *, uint8_t *) { return false; }
bool ThreatIgnoreList::add(ThreatType, const uint8_t *) { return false; }
void ThreatIgnoreList::removeAt(size_t) {}
} // namespace valkyrie

#endif
