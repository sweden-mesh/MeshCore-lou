#pragma once

// `get sensors`: what the node measures, as one line of `k=v` pairs a command reply can
// carry on either road. Pure, so the host suite reaches it (test/test_mqtt_control).
//
// The battery and the MCU's temperature come from the board. Everything else is whatever the
// board's sensor manager reports for a telemetry request, read here from the Cayenne LPP
// records it writes: channel, type, value. A record on a channel other than the node's own
// carries its channel after a slash (`temp/2=21.5C`). A position is left out: the plane does
// not carry one. A type this table does not know ends the line, since its size is unknown.

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>

#define SENSOR_READOUT_SELF_CHANNEL  1    // TELEM_CHANNEL_SELF
#define SENSOR_READOUT_NO_TEMP       (-32768)
// What a sealed answer over the mesh carries of a reply: a longer line would be cut there.
#define SENSOR_READOUT_MAX           125

struct SensorReadoutType {
  uint8_t type;        // the LPP type byte
  uint8_t size;        // bytes of value
  uint16_t divisor;    // the value is this many to the unit; 0 leaves the record out
  bool is_signed;
  const char* key;
  const char* unit;
};

static inline const SensorReadoutType* sensorReadoutType(uint8_t type) {
  static const SensorReadoutType types[] = {
    {   0, 1,    1, false, "din",   ""    },
    {   1, 1,    1, false, "dout",  ""    },
    {   2, 2,  100, true,  "ain",   ""    },
    {   3, 2,  100, true,  "aout",  ""    },
    { 100, 4,    1, false, "gen",   ""    },
    { 101, 2,    1, false, "lux",   "lx"  },
    { 102, 1,    1, false, "present", ""  },
    { 103, 2,   10, true,  "temp",  "C"   },
    { 104, 1,    2, false, "hum",   "%"   },
    { 113, 6,    0, true,  "",      ""    },
    { 115, 2,   10, false, "press", "hPa" },
    { 116, 2,  100, false, "volt",  "V"   },
    { 117, 2, 1000, false, "curr",  "A"   },
    { 118, 4,    1, false, "freq",  "Hz"  },
    { 120, 1,    1, false, "pct",   "%"   },
    { 121, 2,    1, true,  "alt",   "m"   },
    { 125, 2,    1, false, "conc",  "ppm" },
    { 128, 2,    1, false, "pow",   "W"   },
    { 130, 4, 1000, false, "dist",  "m"   },
    { 131, 4, 1000, false, "energy","kWh" },
    { 132, 2,    1, false, "dir",   "deg" },
    { 133, 4,    0, false, "",      ""    },
    { 134, 6,    0, true,  "",      ""    },
    { 135, 3,    0, false, "",      ""    },
    { 136, 9,    0, true,  "",      ""    },
    { 142, 1,    1, false, "sw",    ""    },
  };
  for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
    if (types[i].type == type) return &types[i];
  }
  return NULL;
}

// Appends only what fits whole, so a line never ends in half a pair.
static inline bool sensorReadoutAppend(char* out, size_t out_size, size_t* used, const char* fmt, ...) {
  char pair[48];
  va_list args;
  va_start(args, fmt);
  const int n = vsnprintf(pair, sizeof(pair), fmt, args);
  va_end(args);
  if (n < 0 || (size_t)n >= sizeof(pair) || *used + (size_t)n >= out_size) return false;
  for (int i = 0; i < n; i++) out[(*used)++] = pair[i];
  out[*used] = 0;
  return true;
}

// A value of `divisor` to the unit, with as many decimals as the divisor has zeros.
static inline void sensorReadoutNumber(char* out, size_t out_size, long value, unsigned divisor) {
  if (divisor <= 1) {
    snprintf(out, out_size, "%ld", value);
    return;
  }
  const unsigned long whole = (unsigned long)(value < 0 ? -value : value);
  const int digits = divisor >= 1000 ? 3 : divisor >= 100 ? 2 : 1;
  // Half-percent steps and the like: scale to the decimals shown.
  const unsigned long scale = digits == 3 ? 1000 : digits == 2 ? 100 : 10;
  const unsigned long frac = whole % divisor * scale / divisor;
  snprintf(out, out_size, "%s%lu.%0*lu", value < 0 ? "-" : "", whole / divisor, digits, frac);
}

// `battery_mv` below zero and `mcu_temp_tenths` of SENSOR_READOUT_NO_TEMP are left out.
// Returns the length written; `out` is always terminated when it has room for anything.
static inline size_t sensorReadoutFormat(char* out, size_t out_size, long battery_mv, int mcu_temp_tenths,
                                         const uint8_t* lpp, size_t lpp_len) {
  if (out == NULL || out_size < 2) return 0;
  size_t used = 0;
  out[used++] = '>';
  out[used] = 0;
  if (battery_mv >= 0) sensorReadoutAppend(out, out_size, &used, " batt=%ldmV", battery_mv);
  if (mcu_temp_tenths != SENSOR_READOUT_NO_TEMP) {
    char number[16];
    sensorReadoutNumber(number, sizeof(number), mcu_temp_tenths, 10);
    sensorReadoutAppend(out, out_size, &used, " mcu=%sC", number);
  }
  size_t at = 0;
  while (lpp != NULL && at + 2 <= lpp_len) {
    const uint8_t channel = lpp[at];
    const SensorReadoutType* t = sensorReadoutType(lpp[at + 1]);
    if (t == NULL || at + 2 + t->size > lpp_len) break;
    const uint8_t* v = &lpp[at + 2];
    at += 2 + (size_t)t->size;
    if (t->divisor == 0) continue;
    // LPP values are big-endian.
    unsigned long raw = 0;
    for (uint8_t i = 0; i < t->size; i++) raw = (raw << 8) | v[i];
    long value = (long)raw;
    if (t->is_signed && t->size == 2) value = (int16_t)raw;
    char number[16];
    sensorReadoutNumber(number, sizeof(number), value, t->divisor);
    bool fit;
    if (channel == SENSOR_READOUT_SELF_CHANNEL) {
      fit = sensorReadoutAppend(out, out_size, &used, " %s=%s%s", t->key, number, t->unit);
    } else {
      fit = sensorReadoutAppend(out, out_size, &used, " %s/%u=%s%s", t->key, (unsigned)channel, number, t->unit);
    }
    if (!fit) break;
  }
  if (used == 1) sensorReadoutAppend(out, out_size, &used, " (no sensors)");
  return used;
}
