#pragma once

// Just enough Arduino for rweather/Crypto's RNG.cpp to compile in env:native_v2, which
// builds the whole library to reach ChaChaPoly, HKDF and SHA256. Nothing here is called.
#include <stdint.h>
#include <stddef.h>
#include <string.h>

static inline unsigned long millis() { return 0; }
static inline unsigned long micros() { return 0; }
