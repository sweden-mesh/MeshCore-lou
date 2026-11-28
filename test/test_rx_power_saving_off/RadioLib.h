#pragma once

// Just enough RadioLib for src/helpers/radiolib/RadioLibWrappers.cpp to build on the host:
// a PhysicalLayer that writes every call the wrapper makes into a log, so a test can say
// exactly how the radio was driven. The values are RadioLib 7's.
#include <stdint.h>
#include <stddef.h>
#include <algorithm>
#include <string>
#include <vector>
#include <Arduino.h>

using std::max;
using std::min;

#define RADIOLIB_ERR_NONE                   0
#define RADIOLIB_ERR_UNSUPPORTED          (-31)
#define RADIOLIB_LORA_DETECTED           (-701)
#define RADIOLIB_CHANNEL_FREE            (-702)
#define RADIOLIB_ERR_INVALID_RX_PERIOD   (-707)
#define RADIOLIB_ERR_INVALID_SLEEP_PERIOD (-708)

typedef uint32_t RadioLibIrqFlags_t;
enum {
  RADIOLIB_IRQ_TX_DONE = 0, RADIOLIB_IRQ_RX_DONE, RADIOLIB_IRQ_PREAMBLE_DETECTED,
  RADIOLIB_IRQ_SYNC_WORD_VALID, RADIOLIB_IRQ_HEADER_VALID, RADIOLIB_IRQ_HEADER_ERR,
  RADIOLIB_IRQ_CRC_ERR, RADIOLIB_IRQ_CAD_DONE, RADIOLIB_IRQ_CAD_DETECTED, RADIOLIB_IRQ_TIMEOUT,
};
#define RADIOLIB_IRQ_RX_DEFAULT_FLAGS ((1UL << RADIOLIB_IRQ_RX_DONE) | (1UL << RADIOLIB_IRQ_TIMEOUT) | \
                                       (1UL << RADIOLIB_IRQ_CRC_ERR) | (1UL << RADIOLIB_IRQ_HEADER_VALID) | \
                                       (1UL << RADIOLIB_IRQ_HEADER_ERR))

// Arduino's, which the wrapper takes from the board's core.
inline void noInterrupts() { }
inline void interrupts() { }
inline long random(long lo, long hi) { return lo; }

class PhysicalLayer {
public:
  std::vector<std::string> log;
  void (*isr)(void) = nullptr;
  size_t packet_length = 20;
  uint32_t rx_done_irq = 1;

  void note(const char* what, long value) { log.push_back(std::string(what) + " " + std::to_string(value)); }
  void note(const char* what) { log.push_back(what); }

  void setPacketReceivedAction(void (*func)(void)) { isr = func; note("setPacketReceivedAction"); }
  virtual int16_t setPreambleLength(size_t len) { note("setPreambleLength", (long)len); return 0; }
  virtual int16_t setOutputPower(int8_t power) { note("setOutputPower", power); return 0; }
  virtual int32_t random(int32_t max) { note("random"); return 1; }
  uint8_t randomByte() { note("randomByte"); return 1; }
  virtual int16_t standby() { note("standby"); return 0; }
  virtual int16_t sleep() { note("sleep"); return 0; }
  virtual int16_t startReceive() { note("startReceive"); return 0; }
  virtual size_t getPacketLength(bool update = true) { note("getPacketLength"); return packet_length; }
  virtual int16_t readData(uint8_t* data, size_t len) { note("readData", (long)len); return 0; }
  virtual int16_t startTransmit(const uint8_t* data, size_t len, uint8_t addr = 0) { note("startTransmit", (long)len); return 0; }
  virtual int16_t finishTransmit() { note("finishTransmit"); return 0; }
  virtual int16_t scanChannel() { note("scanChannel"); return RADIOLIB_CHANNEL_FREE; }
  virtual float getRSSI() { note("getRSSI"); return -90.0f; }
  virtual float getSNR() { note("getSNR"); return 5.0f; }
  virtual uint32_t getTimeOnAir(size_t len) { note("getTimeOnAir", (long)len); return 500000; }
  uint32_t checkIrq(uint8_t irq) { note("checkIrq", irq); return rx_done_irq; }
};
