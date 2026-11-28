#pragma once

#include <Mesh.h>
#include <RadioLib.h>
#include "RXPowerSaving.h"

#ifdef USE_CC310_HW_CRYPTO
#include <Adafruit_nRFCrypto.h>
#endif
struct PacketMillis {
  uint32_t preambleMillis;  // preamble-detect -> header-valid deadline
  uint32_t payloadMillis;   // header-valid   -> rx-done deadline
};

#ifdef RX_POWERSAVING
class RadioLibWrapper : public mesh::Radio, public RxPowerSavingControl {
#else
class RadioLibWrapper : public mesh::Radio {
#endif
protected:
  PhysicalLayer* _radio;
  mesh::MainBoard* _board;
  uint32_t n_recv, n_sent, n_recv_errors;
  int16_t _noise_floor, _threshold;
  bool _cad_enabled;
  uint16_t _num_floor_samples;
  int32_t _floor_sample_sum;
  uint8_t _preamble_sf;

  void idle();
  void startRecv();
  float packetScoreInt(float snr, int sf, int packet_len);
  virtual bool isReceivingPacket() =0;
  virtual void doResetAGC();

#ifdef RX_POWERSAVING
  // RX power saving (RXPowerSaving.h). Every path that differs from MeshCore's own is taken
  // only while rxPsInUse(): from `set radio.rxps` or a saved setting until the receiver has
  // left its last duty cycle.
  bool _rx_ps_restart_pending = false;
  bool _rx_ps_config_error = false;
  bool _rx_ps_enabled = false;
  bool _rx_ps_armed = false;
  uint32_t _rx_ps_rx_us = RX_POWERSAVING_DEFAULT_RX_US;
  uint32_t _rx_ps_sleep_us = RX_POWERSAVING_DEFAULT_SLEEP_US;
  uint32_t _rx_ps_eff_rx_us = 0;      // periods the driver actually armed with
  uint32_t _rx_ps_eff_sleep_us = 0;
  int16_t _rx_ps_last_error = RADIOLIB_ERR_NONE;
  uint32_t n_rx_ps_arm_failures = 0;
  RxPowerSavingArmRetryState _rx_ps_arm_retry;
  bool _rx_ps_held = false;             // continuous RX until _rx_ps_hold_until (holdContinuousRx)
  unsigned long _rx_ps_hold_until = 0;
  uint16_t _rx_ps_hold_after_tx = 0;
  float _last_rssi = 0, _last_snr = 0;
  bool _last_metrics_valid = false;

  bool _nf_calib_active = false;
  unsigned long _nf_last_calib = 0;
  unsigned long _nf_calib_deadline = 0;
  unsigned long _nf_sample_from = 0;

  bool rxPsInUse() const { return _rx_ps_enabled || _rx_ps_armed; }
  void requestRestartRecv();
  bool isPacketPendingOrReceiving();
  void prepareForRadioConfig();
  void sampleNoiseFloorOnce();
  bool publishNoiseFloor();
  void noiseFloorCalibCheck();
  void endNoiseFloorCalib(unsigned long now);
  bool isRxHeld() const;
  int16_t startReceiveMode();
  void stopReceiveDutyCycle();
  void resetAGCWithRxPowerSaving();
  // eff_rx_us/eff_sleep_us report the periods the driver really programmed,
  // which may be clamped to satisfy a hardware constraint.
  virtual int16_t armDutyCycle(RadioLibIrqFlags_t irq_flags, RadioLibIrqFlags_t irq_mask,
                               uint32_t* eff_rx_us, uint32_t* eff_sleep_us) {
    return RADIOLIB_ERR_UNSUPPORTED;
  }
  virtual int16_t stopDutyCycleHardware() { return _radio->standby(); }
  virtual int16_t startContinuousReceive() { return _radio->startReceive(); }
  virtual bool isPacketReady();
  virtual bool isChipBusy() { return false; }
#endif

public:
  RadioLibWrapper(PhysicalLayer& radio, mesh::MainBoard& board) : _radio(&radio), _board(&board), _preamble_sf(0) { n_recv = n_sent = 0; }

  void begin() override;
#ifdef RX_POWERSAVING
  virtual void powerOff();

  virtual bool supportsRxPowerSaving() const { return false; }
  void setRxPowerSavingConfigError(bool invalid) override { _rx_ps_config_error = invalid; }
  bool setRxPowerSaving(bool enabled, uint32_t rx_us, uint32_t sleep_us) override;
  RxPowerSavingStatus getRxPowerSavingStatus() const override;
  bool isRxPowerSavingCalibrationActive() const override { return _nf_calib_active; }
  // Listen continuously until 'after_tx_ms' past the end of a transmission, the window an
  // answer to it is expected in; for at most 'ms' if no transmission ends. A no-op while
  // RX power saving is off.
  void holdContinuousRx(uint16_t ms, uint16_t after_tx_ms);
#else
  virtual void powerOff() { _radio->sleep(); }
#endif
  int recvRaw(uint8_t* bytes, int sz) override;
  uint32_t getEstAirtimeFor(int len_bytes) override;
  bool startSendRaw(const uint8_t* bytes, int len) override;
  bool isSendComplete() override;
  void onSendFinished() override;
  bool isInRecvMode() const override;
  bool isChannelActive();

  bool isReceiving() override {
    if (isReceivingPacket()) return true;

    return isChannelActive();
  }

  virtual void setParams(float freq, float bw, uint8_t sf, uint8_t cr) = 0;
  uint32_t getRngSeed();
  void setTxPower(int8_t dbm);

  virtual float getCurrentRSSI() =0;
  virtual uint8_t getSpreadingFactor() const { return LORA_SF; }
  static uint16_t preambleLengthForSF(uint8_t sf) { return sf <= 8 ? 32 : 16; }
  void updatePreamble(uint8_t sf) { _preamble_sf = sf; _radio->setPreambleLength(preambleLengthForSF(sf)); }
  PacketMillis calcMaxPacketMillis(uint8_t sf, float bw, uint8_t cr, uint8_t preambleSymbols);
  virtual int16_t performChannelScan();

  int getNoiseFloor() const override { return _noise_floor; }
  void triggerNoiseFloorCalibrate(int threshold) override;
  void setCADEnabled(bool enable) override { _cad_enabled = enable; }
  void resetAGC() override;

  void loop() override;

  uint32_t getPacketsRecv() const { return n_recv; }
  uint32_t getPacketsRecvErrors() const { return n_recv_errors; }
  uint32_t getPacketsSent() const { return n_sent; }
#ifdef RX_POWERSAVING
  void resetStats() {
    n_recv = n_sent = n_recv_errors = n_rx_ps_arm_failures = 0;
    // Clearing diagnostics also grants a fresh set of arm attempts. If they
    // fail again, the normal three-failure continuous-RX fallback applies.
    _rx_ps_arm_retry.reset();
  }
#else
  void resetStats() { n_recv = n_sent = n_recv_errors = 0; }
#endif

  virtual float getLastRSSI() const override;
  virtual float getLastSNR() const override;

  float packetScore(float snr, int packet_len) override { return packetScoreInt(snr, 10, packet_len); }  // assume sf=10

  virtual bool setRxBoostedGainMode(bool) { return false; }
  virtual bool getRxBoostedGainMode() const { return false; }
  
  virtual bool configSideDetectors(const uint8_t sideDetSFs[], uint8_t num, float bw) { return false; }
};

/**
 * \brief  an RNG impl using the noise from the LoRa radio as entropy.
 *         NOTE: this is VERY SLOW!  Use only for things like creating new LocalIdentity
*/
class RadioNoiseListener : public mesh::RNG {
  PhysicalLayer* _radio;
public:
  RadioNoiseListener(PhysicalLayer& radio): _radio(&radio) { }

  void random(uint8_t* dest, size_t sz) override {
#ifdef USE_CC310_HW_CRYPTO
    nRFCrypto.Random.generate(dest, (uint16_t)sz);
    for (int i = 0; i < sz; i++) {
      dest[i] ^= _radio->randomByte() ^ (::random(0, 256) & 0xFF); // combine with Radio's entropy
    }
#else
    for (int i = 0; i < sz; i++) {
      dest[i] = _radio->randomByte() ^ (::random(0, 256) & 0xFF);
    }
#endif
  }
};
