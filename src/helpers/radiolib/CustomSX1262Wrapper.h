#pragma once

#include "CustomSX1262.h"
#include "RadioLibWrappers.h"
#include "SX126xReset.h"
#ifdef RX_POWERSAVING
#include "SX1262RxPowerSaving.h"
#endif

#ifndef USE_SX1262
#define USE_SX1262
#endif

class CustomSX1262Wrapper : public RadioLibWrapper {
public:
  CustomSX1262Wrapper(CustomSX1262& radio, mesh::MainBoard& board) : RadioLibWrapper(radio, board) { }

  void setParams(float freq, float bw, uint8_t sf, uint8_t cr) override {
#ifdef RX_POWERSAVING
    prepareForRadioConfig();
#endif
    ((CustomSX1262 *)_radio)->setFrequency(freq);
    ((CustomSX1262 *)_radio)->setSpreadingFactor(sf);
    ((CustomSX1262 *)_radio)->setBandwidth(bw);
    ((CustomSX1262 *)_radio)->setCodingRate(cr);
    updatePreamble(sf);
    PacketMillis pm = calcMaxPacketMillis(sf, bw, cr, preambleLengthForSF(sf));
    ((CustomSX1262 *)_radio)->setPreambleMillis(pm.preambleMillis);
    ((CustomSX1262 *)_radio)->setMaxPayloadMillis(pm.payloadMillis);
  }

  bool isReceivingPacket() override { 
#ifdef RX_POWERSAVING
    // While duty-cycling, BUSY marks the sleep phase: probing IRQ flags over
    // SPI there could wake the chip and break the cycle. Only skip the probe
    // in that case - outside RXPS this must stay a real channel check, since
    // Dispatcher::checkSend() relies on it to avoid transmitting over others.
    if (_rx_ps_armed && ((CustomSX1262 *)_radio)->isChipBusy()) return false;
#endif
    return ((CustomSX1262 *)_radio)->isReceiving();
  }
  float getCurrentRSSI() override {
    return ((CustomSX1262 *)_radio)->getRSSI(false);
  }
#ifdef RX_POWERSAVING
  float getLastRSSI() const override {
    return rxPsInUse() ? RadioLibWrapper::getLastRSSI() : ((CustomSX1262 *)_radio)->getRSSI();
  }
  float getLastSNR() const override {
    return rxPsInUse() ? RadioLibWrapper::getLastSNR() : ((CustomSX1262 *)_radio)->getSNR();
  }
#else
  float getLastRSSI() const override { return ((CustomSX1262 *)_radio)->getRSSI(); }
  float getLastSNR() const override { return ((CustomSX1262 *)_radio)->getSNR(); }
#endif

  float packetScore(float snr, int packet_len) override {
    int sf = ((CustomSX1262 *)_radio)->spreadingFactor;
    return packetScoreInt(snr, sf, packet_len);
  }
  uint8_t getSpreadingFactor() const override { return ((CustomSX1262 *)_radio)->spreadingFactor; }
  virtual void powerOff() override {
#ifdef RX_POWERSAVING
    if (_rx_ps_armed) stopReceiveDutyCycle();
#endif
    ((CustomSX1262 *)_radio)->sleep(false);
  }

#ifdef RX_POWERSAVING
  bool supportsRxPowerSaving() const override { return true; }

  // Ask the radio rather than assume RadioLib's 5000 us default: startReceive-
  // DutyCycle subtracts tcxoDelay + 1000 from the sleep and the register
  // underflows below that, so the floor is a property of this board's TCXO.
  uint32_t rxPowerSavingTransitionUs() const override {
    return ((CustomSX1262 *)_radio)->getTcxoDelay() + 1000;
  }

protected:
  int16_t armDutyCycle(RadioLibIrqFlags_t irq_flags, RadioLibIrqFlags_t irq_mask,
                       uint32_t* eff_rx_us, uint32_t* eff_sleep_us) override {
    auto* radio = static_cast<CustomSX1262*>(_radio);
    const uint32_t transition_us = rxPowerSavingTransitionUs();
    // Less than one 15.625 us tick of programmed sleep.
    if (_rx_ps_sleep_us < transition_us + 16) return RADIOLIB_ERR_INVALID_SLEEP_PERIOD;
    if (!adjustSX1262RxPowerSavingPeriod(_rx_ps_rx_us, _rx_ps_sleep_us,
          radio->spreadingFactor, radio->bandwidthKhz, transition_us, eff_rx_us)) {
      return RADIOLIB_ERR_INVALID_RX_PERIOD;
    }
    *eff_sleep_us = _rx_ps_sleep_us;
    return radio->startReceiveDutyCycle(*eff_rx_us, *eff_sleep_us, irq_flags, irq_mask);
  }

  int16_t stopDutyCycleHardware() override {
    int16_t standby_err = _radio->standby();
    int16_t rtc_err = ((CustomSX1262 *)_radio)->stopRTC();
    return standby_err != RADIOLIB_ERR_NONE ? standby_err : rtc_err;
  }

  bool isChipBusy() override {
    return ((CustomSX1262 *)_radio)->isChipBusy();
  }

public:
#endif
  bool setRxBoostedGainMode(bool en) override {
#ifdef RX_POWERSAVING
    prepareForRadioConfig();
#endif
    return ((CustomSX1262 *)_radio)->setRxBoostedGainMode(en) == RADIOLIB_ERR_NONE;
  }
  bool getRxBoostedGainMode() const override {
    return ((CustomSX1262 *)_radio)->getRxBoostedGainMode();
  }

  void doResetAGC() override { sx126xResetAGC((SX126x *)_radio, getRxBoostedGainMode()); }
};
