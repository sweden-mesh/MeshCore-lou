// RX power saving as an addition (L21-H2): built in, and off, the radio is driven exactly as
// MeshCore 1.18 drives it, and 1.18's settings files load unchanged. The wrapper is the real
// RadioLibWrappers.cpp, built against a RadioLib that logs each call (RadioLib.h here).
#include <gtest/gtest.h>

#include <string>
#include <vector>

#define LORA_SF 8   // arduino_base's build flags
#include "RadioLib.h"
#include "helpers/radiolib/RadioLibWrappers.cpp"

struct File {
  int read(uint8_t*, size_t) { return 0; }
  size_t write(const uint8_t*, size_t) { return 0; }
  void close() { }
  explicit operator bool() const { return false; }
};
struct HostFS {
  bool mkdir(const char*) { return true; }
  bool exists(const char*) { return false; }
  File open(const char*, const char* = nullptr, bool = false) { return File(); }
  bool remove(const char*) { return true; }
};
#define FILESYSTEM HostFS
#include "helpers/CommonCLI.h"

// The rest of CommonRadioPrefs lives in CommonRadioPrefs.cpp, which needs a board.
bool CommonRadioPrefs::getByKey(const char*, char*, size_t) { return false; }
bool CommonRadioPrefs::setByKey(const char*, const char*) { return false; }

namespace {

class HostBoard : public mesh::MainBoard {
public:
  uint16_t getBattMilliVolts() override { return 4000; }
  const char* getManufacturerName() const override { return "host"; }
  void reboot() override { }
  uint8_t getStartupReason() const override { return BD_STARTUP_NORMAL; }
};

// A wrapper of the shape CustomSX1262Wrapper has; its duty cycle is logged, not armed.
class HostWrapper : public RadioLibWrapper {
public:
  bool receiving = false;
  bool can_duty_cycle = true;
  HostWrapper(PhysicalLayer& radio, mesh::MainBoard& board) : RadioLibWrapper(radio, board) { }
  void setParams(float, float, uint8_t sf, uint8_t) override { updatePreamble(sf); }
  bool isReceivingPacket() override { return receiving; }
  float getCurrentRSSI() override { _radio->note("currentRSSI"); return -110.0f; }
  void fireInterrupt() { setFlag(); }

  bool supportsRxPowerSaving() const override { return can_duty_cycle; }
  bool armed() const { return _rx_ps_armed; }
protected:
  int16_t armDutyCycle(RadioLibIrqFlags_t, RadioLibIrqFlags_t, uint32_t* rx, uint32_t* sleep) override {
    _radio->note("armDutyCycle", (long)*sleep);
    return RADIOLIB_ERR_NONE;
  }
  int16_t stopDutyCycleHardware() override { _radio->note("stopDutyCycle"); return _radio->standby(); }
};

// One node's day, as Dispatcher and MyMesh drive the radio: boot, listen, hear a packet,
// send one, a CAD before sending, an AGC reset, the noise floor, then power off.
void aDay(HostWrapper& w, PhysicalLayer& radio, bool apply_rx_power_saving) {
  uint8_t buf[256];
  w.begin();
  w.setParams(869.618f, 62.5f, 8, 8);
  if (apply_rx_power_saving) {
    RxPowerSavingConfig saved;  // what a 1.18 file loads to
    applyRxPowerSavingConfig(&saved, 8, 62.5f, &w);
  }
  w.setTxPower(22);
  w.recvRaw(buf, sizeof(buf));                      // starts listening
  for (int i = 0; i < 70; i++) w.loop();            // the noise floor, 64 samples
  w.recvRaw(buf, sizeof(buf));                      // nothing heard
  w.fireInterrupt();
  EXPECT_EQ(20, w.recvRaw(buf, sizeof(buf)));       // a packet
  w.getLastRSSI();
  w.getLastSNR();
  w.setCADEnabled(true);
  EXPECT_FALSE(w.isReceiving());
  w.setCADEnabled(false);
  EXPECT_TRUE(w.startSendRaw(buf, 40));
  w.fireInterrupt();
  EXPECT_TRUE(w.isSendComplete());
  w.onSendFinished();
  w.recvRaw(buf, sizeof(buf));
  w.resetAGC();
  w.recvRaw(buf, sizeof(buf));
  w.loop();
  w.getEstAirtimeFor(40);
  w.powerOff();
  (void)radio;
}

// What MeshCore 1.18's RadioLibWrappers.cpp does for aDay(), call by call. The same list was
// produced by the file as it stood before RX power saving (fork/core c776be60), built with
// this test.
std::vector<std::string> plainDay() {
  std::vector<std::string> want = {
    "setPacketReceivedAction", "setPreambleLength 32", "setPreambleLength 32",
    "setOutputPower 22", "startReceive",
  };
  for (int i = 0; i < 64; i++) want.push_back("currentRSSI");
  want.insert(want.end(), {
    "getPacketLength", "readData 20", "startReceive",
    "getRSSI", "getSNR",
    "scanChannel", "startReceive",
    "startTransmit 40", "finishTransmit", "startReceive",
    "sleep", "startReceive",
    "currentRSSI",
    "getTimeOnAir 40",
    "sleep",
  });
  return want;
}

}  // namespace

TEST(RxPowerSavingOff, TheRadioIsDrivenAsMeshCoreDrivesIt) {
  PhysicalLayer radio;
  HostBoard board;
  HostWrapper w(radio, board);
  g_mock_millis = 1000;
  aDay(w, radio, true);
  EXPECT_EQ(plainDay(), radio.log);
  EXPECT_FALSE(w.armed());
  EXPECT_FALSE(w.isRxPowerSavingCalibrationActive());
}

TEST(RxPowerSavingOff, ARadioThatCannotDutyCycleIsDrivenTheSame) {
  PhysicalLayer radio;
  HostBoard board;
  HostWrapper w(radio, board);
  w.can_duty_cycle = false;
  aDay(w, radio, true);
  EXPECT_EQ(plainDay(), radio.log);
}

TEST(RxPowerSavingOff, AHoldWithItOffChangesNothing) {
  PhysicalLayer radio;
  HostBoard board;
  HostWrapper w(radio, board);
  uint8_t buf[256];
  w.begin();
  w.recvRaw(buf, sizeof(buf));
  radio.log.clear();
  w.holdContinuousRx(10000, 3200);   // what the report ladder asks after a report
  w.startSendRaw(buf, 40);
  w.fireInterrupt();
  w.isSendComplete();
  w.onSendFinished();
  w.recvRaw(buf, sizeof(buf));
  g_mock_millis += 4000;
  w.loop();
  std::vector<std::string> want = { "startTransmit 40", "finishTransmit", "startReceive", "currentRSSI" };
  EXPECT_EQ(want, radio.log);
}

// Switched on, the same calls carry the duty cycle; switched off again, the receiver leaves
// it once and is MeshCore's again.
TEST(RxPowerSavingOn, ArmsListensAfterAReportAndComesBackOff) {
  PhysicalLayer radio;
  HostBoard board;
  HostWrapper w(radio, board);
  uint8_t buf[256];
  g_mock_millis = 1000;
  w.begin();
  w.setParams(869.618f, 62.5f, 8, 8);
  w.recvRaw(buf, sizeof(buf));
  radio.log.clear();

  RxPowerSavingConfig config;
  config.enabled = 1;
  ASSERT_TRUE(applyRxPowerSavingConfig(&config, 8, 62.5f, &w));
  w.loop();
  w.recvRaw(buf, sizeof(buf));
  EXPECT_TRUE(w.armed());
  EXPECT_EQ(std::string("armDutyCycle ") + std::to_string(config.sleep_us), radio.log.back());

  // A report: the duty cycle stops for the transmission, and the receiver stays awake until
  // 3.2 s after it ends.
  w.holdContinuousRx(10000, 3200);
  w.loop();
  w.recvRaw(buf, sizeof(buf));
  EXPECT_FALSE(w.armed());
  w.startSendRaw(buf, 40);
  g_mock_millis += 500;
  w.fireInterrupt();
  w.isSendComplete();
  w.onSendFinished();
  w.recvRaw(buf, sizeof(buf));
  EXPECT_FALSE(w.armed());
  g_mock_millis += 3100;
  w.loop();
  w.recvRaw(buf, sizeof(buf));
  EXPECT_FALSE(w.armed());          // 3.1 s after the report: still awake
  g_mock_millis += 200;
  w.loop();
  w.recvRaw(buf, sizeof(buf));
  EXPECT_TRUE(w.armed());           // 3.3 s: back to the duty cycle

  radio.log.clear();
  config.enabled = 0;
  ASSERT_TRUE(applyRxPowerSavingConfig(&config, 8, 62.5f, &w));
  w.loop();
  w.recvRaw(buf, sizeof(buf));
  EXPECT_FALSE(w.armed());
  std::vector<std::string> want = { "stopDutyCycle", "standby", "startReceive" };
  EXPECT_EQ(want, radio.log);
  radio.log.clear();
  w.fireInterrupt();
  w.recvRaw(buf, sizeof(buf));
  w.getLastRSSI();
  want = { "getPacketLength", "readData 20", "startReceive", "getRSSI" };
  EXPECT_EQ(want, radio.log);
}

TEST(RxPowerSavingOn, AHoldEndsAfterItsLimitWhenNothingIsSent) {
  PhysicalLayer radio;
  HostBoard board;
  HostWrapper w(radio, board);
  uint8_t buf[256];
  g_mock_millis = 1000;
  w.begin();
  RxPowerSavingConfig config;
  config.enabled = 1;
  ASSERT_TRUE(applyRxPowerSavingConfig(&config, 8, 62.5f, &w));
  w.recvRaw(buf, sizeof(buf));
  ASSERT_TRUE(w.armed());
  w.holdContinuousRx(10000, 3200);
  w.loop();
  w.recvRaw(buf, sizeof(buf));
  EXPECT_FALSE(w.armed());
  g_mock_millis += 9900;
  w.loop();
  w.recvRaw(buf, sizeof(buf));
  EXPECT_FALSE(w.armed());
  g_mock_millis += 200;
  w.loop();
  w.recvRaw(buf, sizeof(buf));
  EXPECT_TRUE(w.armed());
}

// ---- the settings file ---------------------------------------------------------------------

namespace {

class Replay : public Stream {
  std::string _text;
  size_t _pos = 0;
public:
  explicit Replay(const std::string& text) : _text(text) { }
  int available() override { return (int)(_text.size() - _pos); }
  int read() override { return _pos < _text.size() ? _text[_pos++] : -1; }
  int peek() override { return _pos < _text.size() ? _text[_pos] : -1; }
};

class Capture : public Stream {
  std::string _text;
  size_t emit(long long v) { std::string s = std::to_string(v); _text += s; return s.size(); }
public:
  size_t write(uint8_t b) override { _text.push_back((char)b); return 1; }
  size_t write(const uint8_t* b, size_t n) override { _text.append((const char*)b, n); return n; }
  size_t print(unsigned char v, int = DEC) override { return emit(v); }
  size_t print(int v, int = DEC) override { return emit(v); }
  size_t print(unsigned int v, int = DEC) override { return emit(v); }
  size_t print(long v, int = DEC) override { return emit(v); }
  size_t print(unsigned long v, int = DEC) override { return emit(v); }
  size_t print(long long v, int = DEC) override { return emit(v); }
  size_t print(unsigned long long v, int = DEC) override { return emit(v); }
  size_t print(double v, int digits = 2) override {
    char text[32];
    int n = snprintf(text, sizeof(text), "%.*f", digits, v);
    _text.append(text, n);
    return n;
  }
  const std::string& text() const { return _text; }
};

// A MeshCore 1.18 repeater's /prefs.json, as that firmware writes it (its NodePrefs, saved).
#include "stock_118_prefs.h"

}  // namespace

TEST(RxPowerSavingPrefs, AStockFileLoadsWithItOff) {
  NodePrefs prefs;
  Replay in(STOCK_118);
  ASSERT_TRUE(prefs.loadSerial(in));
  EXPECT_EQ(8, prefs.sf);
  EXPECT_EQ(1, prefs.rx_boosted_gain);
  EXPECT_EQ(1, prefs.radio_fem_rxgain);
  EXPECT_STREQ("Test node", prefs.node_name);
  EXPECT_EQ(0, prefs.rxps.enabled);
  EXPECT_EQ(RX_POWERSAVING_BALANCED_LEVEL, prefs.rxps.level);
  EXPECT_EQ(RX_POWERSAVING_DEFAULT_RX_US, prefs.rxps.rx_us);
}

TEST(RxPowerSavingPrefs, PowerSaving18sKeysLoad) {
  NodePrefs prefs;
  Replay in("{radio:{sf:8,rxps_en:1,rxps_rx_us:51200,rxps_sleep_us:89300,rxps_level:9,rxps_preamble:32}}");
  ASSERT_TRUE(prefs.loadSerial(in));
  EXPECT_EQ(1, prefs.rxps.enabled);
  EXPECT_EQ(51200U, prefs.rxps.rx_us);
  EXPECT_EQ(89300U, prefs.rxps.sleep_us);
  EXPECT_EQ(9, prefs.rxps.level);
  EXPECT_EQ(32, prefs.rxps.preamble);
}

// What this image writes is 1.18's file plus five keys in the radio object, and a stock
// reader skips keys it does not know: the rest of what it reads back is the same.
TEST(RxPowerSavingPrefs, OurFileIsAStockFilePlusFiveRadioKeys) {
  NodePrefs prefs;
  Replay in(STOCK_118);
  ASSERT_TRUE(prefs.loadSerial(in));
  Capture out;
  ASSERT_TRUE(prefs.saveSerial(out));
  std::string without = out.text();
  for (const char* k : { ",rxps_en:0", ",rxps_rx_us:65625", ",rxps_sleep_us:60000", ",rxps_level:6",
                         ",rxps_preamble:16" }) {
    size_t at = without.find(k);
    ASSERT_NE(std::string::npos, at) << k;
    without.erase(at, strlen(k));
  }
  EXPECT_EQ(STOCK_118, without);

  NodePrefs again;
  Replay back(out.text());
  ASSERT_TRUE(again.loadSerial(back));
  EXPECT_EQ(prefs.sf, again.sf);
  EXPECT_EQ(prefs.tx_power_dbm, again.tx_power_dbm);
  EXPECT_EQ(0, again.rxps.enabled);
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
