#pragma once

// /prefs.json as MeshCore 1.18 writes it: its own NodePrefs (src/helpers/CommonCLI.h at
// 81dbae59) filled with a repeater's settings and saved through the Capture stream of this
// suite. One line, as the firmware writes it.
static const char* const STOCK_118 =
  "{name:\"Test node\",pass:\"\",guest:\"\",owner:\"\",adv_int:1,f_adv_int:12,lat:57.780000,lon:14.160000,radio:{freq:869.6180,bw:62.5000,sf:8,cr:8,cad:0,int_thr:0,rxgain:1,fem_rxgain:1,fem_txgain:0,tx:22,af:1.0000,rxdelay:0,f_txdelay:0.5000,d_txdelay:0.3000,agc_int:0,hash_mode:0,multi_ack:0},bridge:{en:0,delay:0,src:0,baud:0,ch:0,secret:\"\"},gps:{en:0,int:0,adv_loc:0},repeat:{disable:0,f_max:0,f_max_uns:0,f_max_adv:0,loop:0},room:{rd_only:0},power:{adc_mult:0,pwr_sav_en:0},custom:{}}";
