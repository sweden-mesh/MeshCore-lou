#!/bin/bash
# What a pull request compiles (TODO 22 analysis ticket 24): the combinations this branch's
# base releases on one ESP32 board and one nRF52 board, as GitHub Actions matrix rows. An
# Observer board has one image from lou-21, the full one (arrc).
# The Observer has no nRF52 Observer env, so there the nRF52 builds are upstream's plain
# repeater, with auto-reply and with both features, remote command then mesh only.
#
#   scripts/ci-pr-plan.sh      -> [{"env":"Heltec_v3_repeater_observer_mqtt","combo":"arrc"}, ...]
set -euo pipefail
cd "$(dirname "$0")/.."
if [ -f src/helpers/bridges/MQTTBridge.h ]; then
  rows="Heltec_v3_repeater_observer_mqtt arrc
RAK_4631_repeater ar
RAK_4631_repeater arrc"
else
  rows="Heltec_v3_repeater ar
RAK_4631_repeater ar
RAK_4631_repeater arrc"
fi
echo "$rows" | python3 -c '
import json, sys
print(json.dumps([dict(zip(("env", "combo"), l.split())) for l in sys.stdin if l.strip()],
                 separators=(",", ":")))'
