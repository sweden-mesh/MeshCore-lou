#pragma once
// Text helpers every feature of the fork shares, so none has to include another's
// header to read its own settings. Pure, and host-tested in test_fork_seams.
#include <ctype.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>

// Exactly 'n' characters, every one alphanumeric: a region code (n = 3). NULL is not one.
static inline bool forkAlnumOfLength(const char* s, size_t n) {
  if (s == NULL || strlen(s) != n) return false;
  for (size_t i = 0; i < n; i++) {
    if (!isalnum((unsigned char)s[i])) return false;
  }
  return true;
}

// Exactly 'n' hex digits: a public key written out (n = 64). NULL is not one.
static inline bool forkHexOfLength(const char* s, size_t n) {
  if (s == NULL || strlen(s) != n) return false;
  for (size_t i = 0; i < n; i++) {
    if (!isxdigit((unsigned char)s[i])) return false;
  }
  return true;
}

// Read an 'on' or 'off' argument, the form every boolean setting of the fork takes.
// The token ends at the first space or line ending, so a value typed with trailing
// whitespace still reads, while a word that merely starts with 'on' does not. 'out'
// is left alone unless a whole valid token was found.
static inline bool forkParseOnOff(const char* arg, bool* out) {
  if (arg == NULL || out == NULL) return false;

  while (*arg == ' ') arg++;
  size_t len = 0;
  while (arg[len] && arg[len] != ' ' && arg[len] != '\r' && arg[len] != '\n') len++;

  if (len == 2 && strncasecmp(arg, "on", 2) == 0) {
    *out = true;
    return true;
  }
  if (len == 3 && strncasecmp(arg, "off", 3) == 0) {
    *out = false;
    return true;
  }
  return false;
}

// Does the command open the board to whoever is in Wi-Fi or BLE range, with no password of
// its own? Manual OTA does -- the MeshCore-OTA access point, the station web uploader, the
// nRF52's BLE DFU -- and so does the web portal's setup access point, which asks for nothing
// because it assumes the person who raised it is standing at the board. Only a local caller
// starts them. Matched as upstream's CLI matches `start ota`, by the bare prefix. `start
// webconfig` alone raises the setup access point only while the node has no network to join
// ('network_up' false); with one it binds the LAN portal, which takes the admin password.
// 'ble_dfu': the board's `start ota` is the nRF52's BLE DFU, which a remote admin starts as
// on stock MeshCore (operator 2026-11-17): a mast-top nRF52 has no other way to be updated.
static inline bool forkOpensBoardToRange(const char* command, bool network_up, bool ble_dfu) {
  if (command == NULL) return false;
  if (strncmp(command, "start ota", 9) == 0) return !ble_dfu;
  if (strncmp(command, "start webconfig", 15) != 0) return false;
  return command[15] != 0 || !network_up;
}

// The serial console's line editor, one received byte at a time. A terminal sends what its
// keys make: 0x08 or 0x7F for the key that erases, ESC [ ... for the arrow keys. Stored as
// they came, those bytes stayed in the command out of sight -- the terminal had already
// drawn their effect -- so `set cmd on` typed with one correction read as an unknown
// config, and a line after an arrow key as an unknown command (bench, LOUTEST 2026-11-16).
// Erasing takes back the last character, a UTF-8 one whole; an escape sequence and every
// other control byte but the line's own '\r' is dropped. `esc` is the caller's, zero to
// start, and carries a sequence across reads. The return says what to echo.
enum ForkConsoleKey { FORK_KEY_KEEP, FORK_KEY_ERASE, FORK_KEY_DROP };

static inline ForkConsoleKey forkConsoleKey(char* line, size_t* len, unsigned char* esc, char c) {
  const unsigned char b = (unsigned char)c;
  if (*esc == 1) {                                   // after ESC: CSI or SS3 opens, else done
    *esc = (b == '[' || b == 'O') ? 2 : 0;
    return FORK_KEY_DROP;
  }
  if (*esc == 2) {                                   // inside a sequence, up to its final byte
    if (b >= 0x40 && b <= 0x7E) *esc = 0;
    return FORK_KEY_DROP;
  }
  if (b == 0x1B) { *esc = 1; return FORK_KEY_DROP; }
  if (b == 0x08 || b == 0x7F) {
    if (*len == 0) return FORK_KEY_DROP;
    do { (*len)--; } while (*len > 0 && ((unsigned char)line[*len] & 0xC0) == 0x80);
    line[*len] = 0;
    return FORK_KEY_ERASE;
  }
  if (b < 0x20 && b != '\r') return FORK_KEY_DROP;
  line[(*len)++] = c;
  line[*len] = 0;
  return FORK_KEY_KEEP;
}
