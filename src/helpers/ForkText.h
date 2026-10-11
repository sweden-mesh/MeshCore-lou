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
