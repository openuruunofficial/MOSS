/*
  MOSS - A server for the Myst Online: Uru Live client/protocol
  Copyright (C) 2018  a'moaca'

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include "sha.h"

uint32_t f(int t, uint32_t B, uint32_t C, uint32_t D) {
  if (0 <= t && t <= 19) {
    return (B & C) | (~B & D);
  }
  if (40 <= t && t <= 59) {
    return (B & C) | (B & D) | (C & D);
  }
  return B ^ C ^ D;
}

uint32_t K(int t) {
  if (0 <= t && t <= 19) {
    return 0x5A827999;
  }
  if (20 <= t && t <= 39) {
    return 0x6ED9EBA1;
  }
  if (40 <= t && t <= 59) {
    return 0x8F1BBCDC;
  }
  return 0xCA62C1D6;
}

#define S(n, X) ((X << n) | (X >> (32 - n)))

#define process()							\
  for (t = 16; t < 80; t++) {						\
    W[t] = W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16];				\
    if (is1) W[t] = S(1, W[t]);						\
  }									\
  A = H[0]; B = H[1]; C = H[2]; D = H[3]; E = H[4];			\
  for (t = 0; t < 80; t++) {						\
    TEMP = S(5, A) + f(t, B, C, D) + E + W[t] + K(t);			\
    E = D; D = C; C = S(30, B); B = A; A = TEMP;			\
  }									\
  H[0] += A; H[1] += B; H[2] += C; H[3] += D; H[4] += E;

/* returns true if the padding is not completed (and we need another block) */
int pad(unsigned char *message, uint64_t len) {
  int i = len % 64;
  if (i == 0) {
    return 1;
  }
  message[i++] = 0x80;
  if (i <= 56) {
    uint64_t bits = len * 8;
    memset(message + i, 0, 56 - i);
    *(uint32_t*)(message + 56) = htonl(bits >> 32);
    *(uint32_t*)(message + 60) = htonl(bits & 0xffffffff);
    return 0;
  }
  memset(message + i, 0, 64 - i);
  return 1;
}

void extrapad(unsigned char *message, size_t len) {
  int i = 0;
  if (len % 64 == 0) {
    message[i++] = 0x80;
  }
  uint64_t bits = len * 8;
  memset(message + i, 0, 56 - i);
  *(uint32_t*)(message + 56) = htonl(bits >> 32);
  *(uint32_t*)(message + 60) = htonl(bits & 0xffffffff);
}

/*
 * We are doing math with these values so they need to be in native byte
 * order.
 */
void swap_words(uint32_t *buf, int howmany) {
#ifndef WORDS_BIGENDIAN
  int i;
  for (i = 0; i < howmany; i++) {
    buf[i] = htonl(buf[i]);
  }
#endif
}

static void sha_hash(const unsigned char *message, uint64_t len,
		     unsigned char *hash, int is1) {
  /* from the spec */
  uint32_t *H = (uint32_t *)hash;
  uint32_t A, B, C, D, E, TEMP;
  uint32_t W[80];
  /* some business logic */
  uint64_t consumed = 0, n;
  int extra_block = 0, t;

  H[0] = 0x67452301;
  H[1] = 0xEFCDAB89;
  H[2] = 0x98BADCFE;
  H[3] = 0x10325476;
  H[4] = 0xC3D2E1F0;

  while (consumed < len) {
    n = len - consumed;
    if (n > 64) {
      n = 64;
    }
    memcpy(W, message + consumed, n);
    consumed += n;
    if (n < 64) {
      extra_block = pad((unsigned char *)W, len);
    }
    else if (consumed == len) {
      /* len is a multiple of 64 */
      extra_block = 1;
    }
    swap_words(W, 16);
    process();
    if (extra_block) {
      extrapad((unsigned char *)W, len);
      swap_words(W, 16);
      process();
    }
  }
  swap_words(H, 5);
}

void sha0_hash(const unsigned char *message, uint64_t len,
	       unsigned char *hash) {
  sha_hash(message, len, hash, 0);
}

void sha1_hash(const unsigned char *message, uint64_t len,
	       unsigned char *hash) {
  sha_hash(message, len, hash, 1);
}
