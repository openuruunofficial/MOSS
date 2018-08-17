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

#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <netinet/in.h>
#include "sha.h"

/*
 * SHA-1 test values from FIPS180-1: http://www.umich.edu/~x509/ssleay/fip180/fip180-1.htm
 * SHA test values: https://groups.google.com/forum/#!searchin/sci.crypt/shs.c%7Csort:date/sci.crypt/vEHXXK6hrB4/fMM2z578SDMJ
 */

int main(int argc, char *argv[]) {
  unsigned char hash[20];
  uint32_t *hashvals = (uint32_t *)hash;
  sha0_hash("abc", 3, hash);
  assert(hashvals[0] == htonl(0x0164B8A9));
  assert(hashvals[1] == htonl(0x14CD2A5E));
  assert(hashvals[2] == htonl(0x74C4F7FF));
  assert(hashvals[3] == htonl(0x082C4D97));
  assert(hashvals[4] == htonl(0xF1EDF880));
  sha1_hash("abc", 3, hash);
  assert(hashvals[0] == htonl(0xA9993E36));
  assert(hashvals[1] == htonl(0x4706816A));
  assert(hashvals[2] == htonl(0xBA3E2571));
  assert(hashvals[3] == htonl(0x7850C26C));
  assert(hashvals[4] == htonl(0x9CD0D89D));
  sha1_hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	    56, hash);
  assert(hashvals[0] == htonl(0x84983E44));
  assert(hashvals[1] == htonl(0x1C3BD26E));
  assert(hashvals[2] == htonl(0xBAAE4AA1));
  assert(hashvals[3] == htonl(0xF95129E5));
  assert(hashvals[4] == htonl(0xE54670F1));
  unsigned char big[1000000];
  memset(big, 'a', 1000000);
  sha1_hash(big, 1000000, hash);
  assert(hashvals[0] == htonl(0x34AA973C));
  assert(hashvals[1] == htonl(0xD4C4DAA4));
  assert(hashvals[2] == htonl(0xF61EEB2B));
  assert(hashvals[3] == htonl(0xDBAD2731));
  assert(hashvals[4] == htonl(0x6534016F));
  return 0;
}
