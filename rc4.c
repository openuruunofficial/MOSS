/*
  MOSS - A server for the Myst Online: Uru Live client/protocol
  Copyright (C) 2008-2009  a'moaca'

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

#include "rc4.h"

void rc4_init_key(rc4_state_t *state, const unsigned char *key,
		  unsigned int keylen) {
  unsigned int i, k;
  unsigned char j, tmp;

  state->i = state->j = 0;
  for (i = 0; i < 256; i++) {
    state->S[i] = (unsigned char)i;
  }
  j = 0;
  k = 0;
  for (i = 0; i < 256; i++) {
    tmp = state->S[i];
    j = (j + tmp + key[k]);
    state->S[i] = state->S[j];
    state->S[j] = tmp;
    if (++k >= keylen) {
      k = 0;
    }
  }
}

void rc4_encrypt(rc4_state_t *state, unsigned char *buf, unsigned int buflen) {
  unsigned char tmp;
  unsigned int n;

  for (n = 0; n < buflen; n++) {
    state->i++;
    state->j = (state->j + state->S[state->i]);
    tmp = state->S[state->i];
    state->S[state->i] = state->S[state->j];
    state->S[state->j] = tmp;
    tmp += state->S[state->i];
    buf[n] ^= state->S[tmp];
  }
}
