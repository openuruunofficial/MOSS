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

/*
 * Implementation of the RC4 algorithm, based on Wikipedia.
 * It is the obvious implementation, not optimized, because it is
 * a fallback and not worth more effort.
 */

#ifndef _RC4_H_
#define _RC4_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _rc4 {
  unsigned char S[256];
  unsigned char i;
  unsigned char j;
} rc4_state_t;

void rc4_init_key(rc4_state_t *state, const unsigned char *key,
		  unsigned int keylen);
void rc4_encrypt(rc4_state_t *state, unsigned char *buf, unsigned int buflen);

#ifdef __cplusplus
}
#endif

#endif /* _RC4_H_ */
