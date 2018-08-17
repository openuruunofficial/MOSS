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

/*
 * Implementation of SHA and SHA-1, based on FIPS180-1.
 * It is an obvious implementation, not optimized.
 * This is used only for password hashing.
 */

#ifndef _SHA_H
#define _SHA_H

//#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void sha0_hash(const unsigned char *message, uint64_t len,
	       unsigned char *hash);
void sha1_hash(const unsigned char *message, uint64_t len,
	       unsigned char *hash);

#ifdef __cplusplus
}
#endif

#endif /* _SHA_H */
