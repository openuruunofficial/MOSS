/*
  MOSS - A server for the Myst Online: Uru Live client/protocol
  Copyright (C) 2008,2011  a'moaca'

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

#ifndef _CONSTANTS_H_
#define _CONSTANTS_H_

// MOSS server UUID = 8ac671cb-9fd0-4376-9ecb-310c211ae6a4
#define MOSS_UUID "\xcb\x71\xc6\x8a\xd0\x9f\x76\x43\x9e\xcb\x31\x0c\x21\x1a\xe6\xa4"

#define TYPE_GATEKEEPER 0x16
#define TYPE_FILE 0x10
#define TYPE_AUTH 0x0a
#define TYPE_GAME 0x0b
#define TYPE_NONCE 0x00
#define TYPE_NONCE_RESPONSE 0x01

#define KEEPALIVE_INTERVAL 30
#define BACKEND_KEEPALIVE_INTERVAL 1200
#define GAME_STARTUP_TIMEOUT 30

#define FILE_CHUNKSIZE 32768
#define AUTH_CHUNKSIZE 32768

// The threshold is between 254 and 272; I'm guessing it's the somewhat
// arbitrary programmer-round 256 (vs. normal-people round which is 250 or
// 300 or something). For non-SDL messages I see a 257 that's compressed so
// that's a good guess.
#define COMPRESS_THRESHOLD 256

// max number of connections completing TCP handshake/waiting for first data
// and the amount of time they have to send data
#define ACCEPTING_FDS 40 /* XXX completely made up number */
#define ACCEPTING_TIMEOUT 30 /* XXX also made up */

#define MOUL_BUFSIZE 16384
#define BUFSIZE 65536
#define MAX_IOVEC_COUNT ((FILE_CHUNKSIZE / 152) + 7)

// maximum amount of time a given client can hold an object lock (game server)
#define MAX_LOCK_TIME 5 /* XXX made up */

#endif /* _CONSTANTS_H_ */
