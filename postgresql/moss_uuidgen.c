/*
  MOSS - A server for the Myst Online: Uru Live client/protocol
  Copyright (C) 2008  a'moaca'

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

#include <string.h>

#include <pg_config.h>
#include <postgres.h>
#include <fmgr.h>

#include <openssl/rand.h>

#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif

#if PG_VERSION_NUM >= 80300
Datum moss_uuidgen(PG_FUNCTION_ARGS);
#endif
Datum moss_uuidgen_text(PG_FUNCTION_ARGS);

static unsigned char * random_uuid() {
  unsigned char * uuid = (unsigned char *)palloc(16);

  RAND_bytes(uuid, 16);
  /* since this is a random UUID I don't see any need to byte-swap to
     host order */
  uuid[8] &= 0x3f;
  uuid[8] |= 0x80;
  uuid[6] &= 0x0f;
  uuid[6] |= 0x40;

  return uuid;
}

#if PG_VERSION_NUM >= 80300
PG_FUNCTION_INFO_V1(moss_uuidgen);

Datum moss_uuidgen(PG_FUNCTION_ARGS) {
  unsigned char * uuid = random_uuid();
  PG_RETURN_POINTER(uuid);
}
#endif

PG_FUNCTION_INFO_V1(moss_uuidgen_text);

Datum moss_uuidgen_text(PG_FUNCTION_ARGS) {
  unsigned char * uuid = random_uuid();
  text * uuid_string = (text *)palloc(37 + VARHDRSZ);

#if PG_VERSION_NUM < 80300
  VARATT_SIZEP(uuid_string) = 37 + VARHDRSZ;
#else
  SET_VARSIZE(uuid_string, 37 + VARHDRSZ);
#endif
  snprintf(VARDATA(uuid_string), 37,
	"%08x-%04x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
	   *(unsigned int*)uuid, *(unsigned short*)(uuid+4), uuid[6],
	   uuid[7], uuid[8], uuid[9], uuid[10], uuid[11], uuid[12],
	   uuid[13], uuid[14], uuid[15]);
  pfree(uuid);
  PG_RETURN_TEXT_P(uuid_string);
}
