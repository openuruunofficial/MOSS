/*
  MOSS - A server for the Myst Online: Uru Live client/protocol
  Copyright (C) 2008-2011  a'moaca'

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
 * Macros and such to handle different machine architectures, and to some
 * extent, OSes.
 */

#ifndef _MACHINE_ARCH_H_
#define _MACHINE_ARCH_H_

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_STDINT_H
#include <stdint.h>
#else
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#endif

/*
 * The protocol is little-endian, so include conversion macros for that.
 */

#ifndef htole32
#ifdef WORDS_BIGENDIAN
#define htole16(x) \
	(((x) >> 8 & 0x00ff) | ((x) << 8 & 0xff00))
#define htole32(x) \
	(((x) >> 24 & 0x000000ff) | ((x) >> 8 & 0x0000ff00) | \
	 ((x) << 8 & 0x00ff0000) | ((x) << 24 & 0xff000000))
#else /* ! WORDS_BIGENDIAN */
#define htole16(x) (x)
#define htole32(x) (x)
#endif /* WORDS_BIGENDIAN */
#endif
#ifndef le32toh
#define le16toh(x) htole16(x)
#define le32toh(x) htole32(x)
#endif

/*
 * Doing reads/writes to network buffers: pay attention to alignment. The
 * {read,write}{16,32} routines read and convert to/from host byte-order. The
 * {read,write}{16,32}le routines don't byteswap so the result is always
 * in little-endian order (assuming you start with little-endian data, of
 * course) and are really meant to hide strict alignment rather than
 * endianness.
 */
#ifdef NEED_STRICT_ALIGNMENT
inline uint16_t read16(const void *buf, int off) {
  const u_char *lbuf = (const u_char*)buf;
  return (lbuf[off] | (lbuf[off+1] << 8));
}
inline uint32_t read32(const void *buf, int off) {
  const u_char *lbuf = (const u_char*)buf;
  return ((lbuf[off]) | (lbuf[off+1] << 8) |
	  (lbuf[off+2] << 16) | (lbuf[off+3] << 24));
}
inline void write16(void *buf, int off, uint16_t val) {
  u_char *lbuf = (u_char*)buf;
  lbuf[off] = val & 0xFF;
  lbuf[off+1] = (val >> 8) & 0xFF;
}
inline void write32(void *buf, int off, uint32_t val) {
  u_char *lbuf = (u_char*)buf;
  lbuf[off] = val & 0xFF;
  lbuf[off+1] = (val >> 8) & 0xFF;
  lbuf[off+2] = (val >> 16) & 0xFF;
  lbuf[off+3] = (val >> 24) & 0xFF;
}
inline uint16_t read16le(const void *buf, int off) {
  uint16_t res;
  u_char *rbuf = (u_char*)buf;
  if (((unsigned long)(rbuf+off)) % 2) {
    u_char *lbuf = (u_char*)&res;
    lbuf[0] = rbuf[off];
    lbuf[1] = rbuf[off+1];
  }
  else {
    res = *(uint16_t*)(rbuf+off);
  }
  return res;
}
inline uint32_t read32le(const void *buf, int off) {
  uint32_t res;
  u_char *rbuf = (u_char*)buf;
  if (((unsigned long)(rbuf+off)) % 4) {
    u_char *lbuf = (u_char*)&res;
    lbuf[0] = rbuf[off];
    lbuf[1] = rbuf[off+1];
    lbuf[2] = rbuf[off+2];
    lbuf[3] = rbuf[off+3];
  }
  else {
    res = *(uint32_t*)(rbuf+off);
  }
  return res;
}
inline void write16le(void *buf, int off, uint16_t val) {
  u_char *lbuf = (u_char*)buf;
  if (((unsigned long)(lbuf+off)) % 2) {
    u_char *rbuf = (u_char*)&val;
    lbuf[off] = rbuf[0];
    lbuf[off+1] = rbuf[1];
  }
  else {
    *(uint16_t*)(lbuf+off) = val;
  }
}
inline void write32le(void *buf, int off, uint32_t val) {
  u_char *lbuf = (u_char*)buf;
  if (((unsigned long)(lbuf+off)) % 4) {
    u_char *rbuf = (u_char*)&val;
    lbuf[off] = rbuf[0];
    lbuf[off+1] = rbuf[1];
    lbuf[off+2] = rbuf[2];
    lbuf[off+3] = rbuf[3];
  }
  else {
    *(uint32_t*)(lbuf+off) = val;
  }
}
#else /* ! NEED_STRICT_ALIGNMENT */
inline uint16_t read16(const void *buf, int off) {
  uint16_t res = *(uint16_t*)(((u_char*)buf)+off);
  return le16toh(res);
}
inline uint32_t read32(const void *buf, int off) {
  uint32_t res = *(uint32_t*)(((u_char*)buf)+off);
  return le32toh(res);
}
inline void write16(void *buf, int off, uint16_t res) {
  *(uint16_t*)(((u_char*)buf)+off) = htole16(res);
}
inline void write32(void *buf, int off, uint32_t res) {
  *(uint32_t*)(((u_char*)buf)+off) = htole32(res);
}
inline uint16_t read16le(const void *buf, int off) {
  uint16_t res = *(uint16_t*)(((u_char*)buf)+off);
  return res;
}
inline uint32_t read32le(const void *buf, int off) {
  uint32_t res = *(uint32_t*)(((u_char*)buf)+off);
  return res;
}
inline void write16le(void *buf, int off, uint16_t val) {
  *(uint16_t*)(((u_char*)buf)+off) = val;
}
inline void write32le(void *buf, int off, uint32_t val) {
  *(uint32_t*)(((u_char*)buf)+off) = val;
}
#endif /* NEED_STRICT_ALIGNMENT */

/*
 * We have to work with some little-endian doubles too. Note that
 * read_double and write_double are "le" variants -- no byte-swapping. The
 * presumption is the server need not look at the actual values of doubles.
 * If the server needs to use doubles it will have to specially swap them.
 */
#ifdef NEED_STRICT_ALIGNMENT
inline double read_double(const void *buf, int off) {
  double res;
  u_char *rbuf = (u_char*)buf;
  if (((unsigned long)(rbuf+off)) % 8) {
    memcpy((u_char*)&res, rbuf, 8);
  }
  else {
    res = *(double*)(rbuf+off);
  }
  return res;
}
inline void write_double(void *buf, int off, double val) {
  u_char *lbuf = (u_char*)buf;
  if (((unsigned long)(lbuf+off)) % 8) {
    memcpy(lbuf, (u_char*)&val, 8);
  }
  else {
    *(double*)(lbuf+off) = val;
  }
}
#else
inline double read_double(const void *buf, int off) {
  double res = *(double*)(((u_char*)buf)+off);
  return res;
}
inline void write_double(void *buf, int off, double val) {
  *(double*)(((u_char*)buf)+off) = val;
}
#endif /* NEED_STRICT_ALIGNMENT */
#ifdef WORDS_BIGENDIAN
/* XXX test this by doing this math even on little-endian */
inline double htoledouble(double x) {
  uint32_t lo, hi;
  uint64_t dval = (uint64_t)x;
  lo = dval & 0xFFFFFFFF;
  lo = htole32(lo);
  hi = dval >> 32;
  dval = htole32(hi);
  dval = (dval << 32) | lo;
  return (double)dval;
}
#else
#define htoledouble(x) (x)
#endif /* WORDS_BIGENDIAN */
#define letohdouble(x) htoledouble(x)

#endif /* _MACHINE_ARCH_H_ */
