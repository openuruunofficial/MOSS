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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/param.h> /* for PATH_MAX */
#include <sys/stat.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#ifdef HAVE_OPENSSL
#include <openssl/rand.h>
#else
#include <unistd.h> /* for getpid() */
#endif

#include "machine_arch.h"
#include "util.h"

void gen_uuid(u_char *buf, int as_text) {
  u_char mybuf[16];
  u_char *use_buf = (as_text ? mybuf : buf);
  get_random_data(use_buf, 16);
  /* since this is a random UUID there is actually no need to do any
     byte-swapping to little-endian */

  /* clock_seq_hi_and_reserved = byte 8 */
  use_buf[8] &= 0x3f;
  use_buf[8] |= 0x80;
  /* time_hi_and_version = bytes 6-7 */
  use_buf[7] &= 0x0f;
  use_buf[7] |= 0x40;
  if (as_text) {
    uuid_bytes_to_string(buf, 36, mybuf, 16, 1, 1);
  }
}

int uuid_string_to_bytes(u_char *buf, u_int buflen,
			 const char *uuid_string, u_int uuid_string_len,
			 int have_dashes, int byteswap) {
  u_int i;
  u_char *bufp, upper, lower;

  if (((have_dashes && uuid_string_len < 36)
       || (!have_dashes && uuid_string_len < 32))
      || buflen < 16) {
    return -1;
  }
  bufp = (u_char*)uuid_string;
  for (i = 0; i < 16; i++) {
    if (have_dashes && (i == 4 || i == 6 || i == 8 || i == 10)) {
      /* skip '-' */
      bufp++;
    }
    upper = *bufp++;
    lower = *bufp++;
#define do_conversion(c) \
    if (c >= 0x30 && c <= 0x39) { \
      c -= 0x30; \
    } \
    else if (c >= 0x41 && c <= 0x46) { \
      c -= 0x37; \
    } \
    else if (c >= 0x61 && c <= 0x66) { \
      c -= 0x57; \
    } \
    else { \
      return 1; \
    }
    do_conversion(upper);
    do_conversion(lower);
#undef do_conversion
    u_int loc = i;
    if (byteswap) {
      if (i < 4) {
	loc = 3 - i;
      }
      else if (i < 8) {
	if (i & 0x1) {
	  loc = i - 1;
	}
	else {
	  loc = i + 1;
	}
      }
    }
    buf[loc] = (upper << 4) | lower;
  }
  return 0;
}

int uuid_bytes_to_string(u_char *buf, u_int buflen,
			 const u_char *uuid_bytes, u_int uuid_bytes_len,
			 int want_dashes, int byteswap) {
  u_int i;
  u_char *bufp, upper, lower;

  if (((want_dashes && buflen < 36) || (!want_dashes && buflen < 32))
      || uuid_bytes_len < 16) {
    return -1;
  }
  bufp = (u_char*)buf;
  for (i = 0; i < 16; i++) {
    if (want_dashes && (i == 4 || i == 6 || i == 8 || i == 10)) {
      /* add '-' */
      *bufp++ = '-';
    }
    u_int loc = i;
    if (byteswap) {
      if (i < 4) {
	loc = 3 - i;
      }
      else if (i < 8) {
	if (i & 0x1) {
	  loc = i - 1;
	}
	else {
	  loc = i + 1;
	}
      }
    }
    upper = uuid_bytes[loc] >> 4;
    lower = uuid_bytes[loc] & 0x0f;
#define do_conversion(c) \
    c += 0x30; \
    if (c > 0x39) { \
      c += 0x27; \
    }
    do_conversion(upper);
    do_conversion(lower);
#undef do_conversion
    *bufp++ = upper;
    *bufp++ = lower;
  }
  *bufp++ = '\0';
  return 0;
}

int recursive_mkdir( const char *pathname, mode_t mode ) {
  char path[PATH_MAX];
  char *p = NULL;
  char *d;
  size_t len;

  snprintf(path, sizeof(path), "%s", pathname);
  len = strlen(path);
  if (path[len-1] == PATH_SEPARATOR[0])  {
      path[len-1] = 0;
  }

  for (p=path+1, d=p; *p; p++, d++)  {
    if (*p == PATH_SEPARATOR[0]) {
      while (*p && (*(p+1) == PATH_SEPARATOR[0])) p++;
      *d = '\0';
      if (mkdir(path, mode) && (errno != EEXIST)) {
        return -1;
      }
    *d = PATH_SEPARATOR[0];
    } else {
      *d = *p;
    }
  }
  *d = '\0';
  if (mkdir(path, mode) && (errno != EEXIST)) {
    return -1;
  }
  return 0;
}

void do_random_seed() {
#ifndef HAVE_OPENSSL
  struct timeval t;
  gettimeofday(&t, NULL);
  uint32_t seed = (t.tv_sec + (getpid() << 3)) ^ (t.tv_usec << 13);
  srandom(seed); /* XXX or, use cycle counter (on x86) */
#endif
}

void get_random_data(u_char *buf, u_int buflen) {
#ifdef HAVE_OPENSSL
  /* XXX NOTE: see OpenSSL RAND_add and RAND_event man page when considering
     Windows: we may need to manually seed the PRNG and use only
     RAND_pseudo_bytes() instead of RAND_bytes(), in which case perhaps
     using the non-SSL fallback here is good enough */
  RAND_bytes(buf, buflen);
#else
  /* XXX in the future decide if better random numbers must be used
     XXX also, are random() and srandom() thread-safe?
     XXX consider /dev/urandom instead (but not for Windows; look into
         Windows API) */
  u_int bitsleft = 0;
  /* it is rather unclear whether or not, on a 64-bit machine, random()
     returns 64-bit numbers; the man pages all say "long" implying yes, but
     they also seem to say that the value returned is a 31-bit nonnegative
     number implying it should be treated as a 32-bit number regardless */
  uint64_t bucket = 0;
  u_int i = 0;
  while (i < buflen) {
    uint64_t r = (random() & 0x7fffffff);
    bucket |= r << bitsleft;
    bitsleft += 31;
    if (buflen-i < 4) {
      u_int j;
      for (j = 0; j < buflen-i; j++) {
	buf[i+j] = (bucket >> (j*8)) & 0xff;
      }
      return;
    }
    if (bitsleft < 32) {
      continue;
    }
    r = bucket & 0xffffffff;
    write32le(buf, i, r); /* write32le handles NEED_STRICT_ALIGNMENT */
    bucket = bucket >> 32;
    bitsleft -= 32;
    i += 4;
  }
#endif /* ! HAVE_OPENSSL */
}

const char * resolve_hostname(const char *hostname, uint32_t *ipaddr) {
#ifdef HAVE_GETADDRINFO
  struct addrinfo hints, *addrs;
  int err;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = PF_INET; /* ask for IPv4 */
  hints.ai_socktype = SOCK_STREAM;
  err = getaddrinfo(hostname, NULL, &hints, &addrs);
  if (err) {
    return gai_strerror(err);
  }
  struct sockaddr_in *ai = (struct sockaddr_in *)addrs[0].ai_addr;
  *ipaddr = (uint32_t)ai->sin_addr.s_addr;
  freeaddrinfo(addrs);
  return NULL;
#else
#warning Using non-thread-safe gethostbyname!
  /* this is not thread safe, but it should really never be in use */
  struct hostent *h_ent;

  h_ent = gethostbyname(hostname);
  if (!h_ent) {
    return hstrerror(h_errno);
  }
  *ipaddr = *((uint32_t *)h_ent->h_addr);
  return NULL;
#endif /* HAVE_GETADDRINFO */
}
