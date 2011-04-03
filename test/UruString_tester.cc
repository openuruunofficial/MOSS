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
#include <string.h>

#include <iconv.h>

#include <string>

#include "machine_arch.h"

#include "UruString.h"

const char *c_ = "Testing";
const char *c_with_len_ = "\x07\x00Testing";
const char *c_with_len_with_null_ = "\x08\x00Testing";
const char *c_with_extra_ = "Testing\0\0";
const char *uru_ = "\x07\x00Testing";
const char *uru_with_null_ = "\x08\x00Testing";
const char *uru_with_extra_ = "\x07\x00Testing\0\0";
const char *uru_flip_ = "\x07\xf0\xab\x9a\x8c\x8b\x96\x91\x98";
const char *uru_flip_with_null_ = "\x08\xf0\xab\x9a\x8c\x8b\x96\x91\x98\xff\xff";
const char *c_wide_ = "T\0e\0s\0t\0i\0n\0g\0\0";
const char *c_wide_with_len_ = "\x07\x00T\0e\0s\0t\0i\0n\0g\0\0";
const char *c_wide_with_len_with_null_ = "\x08\x00T\0e\0s\0t\0i\0n\0g\0\0";
const char *c_wide_with_extra_ = "T\0e\0s\0t\0i\0n\0g\0\0\0\0\0\0";
const char *uru_wide_ = "\x07\x00T\0e\0s\0t\0i\0n\0g\0\0";
const char *uru_wide_with_null_ = "\x08\x00T\0e\0s\0t\0i\0n\0g\0\0";
const char *uru_wide_with_extra_ = "\x08\x00T\0e\0s\0t\0i\0n\0g\0\0\0\0\0\0";
const char *uru_wide_flip_ = "\x07\xf0\xab\xff\x9a\xff\x8c\xff\x8b\xff\x96\xff\x91\xff\x98\xff";
const char *uru_wide_flip_with_null_ = "\x08\xf0\xab\xff\x9a\xff\x8c\xff\x8b\xff\x96\xff\x91\xff\x98\xff\xff\xff";
const char *empty_c_ = "\0";
const char *empty_c_with_len_ = "\x00\x00";
const char *empty_c_with_extra_ = "\0Testing";
const char *empty_uru_ = "\x00\x00";
const char *empty_uru_with_extra_ = "\x00\x00Testing";
const char *empty_c_wide_ = "\0\0";
const char *empty_c_wide_with_len_ = "\x00\x00\0\0";
const char *empty_uru_wide_ = "\x00\x00";
const char *empty_uru_wide_with_extra_ = "\x00\x00T\0e\0s\0t\0i\0n\0g\0";
// for non 1:2 testing
const char *utf8_2_utf16_2_ = "\xC2\xA2"; // U+00A2
const char *utf16_2_utf8_2_ = "\xA2\x00\0";
const char *utf8_3_utf16_2_ = "\xE2\x82\xAC"; // U+20AC
const char *utf16_2_utf8_3_ = "\xAC\x20\0";
const char *utf8_4_utf16_4_ = "\xF0\xA4\xAD\xA2"; // U+024B62
const char *utf16_4_utf8_4_ = "\x52\xD8\x62\xDF\0";

const u_char *c = (u_char*)c_;
const u_char *c_with_len = (u_char*)c_with_len_;
const u_char *c_with_len_with_null = (u_char*)c_with_len_with_null_;
const u_char *c_with_extra = (u_char*)c_with_extra_;
const u_char *uru = (u_char*)uru_;
const u_char *uru_with_null = (u_char*)uru_with_null_;
const u_char *uru_with_extra = (u_char*)uru_with_extra_;
const u_char *uru_flip = (u_char*)uru_flip_;
const u_char *uru_flip_with_null = (u_char*)uru_flip_with_null_;
const u_char *c_wide = (u_char*)c_wide_;
const u_char *c_wide_with_len = (u_char*)c_wide_with_len_;
const u_char *c_wide_with_len_with_null = (u_char*)c_wide_with_len_with_null_;
const u_char *c_wide_with_extra = (u_char*)c_wide_with_extra_;
const u_char *uru_wide = (u_char*)uru_wide_;
const u_char *uru_wide_with_null = (u_char*)uru_wide_with_null_;
const u_char *uru_wide_with_extra = (u_char*)uru_wide_with_extra_;
const u_char *uru_wide_flip = (u_char*)uru_wide_flip_;
const u_char *uru_wide_flip_with_null = (u_char*)uru_wide_flip_with_null_;
const u_char *empty_c = (u_char*)empty_c_;
const u_char *empty_c_with_len = (u_char*)empty_c_with_len_;
const u_char *empty_c_with_extra = (u_char*)empty_c_with_extra_;
const u_char *empty_uru = (u_char*)empty_uru_;
const u_char *empty_uru_with_extra = (u_char*)empty_uru_with_extra_;
const u_char *empty_c_wide = (u_char*)empty_c_wide_;
const u_char *empty_c_wide_with_len = (u_char*)empty_c_wide_with_len_;
const u_char *empty_uru_wide = (u_char*)empty_uru_wide_;
const u_char *empty_uru_wide_with_extra = (u_char*)empty_uru_wide_with_extra_;
const u_char *utf8_2_utf16_2 = (u_char*)utf8_2_utf16_2_;
const u_char *utf16_2_utf8_2 = (u_char*)utf16_2_utf8_2_;
const u_char *utf8_3_utf16_2 = (u_char*)utf8_3_utf16_2_;
const u_char *utf16_2_utf8_3 = (u_char*)utf16_2_utf8_3_;
const u_char *utf8_4_utf16_4 = (u_char*)utf8_4_utf16_4_;
const u_char *utf16_4_utf8_4 = (u_char*)utf16_4_utf8_4_;

void verify(bool x, int line, const char *err) {
  if (!x) {
    printf("%d: %s\n", line, err);
  }
}
#define VERIFY(a) verify((a), __LINE__, #a);

void full_mesh() {
  UruString str(c, 8, false, false, false);
  str.c_str();

  str.get_str(true, true, true, true);

  VERIFY(!memcmp(str.get_str(false, true, true, false), c_wide, 16));
  VERIFY(str.send_len(false, true, true) == 16);
  VERIFY(!memcmp(str.get_str(true, false, false, true), uru_flip, 9));
  VERIFY(str.send_len(true, false, false) == 9);
  VERIFY(!memcmp(str.get_str(false, false, true, false), c, 8));
  VERIFY(str.send_len(false, false, true) == 8);
  VERIFY(!memcmp(str.get_str(true, false, true, false), uru_with_null, 10));
  VERIFY(str.send_len(true, false, true) == 10);
  VERIFY(!memcmp(str.get_str(false, true, false, true), c_wide, 14));
  VERIFY(str.send_len(false, true, false) == 14);
  VERIFY(!memcmp(str.get_str(false, true, false, false), c_wide, 14));
  VERIFY(str.send_len(false, true, false) == 14);
  VERIFY(!memcmp(str.get_str(false, false, false, false), c, 7));
  VERIFY(str.send_len(false, false, false) == 7);
  VERIFY(!memcmp(str.get_str(false, true, false, false), c_wide, 14));
  VERIFY(str.send_len(false, true, false) == 14);
  VERIFY(!memcmp(str.get_str(true, false, true, true), uru_flip_with_null, 10));
  VERIFY(str.send_len(true, false, true) == 10);
  VERIFY(!memcmp(str.get_str(false, false, false, false), c, 7));
  VERIFY(str.send_len(false, false, false) == 7);
  VERIFY(!memcmp(str.get_str(false, false, false, true), c, 7));
  VERIFY(str.send_len(false, false, false) == 7);
  VERIFY(!memcmp(str.get_str(true, true, false, false), uru_wide, 16));
  VERIFY(str.send_len(true, true, false) == 16);
  VERIFY(!memcmp(str.get_str(true, false, false, false), c_with_len, 9));
  VERIFY(str.send_len(true, false, false) == 9);
  VERIFY(!memcmp(str.get_str(true, false, true, true), uru_flip_with_null, 10));
  VERIFY(str.send_len(true, false, true) == 10);
  VERIFY(!memcmp(str.get_str(false, false, true, false), c, 8));
  VERIFY(str.send_len(false, false, true) == 8);
  VERIFY(!memcmp(str.get_str(true, false, true, true), uru_flip_with_null, 10));
  VERIFY(str.send_len(true, false, true) == 10);
  VERIFY(!memcmp(str.get_str(false, true, false, true), c_wide, 14));
  VERIFY(str.send_len(false, true, false) == 14);
  VERIFY(!memcmp(str.get_str(true, false, false, true), uru_flip, 9));
  VERIFY(str.send_len(true, false, false) == 9);
  VERIFY(!memcmp(str.get_str(true, true, false, true), uru_wide_flip, 16));
  VERIFY(str.send_len(true, true, false) == 16);
  VERIFY(!memcmp(str.get_str(false, true, false, true), c_wide, 14));
  VERIFY(str.send_len(false, true, false) == 14);
  VERIFY(!memcmp(str.get_str(false, true, true, false), c_wide, 16));
  VERIFY(str.send_len(false, true, true) == 16);
  VERIFY(!memcmp(str.get_str(false, false, true, true), c, 8));
  VERIFY(str.send_len(false, false, true) == 8);
  VERIFY(!memcmp(str.get_str(false, true, false, false), c_wide, 14));
  VERIFY(str.send_len(false, true, false) == 14);
  VERIFY(!memcmp(str.get_str(true, false, true, false), uru_with_null, 10));
  VERIFY(str.send_len(true, false, true) == 10);
  VERIFY(!memcmp(str.get_str(true, true, true, false), uru_wide_with_null, 18));
  VERIFY(str.send_len(true, true, true) == 18);
  VERIFY(!memcmp(str.get_str(true, false, false, false), c_with_len, 9));
  VERIFY(str.send_len(true, false, false) == 9);
  VERIFY(!memcmp(str.get_str(false, false, true, true), c, 8));
  VERIFY(str.send_len(false, false, true) == 8);
  VERIFY(!memcmp(str.get_str(false, true, true, true), c_wide, 16));
  VERIFY(str.send_len(false, true, true) == 16);
  VERIFY(!memcmp(str.get_str(false, true, true, false), c_wide, 16));
  VERIFY(str.send_len(false, true, true) == 16);
  VERIFY(!memcmp(str.get_str(false, false, false, true), c, 7));
  VERIFY(str.send_len(false, false, false) == 7);
  VERIFY(!memcmp(str.get_str(false, true, false, true), c_wide, 14));
  VERIFY(str.send_len(false, true, false) == 14);
  VERIFY(!memcmp(str.get_str(true, true, false, true), uru_wide_flip, 16));
  VERIFY(str.send_len(true, true, false) == 16);
  VERIFY(!memcmp(str.get_str(true, false, false, true), uru_flip, 9));
  VERIFY(str.send_len(true, false, false) == 9);
  VERIFY(!memcmp(str.get_str(true, false, true, false), uru_with_null, 10));
  VERIFY(str.send_len(true, false, true) == 10);
  VERIFY(!memcmp(str.get_str(false, true, false, false), c_wide, 14));
  VERIFY(str.send_len(false, true, false) == 14);
  VERIFY(!memcmp(str.get_str(false, true, true, false), c_wide, 16));
  VERIFY(str.send_len(false, true, true) == 16);
  VERIFY(!memcmp(str.get_str(true, false, true, true), uru_flip_with_null, 10));
  VERIFY(str.send_len(true, false, true) == 10);
  VERIFY(!memcmp(str.get_str(true, true, false, true), uru_wide_flip, 16));
  VERIFY(str.send_len(true, true, false) == 16);
  VERIFY(!memcmp(str.get_str(false, false, true, true), c, 8));
  VERIFY(str.send_len(false, false, true) == 8);
  VERIFY(!memcmp(str.get_str(false, false, false, false), c, 7));
  VERIFY(str.send_len(false, false, false) == 7);
  VERIFY(!memcmp(str.get_str(true, false, false, false), c_with_len, 9));
  VERIFY(str.send_len(true, false, false) == 9);
  VERIFY(!memcmp(str.get_str(true, true, false, true), uru_wide_flip, 16));
  VERIFY(str.send_len(true, true, false) == 16);
  VERIFY(!memcmp(str.get_str(false, true, false, false), c_wide, 14));
  VERIFY(str.send_len(false, true, false) == 14);
  VERIFY(!memcmp(str.get_str(false, false, true, true), c, 8));
  VERIFY(str.send_len(false, false, true) == 8);
  VERIFY(!memcmp(str.get_str(false, true, true, false), c_wide, 16));
  VERIFY(str.send_len(false, true, true) == 16);
  VERIFY(!memcmp(str.get_str(true, false, true, false), uru_with_null, 10));
  VERIFY(str.send_len(true, false, true) == 10);
  VERIFY(!memcmp(str.get_str(true, false, false, false), c_with_len, 9));
  VERIFY(str.send_len(true, false, false) == 9);
  VERIFY(!memcmp(str.get_str(true, false, true, false), uru_with_null, 10));
  VERIFY(str.send_len(true, false, true) == 10);
  VERIFY(!memcmp(str.get_str(true, true, false, false), uru_wide, 16));
  VERIFY(str.send_len(true, true, false) == 16);
  VERIFY(!memcmp(str.get_str(false, false, true, false), c, 8));
  VERIFY(str.send_len(false, false, true) == 8);
  VERIFY(!memcmp(str.get_str(false, true, false, false), c_wide, 14));
  VERIFY(str.send_len(false, true, false) == 14);
  VERIFY(!memcmp(str.get_str(true, false, false, true), uru_flip, 9));
  VERIFY(str.send_len(true, false, false) == 9);
  VERIFY(!memcmp(str.get_str(true, false, false, false), c_with_len, 9));
  VERIFY(str.send_len(true, false, false) == 9);
  VERIFY(!memcmp(str.get_str(true, true, true, false), uru_wide_with_null, 18));
  VERIFY(str.send_len(true, true, true) == 18);
  VERIFY(!memcmp(str.get_str(true, false, false, true), uru_flip, 9));
  VERIFY(str.send_len(true, false, false) == 9);
  VERIFY(!memcmp(str.get_str(false, false, false, true), c, 7));
  VERIFY(str.send_len(false, false, false) == 7);
  VERIFY(!memcmp(str.get_str(true, false, true, true), uru_flip_with_null, 10));
  VERIFY(str.send_len(true, false, true) == 10);
  VERIFY(!memcmp(str.get_str(false, false, true, true), c, 8));
  VERIFY(str.send_len(false, false, true) == 8);
  VERIFY(!memcmp(str.get_str(true, false, true, true), uru_flip_with_null, 10));
  VERIFY(str.send_len(true, false, true) == 10);
  VERIFY(!memcmp(str.get_str(true, true, true, false), uru_wide_with_null, 18));
  VERIFY(str.send_len(true, true, true) == 18);
  VERIFY(!memcmp(str.get_str(false, false, false, false), c, 7));
  VERIFY(str.send_len(false, false, false) == 7);
  VERIFY(!memcmp(str.get_str(true, false, false, true), uru_flip, 9));
  VERIFY(str.send_len(true, false, false) == 9);
  VERIFY(!memcmp(str.get_str(true, false, true, true), uru_flip_with_null, 10));
  VERIFY(str.send_len(true, false, true) == 10);
  VERIFY(!memcmp(str.get_str(true, true, true, true), uru_wide_flip_with_null, 18));
  VERIFY(str.send_len(true, true, true) == 18);
  VERIFY(!memcmp(str.get_str(true, true, false, false), uru_wide, 16));
  VERIFY(str.send_len(true, true, false) == 16);
  VERIFY(!memcmp(str.get_str(false, false, false, true), c, 7));
  VERIFY(str.send_len(false, false, false) == 7);
  VERIFY(!memcmp(str.get_str(true, true, true, false), uru_wide_with_null, 18));
  VERIFY(str.send_len(true, true, true) == 18);
  VERIFY(!memcmp(str.get_str(false, false, true, false), c, 8));
  VERIFY(str.send_len(false, false, true) == 8);
  VERIFY(!memcmp(str.get_str(false, false, false, true), c, 7));
  VERIFY(str.send_len(false, false, false) == 7);
  VERIFY(!memcmp(str.get_str(false, true, true, true), c_wide, 16));
  VERIFY(str.send_len(false, true, true) == 16);
  VERIFY(!memcmp(str.get_str(true, true, false, false), uru_wide, 16));
  VERIFY(str.send_len(true, true, false) == 16);
  VERIFY(!memcmp(str.get_str(true, true, false, true), uru_wide_flip, 16));
  VERIFY(str.send_len(true, true, false) == 16);
  VERIFY(!memcmp(str.get_str(false, false, false, false), c, 7));
  VERIFY(str.send_len(false, false, false) == 7);
  VERIFY(!memcmp(str.get_str(false, false, true, false), c, 8));
  VERIFY(str.send_len(false, false, true) == 8);
  VERIFY(!memcmp(str.get_str(false, true, true, true), c_wide, 16));
  VERIFY(str.send_len(false, true, true) == 16);
  VERIFY(!memcmp(str.get_str(false, false, false, false), c, 7));
  VERIFY(str.send_len(false, false, false) == 7);
  VERIFY(!memcmp(str.get_str(true, true, false, true), uru_wide_flip, 16));
  VERIFY(str.send_len(true, true, false) == 16);
  VERIFY(!memcmp(str.get_str(false, false, false, true), c, 7));
  VERIFY(str.send_len(false, false, false) == 7);
  VERIFY(!memcmp(str.get_str(false, false, true, true), c, 8));
  VERIFY(str.send_len(false, false, true) == 8);
  VERIFY(!memcmp(str.get_str(true, true, false, true), uru_wide_flip, 16));
  VERIFY(str.send_len(true, true, false) == 16);
  VERIFY(!memcmp(str.get_str(true, false, false, false), c_with_len, 9));
  VERIFY(str.send_len(true, false, false) == 9);
  VERIFY(!memcmp(str.get_str(false, true, true, true), c_wide, 16));
  VERIFY(str.send_len(false, true, true) == 16);
  VERIFY(!memcmp(str.get_str(false, false, true, false), c, 8));
  VERIFY(str.send_len(false, false, true) == 8);
  VERIFY(!memcmp(str.get_str(true, true, false, true), uru_wide_flip, 16));
  VERIFY(str.send_len(true, true, false) == 16);
  VERIFY(!memcmp(str.get_str(true, true, true, true), uru_wide_flip_with_null, 18));
  VERIFY(str.send_len(true, true, true) == 18);
  VERIFY(!memcmp(str.get_str(false, false, false, false), c, 7));
  VERIFY(str.send_len(false, false, false) == 7);
  VERIFY(!memcmp(str.get_str(false, true, true, true), c_wide, 16));
  VERIFY(str.send_len(false, true, true) == 16);
  VERIFY(!memcmp(str.get_str(true, false, false, false), c_with_len, 9));
  VERIFY(str.send_len(true, false, false) == 9);
  VERIFY(!memcmp(str.get_str(false, false, true, false), c, 8));
  VERIFY(str.send_len(false, false, true) == 8);
  VERIFY(!memcmp(str.get_str(false, true, true, false), c_wide, 16));
  VERIFY(str.send_len(false, true, true) == 16);
  VERIFY(!memcmp(str.get_str(true, true, false, true), uru_wide_flip, 16));
  VERIFY(str.send_len(true, true, false) == 16);
  VERIFY(!memcmp(str.get_str(true, false, true, false), uru_with_null, 10));
  VERIFY(str.send_len(true, false, true) == 10);
  VERIFY(!memcmp(str.get_str(true, true, false, true), uru_wide_flip, 16));
  VERIFY(str.send_len(true, true, false) == 16);
  VERIFY(!memcmp(str.get_str(true, false, true, true), uru_flip_with_null, 10));
  VERIFY(str.send_len(true, false, true) == 10);
  VERIFY(!memcmp(str.get_str(false, true, false, false), c_wide, 14));
  VERIFY(str.send_len(false, true, false) == 14);
  VERIFY(!memcmp(str.get_str(false, true, false, true), c_wide, 14));
  VERIFY(str.send_len(false, true, false) == 14);
  VERIFY(!memcmp(str.get_str(false, true, true, true), c_wide, 16));
  VERIFY(str.send_len(false, true, true) == 16);
  VERIFY(!memcmp(str.get_str(true, true, false, true), uru_wide_flip, 16));
  VERIFY(str.send_len(true, true, false) == 16);
  VERIFY(!memcmp(str.get_str(false, true, true, true), c_wide, 16));
  VERIFY(str.send_len(false, true, true) == 16);
  VERIFY(!memcmp(str.get_str(true, true, true, false), uru_wide_with_null, 18));
  VERIFY(str.send_len(true, true, true) == 18);
  VERIFY(!memcmp(str.get_str(false, true, true, false), c_wide, 16));
  VERIFY(str.send_len(false, true, true) == 16);
  VERIFY(!memcmp(str.get_str(true, false, false, false), c_with_len, 9));
  VERIFY(str.send_len(true, false, false) == 9);
  VERIFY(!memcmp(str.get_str(false, true, true, false), c_wide, 16));
  VERIFY(str.send_len(false, true, true) == 16);
  VERIFY(!memcmp(str.get_str(false, true, true, true), c_wide, 16));
  VERIFY(str.send_len(false, true, true) == 16);
  VERIFY(!memcmp(str.get_str(false, false, true, true), c, 8));
  VERIFY(str.send_len(false, false, true) == 8);
  VERIFY(!memcmp(str.get_str(false, false, true, false), c, 8));
  VERIFY(str.send_len(false, false, true) == 8);
  VERIFY(!memcmp(str.get_str(true, false, false, true), uru_flip, 9));
  VERIFY(str.send_len(true, false, false) == 9);
  VERIFY(!memcmp(str.get_str(false, false, false, false), c, 7));
  VERIFY(str.send_len(false, false, false) == 7);
  VERIFY(!memcmp(str.get_str(false, false, true, true), c, 8));
  VERIFY(str.send_len(false, false, true) == 8);
  VERIFY(!memcmp(str.get_str(true, true, true, false), uru_wide_with_null, 18));
  VERIFY(str.send_len(true, true, true) == 18);
  VERIFY(!memcmp(str.get_str(true, true, true, true), uru_wide_flip_with_null, 18));
  VERIFY(str.send_len(true, true, true) == 18);
  VERIFY(!memcmp(str.get_str(true, false, false, true), uru_flip, 9));
  VERIFY(str.send_len(true, false, false) == 9);
  VERIFY(!memcmp(str.get_str(false, false, true, true), c, 8));
  VERIFY(str.send_len(false, false, true) == 8);
  VERIFY(!memcmp(str.get_str(true, true, false, false), uru_wide, 16));
  VERIFY(str.send_len(true, true, false) == 16);
  VERIFY(!memcmp(str.get_str(true, true, true, true), uru_wide_flip_with_null, 18));
  VERIFY(str.send_len(true, true, true) == 18);
  VERIFY(!memcmp(str.get_str(true, false, true, true), uru_flip_with_null, 10));
  VERIFY(str.send_len(true, false, true) == 10);
  VERIFY(!memcmp(str.get_str(true, true, false, false), uru_wide, 16));
  VERIFY(str.send_len(true, true, false) == 16);
  VERIFY(!memcmp(str.get_str(false, true, false, false), c_wide, 14));
  VERIFY(str.send_len(false, true, false) == 14);
  VERIFY(!memcmp(str.get_str(true, true, true, false), uru_wide_with_null, 18));
  VERIFY(str.send_len(true, true, true) == 18);
  VERIFY(!memcmp(str.get_str(true, false, true, true), uru_flip_with_null, 10));
  VERIFY(str.send_len(true, false, true) == 10);
  VERIFY(!memcmp(str.get_str(false, true, true, false), c_wide, 16));
  VERIFY(str.send_len(false, true, true) == 16);
  VERIFY(!memcmp(str.get_str(false, true, false, true), c_wide, 14));
  VERIFY(str.send_len(false, true, false) == 14);
  VERIFY(!memcmp(str.get_str(true, true, true, true), uru_wide_flip_with_null, 18));
  VERIFY(str.send_len(true, true, true) == 18);
  VERIFY(!memcmp(str.get_str(true, false, true, false), uru_with_null, 10));
  VERIFY(str.send_len(true, false, true) == 10);
  VERIFY(!memcmp(str.get_str(false, false, true, true), c, 8));
  VERIFY(str.send_len(false, false, true) == 8);
  VERIFY(!memcmp(str.get_str(true, true, true, true), uru_wide_flip_with_null, 18));
  VERIFY(str.send_len(true, true, true) == 18);
  VERIFY(!memcmp(str.get_str(true, true, false, true), uru_wide_flip, 16));
  VERIFY(str.send_len(true, true, false) == 16);
  VERIFY(!memcmp(str.get_str(false, false, true, false), c, 8));
  VERIFY(str.send_len(false, false, true) == 8);
  VERIFY(!memcmp(str.get_str(true, true, true, true), uru_wide_flip_with_null, 18));
  VERIFY(str.send_len(true, true, true) == 18);
  VERIFY(!memcmp(str.get_str(false, false, true, false), c, 8));
  VERIFY(str.send_len(false, false, true) == 8);
  VERIFY(!memcmp(str.get_str(false, false, true, true), c, 8));
  VERIFY(str.send_len(false, false, true) == 8);
  VERIFY(!memcmp(str.get_str(false, false, false, true), c, 7));
  VERIFY(str.send_len(false, false, false) == 7);
  VERIFY(!memcmp(str.get_str(true, true, true, true), uru_wide_flip_with_null, 18));
  VERIFY(str.send_len(true, true, true) == 18);
  VERIFY(!memcmp(str.get_str(false, true, false, true), c_wide, 14));
  VERIFY(str.send_len(false, true, false) == 14);
  VERIFY(!memcmp(str.get_str(true, true, false, false), uru_wide, 16));
  VERIFY(str.send_len(true, true, false) == 16);
  VERIFY(!memcmp(str.get_str(false, true, true, false), c_wide, 16));
  VERIFY(str.send_len(false, true, true) == 16);
  VERIFY(!memcmp(str.get_str(true, true, true, false), uru_wide_with_null, 18));
  VERIFY(str.send_len(true, true, true) == 18);
  VERIFY(!memcmp(str.get_str(false, true, false, true), c_wide, 14));
  VERIFY(str.send_len(false, true, false) == 14);
  VERIFY(!memcmp(str.get_str(false, false, true, false), c, 8));
  VERIFY(str.send_len(false, false, true) == 8);
  VERIFY(!memcmp(str.get_str(true, true, false, false), uru_wide, 16));
  VERIFY(str.send_len(true, true, false) == 16);
  VERIFY(!memcmp(str.get_str(true, false, true, true), uru_flip_with_null, 10));
  VERIFY(str.send_len(true, false, true) == 10);
  VERIFY(!memcmp(str.get_str(true, false, true, false), uru_with_null, 10));
  VERIFY(str.send_len(true, false, true) == 10);
  VERIFY(!memcmp(str.get_str(true, false, false, true), uru_flip, 9));
  VERIFY(str.send_len(true, false, false) == 9);
  VERIFY(!memcmp(str.get_str(true, true, true, true), uru_wide_flip_with_null, 18));
  VERIFY(str.send_len(true, true, true) == 18);
  VERIFY(!memcmp(str.get_str(true, true, true, false), uru_wide_with_null, 18));
  VERIFY(str.send_len(true, true, true) == 18);
  VERIFY(!memcmp(str.get_str(true, true, false, false), uru_wide, 16));
  VERIFY(str.send_len(true, true, false) == 16);
  VERIFY(!memcmp(str.get_str(true, true, true, false), uru_wide_with_null, 18));
  VERIFY(str.send_len(true, true, true) == 18);
  VERIFY(!memcmp(str.get_str(false, true, true, true), c_wide, 16));
  VERIFY(str.send_len(false, true, true) == 16);
  VERIFY(!memcmp(str.get_str(true, false, true, false), uru_with_null, 10));
  VERIFY(str.send_len(true, false, true) == 10);
  VERIFY(!memcmp(str.get_str(false, false, false, true), c, 7));
  VERIFY(str.send_len(false, false, false) == 7);
  VERIFY(!memcmp(str.get_str(false, true, false, false), c_wide, 14));
  VERIFY(str.send_len(false, true, false) == 14);
  VERIFY(!memcmp(str.get_str(true, true, false, false), uru_wide, 16));
  VERIFY(str.send_len(true, true, false) == 16);
  VERIFY(!memcmp(str.get_str(false, true, false, true), c_wide, 14));
  VERIFY(str.send_len(false, true, false) == 14);
  VERIFY(!memcmp(str.get_str(true, false, true, false), uru_with_null, 10));
  VERIFY(str.send_len(true, false, true) == 10);
  VERIFY(!memcmp(str.get_str(false, true, true, true), c_wide, 16));
  VERIFY(str.send_len(false, true, true) == 16);
  VERIFY(!memcmp(str.get_str(false, false, false, true), c, 7));
  VERIFY(str.send_len(false, false, false) == 7);
  VERIFY(!memcmp(str.get_str(false, false, false, false), c, 7));
  VERIFY(str.send_len(false, false, false) == 7);
  VERIFY(!memcmp(str.get_str(true, false, true, false), uru_with_null, 10));
  VERIFY(str.send_len(true, false, true) == 10);
  VERIFY(!memcmp(str.get_str(false, false, true, false), c, 8));
  VERIFY(str.send_len(false, false, true) == 8);
  VERIFY(!memcmp(str.get_str(false, false, false, false), c, 7));
  VERIFY(str.send_len(false, false, false) == 7);
  VERIFY(!memcmp(str.get_str(true, true, true, false), uru_wide_with_null, 18));
  VERIFY(str.send_len(true, true, true) == 18);
  VERIFY(!memcmp(str.get_str(true, false, true, false), uru_with_null, 10));
  VERIFY(str.send_len(true, false, true) == 10);
  VERIFY(!memcmp(str.get_str(false, true, true, false), c_wide, 16));
  VERIFY(str.send_len(false, true, true) == 16);
  VERIFY(!memcmp(str.get_str(false, true, false, false), c_wide, 14));
  VERIFY(str.send_len(false, true, false) == 14);
  VERIFY(!memcmp(str.get_str(true, true, true, true), uru_wide_flip_with_null, 18));
  VERIFY(str.send_len(true, true, true) == 18);
  VERIFY(!memcmp(str.get_str(false, true, true, true), c_wide, 16));
  VERIFY(str.send_len(false, true, true) == 16);
  VERIFY(!memcmp(str.get_str(false, true, false, true), c_wide, 14));
  VERIFY(str.send_len(false, true, false) == 14);
  VERIFY(!memcmp(str.get_str(true, false, true, true), uru_flip_with_null, 10));
  VERIFY(str.send_len(true, false, true) == 10);
  VERIFY(!memcmp(str.get_str(false, false, false, true), c, 7));
  VERIFY(str.send_len(false, false, false) == 7);
  VERIFY(!memcmp(str.get_str(true, true, false, true), uru_wide_flip, 16));
  VERIFY(str.send_len(true, true, false) == 16);
  VERIFY(!memcmp(str.get_str(true, true, true, false), uru_wide_with_null, 18));
  VERIFY(str.send_len(true, true, true) == 18);
  VERIFY(!memcmp(str.get_str(false, false, false, true), c, 7));
  VERIFY(str.send_len(false, false, false) == 7);
  VERIFY(!memcmp(str.get_str(false, true, true, false), c_wide, 16));
  VERIFY(str.send_len(false, true, true) == 16);
  VERIFY(!memcmp(str.get_str(false, false, true, false), c, 8));
  VERIFY(str.send_len(false, false, true) == 8);
  VERIFY(!memcmp(str.get_str(false, true, false, true), c_wide, 14));
  VERIFY(str.send_len(false, true, false) == 14);
  VERIFY(!memcmp(str.get_str(true, true, true, false), uru_wide_with_null, 18));
  VERIFY(str.send_len(true, true, true) == 18);
  VERIFY(!memcmp(str.get_str(false, false, true, true), c, 8));
  VERIFY(str.send_len(false, false, true) == 8);
  VERIFY(!memcmp(str.get_str(true, false, false, true), uru_flip, 9));
  VERIFY(str.send_len(true, false, false) == 9);
  VERIFY(!memcmp(str.get_str(false, true, true, false), c_wide, 16));
  VERIFY(str.send_len(false, true, true) == 16);
  VERIFY(!memcmp(str.get_str(true, true, true, true), uru_wide_flip_with_null, 18));
  VERIFY(str.send_len(true, true, true) == 18);
  VERIFY(!memcmp(str.get_str(false, true, true, false), c_wide, 16));
  VERIFY(str.send_len(false, true, true) == 16);
  VERIFY(!memcmp(str.get_str(false, false, false, false), c, 7));
  VERIFY(str.send_len(false, false, false) == 7);
  VERIFY(!memcmp(str.get_str(true, false, true, true), uru_flip_with_null, 10));
  VERIFY(str.send_len(true, false, true) == 10);
  VERIFY(!memcmp(str.get_str(true, false, false, false), c_with_len, 9));
  VERIFY(str.send_len(true, false, false) == 9);
  VERIFY(!memcmp(str.get_str(false, false, false, false), c, 7));
  VERIFY(str.send_len(false, false, false) == 7);
  VERIFY(!memcmp(str.get_str(false, true, false, true), c_wide, 14));
  VERIFY(str.send_len(false, true, false) == 14);
  VERIFY(!memcmp(str.get_str(false, false, false, true), c, 7));
  VERIFY(str.send_len(false, false, false) == 7);
  VERIFY(!memcmp(str.get_str(true, false, true, false), uru_with_null, 10));
  VERIFY(str.send_len(true, false, true) == 10);
  VERIFY(!memcmp(str.get_str(true, false, true, true), uru_flip_with_null, 10));
  VERIFY(str.send_len(true, false, true) == 10);
  VERIFY(!memcmp(str.get_str(false, true, true, true), c_wide, 16));
  VERIFY(str.send_len(false, true, true) == 16);
  VERIFY(!memcmp(str.get_str(true, false, true, true), uru_flip_with_null, 10));
  VERIFY(str.send_len(true, false, true) == 10);
  VERIFY(!memcmp(str.get_str(true, false, false, true), uru_flip, 9));
  VERIFY(str.send_len(true, false, false) == 9);
  VERIFY(!memcmp(str.get_str(false, true, false, false), c_wide, 14));
  VERIFY(str.send_len(false, true, false) == 14);
  VERIFY(!memcmp(str.get_str(true, true, false, true), uru_wide_flip, 16));
  VERIFY(str.send_len(true, true, false) == 16);
  VERIFY(!memcmp(str.get_str(true, true, false, false), uru_wide, 16));
  VERIFY(str.send_len(true, true, false) == 16);
  VERIFY(!memcmp(str.get_str(true, false, false, true), uru_flip, 9));
  VERIFY(str.send_len(true, false, false) == 9);
  VERIFY(!memcmp(str.get_str(true, true, true, false), uru_wide_with_null, 18));
  VERIFY(str.send_len(true, true, true) == 18);
  VERIFY(!memcmp(str.get_str(true, true, false, true), uru_wide_flip, 16));
  VERIFY(str.send_len(true, true, false) == 16);
  VERIFY(!memcmp(str.get_str(false, true, true, false), c_wide, 16));
  VERIFY(str.send_len(false, true, true) == 16);
  VERIFY(!memcmp(str.get_str(true, true, false, false), uru_wide, 16));
  VERIFY(str.send_len(true, true, false) == 16);
  VERIFY(!memcmp(str.get_str(false, false, true, true), c, 8));
  VERIFY(str.send_len(false, false, true) == 8);
  VERIFY(!memcmp(str.get_str(true, false, false, false), c_with_len, 9));
  VERIFY(str.send_len(true, false, false) == 9);
  VERIFY(!memcmp(str.get_str(true, false, false, true), uru_flip, 9));
  VERIFY(str.send_len(true, false, false) == 9);
  VERIFY(!memcmp(str.get_str(false, true, true, true), c_wide, 16));
  VERIFY(str.send_len(false, true, true) == 16);
  VERIFY(!memcmp(str.get_str(true, true, true, true), uru_wide_flip_with_null, 18));
  VERIFY(str.send_len(true, true, true) == 18);
  VERIFY(!memcmp(str.get_str(false, false, false, true), c, 7));
  VERIFY(str.send_len(false, false, false) == 7);
  VERIFY(!memcmp(str.get_str(false, false, true, false), c, 8));
  VERIFY(str.send_len(false, false, true) == 8);
  VERIFY(!memcmp(str.get_str(true, false, false, false), c_with_len, 9));
  VERIFY(str.send_len(true, false, false) == 9);
  VERIFY(!memcmp(str.get_str(false, false, false, true), c, 7));
  VERIFY(str.send_len(false, false, false) == 7);
  VERIFY(!memcmp(str.get_str(true, false, false, true), uru_flip, 9));
  VERIFY(str.send_len(true, false, false) == 9);
  VERIFY(!memcmp(str.get_str(false, true, false, true), c_wide, 14));
  VERIFY(str.send_len(false, true, false) == 14);
  VERIFY(!memcmp(str.get_str(false, false, false, false), c, 7));
  VERIFY(str.send_len(false, false, false) == 7);
  VERIFY(!memcmp(str.get_str(true, true, false, false), uru_wide, 16));
  VERIFY(str.send_len(true, true, false) == 16);
  VERIFY(!memcmp(str.get_str(false, true, true, true), c_wide, 16));
  VERIFY(str.send_len(false, true, true) == 16);
  VERIFY(!memcmp(str.get_str(false, true, false, false), c_wide, 14));
  VERIFY(str.send_len(false, true, false) == 14);
  VERIFY(!memcmp(str.get_str(false, false, false, true), c, 7));
  VERIFY(str.send_len(false, false, false) == 7);
  VERIFY(!memcmp(str.get_str(true, false, false, false), c_with_len, 9));
  VERIFY(str.send_len(true, false, false) == 9);
  VERIFY(!memcmp(str.get_str(false, true, false, true), c_wide, 14));
  VERIFY(str.send_len(false, true, false) == 14);
  VERIFY(!memcmp(str.get_str(true, false, false, false), c_with_len, 9));
  VERIFY(str.send_len(true, false, false) == 9);
  VERIFY(!memcmp(str.get_str(false, true, false, false), c_wide, 14));
  VERIFY(str.send_len(false, true, false) == 14);
  VERIFY(!memcmp(str.get_str(false, false, true, false), c, 8));
  VERIFY(str.send_len(false, false, true) == 8);
  VERIFY(!memcmp(str.get_str(true, true, true, false), uru_wide_with_null, 18));
  VERIFY(str.send_len(true, true, true) == 18);
  VERIFY(!memcmp(str.get_str(false, true, false, false), c_wide, 14));
  VERIFY(str.send_len(false, true, false) == 14);
  VERIFY(!memcmp(str.get_str(false, true, true, true), c_wide, 16));
  VERIFY(str.send_len(false, true, true) == 16);
  VERIFY(!memcmp(str.get_str(true, false, false, true), uru_flip, 9));
  VERIFY(str.send_len(true, false, false) == 9);
  VERIFY(!memcmp(str.get_str(true, true, false, false), uru_wide, 16));
  VERIFY(str.send_len(true, true, false) == 16);
  VERIFY(!memcmp(str.get_str(true, false, true, false), uru_with_null, 10));
  VERIFY(str.send_len(true, false, true) == 10);
  VERIFY(!memcmp(str.get_str(false, false, false, false), c, 7));
  VERIFY(str.send_len(false, false, false) == 7);
  VERIFY(!memcmp(str.get_str(true, true, true, true), uru_wide_flip_with_null, 18));
  VERIFY(str.send_len(true, true, true) == 18);
  VERIFY(!memcmp(str.get_str(true, false, false, false), c_with_len, 9));
  VERIFY(str.send_len(true, false, false) == 9);
  VERIFY(!memcmp(str.get_str(true, true, true, true), uru_wide_flip_with_null, 18));
  VERIFY(str.send_len(true, true, true) == 18);
  VERIFY(!memcmp(str.get_str(false, true, false, false), c_wide, 14));
  VERIFY(str.send_len(false, true, false) == 14);
  VERIFY(!memcmp(str.get_str(true, false, false, false), c_with_len, 9));
  VERIFY(str.send_len(true, false, false) == 9);
  VERIFY(!memcmp(str.get_str(true, true, false, false), uru_wide, 16));
  VERIFY(str.send_len(true, true, false) == 16);
  VERIFY(!memcmp(str.get_str(false, false, false, false), c, 7));
  VERIFY(str.send_len(false, false, false) == 7);
  VERIFY(!memcmp(str.get_str(false, false, true, true), c, 8));
  VERIFY(str.send_len(false, false, true) == 8);
  VERIFY(!memcmp(str.get_str(true, false, true, false), uru_with_null, 10));
  VERIFY(str.send_len(true, false, true) == 10);
  VERIFY(!memcmp(str.get_str(true, true, true, true), uru_wide_flip_with_null, 18));
  VERIFY(str.send_len(true, true, true) == 18);
  VERIFY(!memcmp(str.get_str(false, true, false, true), c_wide, 14));
  VERIFY(str.send_len(false, true, false) == 14);
  VERIFY(!memcmp(str.get_str(false, false, true, true), c, 8));
  VERIFY(str.send_len(false, false, true) == 8);
}

void verify_send_lens(UruString &str) {
  VERIFY(str.send_len(false, false, false) == 7);
  VERIFY(str.send_len(true, false, false) == 9);
  VERIFY(str.send_len(false, false, true) == 8);
  VERIFY(str.send_len(true, false, true) == 10);
  VERIFY(str.send_len(false, true, false) == 14);
  VERIFY(str.send_len(true, true, false) == 16);
  VERIFY(str.send_len(true, true, true) == 18);
  VERIFY(str.send_len(false, true, true) == 16);
}

void verify_c_2nd_half(UruString &str, const u_char *ptr) {
  VERIFY(!memcmp(str.get_str(true, false, true), c_with_len_with_null, 10));
  VERIFY(str.m_altstr_size == 8);
  VERIFY(str.m_altstr != ptr);

  const u_char *keep = str.get_str(false, true, false);
  VERIFY(!memcmp(keep, c_wide, 14));
  VERIFY(str.m_altstr_size == 7);

  VERIFY(keep == str.get_str(true, true, false)+2);
  VERIFY(!memcmp(keep-2, c_wide_with_len, 16));

  keep = str.get_str(true, true, true);
  VERIFY(!memcmp(keep, c_wide_with_len_with_null, 18));
  VERIFY(str.m_altstr_size == 8);

  VERIFY(keep+2 == str.get_str(false, true, true));
  VERIFY(!memcmp(keep+2, c_wide, 16));
}

void verify_flip_2nd_half(UruString &str) {
  const u_char *keep = str.get_str(true, false, true, true);
  VERIFY(str.m_altstr_size == 8);
  VERIFY(!memcmp(keep, uru_flip_with_null, 10));

//  VERIFY(str.get_str(true, false, false, true) != keep); // gets reallocated at same addr
  VERIFY(!memcmp(str.get_str(true, false, false, true), uru_flip, 9));
  VERIFY(str.m_altstr_size == 7);
  keep = str.get_str(true, false, false, true);

  VERIFY(str.get_str(false, false, false, true) != keep+2);
  VERIFY(str.m_cstr_size == 7);

  keep = str.get_str(false, true, false, true);
  VERIFY(!memcmp(keep, c_wide, 14));
  VERIFY(str.m_altstr_size == 7);

  VERIFY(str.get_str(true, true, false, true) != keep+2);
  VERIFY(str.m_altstr_size == 7);
  VERIFY(!memcmp(str.get_str(true, true, false, true), uru_wide_flip, 16));

  keep = str.get_str(false, true, true, true);
  VERIFY(str.m_altstr_size == 8);
  VERIFY(!memcmp(keep, c_wide, 16));

  VERIFY(str.get_str(true, true, true, true) != keep+2);
  VERIFY(str.m_altstr_size == 8);
  VERIFY(!memcmp(str.get_str(true, true, true, true), uru_wide_flip_with_null, 18));
}

void verify_empty_send_lens(UruString &str) {
  VERIFY(str.send_len(false, false, false) == 0);
  VERIFY(str.send_len(true, false, false) == 2);
  VERIFY(str.send_len(false, false, true) == 1);
  VERIFY(str.send_len(true, false, true) == 3);
  VERIFY(str.send_len(false, true, false) == 0);
  VERIFY(str.send_len(true, true, false) == 2);
  VERIFY(str.send_len(true, true, true) == 4);
  VERIFY(str.send_len(false, true, true) == 2);
}

int main(int argc, char *argv[]) {
  full_mesh();

  // test make_cstr from various altstrs
  UruString c1(c, 8, false, false, false);
  VERIFY(!memcmp(c1.c_str(), c, 8));
  UruString c2(c_wide, 17, false, true, false);
  VERIFY(!memcmp(c2.c_str(), c, 8));
  UruString c3(c_with_len, 10, true, false, false);
  VERIFY(!memcmp(c3.c_str(), c, 8));
  UruString c4(c_with_len_with_null, 10, true, false, false);
  VERIFY(!memcmp(c4.c_str(), c, 8));
  UruString c5(c_wide_with_len, 17, true, true, false);
  VERIFY(!memcmp(c5.c_str(), c, 8));
  UruString c6(c_wide_with_len_with_null, 19, true, true, false);
  VERIFY(!memcmp(c6.c_str(), c, 8));
  UruString c7(uru_flip, 9, true, false, false);
  VERIFY(!memcmp(c7.c_str(), c, 8));
  UruString c8(uru_flip_with_null, 10, true, false, false);
  VERIFY(!memcmp(c8.c_str(), c, 8));
  UruString c9(uru_wide_flip, 16, true, true, false);
  VERIFY(!memcmp(c9.c_str(), c, 8));
  UruString c10(uru_wide_flip_with_null, 18, true, true, false);
  VERIFY(!memcmp(c10.c_str(), c, 8));

  // various other tests

  UruString the_c(c, 8, false, false, false);
  VERIFY(the_c.arrival_len() == 8);
  VERIFY(the_c.m_altstr == c);
  VERIFY(!memcmp(the_c.c_str(), c, 8));
  VERIFY(!memcmp(the_c.get_str(false, false, false), c, 8));
  VERIFY((char*)the_c.get_str(true, false, false)+2 == the_c.c_str());
  VERIFY(!memcmp(the_c.get_str(true, false, false), c_with_len, 10));

  verify_send_lens(the_c);
  verify_c_2nd_half(the_c, c);

  UruString copy_the_c(c, 8, false, false);
  VERIFY(copy_the_c.arrival_len() == 8);
  VERIFY(copy_the_c.m_cstr == NULL);
  VERIFY(the_c.m_altstr != c);
  VERIFY(!memcmp(copy_the_c.c_str(), c, 8));
  VERIFY(copy_the_c.get_str(true, false, false) == copy_the_c.m_altstr);
  copy_the_c.get_str(true, true, false); // force m_altstr wide
  VERIFY(copy_the_c.c_str() == (char*)copy_the_c.get_str(true, false, false)+2);
  VERIFY(copy_the_c.m_cstr == (char*)copy_the_c.get_str(true, false, false));

  verify_c_2nd_half(copy_the_c, c);

  UruString the_c_with_len(c_with_len, 9, true, false, false);
  VERIFY(the_c_with_len.arrival_len() == 9);
  VERIFY(the_c_with_len.m_altstr == c_with_len);
  VERIFY(!memcmp(the_c_with_len.c_str(), c, 8));
  VERIFY(the_c_with_len.get_str(false, false, false) == c_with_len+2);
  VERIFY(the_c_with_len.get_str(true, false, false) == c_with_len);
  VERIFY((char*)the_c_with_len.get_str(false, false, true) == the_c_with_len.c_str());

  verify_send_lens(the_c_with_len);
  verify_c_2nd_half(the_c_with_len, c_with_len);

  UruString copy_the_c_with_len(c_with_len, 9, true, false);
  VERIFY(copy_the_c_with_len.arrival_len() == 9);
  VERIFY(copy_the_c_with_len.m_altstr == NULL);
  VERIFY(copy_the_c_with_len.m_cstr != c_with_len_);
  VERIFY(!memcmp(copy_the_c_with_len.c_str(), c, 8));
  VERIFY(!memcmp(copy_the_c_with_len.c_str(), copy_the_c_with_len.get_str(true, false, true)+2, 8));
  verify_c_2nd_half(copy_the_c_with_len, c_with_len);

  UruString the_c_with_len_with_null(c_with_len_with_null, 10, true, false, false);
  VERIFY(the_c_with_len_with_null.arrival_len() == 10);
  VERIFY(the_c_with_len_with_null.m_altstr == c_with_len_with_null);
  VERIFY(the_c_with_len_with_null.get_str(true, false, true) == c_with_len_with_null);
  VERIFY(!memcmp(the_c_with_len_with_null.c_str(), c, 8));
  verify_send_lens(the_c_with_len_with_null);

  VERIFY((char*)the_c_with_len_with_null.get_str(false, false, false) == the_c_with_len_with_null.c_str());
  VERIFY(!memcmp(the_c_with_len_with_null.get_str(false, false, false), c, 8));

  VERIFY((char*)the_c_with_len_with_null.get_str(true, false, false)+2 == the_c_with_len_with_null.c_str());
  VERIFY(!memcmp(the_c_with_len_with_null.get_str(true, false, false), c_with_len, 10));

  VERIFY(the_c_with_len_with_null.get_str(false, false, true) == (u_char*)the_c_with_len_with_null.m_cstr+2);
  VERIFY(!memcmp(the_c_with_len_with_null.get_str(false, false, true), c, 8));

  verify_c_2nd_half(the_c_with_len_with_null, c_with_len_with_null);

  UruString copy_the_c_with_len_with_null(c_with_len_with_null, 10, true, false);
  VERIFY(copy_the_c_with_len_with_null.arrival_len() == 10);
  VERIFY(copy_the_c_with_len_with_null.m_altstr != c_with_len_with_null+2);
  VERIFY(copy_the_c_with_len_with_null.c_str() != c_with_len_with_null_+2);
  VERIFY(!memcmp(copy_the_c_with_len_with_null.c_str(), c, 8));
  VERIFY(!memcmp(copy_the_c_with_len_with_null.c_str(), copy_the_c_with_len_with_null.get_str(true, false, true)+2, 8));
  verify_c_2nd_half(copy_the_c_with_len_with_null, c_with_len_with_null);

  UruString the_c_with_extra(c_with_extra, 10, false, false, false);
  VERIFY(the_c_with_extra.arrival_len() == 8);
  VERIFY(the_c_with_extra.m_altstr == c_with_extra);
  VERIFY(!memcmp(the_c_with_extra.c_str(), c, 8));
  verify_send_lens(the_c_with_extra);
  verify_c_2nd_half(the_c_with_extra, c);

  UruString copy_the_c_with_extra(c_with_extra, 10, false, false);
  VERIFY(copy_the_c_with_extra.arrival_len() == 8);
  VERIFY(copy_the_c_with_extra.m_cstr == NULL);
  VERIFY(copy_the_c_with_extra.m_altstr != c_with_extra);
  VERIFY(!memcmp(copy_the_c_with_extra.c_str(), c, 8));
  verify_c_2nd_half(copy_the_c_with_extra, c);

  // uru == c_with_len

  // uru_with_null == c_with_len_with_null

  UruString the_uru_with_extra(uru_with_extra, 12, true, false, false);
  VERIFY(the_uru_with_extra.arrival_len() == 9);
  VERIFY(the_uru_with_extra.m_altstr == uru_with_extra);
  VERIFY(!memcmp(the_uru_with_extra.c_str(), c, 8));
  verify_send_lens(the_uru_with_extra);
  verify_c_2nd_half(the_uru_with_extra, uru);

  UruString copy_the_uru_with_extra(uru_with_extra, 12, true, false);
  VERIFY(copy_the_uru_with_extra.arrival_len() == 9);
  VERIFY(copy_the_uru_with_extra.m_altstr != uru_with_extra);
  VERIFY(!memcmp(copy_the_uru_with_extra.c_str(), c, 8));
  verify_c_2nd_half(copy_the_uru_with_extra, uru);

  UruString the_uru_flip(uru_flip, 9, true, false, false);
  VERIFY(the_uru_flip.arrival_len() == 9);
  VERIFY(the_uru_flip.m_altstr == uru_flip);
  VERIFY(the_uru_flip.get_str(true, false, false, true) == uru_flip);
  VERIFY(!memcmp(the_uru_flip.c_str(), c, 8));
  verify_send_lens(the_uru_flip);

  VERIFY((char*)the_uru_flip.get_str(false, false, false) == the_uru_flip.c_str());
  VERIFY(!memcmp(the_uru_flip.get_str(false, false, false), c, 8));
  VERIFY((char*)the_uru_flip.get_str(false, false, false, true) == the_uru_flip.c_str());

  VERIFY((char*)the_uru_flip.get_str(false, false, true) == the_uru_flip.c_str());
  VERIFY((char*)the_uru_flip.get_str(false, false, true, true) == the_uru_flip.c_str());

  VERIFY((char*)the_uru_flip.get_str(true, false, false)+2 == the_uru_flip.c_str());
  VERIFY(!memcmp(the_uru_flip.get_str(true, false, false), c_with_len, 9));

  verify_c_2nd_half(the_uru_flip, uru_flip);
  verify_flip_2nd_half(the_uru_flip);

  UruString copy_the_uru_flip(uru_flip, 9, true, false);
  VERIFY(copy_the_uru_flip.arrival_len() == 9);
  VERIFY(copy_the_uru_flip.m_altstr != uru_flip);
  VERIFY(!memcmp(copy_the_uru_flip.c_str(), c, 8));
  VERIFY(!memcmp(copy_the_uru_flip.get_str(true, false, false, true), uru_flip, 9));
  VERIFY(copy_the_uru_flip.get_str(true, false, false, true) == copy_the_uru_flip.m_altstr);
  verify_c_2nd_half(copy_the_uru_flip, uru_flip);
  verify_flip_2nd_half(copy_the_uru_flip);



  UruString::setup_thread_iconv();



  UruString the_uru_flip_with_null(uru_flip_with_null, 10, true, false, false);
  UruString copy_the_uru_flip_with_null(uru_flip_with_null, 10, true, false);

  UruString the_c_wide(c_wide, 16, false, true, false);
  verify_c_2nd_half(the_c_wide, c_wide);
  UruString copy_the_c_wide(c_wide, 16, false, true);
  verify_c_2nd_half(copy_the_c_wide, c_wide);
  UruString the_c_wide_with_len(c_wide_with_len, 18, true, true, false);
  verify_c_2nd_half(the_c_wide_with_len, c_wide_with_len);
  UruString copy_the_c_wide_with_len(c_wide_with_len, 18, true, true);
  verify_c_2nd_half(copy_the_c_wide_with_len, c_wide_with_len);
  UruString the_c_wide_with_len_with_null(c_wide_with_len_with_null, 20, true, true, false);
  verify_c_2nd_half(the_c_wide_with_len_with_null, c_wide_with_len_with_null);
  UruString copy_the_c_wide_with_len_with_null(c_wide_with_len_with_null, 20, true, true);
  verify_c_2nd_half(copy_the_c_wide_with_len_with_null, c_wide_with_len_with_null);
  UruString the_c_wide_with_extra(c_wide_with_extra, 24, false, true, false);
  verify_c_2nd_half(the_c_wide_with_extra, c_wide_with_extra);
  UruString copy_the_c_wide_with_extra(c_wide_with_extra, 24, false, true);
  verify_c_2nd_half(copy_the_c_wide_with_extra, c_wide_with_extra);
  UruString the_uru_wide(uru_wide, 16, true, true, false);
  verify_c_2nd_half(the_uru_wide, uru_wide);
  UruString copy_the_uru_wide(uru_wide, 16, true, true);
  verify_c_2nd_half(copy_the_uru_wide, uru_wide);
  UruString the_uru_wide_with_null(uru_wide_with_null, 18, true, true, false);
  verify_c_2nd_half(the_uru_wide_with_null, uru_wide_with_null);
  UruString copy_the_uru_wide_with_null(uru_wide_with_null, 18, true, true);
  verify_c_2nd_half(copy_the_uru_wide_with_null, uru_wide_with_null);
  UruString the_uru_wide_with_extra(uru_wide_with_extra, 22, true, true, false);
  verify_c_2nd_half(the_uru_wide_with_extra, uru_wide_with_extra);
  UruString copy_the_uru_wide_with_extra(uru_wide_with_extra, 22, true, true);
  verify_c_2nd_half(copy_the_uru_wide_with_extra, uru_wide_with_extra);
  UruString the_uru_wide_flip(uru_wide_flip, 16, true, true, false);
  verify_c_2nd_half(the_uru_wide_flip, uru_wide_flip);
  UruString copy_the_uru_wide_flip(uru_wide_flip, 16, true, true);
  verify_c_2nd_half(copy_the_uru_wide_flip, uru_wide_flip);
  UruString the_uru_wide_flip_with_null(uru_wide_flip_with_null, 18, true, true, false);
  verify_c_2nd_half(the_uru_wide_flip_with_null, uru_wide_flip_with_null);
  UruString copy_the_uru_wide_flip_with_null(uru_wide_flip_with_null, 18, true, true);
  verify_c_2nd_half(copy_the_uru_wide_flip_with_null, uru_wide_flip_with_null);

  


  // I'm sure there is more I could do here, but I'm tired.

  // test other constructors
  UruString s1(c_, false);
  VERIFY(s1.m_altstr == c);
  VERIFY(s1.send_len(true, true, false) == 16);
  VERIFY(!memcmp(s1.m_altstr, c_wide_with_len, 14));
  verify_c_2nd_half(s1, c);
  verify_flip_2nd_half(s1);
  std::string str_c = c_;
  UruString s2(str_c, false);
  VERIFY(s2.send_len(true, true, false) == 16);
  VERIFY(!memcmp(s2.m_altstr, c_wide_with_len, 14));
  verify_c_2nd_half(s2, (const u_char*)str_c.c_str());
  verify_flip_2nd_half(s2);
  UruString s3(c_);
  VERIFY(s3.m_cstr != c_);
  VERIFY(s3.m_altstr == NULL);
  VERIFY(s3.send_len(true, true, false) == 16);
  VERIFY(!memcmp(s3.m_altstr, c_wide_with_len, 14));
  verify_c_2nd_half(s3, c);
  verify_flip_2nd_half(s3);
  UruString s4(str_c);
  VERIFY(s4.send_len(true, true, false) == 16);
  VERIFY(!memcmp(s4.m_altstr, c_wide_with_len, 14));
  verify_c_2nd_half(s4, (const u_char*)str_c.c_str());
  verify_flip_2nd_half(s4);
  UruString s5(c_with_len, -1, true, false, false);
  VERIFY(s5.arrival_len() == 9);
  verify_c_2nd_half(s5, c_with_len);
  verify_flip_2nd_half(s5);

  // test equality
  UruString no_len(c, 8, false, false, false);
  UruString has_len(c_with_len, 9, true, false, false);
  UruString uru_str(uru, 9, true, false, false);
  UruString uru_str_wide(uru_wide, 16, true, true, false);
  UruString flip(uru_flip, 9, true, false, false);
  UruString with_null(uru_with_null, 10, true, false, false);
  // equality tests will create c_str
  VERIFY(no_len == c_);
  VERIFY(no_len == with_null);
  VERIFY(has_len == with_null);
  VERIFY(uru_str == with_null);
  VERIFY(flip == with_null);
  VERIFY(uru_str_wide == with_null);
  UruString blank;
  VERIFY(uru_str != blank);
  VERIFY(!(no_len == blank));
  VERIFY(blank != c_);
  VERIFY(blank == "");
  VERIFY(blank == (char*)NULL);
  UruString e("");
  VERIFY(e == "");


  // test empty strings
  UruString the_empty_c(empty_c, 2, false, false, false);
  VERIFY(the_empty_c.arrival_len() == 1);
  VERIFY(the_empty_c.m_altstr == empty_c);
  VERIFY(strlen(the_empty_c.c_str()) == 0);
  verify_empty_send_lens(the_empty_c);
  UruString copy_the_empty_c(empty_c, 2, false, false);
  VERIFY(copy_the_empty_c.arrival_len() == 1);
  VERIFY(strlen(the_empty_c.c_str()) == 0);
  verify_empty_send_lens(copy_the_empty_c);
  UruString the_empty_c_with_len(empty_c_with_len, 2, true, false);
  VERIFY(the_empty_c_with_len.arrival_len() == 2);
  verify_empty_send_lens(the_empty_c_with_len);
  UruString the_empty_c_with_extra(empty_c_with_extra, 8, false, false);
  VERIFY(the_empty_c_with_extra.arrival_len() == 1);
  verify_empty_send_lens(the_empty_c_with_extra);
  UruString the_empty_uru(empty_uru, 3, true, false);
  VERIFY(the_empty_uru.arrival_len() == 2);
  verify_empty_send_lens(the_empty_uru);
  UruString the_empty_uru_with_extra(empty_uru_with_extra, 10, true, false);
  VERIFY(the_empty_uru_with_extra.arrival_len() == 2);
  verify_empty_send_lens(the_empty_uru_with_extra);
  UruString the_empty_c_wide(empty_c_wide, 3, false, true);
  VERIFY(the_empty_c_wide.arrival_len() == 2);
  verify_empty_send_lens(the_empty_c_wide);
  UruString the_empty_c_wide_with_len(empty_c_wide_with_len, 5, true, true);
  VERIFY(the_empty_c_wide_with_len.arrival_len() == 2);
  verify_empty_send_lens(the_empty_c_wide_with_len);
  UruString the_empty_uru_wide(empty_uru_wide, 3, true, true);
  VERIFY(the_empty_uru_wide.arrival_len() == 2);
  verify_empty_send_lens(the_empty_uru_wide);
  UruString the_empty_uru_wide_with_extra(empty_uru_wide_with_extra, 16, true, true);
  VERIFY(the_empty_uru_wide_with_extra.arrival_len() == 2);
  verify_empty_send_lens(the_empty_uru_wide_with_extra);


  // test empty constructor
  UruString *empty = new UruString();
  VERIFY(strlen(empty->c_str()) == 0);
  delete empty;
  UruString empty2;
  VERIFY(!memcmp("\0\0", empty2.get_str(true, true, false), 2));
  VERIFY(!memcmp("\1\0\0\0", empty2.get_str(true, true, true), 4));


  // test conversions where it *isnt'* 1 UTF-8 byte to 2 UTF-16 bytes
  UruString u82_u162(utf8_2_utf16_2, 3, false, false, false);
  VERIFY(!memcmp(u82_u162.get_str(false, true, false), utf16_2_utf8_2, 2));
  VERIFY(u82_u162.send_len(false, true, false) == 2);
  VERIFY(!memcmp(u82_u162.get_str(false, true, true), utf16_2_utf8_2, 4));
  VERIFY(u82_u162.send_len(false, true, true) == 4);
  VERIFY(u82_u162.get_str(false, false, false) != utf8_2_utf16_2);
  UruString u162_u82(utf16_2_utf8_2, 4, false, true, false);
  VERIFY(!memcmp(u162_u82.get_str(false, false, false), utf8_2_utf16_2, 2));
  VERIFY(u162_u82.send_len(false, false, false) == 2);
  VERIFY(!memcmp(u162_u82.get_str(false, false, true), utf8_2_utf16_2, 3));
  VERIFY(u162_u82.send_len(false, false, true) == 3);
  VERIFY(u162_u82.get_str(false, true, false) == utf16_2_utf8_2);
  UruString u83_u162(utf8_3_utf16_2, 4, false, false, false);
  VERIFY(!memcmp(u83_u162.get_str(false, true, false), utf16_2_utf8_3, 2));
  VERIFY(u83_u162.send_len(false, true, false) == 2);
  VERIFY(!memcmp(u83_u162.get_str(false, true, true), utf16_2_utf8_3, 4));
  VERIFY(u83_u162.send_len(false, true, true) == 4);
  VERIFY(u83_u162.get_str(false, false, false) != utf8_3_utf16_2);
  UruString u162_u83(utf16_2_utf8_3, 4, false, true, false);
  VERIFY(!memcmp(u162_u83.get_str(false, false, false), utf8_3_utf16_2, 3));
  VERIFY(u162_u83.send_len(false, false, false) == 3);
  VERIFY(!memcmp(u162_u83.get_str(false, false, true), utf8_3_utf16_2, 4));
  VERIFY(u162_u83.send_len(false, false, true) == 4);
  VERIFY(u162_u83.get_str(false, true, false) == utf16_2_utf8_3);
  UruString u84_u164(utf8_4_utf16_4, 5, false, false, false);
  VERIFY(!memcmp(u84_u164.get_str(false, true, false), utf16_4_utf8_4, 4));
  VERIFY(u84_u164.send_len(false, true, false) == 4);
  VERIFY(!memcmp(u84_u164.get_str(false, true, true), utf16_4_utf8_4, 6));
  VERIFY(u84_u164.send_len(false, true, true) == 6);
  VERIFY(u84_u164.get_str(false, false, false) != utf8_4_utf16_4);
  UruString u164_u84(utf16_4_utf8_4, 6, false, true, false);
  VERIFY(!memcmp(u164_u84.get_str(false, false, false), utf8_4_utf16_4, 4));
  VERIFY(u164_u84.send_len(false, false, false) == 4);
  VERIFY(!memcmp(u164_u84.get_str(false, false, true), utf8_4_utf16_4, 5));
  VERIFY(u164_u84.send_len(false, false, true) == 5);
  VERIFY(u164_u84.get_str(false, true, false) == utf16_4_utf8_4);

  VERIFY(u162_u82 == u82_u162);
  VERIFY(u162_u83 == u83_u162);
  VERIFY(u164_u84 == u84_u164);

  UruString::clear_thread_iconv();

  // bugs!
  UruString altonly(c_with_len_with_null, -1, true, false, true);
  VERIFY(altonly.arrival_len() == 10);
  VERIFY(altonly.m_cstr == NULL);
  UruString altcopy(altonly);
  UruString altassign = altonly;
  UruString conly;
  conly = c;
  UruString ccopy(conly);
  UruString cassign = conly;
  VERIFY(conly.m_altstr == NULL);
  VERIFY(conly == altonly);
  VERIFY(conly.m_altstr == NULL);
  VERIFY(altonly == conly);
  VERIFY(!memcmp(altcopy.get_str(false, true, true), c_wide, 16));
  VERIFY(!memcmp(altassign.get_str(false, true, true), c_wide, 16));
  VERIFY(!memcmp(ccopy.get_str(true, true, false), uru_wide, 16));
  VERIFY(!memcmp(cassign.get_str(true, true, false), uru_wide, 16));
}
