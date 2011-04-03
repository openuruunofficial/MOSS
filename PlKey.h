/* -*- c++ -*- */

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
 * It should not be difficult to know what a plKey is. :-)
 * (AKA "uru object descriptor")
 */

#ifndef _PLKEY_H_
#define _PLKEY_H_

//#include "machine_arch.h"
//
//#include "UruString.h"

class PlKey {
public:
  // read a plKey into the object from the contents of the buffer,
  // returning how many bytes were read
  // throws truncated_message
  u_int read_in(const u_char *buf, size_t buflen);

  u_int send_len() const;
  u_int write_out(u_char *buf, size_t buflen, bool bitflip=true) const;

  // since I wanted to put this class in a union, I can't have a
  // destructor so I must depend on calling code to clean up
  void delete_name() { if (m_name) delete m_name; }

  // format plKey for logging
  // returned value must be free()d
  char * format();

  // operators
  bool operator==(const PlKey &other) const;
  bool operator!=(const PlKey &other) { return !(*this == other); }

  // "null" keys show up in a few places
  void make_null();
  static u_int null_send_len() { return 15; }
  static u_int write_null_key(u_char *buf, size_t buflen);

  uint8_t m_flags;
  uint8_t m_extra;
  uint16_t m_pagetype;
  uint16_t m_objtype;
  uint32_t m_pageid;
  uint32_t m_prpindex;
  uint32_t m_index;
  uint32_t m_clientid;
  UruString *m_name;
};

#endif /* _PLKEY_H_ */
