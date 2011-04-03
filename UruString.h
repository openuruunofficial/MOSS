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
 * An UruString represents all kinds of strings seen in network messages.
 * This way we can read from the message the particular way required, but
 * work with plain C strings, then write to the message the particular way
 * required. It does mean there are lots of constructor options, but then
 * there is a uniform interface for handling the strings, which should help
 * with all the conversions being done.
 */

#ifndef _URU_STRING_H_
#define _URU_STRING_H_

//#include <iconv.h>
//
//#include <string>
//
//#include "machine_arch.h"


class UruString {
public:
  // The constructor can copy the string data to local storage (default), or
  // not. Strings may be wide (UTF-16LE) or not, and strings may have a 16-bit
  // length field or not. If buflen is < 0, it is assumed that length checking
  // has already been done.
  UruString(const u_char *inbuf, int buflen,
	    bool has_length, bool is_wide,
	    bool copy=true);

  // If "other" has a pointer to a non-copied string, expect the new
  // UruString to as well, unless copy is forced to true. If "other"
  // has a pointer to a copied string, the new UruString will have its
  // own copy (the "copy" paramater is ignored).
  UruString(const UruString &other, bool copy=false);
  // As the input string is never written to, it *is* safe not to copy
  // const strings such as literals...
  UruString(const char *c_str, bool copy=true);
  // ...but you almost certainly want to copy std::strings unless you
  // are certain that string object will not rellocate what's pointed
  // by c_str(), which it is liable to do if any change is made
  // (including, of course, the fact that copies of the string don't
  // preserve the original's memory location).
  UruString(const std::string &str, bool copy=true);
  // Makes an "empty" string (size zero).
  UruString();

  UruString & operator=(const UruString &other);
  // these assignment operators take C strings (no length, one-byte chars,
  // null terminator) and copy the data (note: arrival_len will be 0)
  UruString & operator=(const char *c_str);
  UruString & operator=(const u_char *c_str);
  // this copies as well
  UruString & operator=(const std::string &str);
  ~UruString();

  // this returns the total buffer length the string occupied in the
  // incoming message
  size_t arrival_len() const { return m_arrival_len; }

  bool operator==(const UruString &other);
  bool operator==(const char *c_str);
  bool operator!=(const UruString &other) { return !(*this == other); }
  bool operator!=(const char *c_str) { return !(*this == c_str); }

  // this returns a pointer to a null-terminated string with no length
  const char * const c_str();
  // this returns a pointer to a string in contiguous storage with the
  // requested characteristics (superset of c_str())
  // NOTE: if this is called more than once, the first string will be
  // clobbered and the pointer invalidated. Copy the UruString object if
  // you need to do two non C-string conversions at the same time.
  const u_char * const get_str(bool include_length, bool as_wide,
			       bool include_null, bool bitflip=false);

  // this function returns the total buffer length required to send
  // the string with the requested characteristics
  size_t send_len(bool include_length, bool as_wide, bool include_null);

  // convenience function
  size_t strlen() { return send_len(false, false, false); }

  // Each thread that may do a character conversion should call
  // these methods to set up per-thread iconv data.
  static void setup_thread_iconv();
  static void clear_thread_iconv();

protected:
  typedef enum {
    C = 0,
    WIDE = 1,
    HAS_LEN = 2,
    BITFLIP = 4,
    NO_NULL = 8
  } characteristics_t;

  // look up an iconv_t for the current thread (may return -1 if none)
  static iconv_t get_thread_iconv(bool towide);
  // unconditionally build a "c string" (UTF-8)
  void make_cstr();

#ifdef TEST_CODE
public:
#endif
  // strings in m_cstr always have the 2-byte length field and a null
  // terminator -- effective type: C|HAS_LEN|NO_NULL (terminator not in length)
  char *m_cstr;
  u_char *m_altstr;
  int m_alt_type;
  // strings not owned are not deleted in the destructor
  bool m_owns_cstr;
  bool m_owns_altstr;
  // length values
  size_t m_arrival_len;
  size_t m_cstr_size;
  size_t m_altstr_size;
};

/*
 * data representation:
 *
 * m_cstr is 2 bytes of little-endian length, then UTF-8 data, then a null.
 * The length is in BYTES (not characters, which may be more than one byte).
 *
 * m_altstr depends on the characteristics. If HAS_LEN then the first 2 bytes
 * are little-endian length. Otherwise there is no length. If WIDE, the length
 * is in 16-BITS (not characters, not bytes). If !WIDE the length is in BYTES.
 * Next, if WIDE, there is UTF-16LE data, else it is UTF-8. No null is
 * expected though it may be present if it is counted in the length.
 *
 * No lengths include the null unless a caller provides or requests a string
 * with the 2-byte length that in turn includes a null.
 */

#endif /* _URU_STRING_H_ */
