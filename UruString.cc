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
 * Do not mess with this file unless you are masochistic.
 * If you mess with the file, the test program "UruString_tester" must
 * still run without printing anything when you are done.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#ifdef HAVE_ASSERT_H
#include <assert.h>
#endif
#ifdef TEST_CODE
#include <stdio.h>
#endif

#include <pthread.h>
#include <iconv.h>

#include <string>
#include <map>

#include "machine_arch.h"

#include "UruString.h"

UruString::UruString(const u_char *inbuf, int buflen,
		     bool has_length, bool is_wide,
		     bool copy)
  : m_cstr(NULL), m_altstr(NULL), m_alt_type(NO_NULL),
    m_owns_cstr(false), m_owns_altstr(false), m_arrival_len(0), m_cstr_size(0),
    m_altstr_size(0)
{
  size_t num_chars = 0;
  bool dont_count_null = false;
  if (is_wide) {
    m_alt_type |= WIDE;
  }
  if (has_length) {
    if (buflen >= 0 && buflen < 2) {
      m_arrival_len = buflen;
      return;
    }
    m_alt_type |= HAS_LEN;
    num_chars = read16(inbuf, 0);
    if ((num_chars & 0xF000) == 0xF000) {
      m_alt_type |= BITFLIP;
    }
    // I don't know whether the client will consider surrogate pairs as
    // 1 or 2 in the count it provides here. We're going to assume it counts
    // as 2; to get 1 they would have to use _mbstrlen().
    num_chars &= 0x0FFF;
    if (is_wide) {
      m_arrival_len = 2 + (2*num_chars);
    }
    else {
      m_arrival_len = 2 + num_chars;
    }
    if (buflen >= 0 && m_arrival_len > (u_int)buflen) {
      // the message has been truncated...
#ifdef TEST_CODE
      printf("arrival_len > buflen: %u > %d\n", m_arrival_len, buflen);
#endif
      m_arrival_len = (u_int)buflen;
      if (is_wide) {
	num_chars = ((u_int)buflen - 2) / 2;
      }
      else {
	num_chars = (u_int)buflen - 2;
      }
    }
    if (num_chars > 0) {
      // see if it's already null-terminated
      u_int last_char = num_chars-1;
      u_char end = ((m_alt_type & BITFLIP) ? '\xff' : '\0');
      if ((is_wide && inbuf[2+(2*last_char)] == end 
	           && inbuf[2+(2*last_char)+1] == end)
	  || (!is_wide && inbuf[2+last_char] == end)) {
	m_alt_type &= ~NO_NULL;
	dont_count_null = true;
      }
    }
  }
  else {
    // look for null terminator
    while (buflen < 0 || m_arrival_len < (u_int)buflen) {
      if (inbuf[m_arrival_len] == '\0'
	  && (!is_wide || inbuf[m_arrival_len+1] == '\0')) {
	break;
      }
      if (is_wide) {
	m_arrival_len += 2;
      }
      else {
	m_arrival_len++;
      }
    }
    if (buflen >= 0 && m_arrival_len >= (u_int)buflen) {
      // the message has been truncated...
#ifdef TEST_CODE
      printf("located arrival_len > buflen: %u > %d\n", m_arrival_len, buflen);
#endif
      m_arrival_len = (size_t)buflen;
      if (is_wide) {
	num_chars = (size_t)buflen / 2;
      }
      else {
	num_chars = (size_t)buflen;
      }
    }
    else if (is_wide) {
      num_chars = m_arrival_len / 2;
      if (buflen >= 0 && m_arrival_len + 2 > (u_int)buflen) {
	// this means m_arrival_len + 1 == buflen; the string is truncated in
	// the middle of the last character
	m_arrival_len = (u_int)buflen;
      }
      else {
	m_arrival_len += 2;
      }
    }
    else { // !is_wide
      num_chars = m_arrival_len;
      m_arrival_len++;
    }
  }

  if (m_alt_type == (C|HAS_LEN) && !copy && !dont_count_null) {
    m_cstr = const_cast<char*>((const char*)inbuf);
    m_cstr_size = num_chars;
  }
  else if ((m_alt_type == C || m_alt_type == (C|HAS_LEN|NO_NULL)) && copy) {
    if (dont_count_null) {
      // this means we had input with length and the null included in
      // the length
      num_chars -= 1;
    }
    m_cstr = new char[num_chars+3];
    m_owns_cstr = true;
    write16(m_cstr, 0, num_chars);
    if (has_length) {
      memcpy(m_cstr+2, inbuf+2, num_chars);
    }
    else {
      memcpy(m_cstr+2, inbuf, num_chars);
    }
    m_cstr[2+num_chars] = '\0';
    m_cstr_size = num_chars;
  }
  else {
    if (copy) {
      u_int byte_ct = m_arrival_len;
      if (!has_length) {
	byte_ct += 2;
      }
      m_altstr = new u_char[byte_ct];
      m_owns_altstr = true;
      m_alt_type |= (HAS_LEN|NO_NULL);
      if (dont_count_null) {
	num_chars -= 1;
      }
      u_int chars = num_chars;
      if (m_alt_type & BITFLIP) {
	chars |= 0xF000;
      }
      write16(m_altstr, 0, chars);
      if (has_length) {
	memcpy(m_altstr+2, inbuf+2, m_arrival_len-2);
      }
      else {
	memcpy(m_altstr+2, inbuf, m_arrival_len);
      }
    }
    else {
      m_altstr = const_cast<u_char*>(inbuf);
    }
    m_altstr_size = num_chars;
  }
}

UruString::UruString(const UruString &other, bool copy)
  : m_cstr(NULL), m_altstr(NULL), m_alt_type(other.m_alt_type),
    m_owns_cstr(false), m_owns_altstr(false),
    m_arrival_len(other.m_arrival_len), m_cstr_size(other.m_cstr_size),
    m_altstr_size(other.m_altstr_size)
{
  if (other.m_cstr && (other.m_owns_cstr || copy)) {
    m_cstr = new char[m_cstr_size+3];
    m_owns_cstr = true;
    memcpy(m_cstr, other.m_cstr, m_cstr_size+3);
  }
  else {
    m_cstr = other.m_cstr;
  }
  if (other.m_altstr && (other.m_owns_altstr || copy)) {
    if (m_cstr) {
      // note we don't copy the altstr if we have the cstr (let the altstr be
      // regenerated if needed)
      m_alt_type = C;
    }
    else {
      // we don't have a C string so we have to copy the owned altstr

      // we can't call send_len() in a constructor because the object is not
      // fully built yet, so compute the length by hand here
      size_t altlen = m_altstr_size;
      if (!(m_alt_type & NO_NULL)) {
	altlen += 1;
      }
      if (m_alt_type & WIDE) {
	altlen *= 2;
      }
      if (m_alt_type & HAS_LEN) {
	altlen += 2;
      }
      m_altstr = new u_char[altlen];
      m_owns_altstr = true;
      memcpy(m_altstr, other.m_altstr, altlen);
    }
  }
  else {
    m_altstr = other.m_altstr;
  }
}

UruString::UruString(const char *c_str, bool copy)
  : m_cstr(NULL), m_altstr(NULL), m_alt_type(C), m_owns_cstr(false),
    m_owns_altstr(false), m_arrival_len(0), m_cstr_size(0), m_altstr_size(0)
{
  if (!c_str) {
    return;
  }
  m_cstr_size = ::strlen(c_str);
  if (copy) {
    m_cstr = new char[m_cstr_size+3];
    m_owns_cstr = true;
    write16(m_cstr, 0, m_cstr_size);
    memcpy(m_cstr+2, c_str, m_cstr_size+1);
  }
  else {
    m_alt_type = C|NO_NULL;
    m_altstr = const_cast<u_char*>((const u_char*)c_str);
    m_altstr_size = m_cstr_size;
  }
}

UruString::UruString(const std::string &str, bool copy)
  : m_cstr(NULL), m_altstr(NULL), m_alt_type(C), m_owns_cstr(false),
    m_owns_altstr(false), m_arrival_len(0)
{
  m_cstr_size = str.size();
  if (copy) {
    m_cstr = new char[m_cstr_size+3];
    m_owns_cstr = true;
    write16(m_cstr, 0, m_cstr_size);
    memcpy(m_cstr+2, str.c_str(), m_cstr_size+1);
  }
  else {
    m_alt_type = C|NO_NULL;
    m_altstr = const_cast<u_char*>((const u_char*)str.c_str());
    m_altstr_size = m_cstr_size;
  }
}

UruString & UruString::operator=(const UruString &other) {
  if (this == &other) {
    return *this;
  }
  if (m_owns_cstr) {
    m_owns_cstr = false;
    delete[] m_cstr;
  }
  if (m_owns_altstr) {
    m_owns_altstr = false;
    delete[] m_altstr;
  }
  m_arrival_len = other.m_arrival_len;
  m_cstr_size = other.m_cstr_size;
  if (other.m_owns_cstr) {
    m_cstr = new char[m_cstr_size+3];
    m_owns_cstr = true;
    memcpy(m_cstr, other.m_cstr, m_cstr_size+3);
  }
  else {
    m_cstr = other.m_cstr;
  }
  if (other.m_owns_altstr) {
    m_alt_type = other.m_alt_type;
    m_altstr_size = other.m_altstr_size;
    // we can't call send_len() here because the object is not fully
    // built yet (and other is const), so compute the length by hand here
    size_t altlen = m_altstr_size;
    if (!(m_alt_type & NO_NULL)) {
      altlen += 1;
    }
    if (m_alt_type & WIDE) {
      altlen *= 2;
    }
    if (m_alt_type & HAS_LEN) {
      altlen += 2;
    }
    m_altstr = new u_char[altlen];
    m_owns_altstr = true;
    memcpy(m_altstr, other.m_altstr, altlen);
  }
  else {
    m_alt_type = C;
    m_altstr = other.m_altstr;
  }
  return *this;
}

UruString & UruString::operator=(const char *c_str) {
  if (m_owns_cstr) {
    m_owns_cstr = false;
    delete[] m_cstr;
  }
  if (m_owns_altstr) {
    m_owns_altstr = false;
    delete[] m_altstr;
  }
  m_altstr = NULL;
  m_alt_type = C;
  m_arrival_len = 0;
  if (!c_str) {
    m_cstr_size = 0;
    return *this;
  }
  m_cstr_size = ::strlen(c_str);
  m_cstr = new char[m_cstr_size+3];
  m_owns_cstr = true;
  write16(m_cstr, 0, m_cstr_size);
  memcpy(m_cstr+2, c_str, m_cstr_size+1);
  return *this;
}

UruString & UruString::operator=(const u_char *c_str) {
  return operator=((const char*)c_str);
}

UruString & UruString::operator=(const std::string &str) {
  return operator=(str.c_str());
}

UruString::UruString()
  : m_cstr(NULL), m_altstr(NULL), m_alt_type(NO_NULL), m_owns_cstr(false),
    m_owns_altstr(false), m_arrival_len(0), m_cstr_size(0), m_altstr_size(0)
{
}

UruString::~UruString() {
  if (m_owns_cstr) {
    delete[] m_cstr;
  }
  if (m_owns_altstr) {
    delete[] m_altstr;
  }
}

bool UruString::operator==(const UruString &other) {
  if (m_alt_type == other.m_alt_type) {
    if (m_altstr && other.m_altstr) {
      size_t altlen = send_len(m_alt_type & HAS_LEN, m_alt_type & WIDE,
			       !(m_alt_type & NO_NULL));
      return (!memcmp(m_altstr, other.m_altstr, altlen));
    }
  }
  if (other.m_cstr) {
    if (!m_cstr) {
      make_cstr();
    }
    if (m_cstr_size != other.m_cstr_size) {
      // can't be equal
      return false;
    }
    return (!memcmp(m_cstr, other.m_cstr, m_cstr_size+2));
  }
  if (!other.m_altstr) {
    // other is an empty string (since we know !other.m_cstr)
    if (m_cstr) {
      return (m_cstr_size == 0);
    }
    else if (m_altstr) {
      return (m_altstr_size == 0);
    }
    else {
      // this is an empty string too
      return true;
    }
  }
  // ok, if we get here we have to convert to a common format and we can't
  // call other.c_str() because other is const, yuck
  const u_char *altstr = get_str(other.m_alt_type & HAS_LEN,
				 other.m_alt_type & WIDE,
				 !(other.m_alt_type & NO_NULL),
				 other.m_alt_type & BITFLIP);
  size_t altlen = send_len(m_alt_type & HAS_LEN, m_alt_type & WIDE,
			   !(m_alt_type & NO_NULL));
  return (!memcmp(altstr, other.m_altstr, altlen));
}

bool UruString::operator==(const char *c_str) {
  if (!c_str) {
    if (m_cstr) {
      return (m_cstr_size == 0);
    }
    else if (m_altstr) {
      return (m_altstr_size == 0);
    }
    else {
      return true;
    }
  }
  if (!m_cstr) {
    make_cstr();
  }
  return (::strlen(c_str) == m_cstr_size && !strcmp(c_str, this->c_str()));
}

const char * const UruString::c_str() {
  if (!m_cstr) {
    if (m_altstr && ((m_alt_type & ~HAS_LEN) == C)) {
      // m_alt_type ought to be be C (and not C|HAS_LEN) because otherwise
      // m_cstr should exist
      if (m_alt_type & HAS_LEN) {
	return (char*)m_altstr+2;
      }
      else {
	return (char*)m_altstr;
      }
    }
    make_cstr();
  }
  return m_cstr+2;
}

// I made this mistake of having the two string buffers be different types.
// Casting pointers in the iconv calls results in the annoying
// "dereferencing type-punned pointer will break strict-aliasing rules"
// compiler warning.
typedef union {
  char *c;
  u_char *u;
} bothchar;

// UTF-8 -> UTF-16: 1-3 UTF-8 bytes takes 2 UTF-16, 4 UTF-8 bytes takes 4
// UTF-16, therefore n UTF-8 is at most 2n UTF-16 bytes
// UTF-16 -> UTF-8: 2 UTF-16 bytes could take 1-3 UTF-8 bytes, 4 UTF-16 bytes
// takes 4 UTF-8, therefore n UTF-16 bytes is at most 3n/2 UTF-8 bytes

void UruString::make_cstr() {
#ifdef DEBUG_ENABLE
  assert(!m_cstr);
#endif
  if (m_altstr && (m_alt_type & WIDE)) {
    bothchar read_at;
    read_at.u = m_altstr;
    if (m_alt_type & HAS_LEN) {
      read_at.u += 2;
    }
    u_char *tempbuf = NULL;
    if (m_alt_type & BITFLIP) {
      // don't think this beast exists
      tempbuf = new u_char[2*m_altstr_size];
      for (u_int i = 0; i < 2*m_altstr_size; i++) {
	tempbuf[i] = ~read_at.u[i];
      }
      read_at.u = tempbuf;
    }
    // usually the UTF-16 will convert to ascii, but it's easier not to be
    // miserly
    size_t srclen = m_altstr_size;
    if (!(m_alt_type & NO_NULL)) {
      srclen--;
    }
    // m_altstr_size is in 2-byte increments
    size_t dstlen = srclen*3; // (srclen*2) * (3/2)
    srclen *= 2;
    m_cstr = new char[3+dstlen];
    m_owns_cstr = true;
    char *write_at = m_cstr+2;

    bool close_iconv = false;
    iconv_t iconv_state = get_thread_iconv(false);
    if (iconv_state == (iconv_t)-1) {
      // We have been asked to do a conversion but were not given the
      // iconv_t to use. Be inefficient and make a new one.
      iconv_state = iconv_open("UTF-8", "UTF-16LE");
      if (iconv_state != (iconv_t)-1) {
	close_iconv = true;
      }
    }
    if (iconv_state != (iconv_t)-1) {
      iconv(iconv_state, (ICONV_CONST char**)&read_at.c, &srclen,
	    &write_at, &dstlen);
      // see comments in get_str() about forging on
      write_at[0] = '\0';
      m_cstr_size = write_at - (m_cstr+2);
    }
    else {
      // iconv is broken or something
      read_at.u = (tempbuf ? tempbuf : ((m_alt_type & HAS_LEN) ? m_altstr+2
							       : m_altstr));
      write_at = m_cstr+2;
      // we don't want to create malformed UTF-8... so mangle the data
      for (u_int i = 0; i < m_altstr_size; i++) {
	char readchar = read_at.c[2*i];
	// asciify
	readchar &= 0x7f;
	if (readchar != '\t' && readchar != '\n' && readchar != '\r'
	    && readchar != '\0' && (readchar < ' ' || readchar > '~')) {
	  readchar = '?';
	}
	write_at[m_altstr_size] = '\0';
      }
      m_cstr_size = m_altstr_size;
    }
    write16(m_cstr, 0, m_cstr_size);
    
    if (tempbuf) {
      delete[] tempbuf;
    }
    if (close_iconv) {
      iconv_close(iconv_state);
    }
  }
  else {
    // if altstr isn't WIDE then it must be BITFLIP or !HAS_LEN or !NO_NULL
    if (m_altstr) {
      m_cstr_size = m_altstr_size;
      if (!(m_alt_type & NO_NULL)) {
	m_cstr_size--; // never count the null in m_cstr
      }
    }
    else {
      m_cstr_size = 0;
    }
    m_cstr = new char[m_cstr_size+3];
    m_owns_cstr = true;
    write16(m_cstr, 0, m_cstr_size);
    char *write_at = m_cstr+2;
    if (m_altstr) {
      u_char *read_at = m_altstr;
      if (m_alt_type & HAS_LEN) {
	read_at += 2;
      }
      if (!(m_alt_type & BITFLIP)) {
	// altstr has no null or no length
	memcpy(write_at, read_at, m_cstr_size);
      }
      else {
	for (u_int i = 0; i < m_cstr_size; i++) {
	  write_at[i] = (char)~read_at[i];
	}
      }
    }
    write_at[m_cstr_size] = '\0';
  }
}

const u_char * const UruString::get_str(bool include_length, bool as_wide,
					bool include_null, bool bitflip) {
  int desired_type = C;
  if (include_length) {
    desired_type |= HAS_LEN;
  }
  if (as_wide) {
    desired_type |= WIDE;
  }
  if (!include_null) {
    desired_type |= NO_NULL;
  }
  if (bitflip) {
    // we can't bitflip if there is no length to include the flag
    if (!include_length) {
      bitflip = false;
    }
    else {
      desired_type |= BITFLIP;
    }
  }
  if (m_altstr) {
    if (desired_type == m_alt_type) {
      return m_altstr;
    }
    if ((desired_type|HAS_LEN) == m_alt_type) {
      return m_altstr+2;
    }
    if (((m_alt_type & ~HAS_LEN) | NO_NULL) == desired_type) {
      if (m_alt_type & HAS_LEN) {
	return m_altstr+2;
      }
      else {
	return m_altstr;
      }
    }
  }
  if ((desired_type & ~NO_NULL) == C || desired_type == (C|NO_NULL|HAS_LEN)) {
    if (!m_cstr) {
      make_cstr();
    }
    if (desired_type == (C|NO_NULL|HAS_LEN)) {
      return (u_char*)m_cstr;
    }
    else {
      return (u_char*)m_cstr+2;
    }
  }

  // any types handled from here on must be in m_altstr
  if (m_altstr && ((m_alt_type ^ desired_type) == BITFLIP)) {
    // just do the bitflip in place
    u_int chars = read16(m_altstr, 0);
    chars &= ~0xF000;
    for (u_int i = 0; i < chars; i++) {
      m_altstr[i+2] = ~m_altstr[i+2];
    }
    if (m_alt_type & WIDE) {
      for (u_int i = 0; i < chars; i++) {
	m_altstr[chars+i+2] = ~m_altstr[chars+i+2];
      }
    }
    if (bitflip) {
      chars |= 0xF000;
    }
    write16(m_altstr, 0, chars);
    m_alt_type = desired_type;
  }
  else {
    // avoid calling iconv if possible
    bothchar source_str;
    int source_type;
    size_t source_size;
    bool delete_source = false;
    if (!m_altstr && !m_cstr) {
      // cast ok because we never write to the string
      source_str.c = const_cast<char*>("");
      source_type = C;
      source_size = 0;
    }
    else if (m_cstr && (!m_altstr || !as_wide || !(m_alt_type & WIDE))) {
      source_str.c = m_cstr;
      source_type = C|HAS_LEN|NO_NULL;
      source_size = m_cstr_size;
    }
    else {
      source_str.u = m_altstr;
      source_type = m_alt_type;
      source_size = m_altstr_size;
      delete_source = m_owns_altstr;
    }

    // now make a new altstr, and always include length
    m_alt_type = desired_type|HAS_LEN;
    if (m_owns_altstr && !delete_source) {
      // if delete_source, we have a pointer to it, delete later
      m_owns_altstr = false;
      delete[] m_altstr;
    }
    size_t srclen = source_size;
    size_t dstlen = srclen;
    if (!include_null && !(source_type & NO_NULL)) {
      srclen--;
    }
    else if (include_null && (source_type & NO_NULL)) {
      dstlen++;
    }
    if (source_type & WIDE) {
      srclen *= 2; // source_size is in 2-byte increments
    }
    if (as_wide) {
      dstlen *= 2;
    }
    if ((source_type & WIDE) != (desired_type & WIDE)) {
      // conversion either way could require more space, up to either 3/2 or 2
      dstlen *= 2;
    }
    m_altstr = new u_char[2+dstlen];
    m_owns_altstr = true;
    bothchar read_at = source_str;
    if (source_type & HAS_LEN) {
      read_at.u += 2;
    }
    bothchar write_at;
    write_at.u = m_altstr+2;

    if (as_wide && !(source_type & WIDE)) {
      u_char *tempbufr = NULL, *tempbufw = NULL;
      if (source_type & BITFLIP) {
	tempbufr = new u_char[srclen];
	for (u_int i = 0; i < srclen; i++) {
	  tempbufr[i] = ~read_at.u[i];
	}
	read_at.u = tempbufr;
      }
      if (bitflip) {
	// don't think this beast exists
	tempbufw = new u_char[dstlen];
	write_at.u = tempbufw;
      }

      bool close_iconv = false;
      iconv_t iconv_state = get_thread_iconv(true);
      if (iconv_state == (iconv_t)-1) {
	// We have been asked to do a conversion but were not given the
	// iconv_t to use. Be inefficient and make a new one.
	iconv_state = iconv_open("UTF-16LE", "UTF-8");
	if (iconv_state != (iconv_t)-1) {
	  close_iconv = true;
	}
      }
      if (iconv_state != (iconv_t)-1) {
	iconv(iconv_state, (ICONV_CONST char**)&read_at.c, &srclen,
	      &write_at.c, &dstlen);
	// Since there is no sane way to fail the conversion back to the
	// client, we must forge on. Therefore it does not matter what
	// iconv returns. If no characters are converted we'll just have
	// a zero-length string.
	m_altstr_size = (write_at.u - (bitflip ? tempbufw : m_altstr+2)) / 2;
	if (include_null && (source_type & NO_NULL)) {
	  write_at.u[0] = '\0';
	  write_at.u[1] = '\0';
	  m_altstr_size++;
	}
      }
      else {
	// iconv is broken or something
	read_at.u = (tempbufr ? tempbufr
			      : ((source_type & HAS_LEN) ? source_str.u+2
							 : source_str.u));
	write_at.u = (bitflip ? tempbufw : m_altstr+2);
	m_altstr_size = source_size;
	if (!include_null && !(source_type & NO_NULL)) {
	  m_altstr_size--;
	}
	// we don't want to create malformed UTF-8... so mangle the data
	for (u_int i = 0; i < m_altstr_size; i++) {
	  char readchar = read_at.c[i];
	  // asciify
	  readchar &= 0x7f;
	  if (readchar != '\t' && readchar != '\n' && readchar != '\r'
	      && readchar != '\0' && (readchar < ' ' || readchar > '~')) {
	    readchar = '?';
	  }
	  write_at.c[2*i] = readchar;
	  write_at.c[1+(2*i)] = '\0';
	}
	if (include_null && (source_type & NO_NULL)) {
	  write_at.c[2*m_altstr_size] = '\0';
	  write_at.c[1+(2*m_altstr_size)] = '\0';
	  m_altstr_size++;
	}
      }
      if (close_iconv) {
	iconv_close(iconv_state);
      }

      u_int chars = m_altstr_size;
      if (bitflip) {
	chars |= 0xF000;
      }
      write16(m_altstr, 0, chars);
      if (bitflip) {
	chars = m_altstr_size*2;
	write_at.u = m_altstr+2;
	for (u_int i = 0; i < chars; i++) {
	  write_at.u[i] = ~tempbufw[i];
	}
      }
      if (tempbufr) {
	delete[] tempbufr;
      }
      if (tempbufw) {
	delete[] tempbufw;
      }
    }
    else if (!as_wide && (source_type & WIDE)) {
      u_char *tempbufr = NULL, *tempbufw = NULL;
      if (source_type & BITFLIP) {
	// don't think this beast exists
	tempbufr = new u_char[srclen];
	for (u_int i = 0; i < srclen; i++) {
	  tempbufr[i] = ~read_at.u[i];
	}
	read_at.u = tempbufr;
      }
      if (bitflip) {
	tempbufw = new u_char[dstlen];
	write_at.u = tempbufw;
      }

      bool close_iconv = false;
      iconv_t iconv_state = get_thread_iconv(false);
      if (iconv_state == (iconv_t)-1) {
	// We have been asked to do a conversion but were not given the
	// iconv_t to use. Be inefficient and make a new one.
	iconv_state = iconv_open("UTF-8", "UTF-16LE");
	if (iconv_state != (iconv_t)-1) {
	  close_iconv = true;
	}
      }
      if (iconv_state != (iconv_t)-1) {
	iconv(iconv_state, (ICONV_CONST char**)&read_at.c, &srclen,
	      &write_at.c, &dstlen);
	// Again, we must forge on.
	m_altstr_size = write_at.u - (bitflip ? tempbufw : m_altstr+2);
	if (include_null && (source_type & NO_NULL)) {
	  write_at.u[0] = '\0';
	  m_altstr_size++;
	}
      }
      else {
	// iconv is broken or something
	read_at.u = (tempbufr ? tempbufr
			      : ((source_type & HAS_LEN) ? source_str.u+2
							 : source_str.u));
	write_at.u = (bitflip ? tempbufw : m_altstr+2);
	m_altstr_size = source_size;
	if (!include_null && !(source_type & NO_NULL)) {
	  m_altstr_size--;
	}
	// again, mangle away
	for (u_int i = 0; i < m_altstr_size; i++) {
	  char readchar = read_at.c[2*i];
	  // asciify
	  readchar &= 0x7f;
	  if (readchar != '\t' && readchar != '\n' && readchar != '\r'
	      && readchar != '\0' && (readchar < ' ' || readchar > '~')) {
	    readchar = '?';
	  }
	  write_at.u[i] = readchar;
	}
	if (include_null && (source_type & NO_NULL)) {
	  write_at.u[m_altstr_size] = '\0';
	  m_altstr_size++;
	}
      }
      if (close_iconv) {
	iconv_close(iconv_state);
      }

      u_int chars = m_altstr_size;
      if (bitflip) {
	chars |= 0xF000;
      }
      write16(m_altstr, 0, chars);
      if (bitflip) {
	write_at.u = m_altstr+2;
	for (u_int i = 0; i < m_altstr_size; i++) {
	  write_at.u[i] = ~tempbufw[i];
	}
      }
      if (tempbufr) {
	delete[] tempbufr;
      }
      if (tempbufw) {
	delete[] tempbufw;
      }
    }
    else {
      // here the wide-ness is the same
      m_altstr_size = source_size;
      if (!include_null && !(source_type & NO_NULL)) {
	m_altstr_size--;
      }
      if ((source_type & BITFLIP) != (desired_type & BITFLIP)) {
	for (u_int i = 0; i < srclen; i++) {
	  write_at.u[i] = ~read_at.u[i];
	}
      }
      else {
	memcpy(write_at.u, read_at.u, srclen);
      }
      if (include_null && (source_type & NO_NULL)) {
	m_altstr_size++;
	write_at.u[srclen] = (bitflip ? '\xff' : '\0');
	if (as_wide) {
	  write_at.u[srclen+1] = (bitflip ? '\xff' : '\0');
	}
      }
      u_int chars = m_altstr_size;
      if (bitflip) {
	chars |= 0xF000;
      }
      write16(m_altstr, 0, chars);
    }

    if (delete_source) {
      delete[] source_str.u;
    }
  }

  if (include_length) {
    return m_altstr;
  }
  else {
    return m_altstr+2;
  }
}

size_t UruString::send_len(bool include_length, bool as_wide,
			   bool include_null) {
  size_t result;
  if (as_wide) {
    if (!m_altstr || !(m_alt_type & WIDE)) {
      // we have to convert first
      get_str(include_length, as_wide, include_null);
    }
    result = m_altstr_size;
    if (include_null && (m_alt_type & NO_NULL)) {
      result++;
    }
    else if (!include_null && !(m_alt_type & NO_NULL)) {
      result--;
    }
  }
  else {
    if (m_cstr) {
      result = m_cstr_size;
      if (include_null) {
	result++;
      }
    }
    else if (!m_altstr) {
      result = 0;
      if (include_null) {
	result++;
      }
    }
    else if (!(m_alt_type & WIDE)) {
      // m_alt_type is !NO_NULL or BITFLIP or !HAS_LEN, but m_altstr is still
      // in UTF-8 
      result = m_altstr_size;
      if (include_null && (m_alt_type & NO_NULL)) {
	result++;
      }
      else if (!include_null && !(m_alt_type & NO_NULL)) {
	result--;
      }
    }
    else {
      // we have to convert
      make_cstr();
      result = m_cstr_size;
      if (include_null) {
	result++;
      }
    }
  }
  if (as_wide) {
    result *= 2;
  }
  if (include_length) {
    result += 2;
  }
  return result;
}

// hash tables for thread ID -> iconv_t
static std::map<pthread_t,iconv_t> towide_hash;
static std::map<pthread_t,iconv_t> fromwide_hash;

void UruString::setup_thread_iconv() {
  pthread_t myself = pthread_self();
  if (towide_hash.find(myself) == towide_hash.end()) {
    iconv_t towide = iconv_open("UTF-16LE", "UTF-8");
    if (towide != (iconv_t)-1) {
      towide_hash[myself] = towide;
    }
  }
  if (fromwide_hash.find(myself) == fromwide_hash.end()) {
    iconv_t fromwide = iconv_open("UTF-8", "UTF-16LE");
    if (fromwide != (iconv_t)-1) {
      fromwide_hash[myself] = fromwide;
    }
  }
}

void UruString::clear_thread_iconv() {
  pthread_t myself = pthread_self();
  std::map<pthread_t,iconv_t>::iterator iter;
  iter = towide_hash.find(myself);
  if (iter != towide_hash.end()) {
    iconv_close(towide_hash[myself]);
    towide_hash.erase(iter);
  }
  iter = fromwide_hash.find(myself);
  if (iter != fromwide_hash.end()) {
    iconv_close(fromwide_hash[myself]);
    fromwide_hash.erase(iter);
  }
}

iconv_t UruString::get_thread_iconv(bool towide) {
  pthread_t myself = pthread_self();
  std::map<pthread_t,iconv_t>::iterator iter;
  if (towide) {
    iter = towide_hash.find(myself);
    if (iter != towide_hash.end()) {
      return towide_hash[myself];
    }
  }
  else {
    iter = fromwide_hash.find(myself);
    if (iter != fromwide_hash.end()) {
      return fromwide_hash[myself];
    }
  }
  return (iconv_t)-1;
}
