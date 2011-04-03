/* -*- c++ -*- */

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
 * This is a very simple buffer with reference counting.
 */

//#include <string.h>
//
//#include <pthread.h>

#ifndef _BUFFER_H_
#define _BUFFER_H_

class Buffer {
public:
  Buffer(size_t len)
    : m_buflen(len), m_buf(NULL), m_owns_buf(false) {

    init(true);
  }

  // copylen is ignored if own_buffer is false; -1 means copy whole length
  Buffer(size_t len, const u_char *orig_buf, bool owns_buffer = true,
	 int copylen = -1)
    : m_buflen(len), m_buf(NULL), m_owns_buf(false) {

    init(owns_buffer);
    if (owns_buffer) {
      memcpy(m_buf, orig_buf, copylen >= 0 ? copylen : len);
    }
    else {
      // XXX yuck, look for a better answer
      m_buf = const_cast<u_char*>(orig_buf);
    }
  }

  ~Buffer() {
    if (m_owns_buf && m_buf) {
      delete[] m_buf;
    }
  }

  // Change the buffer to unowned, useful when keeping temporary Buffers
  // around as u_char*s in NetworkMessages. Note that this means something
  // else is responsible for delete[]ing the u_char* so beware dangling
  // pointers.
  void make_unowned() { m_owns_buf = false; }

  // Change buffer to owned. Note there is no copy. This means that this
  // Buffer will delete[] the u_char*.
  void make_owned() { m_owns_buf = true; }

  // Return whether the buffer is owned.
  bool is_owned() const { return m_owns_buf; }

  u_char *buffer() const { return m_buf; }
  size_t len() const { return m_buflen; }

protected:
  void init(bool owns_buffer) {
    if (owns_buffer) {
      m_buf = new u_char[m_buflen];
      m_owns_buf = true;
    }
  }

  size_t m_buflen;
  u_char *m_buf;
  bool m_owns_buf;
};

#endif /* _BUFFER_H_ */
