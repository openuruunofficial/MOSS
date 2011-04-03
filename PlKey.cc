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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <iconv.h>

#include <stdexcept>

#include "machine_arch.h"
#include "exceptions.h"

#include "UruString.h"
#include "PlKey.h"

u_int PlKey::read_in(const u_char *buf, size_t buflen) {
    if (buflen < 1) {
      throw truncated_message("Buffer too short for plKey");
    }

    u_int needlen = 11;
#ifndef OLD_STYLE
    needlen += 4;
#endif
    if (buf[0] & 0x02) {
      needlen += 2;
    }
    if (buflen < needlen) {
      throw truncated_message("Buffer too short for plKey");
    }

    u_int offset = 0;
    m_flags = buf[offset++];
    m_pageid = read32(buf, offset);
    offset += 4;
    m_pagetype = read16(buf, offset);
    offset += 2;
    if (m_flags & 0x02) {
      m_extra = buf[offset++];
    }
    else {
      m_extra = 0;
    }
    m_objtype = read16(buf, offset);
    offset += 2;
#ifndef OLD_STYLE
    m_prpindex = read32(buf, offset);
    offset += 4;
#endif
    // NOTE: we are not calling delete_name()
    m_name = new UruString(buf+offset, buflen-offset, true, false);
    offset += m_name->arrival_len();
    if ((m_flags & 0x01) && (buflen < offset+8)) {
      throw truncated_message("Buffer too short for plKey");
    }
    if (m_flags & 0x01) {
      m_index = read32(buf, offset);
      offset += 4;
      m_clientid = read32(buf, offset);
      offset += 4;
    }
    else {
      m_index = m_clientid = 0;
    }

    return offset;
}

u_int PlKey::send_len() const {
    u_int len = 9;
#ifndef OLD_STYLE
    len += 4;
#endif
    if (m_flags & 0x02) {
      len += 1;
    }
    if (m_flags & 0x01) {
      len += 8;
    }
    if (m_name) {
      len += m_name->send_len(true, false, false);
    }
    else {
      len += 2;
    }
    return len;
}

u_int PlKey::write_out(u_char *buf, size_t buflen, bool bitflip) const {
    if (buflen < send_len()) {
      // XXX programmer error
      return 0;
    }
    u_int offset = 0;
    buf[offset++] = m_flags;
    write32(buf, offset, m_pageid);
    offset += 4;
    write16(buf, offset, m_pagetype);
    offset += 2;
    if (m_flags & 0x02) {
      buf[offset++] = m_extra;
    }
    write16(buf, offset, m_objtype);
    offset += 2;
#ifndef OLD_STYLE
    write32(buf, offset, m_prpindex);
    offset += 4;
#endif
    if (m_name) {
      u_int l = m_name->send_len(true, false, false);
      memcpy(buf+offset, m_name->get_str(true, false, false, bitflip), l);
      offset += l;
    }
    else {
      write16(buf, offset, 0xf000);
      offset += 2;
    }
    if (m_flags & 0x01) {
      write32(buf, offset, m_index);
      offset += 4;
      write32(buf, offset, m_clientid);
      offset += 4;
    }
    return offset;
}

char * PlKey::format() {
    u_int len = sizeof("Page ID: 0x12345678 Page Type: 0x1234 "
		       "Object Type: 0x1234 Name:  Index:  ClientID:  ")+20;
    if (m_name) {
      len += m_name->strlen();
    }

    char *buf = (char*)malloc(len);
    if (buf) {
      snprintf(buf, len,
	       "PageID: 0x%08x Page Type: 0x%04x Object Type: 0x%04x Name: %s ",
	       m_pageid, m_pagetype, m_objtype, m_name ? m_name->c_str() : "");
      u_int at = strlen(buf);
      if (m_flags & 0x01) {
	snprintf(buf+at, len-at, "Index: %u ClientID: %u", m_index, m_clientid);
      }      
    }
    return buf;
}

bool PlKey::operator==(const PlKey &other) const {
  if (this == &other) {
    return true;
  }
  if (m_flags != other.m_flags || m_extra != other.m_extra
      || m_pageid != other.m_pageid || m_pagetype != other.m_pagetype
      || m_objtype != other.m_objtype || m_prpindex != other.m_prpindex
      || m_index != other.m_index || m_clientid != other.m_clientid) {
    return false;
  }
  if (m_name) {
    if (other.m_name) {
      return (*m_name == *other.m_name);
    }
    else {
      return (strlen(m_name->c_str()) == 0);
    }
  }
  else if (other.m_name) {
    return (strlen(other.m_name->c_str()) == 0);
  }
  else {
    // both strings are NULL
    return true;
  }
}

void PlKey::make_null() {
  memset(this, 0, sizeof(PlKey));
  m_pageid = 0xFFFFFFFF;
}

u_int PlKey::write_null_key(u_char *buf, size_t buflen) {
  if (buflen < 15) {
    // XXX programmer error
    return 0;
  }
  memcpy(buf, "\0\xFF\xFF\xFF\xFF\0\0\0\0\0\0\0\0\0\xF0", 15);
  return 15;
}
