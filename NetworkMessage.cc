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
#include <string.h>
#include <sys/uio.h> /* for struct iovec */

#include <stdexcept>

#include "machine_arch.h"
#include "exceptions.h"
#include "constants.h"
#include "NetworkMessage.h"


extern const int NetworkMessage::zero = 0;

NetworkMessage * NegotiationMessage::make_if_enough(const u_char *buf,
						    size_t len, int type) {
  if (len < 1) {
    return NULL;
  }
  u_int msg_len = buf[0] - 1; // first byte eaten by dispatcher
  if (msg_len > 65/* max Negotiation (nonce) length - 1*/) {
    throw overlong_message(msg_len);
  }

  switch (type) {
  case TYPE_NONCE:
    if (len < msg_len) {
      return NULL;
    }
    return new NegotiationMessage(buf, msg_len, type);
  case TYPE_FILE:
  case TYPE_AUTH:
  case TYPE_GAME:
  case TYPE_GATEKEEPER:
    if (len < msg_len + 4) {
      return NULL;
    }
    msg_len += read32(buf, msg_len);
    if (len < msg_len) {
      return NULL;
    }
    return new NegotiationMessage(buf, msg_len, type);
  default:
    return new UnknownMessage(buf, msg_len);
  }
}

bool NegotiationMessage::check_useable() const {
  if ((m_type == TYPE_FILE && m_buflen >= 38)
      || ((m_type == TYPE_AUTH || m_type == TYPE_GAME
	   || m_type == TYPE_GATEKEEPER) && m_buflen >= 30)
      || (m_type == TYPE_NONCE && m_buflen >= 65)) {
    return true;
  }
  return false;
}

// This is overridden because the new select loop infrastructure depends on
// the message length, not a return value, to know how much has been used, so
// the claimed message length for TYPE_NONCE has to be bumped by one to account
// for the byte that was *not* eaten by the dispatcher. This is safe because
// nothing copies the whole buffer, or looks past the first 64 bytes of
// payload.
size_t NegotiationMessage::message_len() const {
  if (m_type == TYPE_NONCE) {
    return m_buflen+1;
  }
  else {
    return m_buflen;
  }
}

NonceResponse::NonceResponse(const u_char *msg_buf, size_t len)
  : NetworkMessage(TYPE_NONCE_RESPONSE) {

  m_buf = new u_char[len + 2];
  m_buflen = len + 2;
  m_buf[0] = (u_char)m_type;
  m_buf[1] = m_buflen;
  memcpy(m_buf+2, msg_buf, len);
}

u_int NonceResponse::fill_iovecs(struct iovec *iov, u_int iov_ct,
				 u_int start_at) {
  if (iov_ct < 1 || start_at >= m_buflen) {
    return 0;
  }
  iov[0].iov_base = m_buf + start_at;
  iov[0].iov_len = m_buflen - start_at;
  return 1;
}

u_int NonceResponse::iovecs_written_bytes(u_int byte_ct, u_int start_at,
					  bool *msg_done) {
  if (byte_ct >= m_buflen - start_at) {
    *msg_done = true;
    return byte_ct - (m_buflen - start_at);
  }
  else {
    *msg_done = false;
    return 0;
  }
}

u_int NonceResponse::fill_buffer(u_char *buffer, size_t len,
				 u_int start_at, bool *msg_done) {
  if (len <= 0 || start_at >= m_buflen) {
    *msg_done = true;
    return 0;
  }
  size_t len_to_write = m_buflen - start_at;
  if (len < len_to_write) {
    len_to_write = len;
    *msg_done = false;
  }
  else {
    *msg_done = true;
  }
  memcpy(buffer, m_buf + start_at, len_to_write);
  return len_to_write;
}
