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
 * This file includes both the client-side and server-side messages for the
 * file server. Because file server transactions, unlike any other
 * transaction except the analogous transactions with the Auth server, can
 * be split up into multiple messages, the state of the transaction must be
 * kept around, and the FileTransaction class handles that.
 */

//#include <sys/uio.h> /* for struct iovec */
//
//#include "protocol.h"
//#include "msg_typecodes.h"
//
//#include "Logger.h"
//#include "NetworkMessage.h"
//#include "FileTransaction.h"

#ifndef _FILE_MESSAGE_H_
#define _FILE_MESSAGE_H_

class FileClientMessage : public NetworkMessage {
public:
  static NetworkMessage * make_if_enough(const u_char *buf, size_t len);

  bool check_useable() const;

  virtual ~FileClientMessage() { }

  /*
   * Additional accessors
   */
  uint32_t request_id() const { return read32(m_buf, 8); }
  // object_name() only for ManifestRequestTrans and DownloadRequestTrans
  const u_char * object_name() const { return m_buf+12; }
  u_int object_name_maxlen() const { return m_buflen - 12; }

protected:
  FileClientMessage(const u_char *msg_buf, size_t msg_len, int msg_type)
    : NetworkMessage(msg_buf, msg_len, msg_type) { }
};

class FileServerMessage : public NetworkMessage {
public:
  FileServerMessage(FileClientMessage *ping);
  FileServerMessage(FileTransaction *trans, int reply_type);
  FileServerMessage(uint32_t reqid, status_code_t status, int build_no);

  virtual ~FileServerMessage() {
    if (m_buf) {
      delete[] m_buf;
    }
  }

  u_int fill_iovecs(struct iovec *iov, u_int iov_ct, u_int start_at);
  u_int iovecs_written_bytes(u_int byte_ct, u_int start_at, bool *msg_done);
  u_int fill_buffer(u_char *buffer, size_t len, u_int start_at,
		    bool *msg_done);

protected:
  FileTransaction *m_transaction;
  static const int zero;

#ifdef DEBUG_ENABLE
public:
  virtual bool persistable() const { return true; } // copies data
#endif
};

#endif /* _FILE_MESSAGE_H_ */
