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
 * This file includes some of the client-side and server-side messages for
 * the auth server.
 */

//#include <sys/uio.h> /* for struct iovec */
//
//#include "msg_typecodes.h"
//#include "VaultNode.h"
//
//#include "Logger.h"
//#include "NetworkMessage.h"
//#include "BackendMessage.h"
//#include "FileTransaction.h"

#ifndef _AUTH_MESSAGE_H_
#define _AUTH_MESSAGE_H_

class AuthClientMessage : public NetworkMessage {
public:
  // want_len should be filled in to the total length of the message, if
  // known, otherwise it should be set to -1
  static NetworkMessage * make_if_enough(const u_char *buf, size_t len,
					 int *want_len,
					 bool become_owner=false);

  virtual bool check_useable() const;

  virtual ~AuthClientMessage() { }

  /*
   * Additional accessors
   */

  // subclass types, since I do not have a typeof operator
  typedef enum {
    Generic = 0,
    Ping = 1,
    File = 2,
    Vault = 3,
    Log = 4,
    LoginReq = 16,
    PlayerCreate = 17,
    AgeReq = 18,
    PasswordChange = 19
  } msg_class_t;
  virtual msg_class_t msg_class() const { return Generic; }

protected:
  AuthClientMessage(const u_char *msg_buf, size_t msg_len, int msg_type)
    : NetworkMessage(msg_buf, msg_len, msg_type) { }
};

class AuthServerMessage : public NetworkMessage {
public:
  /*
   * This class copies the buffer passed in.
   */
  AuthServerMessage(const u_char *contents, size_t content_len, int type);

  virtual ~AuthServerMessage() { if (m_buf) delete[] m_buf; }

  virtual size_t message_len() const { return m_buflen + 2; }

  virtual u_int fill_iovecs(struct iovec *iov, u_int iov_ct, u_int start_at);
  virtual u_int iovecs_written_bytes(u_int byte_ct, u_int start_at,
				     bool *msg_done);
  virtual u_int fill_buffer(u_char *buffer, size_t len, u_int start_at,
			    bool *msg_done);

protected:
  AuthServerMessage(int type) : NetworkMessage(type) { }

#ifdef DEBUG_ENABLE
public:
  virtual bool persistable() const { return true; } // copies buffer
#endif
};

class AuthServerLoginMessage : public AuthServerMessage {
public:
  // for a failed login
  AuthServerLoginMessage(uint32_t reqid, status_code_t status);

  // for a successful login
  AuthServerLoginMessage(uint32_t reqid, status_code_t status,
			 const u_char *uuid, customer_type_t customer_type,
			 const u_char *key);
};

class AuthServerChangePassMessage : public AuthServerMessage {
public:
  AuthServerChangePassMessage(uint32_t reqid, status_code_t status);
};

class AuthServerFileMessage : public AuthServerMessage {
public:
  AuthServerFileMessage(FileTransaction *trans, int msg_type);
  virtual ~AuthServerFileMessage();

  virtual size_t message_len() const;

  u_int fill_iovecs(struct iovec *iov, u_int iov_ct, u_int start_at);
  u_int iovecs_written_bytes(u_int byte_ct, u_int start_at, bool *msg_done);
  u_int fill_buffer(u_char *buffer, size_t len, u_int start_at,
		    bool *msg_done);

protected:
  FileTransaction *m_transaction;
#ifdef DOWNLOAD_NO_ACKS
  u_int m_header_bytes;

  void next_offset();
#endif
};

class AuthServerPlayerCreateMessage : public AuthServerMessage {
public:
  AuthServerPlayerCreateMessage(uint32_t reqid, status_code_t status,
				kinum_t kinum=0,
				customer_type_t acct_type=GUEST_CUSTOMER,
				UruString *name=NULL, UruString *gender=NULL);
};

class AuthServerVaultMessage : public AuthServerMessage {
public:
  AuthServerVaultMessage(VaultPassthrough_BackendMessage *backend);

  virtual ~AuthServerVaultMessage();

  // woe is me if the backend message header changes size!!
  // all four of these would break
  virtual size_t message_len() const { return m_passthru->message_len()-16; }

  u_int fill_iovecs(struct iovec *iov, u_int iov_ct, u_int start_at);
  u_int iovecs_written_bytes(u_int byte_ct, u_int start_at, bool *msg_done);
  u_int fill_buffer(u_char *buffer, size_t len, u_int start_at,
		    bool *msg_done);

protected:
  VaultPassthrough_BackendMessage *m_passthru;

#ifdef DEBUG_ENABLE
  // need special function here, because message is backed by the
  // VaultPassthrough_BackendMessage
public:
  virtual bool persistable() const {
    return (!m_passthru) || m_passthru->persistable();
  }
#endif
};

class AuthServerAgeReplyMessage : public AuthServerMessage {
public:
  AuthServerAgeReplyMessage(uint32_t reqid, status_code_t result,
			    const u_char *contents, size_t content_len);

  virtual size_t message_len() const { return 38; }

  u_int fill_iovecs(struct iovec *iov, u_int iov_ct, u_int start_at);
  u_int fill_buffer(u_char *buffer, size_t len, u_int start_at,
		    bool *msg_done);

protected:
  u_char m_topbuf[10];
};

class AuthServerKickMessage : public AuthServerMessage {
public:
  AuthServerKickMessage(status_code_t reason);
};

class AuthPingMessage : public AuthClientMessage {
public:
  /*
   * This class copies the buffer passed in.
   */
  AuthPingMessage(const u_char *msg_buf, size_t len)
    : AuthClientMessage(NULL, len, kAuth2Cli_PingReply) {

    m_buf = new u_char[len];
    memcpy(m_buf, msg_buf, len);
  }
  virtual ~AuthPingMessage() { if (m_buf) delete[] m_buf; }

  msg_class_t msg_class() const { return Ping; }

  u_int fill_iovecs(struct iovec *iov, u_int iov_ct, u_int start_at);
  u_int iovecs_written_bytes(u_int byte_ct, u_int start_at, bool *msg_done);
  u_int fill_buffer(u_char *buffer, size_t len, u_int start_at,
		    bool *msg_done);

#ifdef DEBUG_ENABLE
  virtual bool persistable() const { return true; } // copies buffer
#endif
};

class AuthClientLoginMessage : public AuthClientMessage {
public:
  static NetworkMessage * make_if_enough(const u_char *buf, size_t len,
					 int *want_len);

  msg_class_t msg_class() const { return LoginReq; }

  /*
   * Additional accessors
   */
  uint32_t reqid() const { return read32(m_buf, 2); }
  uint32_t nonce() const { return read32le(m_buf, 6); } // keep little-endian
  UruString & login() { return m_login; }
  const u_char * hash() const { return m_buf+m_hash_at; }
  UruString & token() { return m_token; }
  UruString & os() { return m_os; }

protected:
  AuthClientLoginMessage(const u_char *msg_buf, size_t msg_len, int msg_type,
			 u_int hash_location, u_int os_location)
    : AuthClientMessage(msg_buf, msg_len, msg_type),
      m_login(msg_buf+10, -1, true, true, false),
      m_hash_at(hash_location),
      m_token(msg_buf+hash_location+20, -1, true, true, false),
      m_os(msg_buf+os_location, -1, true, true, false) { }

  UruString m_login;
  u_int m_hash_at;
  UruString m_token;
  UruString m_os;
};

class AuthClientChangePassMessage : public AuthClientMessage {
public:
  static NetworkMessage * make_if_enough(const u_char *buf, size_t len,
					 int *want_len);

  msg_class_t msg_class() const { return PasswordChange; }

  /*
   * Additional accessors
   */
  uint32_t reqid() const { return read32(m_buf, 2); }
  UruString & login() { return m_login; }
  const u_char * hash() const { return m_buf+m_hash_at; }

protected:
  AuthClientChangePassMessage(const u_char *msg_buf, size_t msg_len,
			      int msg_type, u_int hash_location)
    : AuthClientMessage(msg_buf, msg_len, msg_type),
      m_login(msg_buf+6, -1, true, true, false),
      m_hash_at(hash_location) { }

  UruString m_login;
  u_int m_hash_at;
};

class AuthClientFileMessage : public AuthClientMessage {
public:
  static NetworkMessage * make_if_enough(const u_char *buf, size_t len,
					 int *want_len);

  virtual ~AuthClientFileMessage() { if (m_class) delete m_class; }

  msg_class_t msg_class() const { return File; }

  /*
   * Additional accessors
   */
  uint32_t reqid() const { return read32(m_buf, 2); }
  // FileListRequest, FileDownloadRequest
  UruString & name() { return m_name; }
  // FileListRequest
  UruString & fileclass() { return *m_class; }

protected:
  AuthClientFileMessage(const u_char *msg_buf, size_t msg_len, int msg_type)
    : AuthClientMessage(msg_buf, msg_len, msg_type),
      m_name(msg_buf+6, msg_len-6, true, true, false), m_class(NULL) {

    if (msg_type == kCli2Auth_FileListRequest) {
      m_class = new UruString(msg_buf+6+m_name.arrival_len(),
			      -1, true, true, false);
    }
  }

  UruString m_name;
  UruString *m_class;
};

class AuthClientPlayerCreateMessage : public AuthClientMessage {
public:
  static NetworkMessage * make_if_enough(const u_char *buf, size_t len,
					 int *want_len);

  msg_class_t msg_class() const { return PlayerCreate; }

  /*
   * Additional accessors
   */
  uint32_t reqid() const { return read32(m_buf, 2); }
  UruString & name() { return m_name; }
  UruString & gender() { return m_gender; }
  UruString & code() { return m_code; }

protected:
  AuthClientPlayerCreateMessage(const u_char *msg_buf, size_t msg_len,
				int msg_type)
    : AuthClientMessage(msg_buf, msg_len, msg_type),
      m_name(msg_buf+6, -1, true, true, false),
      m_gender(msg_buf+6+m_name.arrival_len(), -1, true, true, false),
      m_code(msg_buf+6+m_name.arrival_len()+m_gender.arrival_len(),
	     -1, true, true, false) { }

  UruString m_name;
  UruString m_gender;
  UruString m_code;
};

// all just passed through to vault server
class AuthClientVaultMessage : public AuthClientMessage {
public:
  static NetworkMessage * make_if_enough(const u_char *buf, size_t len,
					 int *want_len, bool become_owner);

  virtual bool check_useable() const;

  virtual msg_class_t msg_class() const { return Vault; }

  /*
   * Additional accessors
   */
  bool owns_buffer() const { return m_owns_buf; }
  // this means that someone else is responsible for delete[]ing the buffer;
  // be careful not to use the buffer after this if it could be deleted
  // elsewhere
  void make_unowned() { if (m_owns_buf) m_owns_buf = false; }

  virtual ~AuthClientVaultMessage() { if (m_owns_buf) delete[] m_buf; }

protected:
  AuthClientVaultMessage(const u_char *msg_buf, size_t msg_len, int msg_type,
			 bool become_owner)
    : AuthClientMessage(msg_buf, msg_len, msg_type), m_owns_buf(become_owner)
  { }

  bool m_owns_buf;

#ifdef DEBUG_ENABLE
  // even though the message is technically persistable when it owns the
  // buf, this message should never be enqueued, so use default (false)
  // virtual bool persistable() const { return m_owns_buf; }
#endif
};

class AuthClientAgeRequestMessage : public AuthClientMessage {
public:
  static NetworkMessage * make_if_enough(const u_char *buf, size_t len,
					 int *want_len);

  msg_class_t msg_class() const { return AgeReq; }

  /*
   * Additional accessors
   */
  uint32_t reqid() const { return read32(m_buf, 2); }
  UruString & name() { return m_name; }
  const u_char * uuid() const { return m_buf+m_buflen-16; }

protected:
  AuthClientAgeRequestMessage(const u_char *msg_buf, size_t msg_len,
			      int msg_type)
    : AuthClientMessage(msg_buf, msg_len, msg_type),
      m_name(msg_buf+6, msg_len-22, true, true, false) { }

  UruString m_name;
};

class AuthClientLogMessage : public AuthClientMessage {
public:
  static NetworkMessage * make_if_enough(const u_char *buf, size_t len,
					 int *want_len);

  msg_class_t msg_class() const { return Log; }

protected:
  AuthClientLogMessage(const u_char *msg_buf, size_t msg_len, int msg_type)
    : AuthClientMessage(msg_buf, msg_len, msg_type) { }
};

#endif /* _AUTH_MESSAGE_H_ */
