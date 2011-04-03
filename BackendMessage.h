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
 * All messages to/from backend servers should be BackendMessages. Each
 * message type should have its own class object that represents the data,
 * so that messages on a queue can be operated on without reading/writing
 * buffers.
 */

//#include <sys/uio.h>
//
//#include <stdexcept>
//#include <vector>
//
//#include "protocol.h"
//#include "machine_arch.h"
//#include "UruString.h"
//
//#include "NetworkMessage.h"
class VaultNode; // to not require everything to include VaultNode

#ifndef _BACKEND_MESSAGE_H_
#define _BACKEND_MESSAGE_H_

class BackendMessage : public NetworkMessage {
public:
  // want_len should be filled in to the total length of the message, if
  // known, otherwise it should be set to -1
  static NetworkMessage * make_if_enough(const u_char *buf, size_t len,
					 int *want_len,
					 bool become_owner=false);

  virtual ~BackendMessage() { pthread_mutex_destroy(&m_mutex); }

  // override this to account for 16-byte header
  virtual size_t message_len() const { return read32(m_header, 0); }
  /*
   * Additional accesors.
   */
  uint32_t get_id1() const { return read32(m_header, 8); }
  uint32_t get_id2() const { return read32(m_header, 12); }

  virtual u_int fill_iovecs(struct iovec *iov, u_int iov_ct, u_int start_at);
  virtual u_int iovecs_written_bytes(u_int byte_ct, u_int start_at,
				     bool *msg_done);
  virtual u_int fill_buffer(u_char *buffer, size_t len, u_int start_at,
			    bool *msg_done);

  // returns new refcount
  virtual int add_ref() {
    int ret;

    // XXX use atomic instructions instead?
    pthread_mutex_lock(&m_mutex);
    ret = ++m_refct;
    pthread_mutex_unlock(&m_mutex);
    return ret;
  }
  virtual int del_ref() {
    int ret;

    pthread_mutex_lock(&m_mutex);
    ret = --m_refct;
    pthread_mutex_unlock(&m_mutex);
    return ret;
  }

protected:
  BackendMessage(int msg_type)
    : NetworkMessage(msg_type), m_refct(1), m_total_len(0) {

    if (pthread_mutex_init(&m_mutex, NULL)) {
      throw std::bad_alloc();
    }
#ifdef DEBUG_ENABLE
    m_unsafe = false;
#endif
  }
  // this should always be called before the message is put on any queues;
  // in a constructor is a good place; for post-receive messages we have
  // the data in the constructor so this shouldn't be called
  void setup_header(uint32_t id1, uint32_t id2, u_int content_len) {
    m_total_len = content_len+16;
    write32(m_header, 0, m_total_len);
    write32(m_header, 4, m_type);
    write32(m_header, 8, id1);
    write32(m_header, 12, id2);
  }

  BackendMessage(int msg_type, const u_char *inbuf, size_t in_len)
    : NetworkMessage(msg_type), m_refct(1), m_total_len(0) {

    if (pthread_mutex_init(&m_mutex, NULL)) {
      throw std::bad_alloc();
    }
    memcpy(m_header, inbuf, 16);
    m_total_len = read32(m_header, 0);
#ifdef DEBUG_ENABLE
    m_unsafe = true; // child classes can explicitly override this
#endif
  }

  // this is called by fill_iovecs and fill_buffer
  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen) {
    *msg_done = true;
    return 0;
  }

  pthread_mutex_t m_mutex;
  int m_refct;
  u_char m_header[16];
  int m_total_len;

#ifdef DEBUG_ENABLE
  // we have to do some different bookkeeping here; since backend messages
  // might someday be "sent" only on queues, only messages read from the
  // network are at risk of being non-persistable
  bool m_unsafe;
public:
  virtual bool persistable() const { return !m_unsafe; }
#endif
};

/*
 * Each backend message class has two kinds of constructors: one for creating
 * the message (pre-send) and one for reading the message (post-receive).
 * Avoid creating buffers in the pre-send constructor; let the on-wire format
 * be handled in the write routines. If the message is handled off a queue,
 * we don't need a buffer hanging around. The post-receive constructor only
 * happens when the message is from the network, so it should parse the
 * buffer and toss it if possible (tossing it will probably not make sense
 * for many (most?) messages).
 */

// the admin Hello must be sent by the client of each backend connection
class Hello_BackendMessage : public BackendMessage {
public:
  // pre-send
  Hello_BackendMessage(uint32_t id1, uint32_t id2, uint32_t peer_info,
		       bool to_server=true);

  // post-receive
  Hello_BackendMessage(const u_char *inbuf, size_t in_len,
		       bool become_owner=false);

  // accessors
  uint32_t peer_info() const { return le32toh(m_peer_info); }

protected:
  uint32_t m_peer_info; // little-endian

  u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
		  struct iovec *iov, u_int iov_ct,
		  u_char *buffer, size_t buflen);
};

// the KillClient message signals to frontend servers that the client
// connection should be shut down (due to an unrecoverable error, e.g.,
// "in doubt" DB errors, or due to a second login, timeout, etc.)
class KillClient_BackendMessage : public BackendMessage {
public:
  typedef enum {
    UNKNOWN = 0,
    IN_DOUBT = 1,
    NO_STATE = 2,
    NEW_LOGIN = 3, // translates to ERROR_LOGGED_IN_ELSEWHERE in AuthServer
    AUTH_DISCONNECT = 4
  } kill_reason_t;

  // pre-send
  KillClient_BackendMessage(uint32_t id1, uint32_t id2, kill_reason_t why,
			    kinum_t player_ki=0);

  // post-receive
  KillClient_BackendMessage(const u_char *inbuf, size_t in_len,
			    bool become_owner=false);

  // accessors
  kill_reason_t why() const { return (kill_reason_t)le32toh(m_reason); }
  kinum_t kinum() const { return le32toh(m_ki); }

protected:
  uint32_t m_reason; // little-endian
  uint32_t m_ki; // little-endian

  u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
		  struct iovec *iov, u_int iov_ct,
		  u_char *buffer, size_t buflen);
};

class AuthAcctLogin_ToBackendMessage : public BackendMessage {
public:
  typedef enum {
    PLAIN_HASH = 0, // SHA-1 hash of password (byte-swapped in 4-byte chunks)
    CHALLENGE_RESPONSE = 1 // SHA(client+server+SHA(passwd+username))
  } authtype_t;

  // pre-send
  // note, this keeps a pointer to name and will delete it
  AuthAcctLogin_ToBackendMessage(uint32_t id1, uint32_t id2,
				 uint32_t reqid, const UruString &name,
				 const u_char *hash, authtype_t authtype,
				 uint32_t server_nonce=0,
				 uint32_t client_nonce=0);
  // post-receive
  AuthAcctLogin_ToBackendMessage(const u_char *inbuf, size_t in_len,
				 bool become_owner=false);

  virtual ~AuthAcctLogin_ToBackendMessage() {
    if (m_name) delete m_name;
    if (m_buf) delete[] m_buf;
  }

  // accessors
  uint32_t reqid() const { return le32toh(m_reqid); }
  UruString * name() const { return m_name; }
  const u_char * hash() const { return m_pwhash; }
  authtype_t authtype() const { return (authtype_t)le32toh(m_authtype); }
  // KEEP little-endian as they are hashed in that order
  uint32_t server_nonce() const { return m_server; }
  uint32_t client_nonce() const { return m_client; }

protected:
  uint32_t m_reqid; // little-endian
  UruString *m_name;
  u_char m_pwhash[20];
  uint32_t m_authtype; // little-endian
  uint32_t m_server; // little-endian
  uint32_t m_client; // little-endian

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class AuthAcctLogin_FromBackendMessage : public BackendMessage {
public:
  // pre-send
  // note, this keeps a pointer to dirname and will delete it
  AuthAcctLogin_FromBackendMessage(uint32_t id1, uint32_t id2,
				   uint32_t reqid, status_code_t result,
				   const u_char *acct_uuid=NULL,
				   customer_type_t acct_type=GUEST_CUSTOMER,
				   UruString *dirname=NULL,
				   u_char *p_info=NULL, u_int p_info_len=0,
				   bool become_owner=false);

  // post-receive
  AuthAcctLogin_FromBackendMessage(const u_char *inbuf, size_t in_len,
				   bool become_owner=false);

  virtual ~AuthAcctLogin_FromBackendMessage() {
    if (m_dirname) delete m_dirname;
    if (m_buf) delete[] m_buf;
  }

  // accessors
  uint32_t reqid() const { return le32toh(m_reqid); }
  status_code_t result() const { return (status_code_t)le32toh(m_result); }
  const u_char * acct_uuid() const { return m_uuid; }
  customer_type_t acct_type() const {
    return (customer_type_t)le32toh(m_acct_type);
  }
  UruString * dirname() const { return m_dirname; }
  const u_char * player_info() const { return m_buf; }
  u_int player_info_len() const { return m_buflen; }

protected:
  uint32_t m_reqid; // little-endian
  uint32_t m_result; // little-endian
  u_char m_uuid[UUID_RAW_LEN];
  uint32_t m_acct_type; // little-endian
  UruString *m_dirname;

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class AuthKIValidate_ToBackendMessage : public BackendMessage {
public:
  // pre-send
  AuthKIValidate_ToBackendMessage(uint32_t id1, uint32_t id2,
				  const u_char *acct_uuid, kinum_t kinum);

  // post-receive
  AuthKIValidate_ToBackendMessage(const u_char *inbuf, size_t in_len,
				  bool become_owner=false);

  virtual ~AuthKIValidate_ToBackendMessage() { }

  // accessors
  kinum_t kinum() const { return (kinum_t)le32toh(m_kinum); }
  const u_char * acct_uuid() const { return m_uuid; }

protected:
  uint32_t m_kinum; // little-endian
  u_char m_uuid[UUID_RAW_LEN];

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class AuthKIValidate_FromBackendMessage : public BackendMessage {
public:
  // pre-send
  AuthKIValidate_FromBackendMessage(uint32_t id1, uint32_t id2,
				    kinum_t kinum, status_code_t result);

  // post-receive
  AuthKIValidate_FromBackendMessage(const u_char *inbuf, size_t in_len,
				    bool become_owner=false);

  virtual ~AuthKIValidate_FromBackendMessage() { }

  // accessors
  kinum_t kinum() const { return (kinum_t)le32toh(m_kinum); }
  status_code_t result() const { return (status_code_t)le32toh(m_result); }

protected:
  uint32_t m_kinum; // little-endian
  uint32_t m_result; // little-endian

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class AuthPlayerLogout_BackendMessage : public BackendMessage {
public:
  // pre-send
  AuthPlayerLogout_BackendMessage(uint32_t id1, uint32_t id2,
				  kinum_t kinum);

  // post-receive
  AuthPlayerLogout_BackendMessage(const u_char *inbuf, size_t in_len,
				  bool become_owner=false);

  virtual ~AuthPlayerLogout_BackendMessage() { }

  // accessors
  kinum_t kinum() const { return (kinum_t)le32toh(m_kinum); }

protected:
  uint32_t m_kinum; // little-endian

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class AuthChangePassword_ToBackendMessage : public BackendMessage {
public:
  // pre-send
  AuthChangePassword_ToBackendMessage(uint32_t id1, uint32_t id2,
				      const u_char *uuid,
				      uint32_t reqid, const UruString &name,
				      const u_char *hash);

  // post-receive
  AuthChangePassword_ToBackendMessage(const u_char *inbuf, size_t in_len,
				      bool become_owner=false);

  virtual ~AuthChangePassword_ToBackendMessage() {
    if (m_name) delete m_name;
    if (m_buf) delete[] m_buf;
  }

  // accessors
  const u_char * acct_uuid() const { return m_uuid; }
  uint32_t reqid() const { return le32toh(m_reqid); }
  UruString * name() const { return m_name; }
  const u_char * hash() const { return m_pwhash; }

protected:
  u_char m_uuid[UUID_RAW_LEN];
  uint32_t m_reqid; // little-endian
  UruString *m_name;
  u_char m_pwhash[20];

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class AuthChangePassword_FromBackendMessage : public BackendMessage {
public:
  // pre-send
  AuthChangePassword_FromBackendMessage(uint32_t id1, uint32_t id2,
					uint32_t reqid, status_code_t result);

  // post-receive
  AuthChangePassword_FromBackendMessage(const u_char *inbuf, size_t in_len,
					bool become_owner=false);

  virtual ~AuthChangePassword_FromBackendMessage() { }

  // accessors
  uint32_t reqid() const { return le32toh(m_reqid); }
  status_code_t result() const { return (status_code_t)le32toh(m_result); }

protected:
  uint32_t m_reqid; // little-endian
  uint32_t m_result; // little-endian

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class VaultPlayerCreate_ToBackendMessage : public BackendMessage {
public:
  // pre-send
  VaultPlayerCreate_ToBackendMessage(uint32_t id1, uint32_t id2,
				     uint32_t reqid, u_char *acct_uuid,
				     const UruString &name,
				     const UruString &gender);

  // post-receive
  VaultPlayerCreate_ToBackendMessage(const u_char *inbuf, size_t in_len,
				     bool become_owner=false);

  virtual ~VaultPlayerCreate_ToBackendMessage() {
    if (m_name) delete m_name;
    if (m_gender) delete m_gender;
    if (m_buf) delete[] m_buf;
  }

  // accessors
  uint32_t reqid() const { return le32toh(m_reqid); }
  UruString * name() const { return m_name; }
  UruString * gender() const { return m_gender; }
  const u_char * acct_uuid() const { return m_uuid; }

protected:
  uint32_t m_reqid; // little-endian
  UruString *m_name;
  UruString *m_gender;
  u_char m_uuid[UUID_RAW_LEN];

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class VaultPlayerCreate_FromBackendMessage : public BackendMessage {
public:
  // pre-send
  VaultPlayerCreate_FromBackendMessage(uint32_t id1, uint32_t id2,
				       uint32_t reqid, status_code_t result,
				       kinum_t kinum=0,
				       customer_type_t acct_type=GUEST_CUSTOMER,
				       UruString *name=NULL,
				       UruString *gender=NULL);

  // post-receive
  VaultPlayerCreate_FromBackendMessage(const u_char *inbuf, size_t in_len,
				       bool become_owner=false);

  virtual ~VaultPlayerCreate_FromBackendMessage() {
    if (m_name) delete m_name;
    if (m_gender) delete m_gender;
    if (m_buf) delete[] m_buf;
  }

  // accessors
  uint32_t reqid() const { return le32toh(m_reqid); }
  status_code_t result() const { return (status_code_t)le32toh(m_result); }
  kinum_t kinum() const { return (kinum_t)le32toh(m_kinum); }
  customer_type_t acct_type() const {
    return (customer_type_t)le32toh(m_acct_type);
  }
  UruString * name() const { return m_name; }
  UruString * gender() const { return m_gender; }

protected:
  uint32_t m_reqid; // little-endian
  uint32_t m_result; // little-endian
  uint32_t m_kinum; // little-endian
  uint32_t m_acct_type; // little-endian
  UruString *m_name;
  UruString *m_gender;

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class VaultPlayerDelete_ToBackendMessage : public BackendMessage {
public:
  // pre-send
  VaultPlayerDelete_ToBackendMessage(uint32_t id1, uint32_t id2,
				     uint32_t reqid, kinum_t ki);

  // post-receive
  VaultPlayerDelete_ToBackendMessage(const u_char *inbuf, size_t in_len,
				     bool become_owner=false);

  virtual ~VaultPlayerDelete_ToBackendMessage() { }

  // accessors
  uint32_t reqid() const { return le32toh(m_reqid); }
  kinum_t kinum() const { return (kinum_t)le32toh(m_kinum); }

protected:
  uint32_t m_reqid; // little-endian
  uint32_t m_kinum; // little-endian

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class VaultPlayerDelete_FromBackendMessage : public BackendMessage {
public:
  // pre-send
  VaultPlayerDelete_FromBackendMessage(uint32_t id1, uint32_t id2,
				       uint32_t reqid, status_code_t result);

  // post-receive
  VaultPlayerDelete_FromBackendMessage(const u_char *inbuf, size_t in_len,
				       bool become_owner=false);

  virtual ~VaultPlayerDelete_FromBackendMessage() { }

  // accessors
  uint32_t reqid() const { return le32toh(m_reqid); }
  status_code_t result() const { return (status_code_t)le32toh(m_result); }

protected:
  uint32_t m_reqid; // little-endian
  uint32_t m_result; // little-endian

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

/*
 * For vault messages the auth server doesn't care about, it makes a simple
 * passthrough message to send to the backend and it receives the same from
 * the backend. The vault message classes are somewhat asymmetric, as the
 * backend server parses and creates them, so there are _To messages with only
 * the "post-receive" constructor and _From messages with only the "pre-send"
 * constructor.
 * XXX If the auth<->backend messages are changed to not go over the network
 * but just be passed on message queues, the auth server will have to call
 * the constructors before enqueuing the message instead of the backend server
 * calling them after reading the message.
 */
class VaultPassthrough_BackendMessage : public BackendMessage {
public:
  static NetworkMessage * make_if_enough(const u_char *buf, size_t len,
					 int *want_len,
					 bool become_owner=false);

  // pre-send
  VaultPassthrough_BackendMessage(uint32_t id1, uint32_t id2,
				  const u_char *inbuf, size_t in_len,
				  bool to_server, bool become_owner=false);

  // post-receive
  VaultPassthrough_BackendMessage(const u_char *inbuf, size_t in_len,
				  bool to_server, bool become_owner=false);

  virtual ~VaultPassthrough_BackendMessage() { if (m_buf) delete[] m_buf; }

  // accessors
  virtual uint32_t reqid() const {
    return read32(m_buf, 2+m_vault_offset);
  }
  virtual int16_t uru_msgtype() const { return le16toh(m_msgtype); }

protected:
  u_int m_vault_offset;
  int16_t m_msgtype; // little-endian

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);

  // for subclasses
  // setup_header() call will still be required, obviously
  VaultPassthrough_BackendMessage(int type, int msgtype=0);
  // assumes 16-byte header is present in inbuf & in_len
  VaultPassthrough_BackendMessage(int type, const u_char *inbuf,
				  size_t in_len, bool become_owner);
};

class VaultFetchRefs_ToBackendMessage : public VaultPassthrough_BackendMessage {
public:
  // post-receive
  VaultFetchRefs_ToBackendMessage(const u_char *inbuf, size_t in_len,
				  bool become_owner);

  // accessors
  uint32_t reqid() const { return le32toh(m_reqid); }
  uint32_t node_id() const { return le32toh(m_node); }

protected:
  uint32_t m_reqid; // little-endian
  uint32_t m_node; // little-endian

  // should not be called
  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class VaultNode_ToBackendMessage : public VaultPassthrough_BackendMessage {
public:
  // post-receive
  VaultNode_ToBackendMessage(const u_char *inbuf, size_t in_len,
			     bool become_owner);

  virtual ~VaultNode_ToBackendMessage();

  // accessors
  uint32_t reqid() const { return le32toh(m_reqid); }
  uint32_t node_id() const { return le32toh(m_id); } // Save only
  const u_char * requuid() const { return m_uuid; } // Save only
  const VaultNode * data() const { return m_node; }

protected:
  uint32_t m_reqid; // little-endian
  uint32_t m_id; // little-endian
  u_char m_uuid[UUID_RAW_LEN];
  VaultNode *m_node;

  // should not be called
  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

// unfortunately, this class is code-identical to
// VaultFetchRefs_ToBackendMessage except for the type values
class VaultNodeFetch_ToBackendMessage : public VaultPassthrough_BackendMessage {
public:
  // post-receive
  VaultNodeFetch_ToBackendMessage(const u_char *inbuf, size_t in_len,
				  bool become_owner);

  // accessors
  uint32_t reqid() const { return le32toh(m_reqid); }
  uint32_t node_id() const { return le32toh(m_node); }

protected:
  uint32_t m_reqid; // little-endian
  uint32_t m_node; // little-endian

  // should not be called
  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class VaultNodeFetch_FromBackendMessage
  : public VaultPassthrough_BackendMessage {
public:
  // pre-send; note the _message_ is responsible for deleting the VaultNode
  VaultNodeFetch_FromBackendMessage(uint32_t id1, uint32_t id2,
				    uint32_t reqid, status_code_t result,
				    VaultNode *node);

  virtual ~VaultNodeFetch_FromBackendMessage();

protected:
  uint32_t m_reqid; // little-endian
  uint32_t m_result; // little-endian
  VaultNode *m_node;

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class VaultRefChange_ToBackendMessage
  : public VaultPassthrough_BackendMessage {
public:
  // post-receive
  VaultRefChange_ToBackendMessage(const u_char *inbuf, size_t in_len,
				  bool become_owner);

  // accessors
  bool is_add() const;
  uint32_t reqid() const { return le32toh(m_reqid); }
  uint32_t parent() const { return le32toh(m_parent); }
  uint32_t child() const { return le32toh(m_child); }
  // for add only
  uint32_t owner() const { return le32toh(m_owner); }

protected:
  uint32_t m_reqid; // little-endian
  uint32_t m_parent; // little-endian
  uint32_t m_child; // little-endian
  uint32_t m_owner; // little-endian

  // should not be called
  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class VaultInitAge_ToBackendMessage : public VaultPassthrough_BackendMessage {
public:
  // post-receive
  VaultInitAge_ToBackendMessage(const u_char *inbuf, size_t in_len,
				bool become_owner);

  virtual ~VaultInitAge_ToBackendMessage() {
    if (m_filename) delete m_filename;
    if (m_instance) delete m_instance;
    if (m_username) delete m_username;
    if (m_dispname) delete m_dispname;
  }

  // accessors
  uint32_t reqid() const { return le32toh(m_reqid); }
  const u_char * create_uuid() const { return m_createuuid; }
  const u_char * parent_uuid() const { return m_parentuuid; }
  UruString * age_filename() const { return m_filename; }
  UruString * instance_name() const { return m_instance; }
  UruString * user_defined_name() const { return m_username; }
  UruString * display_name() const { return m_dispname; }
  uint32_t unk() const { return le32toh(m_unk); }
  int32_t node_id() const { return le32toh(m_id); }

protected:
  uint32_t m_reqid; // little-endian
  u_char m_createuuid[UUID_RAW_LEN];
  u_char m_parentuuid[UUID_RAW_LEN];
  UruString *m_filename;
  UruString *m_instance;
  UruString *m_username;
  UruString *m_dispname;
  uint32_t m_unk; // little-endian
  int32_t m_id; // little-endian

  // should not be called
  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class VaultAgeList_ToBackendMessage : public VaultPassthrough_BackendMessage {
public:
  // post-receive
  VaultAgeList_ToBackendMessage(const u_char *inbuf, size_t in_len,
				bool become_owner);

  virtual ~VaultAgeList_ToBackendMessage() {
    if (m_filename) delete m_filename;
  }

  // accessors
  uint32_t reqid() const { return le32toh(m_reqid); }
  UruString * age_filename() const { return m_filename; }

protected:
  uint32_t m_reqid; // little-endian
  UruString *m_filename;

  // should not be called
  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class VaultNodeSend_BackendMessage : public VaultPassthrough_BackendMessage {
public:
  // post-receive
  VaultNodeSend_BackendMessage(const u_char *inbuf, size_t in_len,
			       bool become_owner);

  // accessors
  kinum_t player() const { return (kinum_t)le32toh(m_player); }
  uint32_t nodeid() const { return le32toh(m_nodeid); }

protected:
  uint32_t m_player; // little-endian
  uint32_t m_nodeid; // little-endian

  // should not be called
  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class VaultSetAgePublic_BackendMessage
  : public VaultPassthrough_BackendMessage {
public:
  // post-receive
  VaultSetAgePublic_BackendMessage(const u_char *inbuf, size_t in_len,
				   bool become_owner);

  // accessors
  uint32_t age_nodeid() const { return le32toh(m_nodeid); }
  bool set_public() const { return (m_public != 0); }

protected:
  uint32_t m_nodeid; // little-endian
  u_char m_public;

  // should not be called
  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class VaultScoreGet_ToBackendMessage
  : public VaultPassthrough_BackendMessage {
public:
  // post-receive
  VaultScoreGet_ToBackendMessage(const u_char *inbuf, size_t in_len,
				 bool become_owner);

  virtual ~VaultScoreGet_ToBackendMessage() { if (m_name) delete m_name; }

  // accessors
  uint32_t reqid() const { return le32toh(m_reqid); }
  kinum_t holder() const { return (kinum_t)le32toh(m_holder); }
  UruString * score_name() const { return m_name; }

protected:
  uint32_t m_reqid; // little-endian
  uint32_t m_holder; // little-endian
  UruString *m_name;

  // should not be called
  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class VaultScoreGet_FromBackendMessage
  : public VaultPassthrough_BackendMessage {
public:
  // pre-send, has error
  VaultScoreGet_FromBackendMessage(uint32_t id1, uint32_t id2, uint32_t reqid,
				   status_code_t result);
  // pre-send, no error
  VaultScoreGet_FromBackendMessage(uint32_t id1, uint32_t id2, uint32_t reqid,
				   status_code_t result, uint32_t score_id,
				   kinum_t holder, int32_t create_time,
				   uint32_t type, int32_t score_value,
				   UruString *score_name);

protected:
  uint32_t m_reqid; // little-endian
  uint32_t m_result; // little-endian
  uint32_t m_code; // little-endian
  uint32_t m_msglen; // little-endian

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class VaultScoreCreate_BackendMessage
  : public VaultPassthrough_BackendMessage {
public:
  // post-receive
  VaultScoreCreate_BackendMessage(const u_char *inbuf, size_t in_len,
				  bool become_owner);

  virtual ~VaultScoreCreate_BackendMessage() { if (m_name) delete m_name; }

  // accessors
  uint32_t reqid() const { return le32toh(m_reqid); }
  kinum_t holder() const { return (kinum_t)le32toh(m_holder); }
  UruString * score_name() const { return m_name; }
  uint32_t score_type() const { return le32toh(m_type); }
  uint32_t initial_value() const { return le32toh(m_value); }

protected:
  uint32_t m_reqid; // little-endian
  uint32_t m_holder; // little-endian
  UruString *m_name;
  uint32_t m_type; // little-endian
  uint32_t m_value; // little-endian

  // should not be called
  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class VaultScoreAddPoints_BackendMessage
  : public VaultPassthrough_BackendMessage {
public:
  // post-receive
  VaultScoreAddPoints_BackendMessage(const u_char *inbuf, size_t in_len,
				     bool become_owner=false);

  // accessors
  uint32_t reqid() const { return le32toh(m_reqid); }
  uint32_t score_id() const { return le32toh(m_scoreid); }
  int32_t delta() const { return le32toh(m_delta); }

protected:
  uint32_t m_reqid; // little-endian
  uint32_t m_scoreid; // little-endian
  int32_t m_delta; // little-endian

  // should not be called
  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class VaultScoreXferPoints_BackendMessage
  : public VaultPassthrough_BackendMessage {
public:
  // post-receive
  VaultScoreXferPoints_BackendMessage(const u_char *inbuf, size_t in_len,
				      bool become_owner=false);

  // accessors
  uint32_t reqid() const { return le32toh(m_reqid); }
  uint32_t score_id() const { return le32toh(m_scoreid); }
  uint32_t dest_id() const { return le32toh(m_destid); }
  int32_t delta() const { return le32toh(m_delta); }

protected:
  uint32_t m_reqid; // little-endian
  uint32_t m_scoreid; // little-endian
  uint32_t m_destid; // little-endian
  int32_t m_delta; // little-endian

  // should not be called
  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class TrackPing_BackendMessage : public BackendMessage {
public:
  // pre-send
  TrackPing_BackendMessage(uint32_t id1, uint32_t id2);

  // post-receive
  TrackPing_BackendMessage(const u_char *inbuf, size_t in_len,
			   bool become_owner=false);
};

// obsolete
class TrackDispatcherHello_BackendMessage : public BackendMessage {
public:
  TrackDispatcherHello_BackendMessage(const u_char *inbuf, size_t in_len,
				      bool become_owner=false);
  uint32_t restrict_type() const { return le32toh(m_restrict_type); }
protected:
  uint32_t m_restrict_type; // little-endian
};

// obsolete
class TrackDispatcherBye_BackendMessage : public BackendMessage {
public:
  TrackDispatcherBye_BackendMessage(const u_char *inbuf, size_t in_len,
				    bool become_owner=false);
};

class TrackServiceTypes_BackendMessage : public BackendMessage {
public:
  typedef enum {
    ST_NONE = 0,
    ST_HOSTNAME = 1,
    ST_IPADDR = 2
  } address_type_t;

  // pre-send
  TrackServiceTypes_BackendMessage(uint32_t id1, uint32_t id2,
				   bool auth_enabled, bool file_enabled,
				   bool game_enabled, uint32_t ip_address);
  TrackServiceTypes_BackendMessage(uint32_t id1, uint32_t id2,
				   bool auth_enabled, bool file_enabled,
				   bool game_enabled,
				   const char *resolve_address);

  // post-receive
  TrackServiceTypes_BackendMessage(const u_char *inbuf, size_t in_len,
				   bool become_owner=false);

  virtual ~TrackServiceTypes_BackendMessage() {
    if (m_hostname) delete m_hostname;
  }

  // accessors
  bool has_auth() const { return (m_auth != 0); }
  bool has_file() const { return (m_file != 0); }
  bool has_game() const { return (m_game != 0); }
  // The IP address to use for file/auth server access. These fields are
  // ignored if neither of auth or file is enabled.
  address_type_t addrtype() const { return (address_type_t)m_addrtype; }
  uint32_t address() const { return m_address; } // network order
  UruString * name() const { return m_hostname; }
  // A non-zero value indicates that the dispatcher understands pushes
  // from tracking which indicate how to respond to gatekeeper requests.
  // This is currently unimplemented.
  // A zero value means the gatekeeper will ask tracking for file/auth
  // server addresses, OR that this dispatcher does not do gatekeeper service.
  uint32_t request_pushes() const { return le32toh(m_request_pushes); }
  // A value of zero implies that the dispatcher will accept any game
  // server request. A non-zero value, if ever implemented, signals a list
  // of allowed game servers (wildcards allowed) to follow.
  uint32_t restrict_type() const { return le32toh(m_restrict_type); }

protected:
  u_char m_auth, m_file, m_game, m_addrtype;
  uint32_t m_address; // BIG-endian (network order)
  UruString *m_hostname;
  uint32_t m_request_pushes; // little-endian
  uint32_t m_restrict_type; // little-endian

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class TrackFindService_ToBackendMessage : public BackendMessage {
public:
  // pre-send
  TrackFindService_ToBackendMessage(uint32_t id1, uint32_t id2,
				    uint32_t reqid, uint32_t reqid2,
				    bool want_file);

  // post-receive
  TrackFindService_ToBackendMessage(const u_char *inbuf, size_t in_len,
				    bool become_owner=false);

  // accessors
  uint32_t reqid() const { return le32toh(m_reqid); }
  uint32_t reqid2() const { return le32toh(m_reqid2); } // for future expansion
  bool wants_file() const { return (m_want_file != 0); }

protected:
  uint32_t m_reqid; // little-endian
  uint32_t m_reqid2; // little-endian
  u_char m_want_file;

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class TrackFindService_FromBackendMessage : public BackendMessage {
public:
  typedef enum {
    ST_NONE = 0,
    ST_HOSTNAME = 1,
    ST_IPADDR = 2
  } address_type_t;

  // pre-send
  TrackFindService_FromBackendMessage(uint32_t id1, uint32_t id2,
				      uint32_t reqid, uint32_t reqid2,
				      bool is_file, uint32_t ip_address);
  TrackFindService_FromBackendMessage(uint32_t id1, uint32_t id2,
				      uint32_t reqid, uint32_t reqid2,
				      bool is_file,
				      const char *resolve_address);
  // for when there is NO server! (addrtype() will be ST_NONE)
  TrackFindService_FromBackendMessage(uint32_t id1, uint32_t id2,
				      uint32_t reqid, uint32_t reqid2,
				      bool is_file);

  // post-receive
  TrackFindService_FromBackendMessage(const u_char *inbuf, size_t in_len,
				      bool become_owner=false);

  virtual ~TrackFindService_FromBackendMessage() {
    if (m_hostname) delete m_hostname;
  }

  // accessors
  uint32_t reqid() const { return le32toh(m_reqid); }
  uint32_t reqid2() const { return le32toh(m_reqid2); } // for future expansion
  bool is_file() const { return (m_is_file != 0); }
  address_type_t addrtype() const { return (address_type_t)m_addrtype; }
  uint32_t address() const { return m_address; } // network order
  UruString * name() const { return m_hostname; }

protected:
  uint32_t m_reqid; // little-endian
  uint32_t m_reqid2; // little-endian
  u_char m_is_file;
  u_char m_addrtype;
  uint32_t m_address; // BIG-endian (network order)
  UruString *m_hostname;

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class TrackGameHello_BackendMessage : public BackendMessage {
public:
  // pre-send
  TrackGameHello_BackendMessage(uint32_t id1, uint32_t id2,
				const u_char *uuid, uint32_t server_id,
				uint32_t connect_ipaddr);

  // post-receive
  TrackGameHello_BackendMessage(const u_char *inbuf, size_t in_len,
				bool become_owner=false);

  // accessors
  const u_char * age_uuid() const { return m_uuid; }
  uint32_t server_id() const { return le32toh(m_id); }
  uint32_t ipaddr() const { return le32toh(m_ipaddr); }

protected:
  u_char m_uuid[UUID_RAW_LEN];
  uint32_t m_id; // little-endian
  uint32_t m_ipaddr; // little-endian

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class TrackGameBye_ToBackendMessage : public BackendMessage {
public:
  // pre-send
  TrackGameBye_ToBackendMessage(uint32_t id1, uint32_t id2, bool final);

  // post-receive
  TrackGameBye_ToBackendMessage(const u_char *inbuf, size_t in_len,
				bool become_owner=false);
  // accessors
  bool final() const { return (m_final != 0); }

protected:
  uint32_t m_final;

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class TrackGameBye_FromBackendMessage : public BackendMessage {
public:
  // pre-send
  TrackGameBye_FromBackendMessage(uint32_t id1, uint32_t id2);

  // post-receive
  TrackGameBye_FromBackendMessage(const u_char *inbuf, size_t in_len,
				  bool become_owner=false);
};

class TrackGamePlayerInfo_BackendMessage : public BackendMessage {
public:
  // pre-send
  TrackGamePlayerInfo_BackendMessage(uint32_t id1, uint32_t id2,
				     kinum_t kinum, bool present);

  // post-receive
  TrackGamePlayerInfo_BackendMessage(const u_char *inbuf, size_t in_len,
				     bool become_owner=false);

  // accessors
  kinum_t kinum() const { return (kinum_t)le32toh(m_kinum); }
  bool present() const { return (m_present != 0); }

protected:
  uint32_t m_kinum; // little-endian
  u_char m_present;

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class TrackMsgForward_BackendMessage : public BackendMessage {
public:
  // pre-send
  TrackMsgForward_BackendMessage(uint32_t id1, uint32_t id2,
				 NetworkMessage *msg_to_fwd, u_int recips_at);

  // post-receive
  TrackMsgForward_BackendMessage(const u_char *inbuf, size_t in_len,
				 int msg_type, bool become_owner=false);

  virtual ~TrackMsgForward_BackendMessage();

  // accessors
  uint32_t recips_offset() const { return le32toh(m_recip_offset); }
  u_int fwd_msg_len() const { return message_len() - 20; }
  const u_char *fwd_msg() const;

protected:
  uint32_t m_recip_offset; // little-endian
  NetworkMessage *m_msg;
  u_int m_msg_offset;

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

// this is sent from the vault to game servers when global or "vault" SDL
// is updated
// XXX if tracking and vault were ever separated, the message would
// have to go vault->tracking->game instead
class TrackSDLUpdate_BackendMessage : public BackendMessage {
public:
  typedef enum {
    INVALID = 0,
    GLOBAL_INIT = 1,
    GLOBAL_UPDATE = 2, // not currently used/supported
    VAULT_SDL_UPDATE = 3,
    VAULT_SDL_LOAD = 4
  } sdl_type_t;

  // pre-send
  // this constructor has to copy the buffer
  TrackSDLUpdate_BackendMessage(uint32_t id1, uint32_t id2, kinum_t from_ki,
				uint32_t from_id1, uint32_t from_id2,
				const u_char *sdl_buf, size_t sdl_len,
				sdl_type_t update_type);

  // post-receive
  TrackSDLUpdate_BackendMessage(const u_char *inbuf, size_t in_len,
				bool become_owner);

  virtual ~TrackSDLUpdate_BackendMessage() { if (m_buf) delete[] m_buf; }

  // accessors
  kinum_t sent_by() const { return (kinum_t)le32toh(m_kinum); }
  uint32_t from_id1() const { return le32toh(m_from_id1); }
  uint32_t from_id2() const { return le32toh(m_from_id2); }
  const u_char *sdl_buf() const { return m_buf+m_data_off; }
  uint32_t sdl_len() const { return le32toh(m_datalen); }
  sdl_type_t update_type() const { return (sdl_type_t)le32toh(m_sdl_type); }

protected:
  uint32_t m_kinum; // little-endian
  uint32_t m_from_id1, m_from_id2; // little-endian
  u_int m_data_off;
  uint32_t m_datalen; // little-endian
  uint32_t m_sdl_type; // little-endian

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class TrackNextGameID_BackendMessage : public BackendMessage {
public:
  // pre-send
  TrackNextGameID_BackendMessage(uint32_t id1, uint32_t id2, bool server,
				 u_int howmany, u_int start=0);

  // post-receive
  TrackNextGameID_BackendMessage(const u_char *inbuf, size_t in_len,
				 int msg_type, bool become_owner);

  virtual ~TrackNextGameID_BackendMessage() { }

  // accessors
  // The idea with having the ability to request a block of numbers is that
  // if we ever scaled to a large system, some special code could be used
  // for the global city to request hundreds of IDs at a time (think GZ
  // marker games), the hood to request one (or a few) preemptively, etc.
  // Since there is no expectation to ever get there, the game server
  // doesn't implement any of that, but the message is designed for it.
  uint32_t how_many() const { return le32toh(m_number); }
  uint32_t start_at() const { return le32toh(m_start); }

protected:
  uint32_t m_number; // little-endian
  uint32_t m_start; // little-endian

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class TrackAgeRequest_ToBackendMessage : public BackendMessage {
public:
  // pre-send
  TrackAgeRequest_ToBackendMessage(uint32_t id1, uint32_t id2,
				   uint32_t reqid, const UruString &agename,
				   const u_char *ageuuid);

  // post-receive
  TrackAgeRequest_ToBackendMessage(const u_char *inbuf, size_t in_len,
				   bool become_owner=false);

  virtual ~TrackAgeRequest_ToBackendMessage() {
    if (m_filename) delete m_filename;
  }

  // accessors
  uint32_t reqid() const { return le32toh(m_reqid); }
  UruString * filename() const { return m_filename; }
  const u_char * age_uuid() const { return m_uuid; }

protected:
  uint32_t m_reqid; // little-endian
  u_char m_uuid[UUID_RAW_LEN];
  UruString *m_filename;

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class TrackAgeRequest_FromBackendMessage : public BackendMessage {
public:
  // pre-send
  TrackAgeRequest_FromBackendMessage(uint32_t id1, uint32_t id2,
				     uint32_t reqid, status_code_t result,
				     const u_char *uuid=NULL,
				     uint32_t server_id=0,
				     uint32_t age_node=0, uint32_t ipaddr=0);

  // post-receive
  TrackAgeRequest_FromBackendMessage(const u_char *inbuf, size_t in_len,
				     bool become_owner=false);

  // accessors
  uint32_t reqid() const { return le32toh(m_reqid); }
  status_code_t result() const { return (status_code_t)le32toh(m_result); }
  const u_char * msg_body() const { return m_body; }
  u_int body_len() const { return 28U; }

protected:
  uint32_t m_reqid; // little-endian
  uint32_t m_result; // little-endian
  u_char m_body[28];

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class TrackStartAge_FromBackendMessage : public BackendMessage {
public:
  // pre-send
  TrackStartAge_FromBackendMessage(uint32_t id1, uint32_t id2,
				   UruString *agename, const u_char *ageuuid);

  // post-receive
  TrackStartAge_FromBackendMessage(const u_char *inbuf, size_t in_len,
				   bool become_owner=false);

  virtual ~TrackStartAge_FromBackendMessage() {
    if (m_filename) delete m_filename;
  }

  // accessors
  UruString * filename() const { return m_filename; }
  const u_char * age_uuid() const { return m_ageuuid; }

protected:
  u_char m_ageuuid[UUID_RAW_LEN];
  UruString *m_filename;

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

// this message is only used as a NACK right now
class TrackStartAge_ToBackendMessage : public BackendMessage {
public:
  typedef enum {
    NONE = 0, // just in case, so we don't have to renumber ;-)
    // dispatcher
    NOT_ALLOWED = 1,
    NO_AGE = 2,
    NO_SDL = 3,
    NO_RESOURCE = 4,
  } problem_t;

  // pre-send
  TrackStartAge_ToBackendMessage(uint32_t id1, uint32_t id2,
				 const u_char *ageuuid, problem_t problem);

  // post-receive
  TrackStartAge_ToBackendMessage(const u_char *inbuf, size_t in_len,
				 bool become_owner=false);

  // accessors
  const u_char * age_uuid() const { return m_ageuuid; }
  problem_t problem() const { return (problem_t)le32toh(m_problem); }

protected:
  u_char m_ageuuid[UUID_RAW_LEN];
  uint32_t m_problem; // little-endian

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

// send client info to a game server
class TrackAddPlayer_FromBackendMessage : public BackendMessage {
public:
  // pre-send
  TrackAddPlayer_FromBackendMessage(uint32_t id1, uint32_t id2, kinum_t kinum,
				    const UruString &player_name,
				    const u_char *uuid);

  // post-receive
  TrackAddPlayer_FromBackendMessage(const u_char *inbuf, size_t in_len,
				    bool become_owner=false);

  // accessors
  kinum_t kinum() const { return (kinum_t)le32toh(m_kinum); }
  const u_char * acct_uuid() const { return m_uuid; }
  UruString * player_name() { return m_name; }

  virtual ~TrackAddPlayer_FromBackendMessage() { if (m_name) delete m_name; }

protected:
  uint32_t m_kinum; // little-endian
  u_char m_uuid[UUID_RAW_LEN];
  UruString *m_name;

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class TrackAddPlayer_ToBackendMessage : public BackendMessage {
public:
  // pre-send
  TrackAddPlayer_ToBackendMessage(uint32_t id1, uint32_t id2,
				  kinum_t kinum, status_code_t result);

  // post-receive
  TrackAddPlayer_ToBackendMessage(const u_char *inbuf, size_t in_len,
				  bool become_owner=false);

  // accessors
  kinum_t kinum() const { return (kinum_t)le32toh(m_kinum); }
  status_code_t result() const { return (status_code_t)le32toh(m_result); }

protected:
  uint32_t m_kinum; // little-endian
  uint32_t m_result; // little-endian

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class Marker_BackendMessage : public BackendMessage {
public:
  // note this structure is designed to match the server<->client messages
  typedef struct {
    double x; // little-endian
    double y; // little-endian
    double z; // little-endian
    int32_t number; // little-endian
  } marker_data_t;
  // sizeof(marker_data_t) is 32 bytes on 64-bit machines, which is *not*
  // the size when sent
  static const u_int marker_data_len = 28;

  // accessors
  uint32_t requester() const { return le32toh(m_requester); }
  uint32_t localid() const { return le32toh(m_localid); }
  // for message re-use
  void change_to_server();

protected:
  Marker_BackendMessage(int type, uint32_t requester, uint32_t localid)
    : BackendMessage(type), m_requester(requester), m_localid(localid) { }
  Marker_BackendMessage(int type, const u_char *inbuf, size_t in_len)
    : BackendMessage(type, inbuf, in_len),
      m_requester(read32le(inbuf, 16)), m_localid(read32le(inbuf, 20)) { }
  uint32_t m_requester; // little-endian
  uint32_t m_localid; // little-endian
};

class MarkerGetGame_BackendMessage : public Marker_BackendMessage {
public:
  // pre-send
  MarkerGetGame_BackendMessage(uint32_t id1, uint32_t id2, bool server,
			       uint32_t gameid, bool exists,
			       uint32_t player_or_localid, char type,
			       const u_char *uuid, UruString *name);

  // post-receive
  MarkerGetGame_BackendMessage(const u_char *inbuf, size_t in_len,
			       int msg_type, bool become_owner=false);

  // accessors
  bool exists() const { return (m_game_exists != 0); }
  kinum_t player() const { return le32toh(m_localid); }
  char game_type() const { return m_game_type; }
  const u_char * template_uuid() const { return m_template; }
  UruString * name() const { return m_name; }

  virtual ~MarkerGetGame_BackendMessage() {
    if (m_name) delete m_name;
    if (m_buf) delete[] m_buf;
  }

protected:
  u_char m_game_exists;
  char m_game_type;
  u_char m_template[UUID_RAW_LEN];
  UruString *m_name;

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class MarkerAdd_BackendMessage : public Marker_BackendMessage {
public:
  // pre-send
  // note: these "double"s are all little-endian order, never host order
  MarkerAdd_BackendMessage(uint32_t id1, uint32_t id2, bool server,
			   uint32_t gameid, uint32_t localid,
			   double x, double y, double z,
			   const UruString &name, const UruString &age,
			   int number=-1);

  // post-receive
  MarkerAdd_BackendMessage(const u_char *inbuf, size_t in_len,
			   int msg_type, bool become_owner=false);

  // accessors
  const marker_data_t * const data() { return m_data; }
  int32_t number() const { return le32toh(m_data->number); }
  UruString * name() const { return m_name; }
  UruString * agename() const { return m_agename; }
  // for use in backend (enables message reuse)
  void set_number(int marker) { m_data->number = htole32(marker); }

  virtual ~MarkerAdd_BackendMessage() {
    if (m_name) delete m_name;
    if (m_agename) delete m_agename;
    if (m_buf) delete[] m_buf;
  }

protected:
  marker_data_t *m_data; // all little-endian
  UruString *m_name;
  UruString *m_agename;

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class MarkersAll_BackendMessage : public Marker_BackendMessage {
public:
  // pre-send
  MarkersAll_BackendMessage(uint32_t id1, uint32_t id2, uint32_t localid,
			    uint32_t gameid, size_t num_entries);
  // note: these "double"s are all little-endian order, never host order
  void add_marker(int32_t number, double x, double y, double z,
		  UruString &name, UruString &age);
  void finalize();

  // post-receive
  MarkersAll_BackendMessage(const u_char *inbuf, size_t in_len,
			    bool become_owner=false);

  virtual ~MarkersAll_BackendMessage() {
    if (m_name) delete m_name;
    if (m_agename) delete m_agename;
    if (m_buf) delete[] m_buf;
  }

  // accessors
  size_t size() const { return le32toh(m_listlen); }
  // the following four routines only work post-receive
  void advance_index();
  // the following return values at the current index
  const marker_data_t * data() const { return m_current; }
  UruString * name() const { return m_name; }
  UruString * agename() const { return m_agename; }

protected:
  uint32_t m_listlen; // little-endian

  u_int m_index; // for bookkeeping, so host order
  // pre-send data storage
  struct marker_info {
    marker_data_t data;
    size_t info_size;
    UruString markername;
    UruString agename;
  };
  std::vector<struct marker_info> m_list;
  // post-receive data access
  const u_char *m_bufp;
  marker_data_t *m_current;
  UruString *m_name;
  UruString *m_agename;

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class MarkersCaptured_BackendMessage : public Marker_BackendMessage {
public:
  // pre-send
  MarkersCaptured_BackendMessage(uint32_t id1, uint32_t id2, uint32_t localid,
				 uint32_t gameid, size_t num_entries);
  void add_marker(int32_t number, int32_t value);
  void finalize();

  // post-receive
  MarkersCaptured_BackendMessage(const u_char *inbuf, size_t in_len,
				 bool become_owner=false);

  virtual ~MarkersCaptured_BackendMessage() { if (m_buf) delete[] m_buf; }

  // accessors
  size_t size() const { return le32toh(m_listlen); }
  const u_char * list() const { return m_bufp; }

protected:
  uint32_t m_listlen; // little-endian

  u_int m_index; // for bookkeeping, so host order
  u_char *m_bufp;

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class MarkerGameRename_BackendMessage : public Marker_BackendMessage {
public:
  // pre-send
  MarkerGameRename_BackendMessage(uint32_t id1, uint32_t id2, bool server,
				  uint32_t gameid, uint32_t localid,
				  const UruString &name);

  // post-receive
  MarkerGameRename_BackendMessage(const u_char *inbuf, size_t in_len,
				  int msg_type, bool become_owner=false);

  // accessors
  UruString * name() const { return m_name; }

  virtual ~MarkerGameRename_BackendMessage() {
    if (m_name) delete m_name;
    if (m_buf) delete[] m_buf;
  }

protected:
  UruString *m_name;

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class MarkerGameDelete_BackendMessage : public Marker_BackendMessage {
public:
  // pre-send
  MarkerGameDelete_BackendMessage(uint32_t id1, uint32_t id2, bool server,
				  uint32_t gameid, uint32_t localid);

  // post-receive
  MarkerGameDelete_BackendMessage(const u_char *inbuf, size_t in_len,
				  int msg_type, bool become_owner=false);

  // for use in backend (enables message reuse)
  void clear_id() { m_localid = 0; }

protected:
  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class MarkerGameRenameMarker_BackendMessage : public Marker_BackendMessage {
public:
  // pre-send
  MarkerGameRenameMarker_BackendMessage(uint32_t id1, uint32_t id2,
					bool server, uint32_t gameid,
					uint32_t localid, int32_t number,
					const UruString &name);

  // post-receive
  MarkerGameRenameMarker_BackendMessage(const u_char *inbuf, size_t in_len,
					int msg_type, bool become_owner=false);

  // accessors
  int32_t number() const { return le32toh(m_number); }
  UruString * name() const { return m_name; }

  virtual ~MarkerGameRenameMarker_BackendMessage() {
    if (m_name) delete m_name;
    if (m_buf) delete[] m_buf;
  }

protected:
  int32_t m_number; // little-endian
  UruString *m_name;

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class MarkerGameDeleteMarker_BackendMessage : public Marker_BackendMessage {
public:
  // pre-send
  MarkerGameDeleteMarker_BackendMessage(uint32_t id1, uint32_t id2,
					bool server, uint32_t gameid,
					uint32_t localid, int32_t number);

  // post-receive
  MarkerGameDeleteMarker_BackendMessage(const u_char *inbuf, size_t in_len,
					int msg_type,
					bool become_owner=false);

  // accessors
  int32_t number() const { return le32toh(m_number); }

  virtual ~MarkerGameDeleteMarker_BackendMessage() {
    if (m_buf) delete[] m_buf;
  }

protected:
  int32_t m_number; // little-endian

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class MarkerGameCaptureMarker_BackendMessage : public Marker_BackendMessage {
public:
  // pre-send
  MarkerGameCaptureMarker_BackendMessage(uint32_t id1, uint32_t id2,
					 bool server, uint32_t gameid,
					 uint32_t localid, kinum_t player,
					 int32_t number, int32_t newvalue);

  // post-receive
  MarkerGameCaptureMarker_BackendMessage(const u_char *inbuf, size_t in_len,
					 int msg_type,
					 bool become_owner=false);

  // accessors
  kinum_t player() const { return (kinum_t)le32toh(m_player); }
  int32_t number() const { return le32toh(m_number); }
  int32_t value() const { return le32toh(m_value); }

protected:
  uint32_t m_player; // little-endian
  int32_t m_number; // little-endian
  int32_t m_value; // little-endian

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

class MarkerGameStop_BackendMessage : public Marker_BackendMessage {
public:
  // pre-send
  MarkerGameStop_BackendMessage(uint32_t id1, uint32_t id2, bool server,
				uint32_t gameid, uint32_t localid,
				kinum_t player);

  // post-receive
  MarkerGameStop_BackendMessage(const u_char *inbuf, size_t in_len,
				int msg_type, bool become_owner=false);

  // accessors
  kinum_t player() const { return (kinum_t)le32toh(m_player); }

protected:
  uint32_t m_player; // little-endian

  virtual u_int fill_type(bool iovs, u_int start_at, bool *msg_done,
			  struct iovec *iov, u_int iov_ct,
			  u_char *buffer, size_t buflen);
};

#endif /* _BACKEND_MESSAGE_H_ */
