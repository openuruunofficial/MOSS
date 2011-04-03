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
 * AuthServer is the class representing an auth server connection. It has a
 * backend connection to the vault/tracking server.
 */

#ifndef _AUTH_SERVER_H_
#define _AUTH_SERVER_H_

//#include <sys/time.h>
//
//#include <netinet/in.h>
//
//#include "Buffer.h"
//
//#include "Logger.h"
//#include "FileTransaction.h"
//#include "AuthMessage.h"
//#include "BackendMessage.h"
//
//#include "moss_serv.h"

class AuthServer : public Server {
public:
  AuthServer(int the_fd, const char *server_dir, bool is_a_thread,
	     struct sockaddr_in &vault_address);
  void setkey(void *keydata) { m_keydata = keydata; }
  virtual ~AuthServer();

  int type() const { return TYPE_AUTH; }
  const char * type_name() const { return "auth"; }

  int init();
  bool shutdown(reason_t reason);

  reason_t message_read(Connection *conn, NetworkMessage *msg);

  void conn_completed(Connection *conn);

  reason_t conn_timeout(Connection *conn, reason_t why);
  reason_t conn_shutdown(Connection *conn, reason_t why);

  // protocol info
  typedef enum {
    START = 0,
    NEGOTIATION_DONE = 1,
    NONCE_DONE = 2,
    REGISTER = 3,
    LOGIN = 4,
    LOGIN_DONE = 5,
    DOWNLOAD = 6,
    IN_STARTUP = 7,
    VAULT_DOWNLOAD = 8,
    AGE_REQ = 9,
    IN_GAME = 10
  } state_t;

  class AuthConnection : public Server::Connection {
  public:
    AuthConnection(int the_fd, state_t &state, Logger *log)
      : Connection(the_fd), m_state(state), m_log(log)
    {
      m_interval = KEEPALIVE_INTERVAL*4;
      gettimeofday(&m_timeout, NULL);
      m_timeout.tv_sec += m_interval;
    }
    NetworkMessage * make_if_enough(const u_char *buf, size_t len,
				    int *want_len, bool become_owner=false);
  private:
    state_t &m_state;
    Logger *m_log;
  };

protected:
  void *m_keydata;

  // backend connection(s)
  struct sockaddr_in m_vault_addr;
  Connection *m_vault;

  const char * state_string() {
    switch(m_state) {
    case START:
      return "START";
    case NEGOTIATION_DONE:
      return "NEGOTIATION_DONE";
    case NONCE_DONE:
      return "NONCE_DONE";
    case REGISTER:
      return "REGISTER";
    case LOGIN:
      return "LOGIN";
    case LOGIN_DONE:
      return "LOGIN_DONE";
    case DOWNLOAD:
      return "DOWNLOAD";
    case IN_STARTUP:
      return "IN_STARTUP";
    case VAULT_DOWNLOAD:
      return "VAULT_DOWNLOAD";
    case AGE_REQ:
      return "AGE_REQ";
    case IN_GAME:
      return "IN_GAME";
    default:
      return "(unknown)";
    }
  }
  reason_t backend_message(Connection *conn, BackendMessage *msg);

  // connection state tracking
  state_t m_state;
  u_int m_reqid;
  char *m_download_dir;
  FileTransaction *m_download;

  // other data
  uint32_t m_nonce; // little-endian server nonce
  u_char m_client_uuid[16];
  bool m_is_visitor;
  kinum_t m_kinum;
#ifdef PELLET_SCORE_CACHE
  u_int m_pelletreq;
  u_char *m_pelletbuf;
#endif
};

#endif /* _AUTH_SERVER_H_ */
