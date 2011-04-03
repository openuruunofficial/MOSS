/* -*- c++ -*- */

/*
  MOSS - A server for the Myst Online: Uru Live client/protocol
  Copyright (C) 2011  a'moaca'

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
 * GatekeeperServer is the class representing a gatekeeper server connection.
 */

//#include <sys/time.h>
//
//#include <netinet/in.h>
//
//#include "Buffer.h"
//
//#include "Logger.h"
//#include "NetworkMessage.h"
//#include "GatekeeperMessage.h"
//
//#include "moss_serv.h"

#ifndef _GATEKEEPER_SERVER_H_
#define _GATEKEEPER_SERVER_H_

class GatekeeperServer : public Server {
public:
  GatekeeperServer(int the_fd, const char *server_dir, bool is_a_thread,
		   struct sockaddr_in &vault_address);
  void setkey(void *keydata) { m_keydata = keydata; }
  virtual ~GatekeeperServer();

  int type() const { return TYPE_GATEKEEPER; }
  const char * type_name() const { return "gatekeeper"; }

  int init();
  bool shutdown(reason_t reason);

  reason_t message_read(Connection *conn, NetworkMessage *in);

  void conn_completed(Connection *conn);

  reason_t conn_timeout(Connection *conn, reason_t why);
  reason_t conn_shutdown(Connection *conn, reason_t why);

  typedef enum {
    START = 0,
    NEGOTIATION_DONE = 1,
    NONCE_DONE = 2
  } state_t;

  class GatekeeperConnection : public Server::Connection {
  public:
    GatekeeperConnection(int the_fd, state_t &state, Logger *log)
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
  state_t m_state;

  // backend connection
  struct sockaddr_in m_vault_addr;
  Connection *m_vault;
};

#endif /* _GATEKEEPER_SERVER_H_ */
