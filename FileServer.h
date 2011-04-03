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
 * FileServer is the class representing a file server connection. It manages
 * the state of each transaction, and allows multiple transactions to be
 * going on in parallel (e.g. manifest requests mixed with downloads, multiple
 * files downloaded at once).
 */

//#include <sys/time.h>
//
//#include <netinet/in.h>
//
//#include <list>
//
//#include "Logger.h"
//#include "NetworkMessage.h"
//#include "FileTransaction.h"
//#include "moss_serv.h"
//
//#include "FileMessage.h"

#ifndef _FILE_SERVER_H_
#define _FILE_SERVER_H_

class FileServer : public Server {
public:
  FileServer(int the_fd, const char *server_dir, bool is_a_thread);

  virtual ~FileServer() {
    log_debug(m_log, "deleting\n");
    std::list<FileTransaction*>::iterator iter; 
    for (iter = m_pending_transactions.begin();
	 iter != m_pending_transactions.end();
	 iter++) {
      FileTransaction *tr = *iter;
      delete tr;
    }
  }

  int type() const { return TYPE_FILE; }
  const char * type_name() const { return "file"; }

  reason_t message_read(Connection *conn, NetworkMessage *msg);

  bool shutdown(reason_t reason);

  class FileConnection : public Server::Connection {
  public:
    FileConnection(int the_fd) : Connection(the_fd), negotiation_done(false)
    {
      m_interval = KEEPALIVE_INTERVAL*4;
      gettimeofday(&m_timeout, NULL);
      m_timeout.tv_sec += m_interval;
    }
    NetworkMessage * make_if_enough(const u_char *buf, size_t len,
				    int *want_len, bool become_owner=false);
    bool negotiation_done;
  };

protected:
  // protocol info
  std::list<FileTransaction*> m_pending_transactions;
};

#endif /* _FILE_SERVER_H_ */
