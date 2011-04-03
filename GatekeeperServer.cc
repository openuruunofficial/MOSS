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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <stdarg.h>
#include <pthread.h>
#include <signal.h>
#include <iconv.h>

#include <sys/socket.h>
#include <fcntl.h>
#include <sys/time.h>

#include <arpa/inet.h> /* for inet_ntop() */
#include <netinet/in.h>

#include <stdexcept>
#include <deque>
#include <list>
#include <vector>

#ifdef HAVE_OPENSSL
#include <openssl/rc4.h>
#ifdef USING_RSA
#include <openssl/rsa.h>
#endif
#ifdef USING_DH
#include <openssl/dh.h>
#endif
#else
#include "rc4.h"
#if defined(USING_RSA) || defined(USING_DH)
#error OpenSSL is required to use RSA or D-H!
#endif
#endif

#include "machine_arch.h"
#include "exceptions.h"
#include "constants.h"
#include "protocol.h"
#include "msg_typecodes.h"
#include "backend_typecodes.h"
#include "util.h"
#include "UruString.h"
#include "Buffer.h"

#include "Logger.h"
#include "NetworkMessage.h"
#include "BackendMessage.h"
#include "GatekeeperMessage.h"
#include "MessageQueue.h"

#include "moss_serv.h"
#include "GatekeeperServer.h"

GatekeeperServer::GatekeeperServer(int the_fd, const char *server_dir,
				   bool is_a_thread,
				   struct sockaddr_in &vault_address)
  : Server(server_dir, is_a_thread),
    m_state(START), m_vault_addr(vault_address), m_vault(NULL)
{
  Connection *conn = new GatekeeperConnection(the_fd, m_state, m_log);
  m_conns.push_back(conn);
}

GatekeeperServer::~GatekeeperServer() {
  log_debug(m_log, "deleting\n");
#ifdef USING_RSA
  if (m_keydata) {
    RSA *rsa = (RSA *)m_keydata;
    RSA_free(rsa);
  }
#endif
#ifdef USING_DH
  if (m_keydata) {
    DH *dh = (DH *)m_keydata;
    DH_free(dh);
  }
#endif
  // do not delete m_vault (it is in m_conns and deleted in ~Server)
}

int GatekeeperServer::init() {
  // set up vault/tracking server connection
  m_vault = connect_to_backend(&m_vault_addr);
  if (m_vault) {
    m_conns.push_back(m_vault);
    if (!m_vault->in_connect()) {
      // make sure to send hello
      conn_completed(m_vault);
    }
  }
  else {
    // error was already logged
    return -1;
  }
  return 0;
}

bool GatekeeperServer::shutdown(reason_t reason) {
  log_info(m_log, "Shutdown started\n");
  // there are no messages that need to be sent anywhere
  std::list<Connection*>::iterator iter;
  for (iter = m_conns.begin(); iter != m_conns.end(); ) {
    Connection *conn = *iter;
    delete conn;
    iter = m_conns.erase(iter);
  }
  return true;
}

NetworkMessage *
GatekeeperServer::GatekeeperConnection::make_if_enough(const u_char *buf,
						       size_t len,
						       int *want_len,
						       bool become_owner) {
  NetworkMessage *msg = NULL;

  *want_len = -1;
  if (m_state < NEGOTIATION_DONE) {
    msg = NegotiationMessage::make_if_enough(buf, len, TYPE_GATEKEEPER);
  }
  else if (m_state < NONCE_DONE) {
    if (len < 2) {
      return NULL;
    }
    if (buf[0] != TYPE_NONCE) {
      log_net(m_log, "Unknown message type during negotiation: %u\n",
	      buf[0] & 0xFF);
      msg = new UnknownMessage(buf, len);
    }
    else {
      msg = NegotiationMessage::make_if_enough(buf+1, len-1, TYPE_NONCE);
      if (msg && (msg->message_len() < len)) {
	log_warn(m_log, "Client sent stuff before key was computed!\n");
	if (m_log) {
	  m_log->dump_contents(Logger::LOG_WARN, buf+msg->message_len(),
			       len-msg->message_len());
	}
      }
    }
  }
  else {
    if (!m_is_encrypted && len > 0 && m_state == NONCE_DONE) {
      // turn on encryption, and then decrypt the read buffer
      // (just this once)
#ifndef NO_ENCRYPTION
      set_encrypted();
      decrypt((u_char*)buf, len);
#endif
    }
    msg = GatekeeperClientMessage::make_if_enough(buf, len);
  }

  if (become_owner) {
    // this should never happen
#ifdef DEBUG_ENABLE
    throw std::logic_error("GatekeeperConnection ownership of buffer "
			   "not taken");
#endif
    delete[] buf;
  }
  return msg;
}

Server::reason_t GatekeeperServer::message_read(Connection *conn,
						NetworkMessage *in) {
  if (conn == m_vault) {
    Connection *client = NULL;
    std::list<Connection*>::iterator iter;
    for (iter = m_conns.begin(); iter != m_conns.end(); iter++) {
      if ((*iter) != m_vault) {
	client = *iter;
	break;
      }
    }
    if (!client) {
      // we lost the client connection, so we don't care about what's coming
      // from the backend
      delete in;
      return NO_SHUTDOWN;
    }

    switch (in->type()) {
    case (ADMIN_HELLO|FROM_SERVER):
      {
	Hello_BackendMessage *msg = (Hello_BackendMessage *)in;
	log_msgs(m_log, "Backend connection protocol version %u\n",
		 msg->peer_info());
	// no more required at this time (all speak version 0)
      }
      break;
    case (TRACK_FIND_SERVICE|FROM_SERVER):
      {
	TrackFindService_FromBackendMessage *msg
	  = (TrackFindService_FromBackendMessage *)in;
	GatekeeperServerMessage *reply;

	uint32_t ipaddr = INADDR_ANY;
	if ((msg->addrtype()
	     == TrackFindService_FromBackendMessage::ST_HOSTNAME)
	    && msg->name()->strlen() != 0) {
	  // resolve the hostname now (originating dispatcher had
	  // always_resolve set)
	  const char *result = resolve_hostname(msg->name()->c_str(),
						&ipaddr);
	  if (result) {
	    log_warn(m_log, "Could not resolve \"%s\" for client: %s\n",
		     msg->name()->c_str(), result);
	  }
	}
	else if (msg->addrtype()
		 == TrackFindService_FromBackendMessage::ST_IPADDR) {
	  ipaddr = msg->address(); // no swapping; big-endian
	}

	if (msg->addrtype() == TrackFindService_FromBackendMessage::ST_NONE
	    || ipaddr == INADDR_ANY) {
	  // There is not much we can do. The client will hang if we do
	  // anything but provide a working address. Sending an empty string
	  // will make UruLauncher wedge upon using the Cancel button.
	  // Sending *some* address makes the Cancel button work, so use
	  // 0.0.0.0 to make sure no connections happen.
	  reply = new GatekeeperServerMessage(msg->is_file(),
					      msg->reqid(), "0.0.0.0");
	}
	else {
	  char addrtext[INET_ADDRSTRLEN];
	  if (!inet_ntop(AF_INET, &ipaddr, addrtext, INET_ADDRSTRLEN)) {
	    // cannot format address... again, send 0.0.0.0 to stop things
	    log_err(m_log, "Cannot format IP address 0x%08x!\n", ipaddr);
	    reply = new GatekeeperServerMessage(msg->is_file(),
						msg->reqid(), "0.0.0.0");
	  }
	  else {
	    reply = new GatekeeperServerMessage(msg->is_file(), msg->reqid(),
						addrtext);
	  }
	}
	client->enqueue(reply);
      }
      break;
    case -1:
      // unrecognized message
      log_err(m_log, "Unrecognized backend message received\n");
      if (m_log) {
	m_log->dump_contents(Logger::LOG_ERR, in->buffer(), in->message_len());
      }
      delete in;
      return PROTOCOL_ERROR;
    default:
      log_warn(m_log, "Unrecognized backend message type 0x%08x\n",
	       in->type());
    }
    delete in;
    return NO_SHUTDOWN;
  }

  if (m_state < NEGOTIATION_DONE) {
    if (in->type() == -1) {
      // unrecognized message
      log_net(m_log, "Unrecognized message during negotiation\n");
      if (m_log) {
	m_log->dump_contents(Logger::LOG_NET, in->buffer(), in->message_len());
      }
      delete in;
      return PROTOCOL_ERROR;
    }
    if (in->check_useable()) {
      NegotiationMessage *msg = (NegotiationMessage *)in;
      if (m_log && m_log->would_log_at(Logger::LOG_INFO)) {
	char uuid[UUID_STR_LEN];
	format_uuid(msg->uuid(), uuid);
	log_info(m_log, "Client version: %u Release: %u UUID: %s\n",
		 msg->client_version(), msg->release_number(), uuid);
      }
    }
    else {
      // well, I don't *need* that info...
      log_warn(m_log, "Negotiation message too short!\n");
      if (m_log) {
	m_log->dump_contents(Logger::LOG_WARN,
			     in->buffer(), in->message_len());
      }
    }
    m_state = NEGOTIATION_DONE;
  }
  else if (m_state < NONCE_DONE) {
    if (in->type() == -1) {
      // unrecognized message
      log_net(m_log, "Unrecognized message during negotiation\n");
      if (m_log) {
	m_log->dump_contents(Logger::LOG_NET, in->buffer(), in->message_len());
      }
      delete in;
      return PROTOCOL_ERROR;
    }
    if (in->check_useable()) {
      // decrypt & set up key

      log_msgs(m_log, "Setting up session key (fd %d)\n", conn->fd());
#if defined(USING_RSA) || defined(USING_DH)
      reason_t key_okay = conn->setup_rc4_key(in->buffer()+1, m_keydata,
					      conn->fd(), m_log);
      if (key_okay != NO_SHUTDOWN) {
	// problem is already logged
	delete in;
	return key_okay;
      }
#endif
      m_state = NONCE_DONE;
    }
    else {
      log_warn(m_log, "Nonce message too short!\n");
      if (m_log) {
	m_log->dump_contents(Logger::LOG_WARN,
			     in->buffer(), in->message_len());
      }
      delete in;
      return PROTOCOL_ERROR;
    }
  }

  /* from here is normal processing (after start-up) */

  else {
    if (in->type() == -1) {
      // unrecognized message
      if (in->message_len() <= 0) {
	log_warn(m_log, "Gatekeeper message with length %d\n",
		 in->message_len());
	delete in;
	return PROTOCOL_ERROR;
      }
      log_net(m_log, "Unrecognized gatekeeper message\n");
      if (m_log) {
	m_log->dump_contents(Logger::LOG_NET, in->buffer(), in->message_len());
      }
    }
    else {
      // normal message processing
      if (in->type() == kGateKeeper2Cli_PingReply) {
	gettimeofday(&conn->m_timeout, NULL);
	conn->m_timeout.tv_sec += conn->m_interval;
	conn->enqueue(in);
	// we do not want to delete the message, so skip the end
	return NO_SHUTDOWN;
      }
      GatekeeperClientMessage *gin = (GatekeeperClientMessage*)in;
      TrackFindService_ToBackendMessage *query
	= new TrackFindService_ToBackendMessage(m_ipaddr, m_id, gin->reqid(),
						0, gin->wants_file());
      m_vault->enqueue(query);
    }
  }

  delete in;
  return NO_SHUTDOWN;
}

void GatekeeperServer::conn_completed(Connection *conn) {
  conn->set_in_connect(false);
  if (conn == m_vault) {
    conn->m_interval = BACKEND_KEEPALIVE_INTERVAL;
    gettimeofday(&conn->m_timeout, NULL);
    conn->m_timeout.tv_sec += conn->m_interval;

    Hello_BackendMessage *msg = new Hello_BackendMessage(m_ipaddr, m_id,
							 type());
    conn->enqueue(msg);
  }
  else {
    log_warn(m_log, "Unknown outgoing connection (fd %d) completed!\n",
	     conn->fd());
  }
}

Server::reason_t GatekeeperServer::conn_timeout(Connection *conn,
						Server::reason_t why) {
  if (conn == m_vault) {
    TrackPing_BackendMessage *msg
      = new TrackPing_BackendMessage(m_ipaddr, m_id);
    m_vault->enqueue(msg);
    m_vault->m_timeout.tv_sec += m_vault->m_interval;
    return NO_SHUTDOWN;
  }

  return why;
}

Server::reason_t GatekeeperServer::conn_shutdown(Connection *conn,
						 Server::reason_t why) {
  if (conn == m_vault) {
    if (why == CLIENT_CLOSE) {
      why = BACKEND_ERROR;
    }
  }

  if (why != SERVER_SHUTDOWN) {
    // we have to clear the queue of any messages because otherwise they will
    // keep the server running
    conn->m_write_fill = 0;
    conn->msg_queue()->reset_head();
    conn->msg_queue()->clear_queue();
  }

  return why;
}
