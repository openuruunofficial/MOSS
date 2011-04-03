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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h> /* for read() */
#endif

#include <stdarg.h>
#include <signal.h>
#include <iconv.h>
#include <sys/mman.h> /* for mmap() */

#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/uio.h> /* for struct iovec */

#include <netinet/in.h>

#include <stdexcept>
#include <deque>
#include <list>
#include <vector>
#include <string>

#ifdef HAVE_OPENSSL
#include <openssl/rc4.h>
#else
#include "rc4.h"
#endif

#include "machine_arch.h"
#include "exceptions.h"
#include "constants.h"
#include "protocol.h"
#include "msg_typecodes.h"
#include "util.h"
#include "UruString.h"
#include "Buffer.h"

#include "Logger.h"
#include "NetworkMessage.h"
#include "FileTransaction.h"
#include "FileMessage.h"
#include "BackendMessage.h"
#include "MessageQueue.h"

#include "moss_serv.h"
#include "FileServer.h"

FileServer::FileServer(int the_fd, const char *server_dir, bool is_a_thread)
  : Server(server_dir, is_a_thread)
{
  Connection *conn = new FileConnection(the_fd);
  m_conns.push_back(conn);
}

bool FileServer::shutdown(reason_t reason) {
  if (m_conns.size() > 0) {
    m_conns.front()->m_write_fill = 0;
    MessageQueue *queue = m_conns.front()->msg_queue();
    queue->reset_head();
    queue->clear_queue();
  }
  return true;
}

NetworkMessage *
FileServer::FileConnection::make_if_enough(const u_char *buf, size_t len,
					   int *want_len, bool become_owner) {
  NetworkMessage *msg;

  *want_len = -1;
  if (!negotiation_done) {
    msg = NegotiationMessage::make_if_enough(buf, len, TYPE_FILE);
  }
  else {
    msg = FileClientMessage::make_if_enough(buf, len);
  }

  if (msg && become_owner) {
    // this should never happen
#ifdef DEBUG_ENABLE
    throw std::logic_error("FileConnection ownership of buffer not taken");
#endif
    delete[] buf;
  }
  return msg;
}

Server::reason_t FileServer::message_read(Connection *c,
					  NetworkMessage *in) {
  FileConnection *conn = (FileConnection*)c;
  if (!conn->negotiation_done) {
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
      if (m_log && m_log->would_log_at(Logger::LOG_INFO)) {
	NegotiationMessage *msg = (NegotiationMessage *)in;
	int version = msg->client_version();
	char uuid[UUID_STR_LEN];
	format_uuid(msg->uuid(), uuid);
	log_info(m_log, "Client version: %u%s Release: %u UUID: %s\n",
		 version,
		 version == 0 ? " (launcher)" :"", msg->release_number(),
		 uuid);
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
    conn->negotiation_done = true;
  }
  else {
      if (in->type() == -1) {
	// unrecognized message
	if (in->message_len() <= 0) {
	  log_net(m_log, "File message with length %d\n", in->message_len());
	  delete in;
	  return PROTOCOL_ERROR;
	}
	log_net(m_log, "Unrecognized file message\n");
	if (m_log) {
	  m_log->dump_contents(Logger::LOG_NET,
			       in->buffer(), in->message_len());
	}
      }
      else if (!in->check_useable()) {
	// protocol error
	log_warn(m_log, "File message too short!\n");
	if (m_log) {
	  m_log->dump_contents(Logger::LOG_WARN,
			       in->buffer(), in->message_len());
	}
	delete in;
	return PROTOCOL_ERROR;
      }
      else {
	FileClientMessage *msg = (FileClientMessage *)in;
	if (msg->type() == PingRequestTrans) {
	  gettimeofday(&conn->m_timeout, NULL);
	  conn->m_timeout.tv_sec += conn->m_interval;
	  FileServerMessage *reply = new FileServerMessage(msg);
	  conn->enqueue(reply, MessageQueue::NORMAL);
	}
	else if (msg->type() == ManifestRequestTrans
		 || msg->type() == DownloadRequestTrans) {
	  bool is_manifest = (msg->type() == ManifestRequestTrans);
	  FileTransaction *trans
	    = new FileTransaction(msg->request_id(), m_log,
				  is_manifest, false);
	  
	  UruString namestr(msg->object_name(), msg->object_name_maxlen(),
			    false, true, false);
	  u_int ret = namestr.strlen();
	  u_int len = ret + sizeof(".mbm");
	  char fname[len];
	  strncpy(fname, namestr.c_str(), ret);
	  fname[ret] = '\0';
	  log_msgs(m_log, "%s request for %s\n",
		   is_manifest ? "ManifestRequest" : "DownloadRequest",
		   fname);
	  if (is_manifest) {
	    strncpy(fname+ret, ".mbm", len-ret);
	  }
	  // CRITICAL FOR SECURITY: make sure there are no .. elements
	  for (u_int i = 0; i < ret; i++) {
	    if ((fname[i] == '.' && fname[i+1] == '.')
		|| fname[i] == '/' || fname[i] == '\\') {
	      if (!is_manifest && (fname[i] == '\\' || fname[i] == '/')) {
		fname[i] = PATH_SEPARATOR[0];
	      }
	      else {
		log_warn(m_log, "Possibly malicious %s requested: %s; "
			 "killing connection\n",
			 is_manifest ? "manifest" : "download", fname);
		if (m_log) {
		  m_log->dump_contents(Logger::LOG_WARN, msg->object_name(),
				       msg->object_name_maxlen());
		}
		// kill the connection
		delete in;
		return SERVER_SHUTDOWN;
	      }
	    }
	  }

	  trans->init(m_serv_dir, fname);
	  m_pending_transactions.push_back(trans);
	  FileServerMessage *reply = new FileServerMessage(trans, msg->type());
	  conn->enqueue(reply, MessageQueue::NORMAL);
	}
	else if (msg->type() == FileRcvdFileDownloadChunkTrans
		 || msg->type() == FileRcvdFileManifestChunkTrans) {
	  uint32_t id = msg->request_id();
	  bool found = false;
	  std::list<FileTransaction*>::iterator iter;
	  for (iter = m_pending_transactions.begin();
	       iter != m_pending_transactions.end();
	       iter++) {
	    if ((*iter)->request_id() == id) {
	      FileTransaction *trans = *iter;
	      trans->chunk_acked();
	      if (trans->file_complete()) {
		// the file is done being downloaded
		delete trans;
		m_pending_transactions.erase(iter); // invalidates iter
	      }
	      else {
		FileServerMessage *next = new FileServerMessage(trans,
			msg->type() == FileRcvdFileDownloadChunkTrans
			? DownloadRequestTrans : ManifestRequestTrans);
		conn->enqueue(next, MessageQueue::NORMAL);
	      }
	      found = true;
	      break;
	    }
	  }
	  if (!found) {
	    log_warn(m_log, "Got ChunkAck for unknown transaction %u\n", id);
	  }
	  else {
//	    log_msgs(m_log, "ChunkAck for transaction %u\n", id);
	  }
	}
	else if (msg->type() == BuildIdRequestTrans) {
#ifdef OLD_PROTOCOL
#ifdef OLD_PROTOCOL4
	  int build = 556; // Live4
#else
	  int build = 401; // last open beta?
#endif
#else
	  int build = 847; // Live9
#endif
	  FileServerMessage *reply = new FileServerMessage(msg->request_id(),
							   NO_ERROR, build);
	  conn->enqueue(reply, MessageQueue::NORMAL);
	}
	else {
	  // this should only happen with a serious coding bug
	  log_err(m_log, "Server bug: FileServerMessage type %d created\n",
		  msg->type());
	}
      }
  }
  delete in;
  return NO_SHUTDOWN;
}
