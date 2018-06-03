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
#include <errno.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdarg.h>
#include <pthread.h>
#include <signal.h>
#include <iconv.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>

#include <netinet/in.h>

#include <stdexcept>
#include <deque>
#include <list>
#include <vector>

#ifdef HAVE_OPENSSL
#ifdef USING_RSA
#include <openssl/rsa.h>
#endif
#ifdef USING_DH
#include <openssl/dh.h>
#endif
#else
#if defined(USING_RSA) || defined(USING_DH)
#error OpenSSL is required to use RSA or D-H!
#endif
#endif

#ifdef HAVE_OPENSSL_RC4
#include <openssl/rc4.h>
#else
#include "rc4.h"
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
#include "FileTransaction.h"
#include "NetworkMessage.h"
#include "BackendMessage.h"
#include "AuthMessage.h"
#include "MessageQueue.h"
#include "VaultNode.h"

#include "moss_serv.h"
#include "AuthServer.h"

AuthServer::AuthServer(int the_fd, const char *server_dir, bool is_a_thread,
		       struct sockaddr_in &vault_address)
  : Server(server_dir, is_a_thread), m_keydata(NULL),
    m_vault_addr(vault_address), m_vault(NULL),
    m_state(START), m_reqid(0),
    m_download_dir(NULL), m_download(NULL),
    m_is_visitor(true/*until authed*/), m_kinum(0)
{
  memset(m_client_uuid, 0, 16);
  Connection *conn = new AuthConnection(the_fd, m_state, m_log);
  m_conns.push_back(conn);
}

AuthServer::~AuthServer() {
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
  if (m_download_dir) {
    delete[] m_download_dir;
  }
  if (m_download) {
    delete m_download;
  }
#ifdef PELLET_SCORE_CACHE
  if (m_pelletbuf) {
    delete[] m_pelletbuf;
  }
#endif
  // do not delete m_vault (it is in m_conns and deleted in ~Server)
}

int AuthServer::init() {
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

bool AuthServer::shutdown(reason_t reason) {
  log_info(m_log, "Shutdown started\n");
  std::list<Connection*>::iterator iter;
  for (iter = m_conns.begin(); iter != m_conns.end(); iter++) {
    Connection *conn = *iter;
    if (conn == m_vault) {
      conn->msg_queue()->clear_queue();
      // here, we don't bother to queue a message to the backend server saying
      // the player is offline; the backend will notice our shutdown and do
      // the proper cleanup (it has to, in order to prod the game server)
    }
    else if (reason == SERVER_SHUTDOWN || reason == UNEXPECTED_STATE) {
      // let the queue drain; either the server is trying to send a KickedOff
      // message, or the server process was killed
    }
    else {
      conn->msg_queue()->clear_queue();
    }
  }
  return false;
}

NetworkMessage *
AuthServer::AuthConnection::make_if_enough(const u_char *buf, size_t len,
					   int *want_len, bool become_owner) {
  NetworkMessage *msg = NULL;
  bool became_owner = false;

  if (m_state < NEGOTIATION_DONE) {
    *want_len = -1;
    msg = NegotiationMessage::make_if_enough(buf, len, TYPE_AUTH);
  }
  else if (m_state < NONCE_DONE) {
    if (len < 2) {
      *want_len = -1;
      return NULL;
    }
    if (buf[0] != TYPE_NONCE) {
      log_net(m_log, "Unknown message type during negotiation: %u\n",
	      buf[0] & 0xFF);
      msg = new UnknownMessage(buf, len);
    }
    else {
      *want_len = -1;
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
    msg = AuthClientMessage::make_if_enough(buf, len, want_len, become_owner);
    became_owner = true;
  }

  if (msg && become_owner && !became_owner) {
    // this should never happen
#ifdef DEBUG_ENABLE
    throw std::logic_error("AuthConnection ownership of buffer not taken");
#endif
    delete[] buf;
  }
  return msg;
}

// utility function for differentiating "email address" usernames (x@x.x)
bool is_email_username(const char *c_str, size_t len) {
  if (len < 5) {
    return false;
  }
  const char *end = c_str+len;
  const char *where = strchr(c_str/*skip first x*/+1, '@');
  if (!where) {
    return false;
  }
  where += 2; /* skip @ and second x */
  if (where >= end) {
    return false;
  }
  where = strchr(where, '.');
  if (!where || where/*require third x*/+1 >= end) {
    return false;
  }
  return true;
}

#define KICK_FOR_ERROR(a)					  \
    AuthServerKickMessage *kicked = new AuthServerKickMessage(a); \
    conn->msg_queue()->clear_queue();				  \
    conn->enqueue(kicked);

Server::reason_t AuthServer::message_read(Connection *conn,
					  NetworkMessage *in) {
  if (conn == m_vault) {
    // retrofit (from old style)
    return backend_message(conn, (BackendMessage*)in);
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
      reason_t key_okay = conn->setup_rc4_key(in->buffer()+1,
					      in->message_len()-2, m_keydata,
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
	log_warn(m_log, "Auth message with length %d\n", in->message_len());
	delete in;
	return PROTOCOL_ERROR;
      }
      log_net(m_log, "Unrecognized auth message\n");
      if (m_log) {
	m_log->dump_contents(Logger::LOG_NET, in->buffer(), in->message_len());
      }
    }
    else if (!in->check_useable()) {
      // protocol error
      log_warn(m_log, "Auth message too short!\n");
      if (m_log) {
	m_log->dump_contents(Logger::LOG_WARN,
			     in->buffer(), in->message_len());
      }
      delete in;
      return PROTOCOL_ERROR;
    }
    else {
      // normal message processing
      AuthClientMessage *ain = (AuthClientMessage*)in;

      switch (ain->msg_class()) {
      case AuthClientMessage::Ping:
	gettimeofday(&conn->m_timeout, NULL);
	conn->m_timeout.tv_sec += conn->m_interval;
	conn->enqueue(in);
	// we do not want to delete the message, so skip the end
	return NO_SHUTDOWN;
      case AuthClientMessage::LoginReq:
	if (m_state > LOGIN || m_state < REGISTER) {
	  log_warn(m_log, "AcctLoginRequest at unexpected time (state %s)\n",
		   state_string());
	}
	else {
	  AuthClientLoginMessage *login = (AuthClientLoginMessage*)in;
	  if (m_log && m_log->would_log_at(Logger::LOG_WARN)) {
	    if (login->token().strlen() != 0) {
	      log_warn(m_log, "Non-empty \"auth token\" provided: %s\n",
		       login->token().c_str());
	    }
	  }
	  if (login->login().strlen() == 0) {
	    log_warn(m_log, "AcctLoginRequest with empty name (os: %s)\n",
		     login->os().c_str());
	    AuthServerLoginMessage *reply
	      = new AuthServerLoginMessage(login->reqid(),
					   ERROR_ACCT_NOT_FOUND);
	    conn->enqueue(reply);
	  }
	  else {
	    log_info(m_log, "AcctLoginRequest for %s (os: %s)\n",
		     login->login().c_str(),
		     login->os().strlen() == 0 ? "<none>"
					       : login->os().c_str());

	    m_reqid = login->reqid();
	    m_state = LOGIN;
	    // send message to backend server

	    // unless we find out that the server knowing when to use
	    // which algorithm is part of the authentication of the server
	    // to the client, I think the best is to look at the choice the
	    // client made
	    AuthAcctLogin_ToBackendMessage::authtype_t atype =
	      AuthAcctLogin_ToBackendMessage::CHALLENGE_RESPONSE;
	    if (login->nonce() == 0) {
	      atype = AuthAcctLogin_ToBackendMessage::PLAIN_HASH;
	    }
	    AuthAcctLogin_ToBackendMessage *query =
	      new AuthAcctLogin_ToBackendMessage(m_ipaddr, m_id, m_reqid,
						 login->login(),
						 login->hash(), atype,
						 m_nonce, login->nonce());
	    m_vault->enqueue(query);
	  }
	}
	break;
      case AuthClientMessage::PasswordChange:
	{
	  AuthClientChangePassMessage *pass = (AuthClientChangePassMessage*)in;
	  if (m_state > IN_GAME) {
	    log_warn(m_log, "Rejecting AcctChangePasswordRequest at unexpected"
		     " time (state %s)\n", state_string());
	    AuthServerChangePassMessage *reply
	      = new AuthServerChangePassMessage(pass->reqid(),
						ERROR_FORBIDDEN);
	    conn->enqueue(reply);
	  }
	  else {
	    // send to backend
	    UruString &name = pass->login();
	    if (name.strlen() == 0) {
	      log_warn(m_log, "AcctChangePasswordRequest with empty name\n");
	      AuthServerChangePassMessage *reply
		= new AuthServerChangePassMessage(pass->reqid(),
						  ERROR_ACCT_NOT_FOUND);
	      conn->enqueue(reply);
	    } else if (!is_email_username(name.c_str(), name.strlen())) {
	      // The client always uses the email-address hash algorithm
	      // with /changepassword, even if the username isn't an
	      // email address. Without fixing the client, we can't do
	      // anything but reject such requests.
	      log_msgs(m_log, "AcctChangePasswordRequest for %s rejected due "
		       "to login name not being an email address\n",
		       name.c_str());
	      AuthServerChangePassMessage *reply
		= new AuthServerChangePassMessage(pass->reqid(),
						  ERROR_INVALID_PARAM);
	      conn->enqueue(reply);
	    }
	    else {
	      log_msgs(m_log, "AcctChangePasswordRequest for %s\n",
		       name.c_str());
	      // send message to backend server
	      AuthChangePassword_ToBackendMessage *query =
		new AuthChangePassword_ToBackendMessage(m_ipaddr, m_id,
							m_client_uuid,
							pass->reqid(), name,
							pass->hash());
	      m_vault->enqueue(query);
	    }
	  }
	}
	break;
      case AuthClientMessage::File:
	if (m_state <= DOWNLOAD) {
	  AuthClientFileMessage *msg = (AuthClientFileMessage*)in;
	  if (msg->type() == kCli2Auth_FileDownloadChunkAck) {
#ifndef DOWNLOAD_NO_ACKS
	    if (!m_download) {
	      log_warn(m_log, "Got FileDownloadChunkAck when no download in "
		       "progress\n");
	    }
	    else {
	      log_msgs(m_log, "FileDownloadChunkAck received\n");
	      m_download->chunk_acked();
	      if (!m_download->file_complete()) {
		AuthServerFileMessage *reply
		  = new AuthServerFileMessage(m_download,
					      kAuth2Cli_FileDownloadChunk);
		conn->enqueue(reply);
	      }
	      else {
		delete m_download;
		m_download = NULL;
	      }
	    }
#endif /* DOWNLOAD_NO_ACKS */
	  }
	  else {
	    bool is_manifest = (msg->type() == kCli2Auth_FileListRequest);
	    if (!m_download_dir) {
	      // this should not happen, login sequence from client is wrong
	      if (is_manifest) {
		log_warn(m_log, "FileListRequest for name %s class %s "
			 "without having logged in!\n",
			 msg->name().c_str(), msg->fileclass().c_str());
	      }
	      else {
		log_warn(m_log, "FileDownloadRequest for file %s"
			 "without having logged in!\n", msg->name().c_str());
	      }
	      KICK_FOR_ERROR(ERROR_DISCONNECTED);
	      delete in;
	      return UNEXPECTED_STATE;
	    }

	    if (m_download) {
	      log_warn(m_log, "New download request before previous one "
		       "completed!\n");
	      KICK_FOR_ERROR(ERROR_DISCONNECTED);
	      delete in;
	      return UNEXPECTED_STATE;
	    }

	    m_state = DOWNLOAD;
	    m_download = new FileTransaction(msg->reqid(), m_log,
					     is_manifest, true);
	    u_int ret = msg->name().strlen();
	    u_int len = ret + sizeof(".mbam");
	    char fname[len];
	    strncpy(fname, msg->name().c_str(), ret);
	    fname[ret] = '\0';
	    log_msgs(m_log, "%s request for %s\n",
		     is_manifest ? "FileListRequest" : "FileDownloadRequest",
		     fname);
	    if (is_manifest) {
	      strncpy(fname+ret, ".mbam", len-ret);
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
			   is_manifest ? "FileList" : "Download", fname);
		  if (m_log) {
		    m_log->dump_contents(Logger::LOG_WARN, msg->buffer()+6,
					 msg->message_len() - 6);
		  }
		  // kill the connection
		  KICK_FOR_ERROR(ERROR_INVALID_PARAM);
		  delete in;
		  return UNEXPECTED_STATE;
		}
	      }
	    }
	    m_download->init(m_download_dir, fname);
	    AuthServerFileMessage *reply
	      = new AuthServerFileMessage(m_download,
		  is_manifest ? kAuth2Cli_FileListReply
			      : kAuth2Cli_FileDownloadChunk);
	    conn->enqueue(reply);
#ifndef DOWNLOAD_NO_ACKS
	    if (is_manifest)
	      // forget the FileTransaction (let the AuthServerFileMessage
	      // clean up) because I think the client might request a FileList
	      // and a Download at the same time (but not more than one of
	      // each)
#else
	      // if DOWNLOAD_NO_ACKS is defined, always forget the transaction
	      // (we don't use it again)
#endif
	      m_download = NULL;
	  }
	}
	else {
	  log_warn(m_log, "Got a File transaction at unexpected time "
		   "(state %s)\n", state_string());
	  KICK_FOR_ERROR(ERROR_DISCONNECTED);
	  delete in;
	  return UNEXPECTED_STATE;
	}
	break;
      case AuthClientMessage::PlayerCreate:
	if (m_state != IN_STARTUP) {
	  log_warn(m_log, "PlayerCreateRequest at incorrect time "
		   "(state %s)\n", state_string());
	  KICK_FOR_ERROR(ERROR_DISCONNECTED);
	  delete in;
	  return UNEXPECTED_STATE;
	}
	else if (m_reqid != 0) {
	  log_warn(m_log, "PlayerCreateRequest arrived when another request "
		   "reqid=(%u) is not completed\n", m_reqid);
	  // fail this one, because I don't think this should happen here
	  AuthClientPlayerCreateMessage *msg
	    = (AuthClientPlayerCreateMessage *)in;
	  AuthServerPlayerCreateMessage *reply
	    = new AuthServerPlayerCreateMessage(msg->reqid(),
						ERROR_NO_RESPONSE,
						0, GUEST_CUSTOMER,
						NULL, NULL);
	  conn->enqueue(reply);
	}
	else {
	  AuthClientPlayerCreateMessage *msg
	    = (AuthClientPlayerCreateMessage *)in;

	  m_reqid = msg->reqid();
	  if (msg->code().strlen() > 0) {
	    if (m_log && m_log->would_log_at(Logger::LOG_DEBUG)) {
	      log_debug(m_log, "PlayerCreateRequest with invite code %s "
			"(avatar %s, gender %s, reqid %u)\n",
			msg->code().c_str(), msg->name().c_str(),
			msg->gender().c_str(), m_reqid);
	    }
	  }

	  UruString &name = msg->name();
	  // validate name string
	  /*
	   * XXX There is some debate about what characters are valid; the
	   * client does do checking but of course we are not going to rely on
	   * that. Yet I suspect even the client checking is more strict than
	   * strictly necessary (this can be experimented with by editing the
	   * name in the vault). For now, be strict (accept only what is in
	   * the list, rather than deny what is in a list).
	  */
	  const char *namestr = name.c_str();
	  u_int i = 0;
	  for ( ; i < name.strlen(); i++) {
	    if (namestr[i] >= ' ' && namestr[i] <= '~') {
	    }
	    else {
	      break;
	    }
	  }
	  if (i < name.strlen()) {
	    log_msgs(m_log, "Rejecting PlayerCreateRequest for name \"%s\"\n",
		     msg->name().c_str());
	    u_char repbuf[8];
	    write32(repbuf, 0, m_reqid);
	    write32(repbuf, 4, ERROR_NAME_INVALID);
	    AuthServerMessage *reply
	      = new AuthServerMessage(repbuf, 8, kAuth2Cli_AcctSetPlayerReply);
	    conn->enqueue(reply);
	    m_reqid = 0;
	  }
	  else {
	    log_msgs(m_log, "PlayerCreateRequest for name \"%s\" -> backend\n",
		     msg->name().c_str());
	    VaultPlayerCreate_ToBackendMessage *query
	      = new VaultPlayerCreate_ToBackendMessage(m_ipaddr, m_id, m_reqid,
						       m_client_uuid, name,
						       msg->gender());
	    m_vault->enqueue(query);
	  }
	}
	break;
      case AuthClientMessage::Vault:
	if (m_state < VAULT_DOWNLOAD) {
	  log_net(m_log,
		  "Got a Vault message at an unexpected time (state %s)\n",
		  state_string());
	  if (m_log) {
	    m_log->dump_contents(Logger::LOG_NET,
				 in->buffer(), in->message_len());
	  }
	  // ignore it, I guess
	}
	else {
	  AuthClientVaultMessage *msg = (AuthClientVaultMessage*)in;
	  switch(msg->type()) {
#ifndef OLD_PROTOCOL
	  case kCli2Auth_ScoreGetScores:
#ifdef PELLET_SCORE_CACHE
	    {
	      const u_char *score_buf = in->buffer();
	      kinum_t score_holder = (kinum_t)read32(score_buf, 6);
	      if (score_holder == m_kinum) {
		UruString score_name(score_buf+10, in->message_len()-10,
				     true, false, false);
		if (score_name == "PelletDrop") {
		  uint32_t reqid = read32(score_buf, 2);
		  if (m_pelletbuf) {
		    log_debug(m_log, "Providing cached pellet score\n");
		    write32(m_pelletbuf, 0, reqid);
		    size_t score_len = read32(m_pelletbuf, 12) + 16;
		    AuthServerMessage *cached
		      = new AuthServerMessage(m_pelletbuf, score_len,
					      kAuth2Cli_ScoreGetScoresReply);
		    conn->enqueue(cached);
		    break;
		  }
		  else {
		    // keep reqid
		    m_pelletreq = reqid;
		  }
		}
	      }
	    }
	    // FALLTHROUGH if cached score not provided
#endif /* PELLET_SCORE_CACHE */
	  case kCli2Auth_ScoreAddPoints:
	  case kCli2Auth_ScoreTransferPoints:
	  case kCli2Auth_ScoreCreate:
#endif /* OLD_PROTOCOL */
	  case kCli2Auth_VaultFetchNodeRefs:
	  case kCli2Auth_VaultNodeFind:
	  case kCli2Auth_VaultNodeFetch:
	  case kCli2Auth_VaultNodeSave:
	  case kCli2Auth_VaultNodeCreate:
	  case kCli2Auth_VaultNodeAdd:
	  case kCli2Auth_VaultNodeRemove:
	  case kCli2Auth_VaultInitAgeRequest:
	  case kCli2Auth_VaultSendNode:
	  case kCli2Auth_GetPublicAgeList:
	  case kCli2Auth_SetAgePublic:
	    // pass through to vault server
	    {
//	      log_msgs(m_log, "Passthrough vault request 0x%04x\n",
//		       msg->type());
#if !defined(OLD_PROTOCOL) && defined(PELLET_SCORE_CACHE)
	      if (m_pelletbuf
		  && (msg->type() == kCli2Auth_ScoreAddPoints
		      // XXX also ScoreDelete, ScoreSetPoints
		      || msg->type() == kCli2Auth_ScoreTransferPoints)) {
		// throw out the cached score because it might be changing --
		// this could be more selective but it's just a cache so
		// there's no need to be picky
		delete[] m_pelletbuf;
		m_pelletbuf = NULL;
	      }
#endif /* !OLD_PROTOCOL && PELLET_SCORE_CACHE */
	      VaultPassthrough_BackendMessage *vaultmsg
		= new VaultPassthrough_BackendMessage(m_ipaddr, m_id,
						      in->buffer(),
						      in->message_len(),
						      true,
						      msg->owns_buffer());
	      // make sure to do this before queuing or we may leak memory!
	      if (msg->owns_buffer()) {
		msg->make_unowned();
	      }
	      m_vault->enqueue(vaultmsg);
	    }
	    break;
	  default:
	    log_debug(m_log, "Got an unimplemented Vault message from the "
		      "client: 0x%04x\n", in->type());
	  }
	}
	break;
      case AuthClientMessage::AgeReq:
	{
	  if (m_state < VAULT_DOWNLOAD) {
	    log_warn(m_log, "AgeRequest before vault download (state %s)\n",
		     state_string());
	    KICK_FOR_ERROR(ERROR_DISCONNECTED);
	    delete in;
	    return UNEXPECTED_STATE;
	  }
	  else if (m_state == AGE_REQ && m_reqid) {
	    log_warn(m_log, "AgeRequest arrived when another AgeRequest "
		     "reqid=(%u) is not completed\n", m_reqid);
	  }
	  m_state = AGE_REQ;
	  AuthClientAgeRequestMessage *msg
	    = (AuthClientAgeRequestMessage *)in;

	  m_reqid = msg->reqid();
	  if (m_log && m_log->would_log_at(Logger::LOG_MSGS)) {
	    char ageuuid[UUID_STR_LEN];
	    format_uuid(msg->uuid(), ageuuid);
	    log_msgs(m_log, "AgeRequest for %s UUID %s\n", msg->name().c_str(),
		     ageuuid);
	  }

	  TrackAgeRequest_ToBackendMessage *query
	    = new TrackAgeRequest_ToBackendMessage(m_ipaddr, m_id, m_reqid,
						   msg->name(), msg->uuid());
	  m_vault->enqueue(query);
	}
	break;
      case AuthClientMessage::Log:
	if (m_log && m_log->would_log_at(Logger::LOG_WARN)) {
	  UruString str(in->buffer()+4, in->message_len()-4, false, true,
			false);
	  log_warn(m_log, "Got a Log message from the client:\n%s\n",
		   str.c_str());
	}
	break;
      case AuthClientMessage::Generic:
      default:
	switch (in->type()) {
	case kCli2Auth_ClientRegisterRequest:
	  if (m_state > LOGIN) {
	    log_warn(m_log, "ClientRegisterRequest at unexpected time "
		     "(state %s)\n", state_string());
	  }
	  else if (m_state == NONCE_DONE) {
	    log_msgs(m_log, "Received ClientRegisterRequest\n");
	    // XXX should I bother to check/care about the client version?
	    m_state = REGISTER;
	    // XXX see comments in get_random_data() about random numbers --
	    // technically, these need to be unpredictable much more than
	    // the RC4 key or even UUIDs
	    get_random_data((u_char*)&m_nonce, 4);
	    AuthServerMessage *reply
	      = new AuthServerMessage((u_char*)&m_nonce, 4,
				      kAuth2Cli_ClientRegisterReply);
	    conn->enqueue(reply);
	    u_char repbuf[20];
	    write32(repbuf, NO_ERROR, ntohl(m_ipaddr));
	    memcpy(repbuf+4, MOSS_UUID, 16);
	    reply = new AuthServerMessage(repbuf, 20, kAuth2Cli_ServerAddr);
	    conn->enqueue(reply);
	  }
	  else {
	    // ignore it
	    log_msgs(m_log, "Ignoring ClientRegisterRequest at weird time\n");
	  }
	  break;
	case kCli2Auth_AcctSetPlayerRequest:
#ifdef DISALLOW_NO_DOWNLOAD
	  if (m_state < DOWNLOAD) {
	    // the user did not download anything
	    log_info(m_log, "Client did not initiate \"secure download\"\n");
	    KICK_FOR_ERROR(ERROR_DISCONNECTED);
	    delete in;
	    return UNEXPECTED_STATE;
	  }
#endif
	  if (m_state != DOWNLOAD && m_state != IN_STARTUP
#ifndef DISALLOW_NO_DOWNLOAD
	      && m_state != LOGIN_DONE
#endif
	      // following is the "log out" -> StartUp transition
	      && !(m_state == IN_GAME && read32(in->buffer(), 6) == 0)) {
	    log_warn(m_log, "AcctSetPlayerRequest at unexpected time "
		     "(state %s)\n", state_string());
	    // ignore it
	  }
	  else {
	    if (m_state == DOWNLOAD && m_download) {
	      // the user did not *complete* the download
	      log_warn(m_log, "Client initiated \"secure download\" but did "
		       "not complete it\n");
	      delete m_download;
	      m_download = NULL;
	    }
	    m_state = IN_STARTUP;
	    const u_char *playerbuf = in->buffer();
	    m_reqid = read32(playerbuf, 2);
	    kinum_t newkinum = read32(playerbuf, 6);
	    log_msgs(m_log, "AcctSetPlayerRequest for %u\n", newkinum);
	    if (newkinum != 0) {
	      // verify this KI number against the auth backend server
	      // using the client UUID received earlier (we could instead
	      // cache the values in the AcctPlayerInfo messages, if we had
	      // to)
	      AuthKIValidate_ToBackendMessage *query
		= new AuthKIValidate_ToBackendMessage(m_ipaddr, m_id,
						      m_client_uuid, newkinum);
	      m_vault->enqueue(query);
	    }
	    else {
	      // shortcut
	      m_reqid = 0;
	      AuthServerMessage *reply
		= new AuthServerMessage(playerbuf+2, 8,
					kAuth2Cli_AcctSetPlayerReply);
	      conn->enqueue(reply);
	      if (m_kinum != 0) {
		// need to tell backend so it can clean up the previously
		// logged in player properly
		AuthPlayerLogout_BackendMessage *notice
		  = new AuthPlayerLogout_BackendMessage(m_ipaddr, m_id,
							m_kinum);
		m_vault->enqueue(notice);
	      }
	    }
	    m_kinum = newkinum;
	  }
	  break;
	case kCli2Auth_UpgradeVisitorRequest:
	  {
	    // XXX it appears we can safely ignore this
	    kinum_t req_ki = read32(in->buffer(), 6);
	    if (m_state != IN_STARTUP) {
	      log_warn(m_log, "UpgradeVisitorRequest for %u at unexpected "
		       "time (state %s)\n", req_ki, state_string());
	    }
	    else {
	      log_debug(m_log, "UpgradeVisitorRequest for %u ignored\n",
			req_ki);
	    }
	  }
	  break;
	case kCli2Auth_PlayerDeleteRequest:
	  {
	    kinum_t req_ki = read32(in->buffer(), 6);
	    m_reqid = read32(in->buffer(), 2);
	    if (m_state != IN_STARTUP) {
	      log_warn(m_log, "PlayerDeleteReqeust for %u at unexpected time "
		       "(state %s)\n", req_ki, state_string());
	      u_char no_delete[8];
	      write32(no_delete, 0, m_reqid);
	      write32(no_delete, 4, ERROR_INVALID_PARAM);
	      AuthServerMessage *reply
		= new AuthServerMessage(no_delete, 8,
					kAuth2Cli_PlayerDeleteReply);
	      conn->enqueue(reply);
	      m_reqid = 0;
	    }
	    else {
	      log_msgs(m_log, "PlayerDeleteRequest for %u -> backend\n",
		       req_ki);
	      VaultPlayerDelete_ToBackendMessage *query
		= new VaultPlayerDelete_ToBackendMessage(m_ipaddr, m_id,
							 m_reqid, req_ki);
	      m_vault->enqueue(query);
	    }
	  }
	  break;
#ifndef OLD_PROTOCOL
	case kCli2Auth_SendFriendInviteRequest:
	  // not really supported, functionality-wise; we just handle the
	  // message so as not to give grief to the client
	  {
	    log_msgs(m_log, "SendFriendInviteRequest\n");
	    u_char repbuf[8];
	    const u_char *playerbuf = in->buffer();
	    uint32_t reqid = read32(playerbuf, 2);
	    write32(repbuf, 0, reqid);
	    write32(repbuf, 4, ERROR_NOT_SUPPORTED);
	    AuthServerMessage *reply
		= new AuthServerMessage(repbuf, 8,
					kAuth2Cli_SendFriendInviteReply);
	    conn->enqueue(reply);
	  }
	  break;
#endif
	case kCli2Auth_LogClientDebuggerConnect:
	  log_warn(m_log, "Got a DebuggerConnect from the client\n");
	  break;
	default:
	  log_net(m_log, "Unknown message type %d\n", in->type());
	}
      }
    }
  }
  delete in;
  return NO_SHUTDOWN;
}

Server::reason_t AuthServer::backend_message(Connection *vault,
					     BackendMessage *in) {
  status_code_t response;
  uint32_t msg_reqid;

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

  switch (in->type() & ~FROM_SERVER) {
  case ADMIN_HELLO:
    {
      Hello_BackendMessage *msg = (Hello_BackendMessage *)in;
      log_msgs(m_log, "Backend connection protocol version %u\n",
	       msg->peer_info());
      // no more required at this time (all speak version 0)
    }
    break;
  case ADMIN_KILL_CLIENT:
    {
      bool terrible = true;
      status_code_t reason = ERROR_INTERNAL;
      KillClient_BackendMessage *msg = (KillClient_BackendMessage *)in;
      switch (msg->why()) {
      case KillClient_BackendMessage::IN_DOUBT:
	log_warn(m_log, "Received a connection kill message due to "
		 "\"in doubt\"\n");
	break;
      case KillClient_BackendMessage::NEW_LOGIN:
	reason = ERROR_LOGGED_IN_ELSEWHERE;
	log_warn(m_log, "Received a connection kill message due to "
		 "account logging in elsewhere\n");
	terrible = false;
	break;
      default:
	log_warn(m_log, "Received a connection kill message, reason %u\n",
		 msg->why());
      }
      if (terrible) {
	log_warn(m_log, "Something terribly has gone wrong.  "
		 "Head for the cover!\n");
      }
      AuthServerKickMessage *kicked = new AuthServerKickMessage(reason);
      client->msg_queue()->clear_queue(); // throw out any pending messages
      client->enqueue(kicked);
      delete in;
      return SERVER_SHUTDOWN;
    }
    break;
  case AUTH_ACCT_LOGIN:
    {
      AuthAcctLogin_FromBackendMessage *msg
	= (AuthAcctLogin_FromBackendMessage *)in;
      msg_reqid = msg->reqid();
      if (m_state != LOGIN) {
	// old reply somehow?
	log_debug(m_log, "Stale Login reply from backend (reqid=%u)!\n",
		  msg_reqid);
      }
      else if (m_reqid != msg_reqid) {
	log_debug(m_log, "Superceded Login reply from backend (reqid=%u)\n",
		  msg_reqid);
      }
      else {
	response = msg->result();
	if (response != NO_ERROR) {
	  // login failed
	  log_msgs(m_log, "(backend) Login failed, result=%u\n", response);
	  AuthServerLoginMessage *reply
	    = new AuthServerLoginMessage(m_reqid, response);
	  client->enqueue(reply);
	}
	else {
	  log_msgs(m_log, "(backend) Login succeeded\n");
	  memcpy(m_client_uuid, msg->acct_uuid(), 16);
	  m_is_visitor = (msg->acct_type() == GUEST_CUSTOMER);

	  // get download directory
	  u_int len = strlen(m_serv_dir)+2;
	  if (msg->dirname()->strlen()+1 < sizeof("default")) {
	    len += sizeof("default");
	  }
	  else {
	    len += msg->dirname()->strlen()+1;
	  }
	  m_download_dir = new char[len];
	  snprintf(m_download_dir, len, "%s%s%s", m_serv_dir, PATH_SEPARATOR,
		   msg->dirname()->strlen() > 0
		     ? msg->dirname()->c_str() : "default");
	  if (msg->dirname()->strlen() > 0) {
	    struct stat s;
	    int ret = stat(m_download_dir, &s);
	    if (ret < 0) {
	      log_warn(m_log,
		       "Expected \"secure download\" directory %s not found\n",
		       m_download_dir);
	      snprintf(m_download_dir, len, "%s%sdefault", m_serv_dir,
		       PATH_SEPARATOR);
	    }
	    else if (!(S_ISDIR(s.st_mode))) {
	      log_warn(m_log, "%s is not a directory\n", m_download_dir);
	      snprintf(m_download_dir, len, "%s%sdefault", m_serv_dir,
		       PATH_SEPARATOR);
	    }
	  }

	  // get the key
	  char keyfile[len+sizeof("/encryption.key")];
	  u_char keybuf[16];
	  memset(keybuf, 0, 16);
	  snprintf(keyfile, len+sizeof("/encryption.key"),
		   "%s%sencryption.key", m_download_dir, PATH_SEPARATOR);
	  int fd = open(keyfile, O_RDONLY, 0);
	  if (fd < 0) {
	    log_warn(m_log, "Error opening encryption key file %s: %s\n",
		     keyfile, strerror(errno));
	  }
	  else {
	    if (read(fd, keybuf, 16) != 16) {
	      log_err(m_log, "Error in key file read: %s\n", strerror(errno));
	    }
	    close(fd);
	  }
	  m_state = LOGIN_DONE;

	  // send any AcctPlayerInfo messages
	  if (msg->player_info_len() > 0) {
	    AuthServerMessage *reply
	      = new AuthServerMessage(msg->player_info()+2,
				      msg->player_info_len()-2,
				      kAuth2Cli_AcctPlayerInfo);
	    client->enqueue(reply);
	  }
	  // send reply message
	  AuthServerLoginMessage *reply2
	    = new AuthServerLoginMessage(m_reqid, response, msg->acct_uuid(),
			(customer_type_t)(2/*unknown*/ | msg->acct_type()),
			keybuf);
	  client->enqueue(reply2);
	}
	m_reqid = 0;
      }
    }
    break;
  case AUTH_KI_VALIDATE:
    {
      AuthKIValidate_FromBackendMessage *msg
	= (AuthKIValidate_FromBackendMessage *)in;

      msg_reqid = msg->kinum(); // actually KI number
      if (m_state != IN_STARTUP) {
	// old reply somehow?
	log_debug(m_log, "Stale KI validate reply from backend (ki=%u)!\n",
		  msg_reqid);
      }
      else if (m_kinum != msg_reqid) {
	log_debug(m_log, "Superceded KI validate reply (ki=%u)\n", msg_reqid);
      }
      else {
	response = msg->result();
	if (response != NO_ERROR) {
	  if (response == ERROR_PLAYER_NOT_FOUND) {
	    log_warn(m_log,
		     "Attack: Attempt to use an improper KI number (%u)!\n",
		     msg_reqid);
	    // kill that bugger
	    AuthServerKickMessage *kill = new AuthServerKickMessage(response);
	    client->msg_queue()->clear_queue();
	    client->enqueue(kill);
	    return UNEXPECTED_STATE;
	  }
	  else {
	    log_warn(m_log, "Server error validating KI number: %u\n",
		     response);
	  }
	}
	else {
	  log_msgs(m_log, "(backend) Validating KI number %u suceeded\n",
		   response);
	  m_state = VAULT_DOWNLOAD;
	}
	u_char repbuf[8];
	write32(repbuf, 0, m_reqid);
	write32(repbuf, 4, response);
	AuthServerMessage *reply
	  = new AuthServerMessage(repbuf, 8, kAuth2Cli_AcctSetPlayerReply);
	client->enqueue(reply);
      }
    }
    break;
  case AUTH_CHANGE_PASSWORD:
    {
      AuthChangePassword_FromBackendMessage *msg
	= (AuthChangePassword_FromBackendMessage *)in;

      response = msg->result();
      log_msgs(m_log, "(backend) change password request %s\n",
	       response == NO_ERROR ? "succeeded" : "failed");
      AuthServerChangePassMessage *reply
	= new AuthServerChangePassMessage(msg->reqid(), response);
      client->enqueue(reply);
    }
    break;
  case VAULT_PLAYER_CREATE:
    {
      VaultPlayerCreate_FromBackendMessage *msg
	= (VaultPlayerCreate_FromBackendMessage *)in;
      msg_reqid = msg->reqid();
      if (m_state != IN_STARTUP || m_reqid != msg_reqid) {
	// ???
	log_debug(m_log, "Stale player create reply from backend (reqid=%u)!\n",
		  msg_reqid);
      }
      else {
	m_reqid = 0;
      }
      response = msg->result();
      log_msgs(m_log, "(backend) Player create reply result=%u\n",
	       msg->result());
      if (response != NO_ERROR) {
	AuthServerPlayerCreateMessage *reply
	  = new AuthServerPlayerCreateMessage(msg_reqid, response);
	client->enqueue(reply);
      }
      else {
	AuthServerPlayerCreateMessage *reply
	  = new AuthServerPlayerCreateMessage(msg_reqid, response, msg->kinum(),
					      msg->acct_type(),
					      msg->name(), msg->gender());
	client->enqueue(reply);
      }
    }
    break;
  case VAULT_PLAYER_DELETE:
    {
      VaultPlayerDelete_FromBackendMessage *msg
	= (VaultPlayerDelete_FromBackendMessage *)in;
      msg_reqid = msg->reqid();
      if (m_state != IN_STARTUP || m_reqid != msg_reqid) {
	// ???
	log_debug(m_log, "Stale player delete reply from backend (reqid=%u)!\n",
		  msg_reqid);
      }
      else {
	m_reqid = 0;
      }
      response = msg->result();
      log_msgs(m_log, "(backend) Player delete reply result=%u\n",
	       msg->result());
      u_char deletebuf[8];
      write32(deletebuf, 0, msg_reqid);
      write32(deletebuf, 4, response);
      AuthServerMessage *reply
	= new AuthServerMessage(deletebuf, 8, kAuth2Cli_PlayerDeleteReply);
      client->enqueue(reply);
    }
    break;
  case VAULT_PASSTHRU:
    {
      VaultPassthrough_BackendMessage *msg
	= (VaultPassthrough_BackendMessage *)in;
      AuthServerVaultMessage *reply = new AuthServerVaultMessage(msg);
#if !defined(OLD_PROTOCOL) && defined(PELLET_SCORE_CACHE)
      // before proceeding, snoop score messages (makes a difference with
      // client freezing)
      if (reply->type() == kAuth2Cli_ScoreGetScoresReply) {
	if (reply->message_len() < 18) {
	  log_err(m_log, "Too short score reply message from backend\n");
	  if (m_log) {
	    m_log->dump_contents(Logger::LOG_ERR, reply->buffer(),
				 reply->message_len());
	  }
	}
	else {
	  size_t score_len = reply->message_len() - 2;
	  u_int lastreq = read32(reply->buffer(), 2);
	  // we only want to cache responses matching a personal PelletDrop
	  if (m_pelletreq == lastreq) {
	    log_debug(m_log, "Caching pellet score\n");
	    if (m_pelletbuf) {
	      size_t current_len = read32(m_pelletbuf, 12) + 16;
	      if (current_len < score_len) {
		delete[] m_pelletbuf;
		m_pelletbuf = new u_char[score_len];
	      }
	    }
	    else {
	      m_pelletbuf = new u_char[score_len];
	    }
	    memcpy(m_pelletbuf, reply->buffer()+2, score_len);
	  }
	}
      }
#endif /* !OLD_PROTOCOL && PELLET_SCORE_CACHE */
//      log_msgs(m_log, "(backend) Passthrough vault msg\n");

      // the reference taken by the reply message will prevent del_ref() from
      // returning 0 as long as we forget about msg here *before* enqueuing on
      // the final queue, so we don't need to test whether to delete msg
      msg->del_ref();
      // forget this reference
      in = NULL;
      client->enqueue(reply);
    }
    break;
  case TRACK_FIND_GAME:
    {
      TrackAgeRequest_FromBackendMessage *msg
	= (TrackAgeRequest_FromBackendMessage *)in;
      if (m_state != AGE_REQ) {
	// old reply somehow?
	log_debug(m_log, "Stale find age reply from backend (reqid=%u)!\n",
		  msg->reqid());
      }
      else if (m_reqid != msg->reqid()) {
	log_debug(m_log,
		  "Superceded find age reply (reqid=%u)\n", msg->reqid());
      }
      else {
	m_reqid = 0;
	if (msg->result() != NO_ERROR) {
	  log_warn(m_log, "AgeRequest failed, result=%u\n", msg->result());
	}
	else {
	  log_msgs(m_log, "(backend) AgeRequest reply\n");
	  m_state = IN_GAME;
	}
	AuthServerAgeReplyMessage *reply
	  = new AuthServerAgeReplyMessage(msg->reqid(), msg->result(),
					  msg->msg_body(), msg->body_len());
	client->enqueue(reply);
      }
    }
    break;
  default:
    ;
  }
  delete in;
  return NO_SHUTDOWN;
}

void AuthServer::conn_completed(Connection *conn) {
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

Server::reason_t AuthServer::conn_timeout(Connection *conn,
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

Server::reason_t AuthServer::conn_shutdown(Connection *conn,
					   Server::reason_t why) {
  if (conn == m_vault) {
    // XXX this is only recoverable in very particular circumstances,
    // and I will do them later if I ever get to it

    if (why == CLIENT_CLOSE) {
      why = BACKEND_ERROR;
    }
  }

  if (why != SERVER_SHUTDOWN && why != UNEXPECTED_STATE) {
    // we have to clear the queue of any messages because otherwise they will
    // keep the server running
    conn->m_write_fill = 0;
    conn->msg_queue()->reset_head();
    conn->msg_queue()->clear_queue();
  }

  return why;
}
