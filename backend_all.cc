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

#include <stdarg.h>
#include <pthread.h>
#include <signal.h>
#include <iconv.h>

#include <sys/time.h>
#include <sys/uio.h> /* for struct iovec */

#include <exception>
#include <map>
#include <list>
#include <vector>
#include <deque>
#include <string>
#include <sstream>

#ifdef USE_POSTGRES
#ifdef USE_PQXX
#include <pqxx/pqxx>
#include <pqxx/binarystring>
#else
#include <libpq-fe.h>
#error "libpqxx is required"
#endif
#else
#error "postgres is required"
#endif

#ifdef HAVE_OPENSSL
#include <openssl/rand.h>
#include <openssl/rc4.h>
#include <openssl/sha.h>
#else
#include "rc4.h"
#endif

#include "machine_arch.h"
#include "constants.h"
#include "protocol.h"
#include "msg_typecodes.h"
#include "backend_typecodes.h"
#include "util.h"
#include "UruString.h"
#include "VaultNode.h"
#include "Buffer.h"

#include "Logger.h"
#include "NetworkMessage.h"
#include "BackendMessage.h"
#include "MessageQueue.h"
#include "VaultNode.h"

#include "moss_serv.h"
#include "moss_backend.h"
#include "db_requests.h"


Server::reason_t BackendServer::handle_auth(Connection *c,
					    BackendMessage *in) {
  switch (in->type()) {

  case AUTH_ACCT_LOGIN:
    {
      AuthAcctLogin_ToBackendMessage *msg
	= (AuthAcctLogin_ToBackendMessage *)in;

      AuthAcctLogin_AcctQuery_Result login_result;
      login_result.result_code = ERROR_INTERNAL;
      u_char *buf = NULL;
      u_int buflen = 0;
      AuthAcctLogin_FromBackendMessage *reply = NULL;

#ifdef USE_POSTGRES
#ifdef USE_PQXX
      try {
	try {
	  my->C->perform(AuthAcctLogin_AcctQuery(msg->name()->c_str(),
						 login_result));
	}
	catch(const pqxx::in_doubt_error &e) {
	  // retry once (read-only operation)
	  // XXX consider using a nontransaction in read-only cases like this
	  log_warn(m_log, "in_doubt in AuthAcctLogin_AcctQuery; retrying\n");
	  my->C->perform(AuthAcctLogin_AcctQuery(msg->name()->c_str(),
						 login_result));
	}
      }
      catch(const pqxx::in_doubt_error &e) {
	log_warn(m_log, "in_doubt again in AuthAcctLogin_AcctQuery; "
		 "is something badly wrong with the DB?\n");
      }
      catch(const pqxx::broken_connection &e) {
	// pretty much fatal -- need to shut down or something
	log_err(m_log, "Connection to DB failed!\n");
	login_result.result_code = ERROR_DB_TIMEOUT;
      }
      catch(const pqxx::sql_error &e) {
	log_warn(m_log, "SQL error in AuthAcctLogin_AcctQuery: %s\n",
		 e.what());
      }
#else /* ! USE_PQXX */
      AuthAcctLogin_AcctQuery(my, msg->name()->c_str(), login_result);
      if (login_result.result_code == ERROR_DB_TIMEOUT) {
	// pretty much fatal -- need to shut down or something
	log_err(m_log, "Connection to DB failed!\n");
      }
      else if (login_result.result_code == ERROR_INTERNAL) {
	log_warn(m_log, "SQL error in AuthAcctLogin_AcctQuery\n");
      }
#endif /* USE_PQXX */
      if (login_result.result_code == ERROR_INVALID_PARAM) {
	// warn operator they goofed up
	log_err(m_log, "Password hash in DB for user %s is invalid\n",
		msg->name()->c_str());
	login_result.result_code = ERROR_LOGIN_DENIED;
      }

      // now verify the password
      if (login_result.result_code == NO_ERROR) {
	u_char new_hash[20];
	u_char *use_hash = new_hash;
	if (msg->authtype() == AuthAcctLogin_ToBackendMessage::PLAIN_HASH) {
	  use_hash = login_result.hash;
	  // now, byte-swap the computed hash (why oh why?)
	  u_char tmp;
#define HASH_SWAP(a, b) tmp = (a); (a) = (b); (b) = tmp;
	  HASH_SWAP(use_hash[0], use_hash[3]);
	  HASH_SWAP(use_hash[1], use_hash[2]);
	  HASH_SWAP(use_hash[4], use_hash[7]);
	  HASH_SWAP(use_hash[5], use_hash[6]);
	  HASH_SWAP(use_hash[8], use_hash[11]);
	  HASH_SWAP(use_hash[9], use_hash[10]);
	  HASH_SWAP(use_hash[12], use_hash[15]);
	  HASH_SWAP(use_hash[13], use_hash[14]);
	  HASH_SWAP(use_hash[16], use_hash[19]);
	  HASH_SWAP(use_hash[17], use_hash[18]);
#undef HASH_SWAP
	}
	else {
	  // compute a new hash
	  u_char inbuf[28];
	  write32le(inbuf, 0, msg->client_nonce());
	  write32le(inbuf, 4, msg->server_nonce());
	  memcpy(inbuf+8, login_result.hash, 20);
#ifdef HAVE_OPENSSL
	  SHA(inbuf, 28, new_hash);
#else
	  // cannot verify password!
	  log_err(m_log, "Cannot verify password for user %s (no OpenSSL)\n",
		  msg->name()->c_str());
	  login_result.result_code = ERROR_LOGIN_DENIED;
#endif
	}
	if (login_result.result_code == NO_ERROR) {
	  if (memcmp(use_hash, msg->hash(), 20)) {
	    login_result.result_code = ERROR_BAD_PASSWD;
	  }
	}
      }

#ifndef MULTI_LOGIN
      // if the player is already logged in, punt him there
      if (login_result.result_code == NO_ERROR) {
	ConnectionEntity *current = find_by_uuid(login_result.uuid,
						 TYPE_AUTH);
	if (current) {
	  // punt this one
	  log_debug(m_log, "Account %s has re-logged in, kicking off a "
		    "previous login\n", msg->name()->c_str());
	  KillClient_BackendMessage *killit
	    = new KillClient_BackendMessage(
					current->ipaddr(),
					current->server_id(),
					KillClient_BackendMessage::NEW_LOGIN);
	  current->conn()->enqueue(killit);
	  if (current->kinum() != 0) {
	    set_player_offline(current->kinum(), "punt");
	  }
	}
      }
#endif

      if (login_result.result_code == NO_ERROR) {
	// set the connection's UUID to the account UUID
	HashKey key(in->get_id1(), in->get_id2());
	ConnectionEntity *entity;
	if (m_hash_table.find(key) == m_hash_table.end()) {
	  log_net(m_log,
		  "No ADMIN_HELLO message from peer %08x,%08x type %d\n",
		  in->get_id1(), in->get_id2(), TYPE_AUTH);
	  entity = new ConnectionEntity(c, TYPE_AUTH);
	  m_hash_table[key] = entity;
	}
	else {
	  entity = m_hash_table[key];
	  // XXX if entity already has a non-zero UUID, verify UUIDs match
	}
	entity->set_uuid(login_result.uuid);

	// now we need the avatar messages
#ifdef USE_PQXX
	std::list<AuthAcctLogin_PlayerQuery_Player> plist;
	try {
	  my->C->perform(AuthAcctLogin_PlayerQuery(login_result.uuid, plist));
	}
	catch(const pqxx::broken_connection &e) {
	  // pretty much fatal -- need to shut down or something
	  log_err(m_log, "Connection to DB failed!\n");
	  login_result.result_code = ERROR_DB_TIMEOUT;
	}
	catch(const pqxx::sql_error &e) {
	  log_warn(m_log, "SQL error in AuthAcctLogin_PlayerQuery: %s\n",
		   e.what());
	  login_result.result_code = ERROR_INTERNAL;
	}
	if (login_result.result_code == NO_ERROR && plist.size() > 0) {
	  buf = new u_char[plist.size()*(((64+12)*2)+18)];
	  for (std::list<AuthAcctLogin_PlayerQuery_Player>::iterator
		 player = plist.begin(); player != plist.end(); player++) {
	    write32(buf, buflen, kAuth2Cli_AcctPlayerInfo);
	    buflen += 2;
	    write32(buf, buflen, msg->reqid());
	    buflen += 4;
	    write32(buf, buflen, player->kinum);
	    buflen += 4;
	    memcpy(buf+buflen, player->name.get_str(true, true, false),
		   player->name.send_len(true, true, false));
	    buflen += player->name.send_len(true, true, false);
	    memcpy(buf+buflen, player->gender.get_str(true, true, false),
		   player->gender.send_len(true, true, false));
	    buflen += player->gender.send_len(true, true, false);
	    write32(buf, buflen, player->explorer_type);
	    buflen += 4;
	  }
	}
      }
      if (m_log && m_log->would_log_at(Logger::LOG_MSGS)) {
	char uuid_formatted[UUID_STR_LEN];
	format_uuid(login_result.uuid, uuid_formatted);
	log_msgs(m_log, "AUTH_ACCT_LOGIN received for %s: "
		 "result %u UUID %s\n", msg->name()->c_str(),
		 login_result.result_code, uuid_formatted);
      }
      if (login_result.result_code == NO_ERROR) {
	reply = new AuthAcctLogin_FromBackendMessage(in->get_id1(),
			in->get_id2(), msg->reqid(),
			login_result.result_code, login_result.uuid,
			login_result.is_visitor
			  ? GUEST_CUSTOMER : PAYING_CUSTOMER,
			new UruString(login_result.user_class), buf, buflen,
			true);
      }
      else {
	reply = new AuthAcctLogin_FromBackendMessage(in->get_id1(),
						     in->get_id2(),
						     msg->reqid(),
						     login_result.result_code);
      }
#endif /* USE_PQXX */
#else /* ! USE_POSTGRES */
      // totally faked up
      reply = new AuthAcctLogin_FromBackendMessage(in->get_id1(),
			in->get_id2(), msg->reqid(), NO_ERROR,
			(u_char*)"123456789abcdef0", PAYING_CUSTOMER,
			new UruString("admin", false), NULL, 0, false);
#endif /* USE_POSTGRES */

      c->enqueue(reply);
    }
    break;
  case AUTH_KI_VALIDATE:
    {
      AuthKIValidate_ToBackendMessage *msg
	= (AuthKIValidate_ToBackendMessage *)in;

      status_code_t ki_result = ERROR_PLAYER_NOT_FOUND;
      UruString player_name;

#ifdef USE_PQXX
      try {
	my->C->perform(AuthValidateKI(msg->acct_uuid(), msg->kinum(),
				      ki_result, player_name));
      }
      catch(const pqxx::broken_connection &e) {
	// pretty much fatal -- need to shut down or something
	log_err(m_log, "Connection to DB failed!\n");
	ki_result = ERROR_DB_TIMEOUT;
      }
      catch(const pqxx::sql_error &e) {
	log_warn(m_log, "SQL error in AuthValidateKI: %s\n", e.what());
	ki_result = ERROR_INTERNAL;
      }
#endif

      if (m_log && m_log->would_log_at(Logger::LOG_DEBUG)) {
	char uuid_formatted[UUID_STR_LEN];
	format_uuid(msg->acct_uuid(), uuid_formatted);
	log_debug(m_log,
		  "AUTH_KI_VALIDATE request KI %u UUID %s: result %u\n",
		  msg->kinum(), uuid_formatted, ki_result);
      }
      AuthKIValidate_FromBackendMessage *reply
	= new AuthKIValidate_FromBackendMessage(in->get_id1(),
						in->get_id2(),
						msg->kinum(), ki_result);
      c->enqueue(reply);

#ifdef MULTI_LOGIN
      // if the player is already logged in, punt him there
      if (ki_result == NO_ERROR) {
	ConnectionEntity *current = find_by_kinum(msg->kinum(),
						  TYPE_AUTH);
	if (current) {
	  // punt this one
	  log_debug(m_log, "Player %u has re-logged in, kicking off a "
		    "previous login\n", msg->kinum());
	  KillClient_BackendMessage *killit
	    = new KillClient_BackendMessage(
					current->ipaddr(),
					current->server_id(),
					KillClient_BackendMessage::NEW_LOGIN);
	  current->conn()->enqueue(killit);
	  if (current->kinum() != 0) {
	    set_player_offline(current->kinum(), "punt");
	  }
	}
      }
#endif

      // now, keep track of this connection's info
      if (ki_result == NO_ERROR) {
	HashKey key(in->get_id1(), in->get_id2());
	if (m_hash_table.find(key) == m_hash_table.end()) {
	  log_err(m_log, "AUTH_KI_VALIDATE for connection ID %08x,%08x "
		  "but I don't know about that connection!\n",
		  in->get_id1(), in->get_id2());
	  // auth server goofed up
	}
	else {
	  ConnectionEntity *entity = m_hash_table[key];
	  // XXX verify UUIDs match
	  entity->set_kinum(msg->kinum());
	  entity->name() = player_name;
	}

#ifdef USE_PQXX
	status_code_t spc = ERROR_INTERNAL;
	try {
	  try {
	    my->C->perform(SetPlayerConnected(msg->kinum(), spc));
	  }
	  catch(const pqxx::in_doubt_error &e) {
	    log_warn(m_log,
		     "in_doubt in SetPlayerConnected; retrying\n");
	    my->C->perform(SetPlayerConnected(msg->kinum(), spc));
	  }
	}
	catch(const pqxx::in_doubt_error &e) {
	  log_err(m_log, "in_doubt again in SetPlayerConnected; "
		  "is something badly wrong with the DB?\n");
	}
	catch(const pqxx::broken_connection &e) {
	  // pretty much fatal -- need to shut down or something
	  log_err(m_log, "Connection to DB failed!\n");
	}
	catch(const pqxx::sql_error &e) {
	  log_warn(m_log, "SQL error in SetPlayerConnected: %s\n",
		   e.what());
	}
	// if there were any errors, the player will miss out on certain vault
	// update messages
#endif
      }
    }
    break;
  case AUTH_PLAYER_LOGOUT:
    {
      AuthPlayerLogout_BackendMessage *msg
	= (AuthPlayerLogout_BackendMessage *)in;

#ifdef MULTI_LOGIN
      // clear the avatar info from the ConnectionEntity so that if
      // the player logs in again it's not detected as a re-login
      ConnectionEntity *entity = find_by_kinum(msg->kinum(), TYPE_AUTH);
      if (entity) {
	entity->set_kinum(0);
	entity->name() = "";
      }
#endif

      status_code_t offline = set_player_offline(msg->kinum(), "logout");
      log_debug(m_log, "AUTH_PLAYER_LOGOUT %s%u\n",
		offline == ERROR_NODE_NOT_FOUND ? "UNKNOWN player " : "",
		msg->kinum());
    }
    break;
  case AUTH_CHANGE_PASSWORD:
    {
      AuthChangePassword_ToBackendMessage *msg
	= (AuthChangePassword_ToBackendMessage *)in;

      const u_char *hash = msg->hash();
      char text_version[41];
      snprintf(text_version, 41,
	       "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
	       "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
	       hash[0], hash[1], hash[2], hash[3],
	       hash[4], hash[5], hash[6], hash[7],
	       hash[8], hash[9], hash[10], hash[11],
	       hash[12], hash[13], hash[14], hash[15],
	       hash[16], hash[17], hash[18], hash[19]);
      status_code_t change_result = ERROR_INTERNAL;

#ifdef USE_PQXX
      try {
	try {
	  my->C->perform(AuthChangePassword(msg->acct_uuid(),
					    msg->name()->c_str(), text_version,
					    change_result));
	}
	catch(const pqxx::in_doubt_error &e) {
	  // we can check the DB to see if the new hash is present
	  log_warn(m_log,
		   "in_doubt in AuthChangePassword; checking result\n");
	  my->C->perform(AuthVerifyPassword(msg->acct_uuid(),
					    msg->name()->c_str(),
					    text_version, change_result));
	  if (change_result == ERROR_BAD_PASSWD) {
	    // the change failed
	    change_result = ERROR_INTERNAL;
	  }
	}
      }
      catch(const pqxx::in_doubt_error &e) {
	log_warn(m_log, "in_doubt again in AuthChangePassword; "
		 "is something badly wrong with the DB?\n");
      }
      catch(const pqxx::broken_connection &e) {
	// pretty much fatal -- need to shut down or something
	log_err(m_log, "Connection to DB failed!\n");
	change_result = ERROR_DB_TIMEOUT;
      }
      catch(const pqxx::sql_error &e) {
	log_warn(m_log, "SQL error in AuthChangePassword: %s\n", e.what());
      }
#endif

      if (change_result == ERROR_ACCT_NOT_FOUND) {
	// this means the client provided a username other than his own
	// (based on the client UUID saved by the auth server at login)
	char uuid[UUID_STR_LEN];
	format_uuid(msg->acct_uuid(), uuid);
	log_warn(m_log, "Bad AUTH_CHANGE_PASSWORD for %s from UUID %s\n",
		 msg->name()->c_str(), uuid);
      }
      else {
	log_msgs(m_log, "AUTH_CHANGE_PASSWORD for %s%s\n",
		 msg->name()->c_str(),
		 change_result == NO_ERROR ? "" : " FAILED");
      }

      AuthChangePassword_FromBackendMessage *reply
	= new AuthChangePassword_FromBackendMessage(in->get_id1(),
						    in->get_id2(),
						    msg->reqid(),
						    change_result);
      c->enqueue(reply);
    }
    break;
  default:
    // unknown type
    log_warn(m_log, "Unknown message type 0x%08x\n", in->type());
    break;
  }
  return NO_SHUTDOWN;
}

Server::reason_t BackendServer::handle_vault(Connection *c,
					     BackendMessage *in) {
  switch (in->type()) {
  case VAULT_PLAYER_CREATE:
    {
      VaultPlayerCreate_ToBackendMessage *msg
	= (VaultPlayerCreate_ToBackendMessage *)in;

      AuthAcctLogin_PlayerQuery_Player player;
      uint32_t neighbors_list = 0, pinfo;

#ifdef USE_PQXX
      try {
	try {
	  my->C->perform(VaultPlayerCreate_Request(msg->acct_uuid(),
						   msg->name()->c_str(),
						   msg->gender()->c_str(),
						   player,
						   neighbors_list, pinfo));
	}
	catch(const pqxx::in_doubt_error &e) {
	  log_warn(m_log,
		   "in_doubt in VaultPlayerCreate; attempting to recover\n");
	  // let us see if the create happened
	  my->C->perform(VaultPlayerRequest_Verify(msg->acct_uuid(),
						   msg->name()->c_str(),
						   player));
	  if (player.kinum == ERROR_PLAYER_NOT_FOUND) {
	    // Either the create did happen but failed because the avatar
	    // name already existed (or similar), or it did not get
	    // committed. Either way, try again; if it's the former it will
	    // fail again and we'll propagate that back.
	    my->C->perform(VaultPlayerCreate_Request(msg->acct_uuid(),
						     msg->name()->c_str(),
						     msg->gender()->c_str(),
						     player,
						     neighbors_list, pinfo));
	  }
	  else {
	    // The create went through, and we have now filled in the
	    // necessary info, or we had some other bad error that gets
	    // propgated back anyway.
	  }
	}
      }
      catch(const pqxx::in_doubt_error &e) {
	log_warn(m_log, "in_doubt again in VaultPlayerCreate; "
		 "is something badly wrong with the DB?\n");
	KillClient_BackendMessage *killit =
	  new KillClient_BackendMessage(in->get_id1(), in->get_id2(),
					KillClient_BackendMessage::IN_DOUBT);
	c->enqueue(killit);
	break;
      }
      catch(const pqxx::broken_connection &e) {
	// pretty much fatal -- need to shut down or something
	log_err(m_log, "Connection to DB failed!\n");
	player.kinum = ERROR_DB_TIMEOUT;
      }
      catch(const pqxx::sql_error &e) {
	log_warn(m_log, "SQL error in VaultPlayerCreate: %s\n", e.what());
	player.kinum = ERROR_INTERNAL;
      }
#endif

      log_msgs(m_log, "VAULT_PLAYER_CREATE for %s (%s) %s %u\n",
	       msg->name()->c_str(), msg->gender()->c_str(),
	       player.kinum >= MIN_NODEVAL ? "-> KI" : "failed:",
	       player.kinum);
      VaultPlayerCreate_FromBackendMessage *reply;
      if (player.kinum >= MIN_NODEVAL) {
	reply = new VaultPlayerCreate_FromBackendMessage(in->get_id1(),
				in->get_id2(), msg->reqid(), NO_ERROR,
				player.kinum, player.explorer_type,
				new UruString(player.name),
				new UruString(player.gender));
#ifndef STANDALONE
	if (neighbors_list != 0) {
	  // XXX Need ownerid, but then, does it really matter if clients
	  // have the wrong ownerid in their local non-persistent copies of
	  // the ref? (In fact why does the client ever need the ownerid?)
	  propagate_add_to_interested(neighbors_list, pinfo, 0, false);
	}
#endif
      }
      else {
	reply = new VaultPlayerCreate_FromBackendMessage(in->get_id1(),
				in->get_id2(), msg->reqid(),
				(status_code_t)player.kinum);
      }
      c->enqueue(reply);
    }
    break;
  case VAULT_PLAYER_DELETE:
    {
      VaultPlayerDelete_ToBackendMessage *msg
	= (VaultPlayerDelete_ToBackendMessage *)in;

      status_code_t del_result = ERROR_INTERNAL;
      std::multimap<kinum_t,uint32_t> notifies;
      uint32_t pinfo;

#ifdef USE_PQXX
      try {
	my->C->perform(VaultPlayerDelete_Request(msg->kinum(), del_result,
						 notifies, pinfo));
      }
      catch(const pqxx::in_doubt_error &e) {
	log_warn(m_log, "in_doubt in VaultPlayerDelete\n");
      }
      catch(const pqxx::broken_connection &e) {
	// pretty much fatal -- need to shut down or something
	log_err(m_log, "Connection to DB failed!\n");
	del_result = ERROR_DB_TIMEOUT;
      }
      catch(const pqxx::sql_error &e) {
	log_warn(m_log, "SQL error in VaultPlayerDelete: %s\n", e.what());
      }
#endif

      log_at((del_result == NO_ERROR ? Logger::LOG_MSGS : Logger::LOG_WARN),
	     m_log, "VAULT_PLAYER_DELETE for %u%s\n",
	     msg->kinum(), del_result == NO_ERROR ? "" : " failed");
      VaultPlayerDelete_FromBackendMessage *reply
	= new VaultPlayerDelete_FromBackendMessage(in->get_id1(),
		in->get_id2(), msg->reqid(),
		del_result == ERROR_NODE_NOT_FOUND ? NO_ERROR : del_result);
#ifndef STANDALONE
      if (del_result == NO_ERROR) {
	propagate_player_delete_to_interested(notifies, pinfo);
      }
#endif
      c->enqueue(reply);
    }
    break;
  case VAULT_FETCHREFS:
    {
      VaultFetchRefs_ToBackendMessage *msg
	= (VaultFetchRefs_ToBackendMessage *)in;

      status_code_t refs_result = ERROR_INTERNAL;
      std::vector<VaultFetchRefs_VaultRef> refs_list;

#ifdef USE_PQXX
      try {
	my->C->perform(VaultFetchRefs_Request(msg->node_id(), refs_result,
					      refs_list));
      }
      catch(const pqxx::broken_connection &e) {
	// pretty much fatal -- need to shut down or something
	log_err(m_log, "Connection to DB failed!\n");
	refs_result = ERROR_DB_TIMEOUT;
      }
      catch(const pqxx::sql_error &e) {
	log_warn(m_log, "SQL error in VaultFetchRefs: %s\n", e.what());
      }
#endif

      u_char *refs_buf = new u_char[14+(13*refs_list.size())];
      write16(refs_buf, 0, kAuth2Cli_VaultNodeRefsFetched);
      write32(refs_buf, 2, msg->reqid());
      write32(refs_buf, 6, refs_result);
      write32(refs_buf, 10, refs_list.size());
      u_int ref_at = 14;
      for (std::vector<VaultFetchRefs_VaultRef>::const_iterator
	     ref_el = refs_list.begin(); ref_el != refs_list.end(); ref_el++) {
	write32(refs_buf, ref_at, ref_el->parent);
	write32(refs_buf, ref_at+4, ref_el->child);
	write32(refs_buf, ref_at+8, ref_el->owner);
	refs_buf[ref_at+12] = 0xcc;
	ref_at += 13;
      }

      log_msgs(m_log, "VAULT_FETCHREFS reqid %u node %u: %u refs\n",
	       msg->reqid(), msg->node_id(), refs_list.size());
      VaultPassthrough_BackendMessage *reply =
	new VaultPassthrough_BackendMessage(in->get_id1(), in->get_id2(),
					    refs_buf, ref_at, false, true);
      c->enqueue(reply);
    }
    break;
  case VAULT_FINDNODE:
    {
      VaultNode_ToBackendMessage *msg = (VaultNode_ToBackendMessage *)in;

      status_code_t find_result = ERROR_INTERNAL;
      std::vector<uint32_t> find_list;

      const VaultNode *findnode = msg->data();
      if (findnode->bitfield1() == 0x00001080 && findnode->bitfield2() == 0
	  && findnode->type() == VaultNode::PlayerInfoNode) {
	// use original, simple code
	uint32_t find_val = 0;
	uint32_t node_id = findnode->num_val(UInt32_1);
#ifdef USE_PQXX
	try {
	  my->C->perform(VaultFindNode_Request(node_id,
					       find_result, find_val));
	}
	catch(const pqxx::broken_connection &e) {
	  // pretty much fatal -- need to shut down or something
	  log_err(m_log, "Connection to DB failed!\n");
	  find_result = ERROR_DB_TIMEOUT;
	}
	catch(const pqxx::sql_error &e) {
	  log_warn(m_log, "SQL error in PlayerInfo VaultFindNode: %s\n",
		   e.what());
	}
#endif
	find_list.push_back(find_val);
      }
      else {
	// use general-purpose find
#ifdef USE_PQXX
	try {
	  my->C->perform(VaultFindNode_Generic(findnode, find_result,
					       find_list, m_log));
	}
	catch(const pqxx::broken_connection &e) {
	  // pretty much fatal -- need to shut down or something
	  log_err(m_log, "Connection to DB failed!\n");
	  find_result = ERROR_DB_TIMEOUT;
	}
	catch(const pqxx::sql_error &e) {
	  log_warn(m_log, "SQL error in VaultFindNode: %s\n", e.what());
	}
#endif
      }

      if (find_result == ERROR_INVALID_DATA) {
	// this signals that more than one result was returned
	// (VaultFindNode_Request only)
	log_err(m_log, "More than one result was returned for "
		"PlayerInfo VaultNodeFind (reqid %u)\n", msg->reqid());
	if (m_log) {
	  u_int nlen = findnode->message_len();
	  u_char *nbuf = new u_char[nlen];
	  bool msg_done;
	  findnode->fill_buffer(nbuf, nlen, 0, &msg_done);
	  m_log->dump_contents(Logger::LOG_ERR, nbuf, nlen);
	  delete[] nbuf;
	}
	find_result = NO_ERROR;
      }
      u_int msglen = 14+(4*find_list.size());
      u_char *find_buf = new u_char[msglen];
      write16(find_buf, 0, kAuth2Cli_VaultNodeFindReply);
      write32(find_buf, 2, msg->reqid());
      if (find_result != NO_ERROR) {
	if (find_result == ERROR_NODE_NOT_FOUND) {
	  write32(find_buf, 6, NO_ERROR);
	}
	else {
	  write32(find_buf, 6, find_result);
	}
	write32(find_buf, 10, 0);
	msglen = 14;
      }
      else {
	write32(find_buf, 6, NO_ERROR);
	write32(find_buf, 10, find_list.size());
	for (u_int i = 0; i < find_list.size(); i++) {
	  write32(find_buf, 14+(4*i), find_list[i]);
	}
      }

      log_msgs(m_log, "VAULT_FINDNODE for type %d reqid %u: %u results\n",
	       findnode->type(), msg->reqid(), read32(find_buf, 10));
      VaultPassthrough_BackendMessage *reply =
	new VaultPassthrough_BackendMessage(in->get_id1(), in->get_id2(),
					    find_buf, msglen,
					    false, true);
      c->enqueue(reply);
    }
    break;
  case VAULT_FETCH:
    {
      VaultNodeFetch_ToBackendMessage *msg =
	(VaultNodeFetch_ToBackendMessage *)in;

      VaultNode *f_node = new VaultNode();
      status_code_t f_result = ERROR_INTERNAL;

#ifdef USE_PQXX
      try {
	my->C->perform(VaultFetchNode_Request(msg->node_id(), f_result,
					      *f_node, m_log));
      }
      catch(const pqxx::broken_connection &e) {
	// pretty much fatal -- need to shut down or something
	log_err(m_log, "Connection to DB failed!\n");
	f_result = ERROR_DB_TIMEOUT;
      }
      catch(const pqxx::sql_error &e) {
	log_warn(m_log, "SQL error in VaultFetchNode: %s\n", e.what());
      }
#endif

      if (f_result != NO_ERROR) {
	log_err(m_log, "Error fetching vault node %u (reqid %u)\n",
		msg->node_id(), msg->reqid());
	delete f_node;
	f_node = NULL;
      }
      else {
	log_msgs(m_log, "VAULT_FETCH reqid %u node %u -> node of type %d\n",
		 msg->reqid(), msg->node_id(), f_node->type());
      }
      VaultNodeFetch_FromBackendMessage *reply =
	  new VaultNodeFetch_FromBackendMessage(in->get_id1(), in->get_id2(),
						msg->reqid(), f_result,
						f_node);
      c->enqueue(reply);
    }
    break;
  case VAULT_SAVENODE:
    {
      VaultNode_ToBackendMessage *msg = (VaultNode_ToBackendMessage *)in;

      status_code_t save_result = ERROR_INTERNAL;

      // XXX check, for the purposes of logging, whether bitfield2 is zero
#ifdef USE_PQXX
      try {
	try {
	  my->C->perform(VaultSaveNode_Request(msg->node_id(), msg->data(),
					       save_result, m_log));
	}
	catch(const pqxx::in_doubt_error &e) {
	  // just retry, it does not hurt to save with the same data
	  my->C->perform(VaultSaveNode_Request(msg->node_id(), msg->data(),
					       save_result, m_log));
	}
      }
      catch(const pqxx::in_doubt_error &e) {
	log_warn(m_log, "in_doubt again in VaultSaveNode; "
		 "is something badly wrong with the DB?\n");
      }
      catch(const pqxx::broken_connection &e) {
	// pretty much fatal -- need to shut down or something
	log_err(m_log, "Connection to DB failed!\n");
	save_result = ERROR_DB_TIMEOUT;
      }
      catch(const pqxx::sql_error &e) {
	log_warn(m_log, "SQL error in VaultSaveNode: %s\n", e.what());
      }
#endif

#ifdef OLD_PROTOCOL
      if (save_result == ERROR_INVALID_PARAM) {
	// saving empty node, ignore it
	log_debug(m_log, "Ignoring node %u VAULT_SAVENODE with no contents\n",
		  msg->node_id());
	break;
      }
#endif
      log_at((save_result == NO_ERROR ? Logger::LOG_MSGS : Logger::LOG_WARN),
	     m_log, "VAULT_SAVENODE reqid %u node %u%s\n",
	     msg->reqid(), msg->node_id(),
	     save_result == NO_ERROR ? "" : " FAILED");
#if !defined(OLD_PROTOCOL) || defined(OLD_PROTOCOL4) || defined(STANDALONE)
      VaultPassthrough_BackendMessage *reply;
#endif
#if !defined(OLD_PROTOCOL) || defined(OLD_PROTOCOL4)
      // send the reply to the client
      u_char *save_buf = new u_char[10];
      write16(save_buf, 0, kAuth2Cli_VaultSaveNodeReply);
      write32(save_buf, 2, msg->reqid());
      write32(save_buf, 6, save_result);
      reply = new VaultPassthrough_BackendMessage(in->get_id1(), in->get_id2(),
						  save_buf, 10, false, true);
      c->enqueue(reply);
#endif
      if (save_result == NO_ERROR) {
#ifdef STANDALONE
	// for now just bounce it back to the original (only!) client
	u_char *changed_buf = new u_char[22];
	write16(changed_buf, 0, kAuth2Cli_VaultNodeChanged);
	write32(changed_buf, 2, msg->node_id());
	memcpy(changed_buf+6, msg->requuid(), 16);
	reply = new VaultPassthrough_BackendMessage(in->get_id1(),
						    in->get_id2(),
						    changed_buf, 22,
						    false, true);
	c->enqueue(reply);
#else
	propagate_change_to_interested(msg->node_id(), msg->requuid(), true);
#endif
	  
	// now push SDL to game servers
	if (msg->data()->type() == VaultNode::SDLNode) {
	  const u_char *sdl_data = msg->data()->const_data_ptr(Blob_1);
	  if (sdl_data && read32(sdl_data, 0) > 0) {
	    // XXX there needs to be a distinction between player node updates
	    // and AllAgeGlobalSDLNodes updates, but since currently the
	    // latter cannot be set in a way that would propagate anyway, we
	    // know here that it's a player-created node -- if we get to
	    // propagation, we may have to do a DB query, or perhaps the
	    // Connection 'c' will reveal what to do...

	    // XXX note the following logic would be in tracking server if
	    // it was separate from vault; here we'd send the TrackSDLUpdate
	    // to tracking instead of finding the game server in-place
	    HashKey key(in->get_id1(), in->get_id2());
	    if (m_hash_table.find(key) == m_hash_table.end()) {
	      log_warn(m_log, "VAULT_SAVENODE for connection ID %08x,%08x "
		       "but I don't know about that connection!\n",
		       in->get_id1(), in->get_id2());
	    }
	    else {
	      ConnectionEntity *from_entity = m_hash_table[key];
#ifdef STANDALONE
	      // this simply bounces the SDL to the player's own game server
	      uint32_t game_id1 = from_entity->ipaddr();
	      uint32_t game_id2 = from_entity->server_id();
	      HashKey key2(game_id1, game_id2);
	      if (m_hash_table.find(key2) == m_hash_table.end()) {
		// this is normal: the client saves nodes before connecting
		// to a game server, when an avatar was just created, and
		// maybe other times
	      }
	      else {
		ConnectionEntity *to_entity = m_hash_table[key2];
		log_debug(m_log, "Forwarding saved vault SDL to player's "
			  "game server id %08x,%08x\n", game_id1, game_id2);
		TrackSDLUpdate_BackendMessage *sdlmsg
		  = new TrackSDLUpdate_BackendMessage(to_entity->ipaddr(),
						      to_entity->server_id(),
						      from_entity->kinum(),
						      in->get_id1(),
						      in->get_id2(),
						      sdl_data+4,
						      read32(sdl_data, 0),
			TrackSDLUpdate_BackendMessage::VAULT_SDL_UPDATE);
		to_entity->conn()->enqueue(sdlmsg);
	      }
#else
	      // it's actually incorrect to send the SDL update to
	      // the player's own server; imagine what would happen if I
	      // toggle a Relto page while in someone else's Relto!
	      status_code_t getuuid_result = ERROR_INTERNAL;
#ifdef USE_PQXX
	      u_char ageuuid[UUID_RAW_LEN];
	      try {
		my->C->perform(GetAgeUUIDFor(msg->node_id(), ageuuid,
					     getuuid_result));
	      }
	      catch(const pqxx::in_doubt_error &e) {
		log_warn(m_log, "in_doubt in GetAgeUUIDFor\n");
	      }
	      catch(const pqxx::broken_connection &e) {
		// pretty much fatal -- need to shut down or something
		log_err(m_log, "Connection to DB failed!\n");
		getuuid_result = ERROR_DB_TIMEOUT;
	      }
	      catch(const pqxx::sql_error &e) {
		log_warn(m_log, "SQL error in GetAgeUUIDFor: %s\n", e.what());
	      }
#endif
	      if (getuuid_result == ERROR_NODE_NOT_FOUND) {
		log_warn(m_log, "Vault SDL was saved for node %u, which has "
			 "no age??\n", msg->node_id());
	      }
	      if (getuuid_result == NO_ERROR) {
		// see if there is currently a game server for the UUID
		ConnectionEntity *to_entity = find_by_uuid(ageuuid, TYPE_GAME);
		if (to_entity) {
		  // yep, forward it on
		  log_debug(m_log, "Forwarding saved vault SDL to "
			    "corresponding game server id %08x,%08x\n",
			    to_entity->ipaddr(), to_entity->server_id());
		  TrackSDLUpdate_BackendMessage *sdlmsg
		    = new TrackSDLUpdate_BackendMessage(to_entity->ipaddr(),
							to_entity->server_id(),
							from_entity->kinum(),
							in->get_id1(),
							in->get_id2(),
							sdl_data+4,
							read32(sdl_data, 0),
			TrackSDLUpdate_BackendMessage::VAULT_SDL_UPDATE);
		  to_entity->conn()->enqueue(sdlmsg);
		}
	      }
#endif
	    }
	  }
	}
      }
    }
    break;
  case VAULT_CREATENODE:
    {
      VaultNode_ToBackendMessage *msg = (VaultNode_ToBackendMessage *)in;

      HashKey key(in->get_id1(), in->get_id2());
      if (m_hash_table.find(key) == m_hash_table.end()) {
	log_err(m_log, "VAULT_CREATENODE for connection ID %08x,%08x but "
		"I don't know about that connection!\n",
		in->get_id1(), in->get_id2());
	KillClient_BackendMessage *killit =
	  new KillClient_BackendMessage(in->get_id1(), in->get_id2(),
					KillClient_BackendMessage::NO_STATE);
	c->enqueue(killit);
	break;
      }
      ConnectionEntity *entity = m_hash_table[key];
      uint32_t c_node = 0;
      status_code_t c_result = NO_ERROR;

      // XXX check, for the purposes of logging, whether bitfield2 is zero
#ifdef USE_PQXX
      try {
	try {
	  my->C->perform(VaultCreateNode_Request(msg->data(),
						 entity->uuid(),
						 entity->kinum(),
						 c_node, m_log));
	}
	catch(const pqxx::in_doubt_error &e) {
	  log_warn(m_log, "in_doubt in VaultCreateNode; creating a new "
		   "node\n");
	  // well, we may have made a node, but there's nothing pointing at
	  // it, so just make another one (leaves trash in the vault)
	  my->C->perform(VaultCreateNode_Request(msg->data(),
						 entity->uuid(),
						 entity->kinum(),
						 c_node, m_log));
	}
      }
      catch(const pqxx::in_doubt_error &e) {
	log_warn(m_log, "in_doubt again in VaultCreateNode; "
		 "is something badly wrong with the DB?\n");
	c_result = ERROR_INTERNAL;
      }
      catch(const pqxx::broken_connection &e) {
	// pretty much fatal -- need to shut down or something
	log_err(m_log, "Connection to DB failed!\n");
	c_result = ERROR_DB_TIMEOUT;
      }
      catch(const pqxx::sql_error &e) {
	log_warn(m_log, "SQL error in VaultCreateNode: %s\n", e.what());
	c_result = ERROR_INTERNAL;
      }
#endif

      if (c_result == NO_ERROR && c_node < MIN_NODEVAL) {
	c_result = (status_code_t)c_node;
	c_node = 0;
      }
      // send the reply to the client
      u_char *create_buf = new u_char[14];
      write16(create_buf, 0, kAuth2Cli_VaultNodeCreated);
      write32(create_buf, 2, msg->reqid());
      write32(create_buf, 6, c_result);
      write32(create_buf, 10, c_node);
      log_at((c_result == NO_ERROR ? Logger::LOG_MSGS : Logger::LOG_WARN),
	     m_log, "VAULT_CREATENODE reqid %u node %u%s\n",
	     msg->reqid(), c_node,
	     c_result == NO_ERROR ? "" : " FAILED");
      VaultPassthrough_BackendMessage *reply = 
	new VaultPassthrough_BackendMessage(in->get_id1(), in->get_id2(),
					    create_buf, 14, false, true);
      c->enqueue(reply);
    }
    break;
  case VAULT_ADDREF:
    {
      VaultRefChange_ToBackendMessage *msg
	= (VaultRefChange_ToBackendMessage *)in;

      status_code_t add_result = ERROR_INTERNAL;
#ifdef USE_PQXX
      try {
	try {
	  my->C->perform(VaultAddRef_Request(msg->parent(), msg->child(),
					     msg->owner(), add_result));
	}
	catch(const pqxx::in_doubt_error &e) {
	  log_warn(m_log, "in_doubt in VaultAddRef; retrying\n");
	  my->C->perform(VaultAddRef_Request(msg->parent(), msg->child(),
					     msg->owner(), add_result));
	  if (add_result == ERROR_INVALID_DATA) {
	    add_result = NO_ERROR;
	  }
	}
      }
      catch(const pqxx::in_doubt_error &e) {
	log_warn(m_log, "in_doubt again in VaultAddRef; "
		 "is something badly wrong with the DB?\n");
	KillClient_BackendMessage *killit =
	  new KillClient_BackendMessage(in->get_id1(), in->get_id2(),
					KillClient_BackendMessage::IN_DOUBT);
	c->enqueue(killit);
	break;
      }
      catch(const pqxx::broken_connection &e) {
	// pretty much fatal -- need to shut down or something
	log_err(m_log, "Connection to DB failed!\n");
	add_result = ERROR_DB_TIMEOUT;
      }
      catch(const pqxx::sql_error &e) {
	log_warn(m_log, "SQL error in VaultAddRef: %s\n", e.what());
      }
#endif

      log_at((add_result == NO_ERROR ? Logger::LOG_MSGS : Logger::LOG_WARN),
	     m_log, "VAULT_ADDREF reqid %u add %u->%u (%u)%s\n",
	     msg->reqid(), msg->parent(), msg->child(), msg->owner(),
	     add_result == NO_ERROR ? "" : " FAILED");
      if (add_result == NO_ERROR) {
#ifdef STANDALONE
	// for now just bounce it back to the original (only!) client
	u_char *added_buf = new u_char[14];
	write16(added_buf, 0, kAuth2Cli_VaultNodeAdded);
	write32(added_buf, 2, msg->parent());
	write32(added_buf, 6, msg->child());
	write32(added_buf, 10, msg->owner());
	VaultPassthrough_BackendMessage *reply
	  = new VaultPassthrough_BackendMessage(in->get_id1(), in->get_id2(),
						added_buf, 14, false, true);
	c->enqueue(reply);
#else
	propagate_add_to_interested(msg->parent(), msg->child(), msg->owner(),
				    true);
#endif
      }
#if !defined(OLD_PROTOCOL) || defined(OLD_PROTOCOL4)
      u_char *add_buf = new u_char[10];
      write16(add_buf, 0, kAuth2Cli_VaultAddNodeReply);
      write32(add_buf, 2, msg->reqid());
      write32(add_buf, 6, add_result);
      VaultPassthrough_BackendMessage *reply = 
	new VaultPassthrough_BackendMessage(in->get_id1(), in->get_id2(),
					    add_buf, 10, false, true);
      c->enqueue(reply);
#endif
    }
    break;
  case VAULT_REMOVEREF:
    {
      VaultRefChange_ToBackendMessage *msg
	= (VaultRefChange_ToBackendMessage *)in;

      status_code_t rem_result = NO_ERROR;
      int removed = 0;

#ifdef USE_PQXX
      try {
	try {
	  my->C->perform(VaultRemoveRef_Request(msg->parent(), msg->child(),
						removed));
	}
	catch(const pqxx::in_doubt_error &e) {
	  log_warn(m_log, "in_doubt in VaultRemoveRef; retrying\n");
	  my->C->perform(VaultRemoveRef_Request(msg->parent(), msg->child(),
						removed));
	  if (removed == 0) {
	    // this could have been a request error instead of the
	    // previous attempt succeeding, but oh well
	    removed = 1;
	  }
	}
      }
      catch(const pqxx::in_doubt_error &e) {
	log_warn(m_log, "in_doubt again in VaultRemoveRef; "
		 "is something badly wrong with the DB?\n");
	KillClient_BackendMessage *killit =
	  new KillClient_BackendMessage(in->get_id1(), in->get_id2(),
					KillClient_BackendMessage::IN_DOUBT);
	c->enqueue(killit);
	break;
      }
      catch(const pqxx::broken_connection &e) {
	// pretty much fatal -- need to shut down or something
	log_err(m_log, "Connection to DB failed!\n");
	rem_result = ERROR_DB_TIMEOUT;
      }
      catch(const pqxx::sql_error &e) {
	log_warn(m_log, "SQL error in VaultCreateNode: %s\n", e.what());
	rem_result = ERROR_INTERNAL;
      }
#endif

      if (removed == -1) {
	removed = 0;
	rem_result = ERROR_INTERNAL;
      }
      if (removed == 0) {
	log_net(m_log, "Remove ref request for %u->%u removed no refs!\n",
		msg->parent(), msg->child());
      }
      else if (removed != 1) {
	log_err(m_log, "More than one ref for %u->%u was found in a remove "
		"ref request!\n", msg->parent(), msg->child());
      }

      log_at((rem_result == NO_ERROR ? Logger::LOG_MSGS : Logger::LOG_WARN),
	     m_log, "VAULT_REMOVEREF reqid %u remove %u->%u%s\n",
	     msg->reqid(), msg->parent(), msg->child(),
	     rem_result == NO_ERROR ? "" : " FAILED");
      if (rem_result == NO_ERROR && removed > 0) {
#ifdef STANDALONE
	// for now just bounce it back to the original (only!) client
	u_char *remd_buf = new u_char[10];
	write16(remd_buf, 0, kAuth2Cli_VaultNodeRemoved);
	write32(remd_buf, 2, msg->parent());
	write32(remd_buf, 6, msg->child());
	VaultPassthrough_BackendMessage *reply
	  = new VaultPassthrough_BackendMessage(in->get_id1(), in->get_id2(),
						remd_buf, 10, false, true);
	c->enqueue(reply);
#else
	propagate_remove_to_interested(msg->parent(), msg->child(), true);
#endif
      }
#if !defined(OLD_PROTOCOL) || defined(OLD_PROTOCOL4)
      u_char *rem_buf = new u_char[10];
      write16(rem_buf, 0, kAuth2Cli_VaultRemoveNodeReply);
      write32(rem_buf, 2, msg->reqid());
      write32(rem_buf, 6, rem_result);
      VaultPassthrough_BackendMessage *reply = 
	new VaultPassthrough_BackendMessage(in->get_id1(), in->get_id2(),
					    rem_buf, 10, false, true);
      c->enqueue(reply);
#endif
    }
    break;
  case VAULT_INIT_AGE:
    {
      VaultInitAge_ToBackendMessage *msg = (VaultInitAge_ToBackendMessage *)in;

      uint32_t age_node = 0, age_info_node = 0;
      status_code_t init_result = ERROR_INTERNAL;

#ifdef USE_PQXX
      try {
	my->C->perform(VaultCreateAge_Request(msg->age_filename()->c_str(),
				msg->instance_name()->c_str(),
				msg->user_defined_name()->c_str(),
				msg->display_name()->c_str(),
				msg->create_uuid(), msg->parent_uuid(),
				age_node, age_info_node, init_result));
      }
      catch(const pqxx::in_doubt_error &e) {
	log_warn(m_log, "in_doubt in CreateAge\n");
	// this one, we really can't do much about, the client needs to
	// re-inspect the lists
	KillClient_BackendMessage *killit =
	  new KillClient_BackendMessage(in->get_id1(), in->get_id2(),
					KillClient_BackendMessage::IN_DOUBT);
	c->enqueue(killit);
	break;
      }
      catch(const pqxx::broken_connection &e) {
	// pretty much fatal -- need to shut down or something
	log_err(m_log, "Connection to DB failed!\n");
	init_result = ERROR_DB_TIMEOUT;
      }
      catch(const pqxx::sql_error &e) {
	log_warn(m_log, "SQL error in VaultCreateNode: %s\n", e.what());
      }
#endif

      u_char *initage_buf = new u_char[18];
      write16(initage_buf, 0, kAuth2Cli_VaultInitAgeReply);
      write32(initage_buf, 2, msg->reqid());
      write32(initage_buf, 6, init_result);
      write32(initage_buf, 10, age_node);
      write32(initage_buf, 14, age_info_node);
      log_at((init_result == NO_ERROR ? Logger::LOG_MSGS : Logger::LOG_WARN),
	     m_log, "VAULT_INIT_AGE for %s (%s)%s\n",
	     msg->display_name()->c_str(), msg->age_filename()->c_str(),
	     init_result == NO_ERROR ? "" : " failed");
      VaultPassthrough_BackendMessage *reply = 
	new VaultPassthrough_BackendMessage(in->get_id1(), in->get_id2(),
					    initage_buf, 18, false, true);
      c->enqueue(reply);
    }
    break;
  case VAULT_AGE_LIST:
    {
      VaultAgeList_ToBackendMessage *msg = (VaultAgeList_ToBackendMessage *)in;
      UruString &filename = *(msg->age_filename());

      status_code_t list_result = ERROR_INTERNAL;
      std::vector<VaultAgeList_AgeInfo> age_list;

#ifdef USE_PQXX
      try {
	my->C->perform(VaultAgeList_Request(filename, list_result, age_list));
      }
      catch(const pqxx::broken_connection &e) {
	// pretty much fatal -- need to shut down or something
	log_err(m_log, "Connection to DB failed!\n");
	list_result = ERROR_DB_TIMEOUT;
      }
      catch(const pqxx::sql_error &e) {
	log_warn(m_log, "SQL error in VaultAgeList: %s\n", e.what());
      }
#endif
      u_int list_size = 0;
      if (list_result == NO_ERROR) {
	list_size = age_list.size();
      }
      u_char *agelist_buf = new u_char[14+(2464*list_size)];
      write16(agelist_buf, 0, kAuth2Cli_PublicAgeList);
      write32(agelist_buf, 2, msg->reqid());
      write32(agelist_buf, 6, list_result);
      write32(agelist_buf, 10, age_list.size());
      if (list_result == NO_ERROR) {
	memset(agelist_buf+14, 0, 2464*list_size);
	u_int age_at = 14;
	for (std::vector<VaultAgeList_AgeInfo>::iterator
	     age_el = age_list.begin(); age_el != age_list.end(); age_el++) {
	  memcpy(agelist_buf+age_at, age_el->uuid, UUID_RAW_LEN);
	  age_at += 16;
#define WRITE_STR(urustr)					  \
	do {							  \
	  u_int str_len = urustr.send_len(false, true, false);	  \
	  memcpy(agelist_buf+age_at,				  \
		 urustr.get_str(false, true, false, false),	  \
		 (str_len < 126 ? str_len : 126));		  \
	  age_at += 128;					  \
	} while (0);

	  WRITE_STR(filename);
	  WRITE_STR(age_el->instance_name);
	  WRITE_STR(age_el->user_defined);
	  WRITE_STR(age_el->display_name);

#undef WRITE_STR
	  age_at += 1920; // 15 more 128-byte strings?
	  write32(agelist_buf, age_at, age_el->instance_num);
	  age_at += 4;
	  write32(agelist_buf, age_at, -1L);
	  age_at += 4;
	  write32(agelist_buf, age_at, age_el->num_owners);
	  age_at += 4;
#ifdef STANDALONE
	  write32(agelist_buf, age_at, 0);
#else
	  ConnectionEntity *game_server = find_by_uuid(age_el->uuid,
						       TYPE_GAME);
	  if (game_server) {
	    write32(agelist_buf, age_at, game_server->player_count());
	  }
	  else {
	    // no server running, population must be zero
	    write32(agelist_buf, age_at, 0);
	  }
#endif
	  age_at += 4;
	} // for
      }
      log_at((list_result == NO_ERROR ? Logger::LOG_MSGS : Logger::LOG_WARN),
	     m_log, "VAULT_AGE_LIST %s (%u entr%s)%s\n",
	     msg->age_filename()->c_str(), list_size,
	     (list_size == 1 ? "y" : "ies"),
	     list_result == NO_ERROR ? "" : " failed");
      VaultPassthrough_BackendMessage *reply = 
	new VaultPassthrough_BackendMessage(in->get_id1(), in->get_id2(),
					    agelist_buf, 14+(2464*list_size),
					    false, true);
      c->enqueue(reply);
    }
    break;
  case VAULT_SENDNODE:
    {
      VaultNodeSend_BackendMessage *msg = (VaultNodeSend_BackendMessage *)in;

      status_code_t send_result = ERROR_INTERNAL;
      uint32_t inboxid = 0;
#ifdef USE_PQXX
      try {
	try {
	  my->C->perform(VaultSendNode_Request(msg->player(), msg->nodeid(),
					       send_result, inboxid));
	}
	catch(const pqxx::in_doubt_error &e) {
	  log_warn(m_log, "in_doubt in VaultSendNode; retrying\n");
	  my->C->perform(VaultSendNode_Request(msg->player(), msg->nodeid(),
					       send_result, inboxid));
	  if (send_result == ERROR_INVALID_DATA) {
	    send_result = NO_ERROR;
	  }
	}
      }
      catch(const pqxx::in_doubt_error &e) {
	log_warn(m_log, "in_doubt again in VaultSendNode; "
		 "is something badly wrong with the DB?\n");
      }
      catch(const pqxx::broken_connection &e) {
	// pretty much fatal -- need to shut down or something
	log_err(m_log, "Connection to DB failed!\n");
	send_result = ERROR_DB_TIMEOUT;
      }
      catch(const pqxx::sql_error &e) {
	log_warn(m_log, "SQL error in VaultSendNode: %s\n", e.what());
      }
#endif
      log_msgs(m_log, "VAULT_SENDNODE %u to %u%s\n", msg->nodeid(),
	       msg->player(), send_result == NO_ERROR ? "" : " failed");
#ifndef STANDALONE
      if (send_result == NO_ERROR) {
	// we only need to send the update to the affected player
	ConnectionEntity *auth = find_by_kinum(msg->player(), TYPE_AUTH);
	if (auth) {
	  u_char *added_buf = new u_char[14];
	  write16(added_buf, 0, kAuth2Cli_VaultNodeAdded);
	  write32(added_buf, 2, inboxid);
	  write32(added_buf, 6, msg->nodeid());
	  write32(added_buf, 10, msg->player());
	  VaultPassthrough_BackendMessage *reply
	    = new VaultPassthrough_BackendMessage(in->get_id1(), in->get_id2(),
						  added_buf, 14, false, true);

	  auth->conn()->enqueue(reply);
	}
      }
#endif
    }
    break;
  case VAULT_SET_AGE_PUBLIC:
    {
      VaultSetAgePublic_BackendMessage *msg
	= (VaultSetAgePublic_BackendMessage *)in;

      status_code_t public_result = ERROR_INTERNAL;
#ifdef USE_PQXX
      try {
	try {
	  my->C->perform(VaultSetAgePublic_Request(msg->age_nodeid(),
						   msg->set_public(),
						   public_result));
	}
	catch(const pqxx::in_doubt_error &e) {
	  log_warn(m_log, "in_doubt in VaultSetAgePublic; retrying\n");
	  my->C->perform(VaultSetAgePublic_Request(msg->age_nodeid(),
						   msg->set_public(),
						   public_result));
	}
      }
      catch(const pqxx::in_doubt_error &e) {
	log_warn(m_log, "in_doubt again in VaultSetAgePublic; "
		 "is something badly wrong with the DB?\n");
      }
      catch(const pqxx::broken_connection &e) {
	// pretty much fatal -- need to shut down or something
	log_err(m_log, "Connection to DB failed!\n");
	public_result = ERROR_DB_TIMEOUT;
      }
      catch(const pqxx::sql_error &e) {
	log_warn(m_log, "SQL error in VaultSetAgePublic: %s\n", e.what());
      }
#endif
      log_msgs(m_log, "VAULT_SET_AGE_PUBLIC %u to %s%s\n", msg->age_nodeid(),
	       msg->set_public() ? "public" : "private",
	       public_result == NO_ERROR ? "" : " failed");

      if (public_result == NO_ERROR) {
#ifdef STANDALONE
	// for now just bounce it back to the original (only!) client
	u_char *changed_buf = new u_char[22];
	write16(changed_buf, 0, kAuth2Cli_VaultNodeChanged);
	write32(changed_buf, 2, msg->age_nodeid());
	gen_uuid(changed_buf+6, 0);
	VaultPassthrough_BackendMessage *reply;
	reply = new VaultPassthrough_BackendMessage(in->get_id1(),
						    in->get_id2(),
						    changed_buf, 22,
						    false, true);
	c->enqueue(reply);
#else
	propagate_change_to_interested(msg->age_nodeid(), NULL, false);
#endif
      }
    }
    break;
#ifndef OLD_PROTOCOL
  case VAULT_SCORE_GET:
    {
      VaultScoreGet_ToBackendMessage *msg
	= (VaultScoreGet_ToBackendMessage *)in;

      status_code_t sget_result = ERROR_INTERNAL;
      uint32_t sget_id = 0, sget_type = 0;
      int32_t sget_time = 0, sget_value = 0;
#ifdef USE_PQXX
      try {
	try {
	  my->C->perform(VaultGetScore_Request(msg->holder(),
					       msg->score_name(),
					       sget_id, sget_time,
					       sget_type, sget_value,
					       sget_result));
	}
	catch(const pqxx::in_doubt_error &e) {
	  log_warn(m_log, "in_doubt in VaultGetScore; retrying\n");
	  my->C->perform(VaultGetScore_Request(msg->holder(),
					       msg->score_name(),
					       sget_id, sget_time,
					       sget_type, sget_value,
					       sget_result));
	}
      }
      catch(const pqxx::in_doubt_error &e) {
	log_warn(m_log, "in_doubt again in VaultGetScore; "
		 "is something badly wrong with the DB?\n");
      }
      catch(const pqxx::broken_connection &e) {
	// pretty much fatal -- need to shut down or something
	log_err(m_log, "Connection to DB failed!\n");
	sget_result = ERROR_DB_TIMEOUT;
      }
      catch(const pqxx::sql_error &e) {
	log_warn(m_log, "SQL error in VaultGetScore: %s\n", e.what());
      }
#endif
      log_msgs(m_log, "VAULT_SCORE_GET %u's %s%s\n", msg->holder(),
	       msg->score_name()->c_str(),
	       sget_result == NO_ERROR ? "" :
		  (sget_result == ERROR_NO_SCORE ? " (none)": " failed"));

      VaultScoreGet_FromBackendMessage *reply;
      if (sget_result != NO_ERROR) {
	reply = new VaultScoreGet_FromBackendMessage(in->get_id1(),
						     in->get_id2(),
						     msg->reqid(),
						     sget_result);
      }
      else {
	reply = new VaultScoreGet_FromBackendMessage(in->get_id1(),
						     in->get_id2(),
						     msg->reqid(),
						     sget_result, sget_id,
						     msg->holder(), sget_time,
						     sget_type, sget_value,
						     msg->score_name());
      }
      c->enqueue(reply);
    }
    break;
  case VAULT_SCORE_CREATE:
    {
      VaultScoreCreate_BackendMessage *msg
	= (VaultScoreCreate_BackendMessage *)in;

      status_code_t scr_result = ERROR_INTERNAL;
      uint32_t scr_id = 0;
      int32_t scr_time = 0;
#ifdef USE_PQXX
      try {
	try {
	  my->C->perform(VaultCreateScore_Request(msg->holder(),
						  msg->score_name(),
						  msg->score_type(),
						  msg->initial_value(),
						  scr_id, scr_time,
						  scr_result));
	}
	catch(const pqxx::in_doubt_error &e) {
	  log_warn(m_log, "in_doubt in VaultCreateScore; retrying\n");
	  my->C->perform(VaultCreateScore_Request(msg->holder(),
						  msg->score_name(),
						  msg->score_type(),
						  msg->initial_value(),
						  scr_id, scr_time,
						  scr_result));
	  if (scr_result == ERROR_SCORE_EXISTS) {
	    // Either it was created successfully after all, or it existed
	    // before the request, and there is no way to know which it was.
	    // Assume it's the former, which is presumably less disruptive to
	    // the client. Alternately return ERROR_INTERNAL.
	    scr_result = ERROR_INTERNAL;
	    uint32_t sget_type = 0;
	    int32_t sget_value = 0;
	    my->C->perform(VaultGetScore_Request(msg->holder(),
						 msg->score_name(),
						 scr_id, scr_time,
						 sget_type, sget_value,
						 scr_result));
	  }
	}
      }
      catch(const pqxx::in_doubt_error &e) {
	log_warn(m_log, "in_doubt again in VaultCreateScore; "
		 "is something badly wrong with the DB?\n");
      }
      catch(const pqxx::broken_connection &e) {
	// pretty much fatal -- need to shut down or something
	log_err(m_log, "Connection to DB failed!\n");
	scr_result = ERROR_DB_TIMEOUT;
      }
      catch(const pqxx::sql_error &e) {
	log_warn(m_log, "SQL error in VaultCreateScore: %s\n", e.what());
      }
#endif
      if (scr_result == ERROR_BAD_SCORE_TYPE
	  || scr_result == ERROR_SCORE_EXISTS) {
	log_msgs(m_log, "VAULT_SCORE_CREATE %u's %s: %s %d\n",
		 msg->holder(), msg->score_name()->c_str(),
		 scr_result == ERROR_SCORE_EXISTS ? "exists" : "bad type",
		 scr_result == ERROR_SCORE_EXISTS ? 1 : msg->score_type());
      }
      else {
	log_msgs(m_log, "VAULT_SCORE_CREATE %u's %s -> %u%s\n",
		 msg->holder(), msg->score_name()->c_str(), scr_id,
		 scr_result == NO_ERROR ? "" : " (failed)");
      }

      u_char *scr_buf = new u_char[18];
      write16(scr_buf, 0, kAuth2Cli_ScoreCreateReply);
      write32(scr_buf, 2, msg->reqid());
      write32(scr_buf, 6, scr_result);
      write32(scr_buf, 10, scr_id);
      write32(scr_buf, 14, scr_time);
      VaultPassthrough_BackendMessage *reply
	= new VaultPassthrough_BackendMessage(in->get_id1(),
					      in->get_id2(),
					      scr_buf, 18,
					      false, true);
      c->enqueue(reply);
    }
    break; 
  case VAULT_SCORE_ADD:
    {
      VaultScoreAddPoints_BackendMessage *msg
	= (VaultScoreAddPoints_BackendMessage *)in;

      status_code_t sadd_result = ERROR_INTERNAL;
#ifdef USE_PQXX
      try {
	my->C->perform(VaultAddToScore_Request(msg->score_id(),
					       msg->delta(),
					       sadd_result));
      }
      catch(const pqxx::in_doubt_error &e) {
	log_warn(m_log, "in_doubt in VaultAddToScore\n");
      }
      catch(const pqxx::broken_connection &e) {
	// pretty much fatal -- need to shut down or something
	log_err(m_log, "Connection to DB failed!\n");
	sadd_result = ERROR_DB_TIMEOUT;
      }
      catch(const pqxx::sql_error &e) {
	log_warn(m_log, "SQL error in VaultAddToScore: %s\n", e.what());
      }
#endif
      log_msgs(m_log, "VAULT_SCORE_ADD %d to score %u%s\n",
	       msg->delta(), msg->score_id(),
	       sadd_result == NO_ERROR ? "" : " failed");

      u_char *sadd_buf = new u_char[10];
      write16(sadd_buf, 0, kAuth2Cli_ScoreAddPointsReply);
      write32(sadd_buf, 2, msg->reqid());
      write32(sadd_buf, 6, sadd_result);
      VaultPassthrough_BackendMessage *reply
	= new VaultPassthrough_BackendMessage(in->get_id1(),
					      in->get_id2(),
					      sadd_buf, 10,
					      false, true);
      c->enqueue(reply);
    }
    break;
  case VAULT_SCORE_XFER:
    {
      VaultScoreXferPoints_BackendMessage *msg
	= (VaultScoreXferPoints_BackendMessage *)in;

      status_code_t sxfer_result = ERROR_INTERNAL;
#ifdef USE_PQXX
      try {
	my->C->perform(VaultTransferScore_Request(msg->score_id(),
						  msg->dest_id(),
						  msg->delta(),
						  sxfer_result));
      }
      catch(const pqxx::in_doubt_error &e) {
	log_warn(m_log, "in_doubt in VaultTransferScore\n");
      }
      catch(const pqxx::broken_connection &e) {
	// pretty much fatal -- need to shut down or something
	log_err(m_log, "Connection to DB failed!\n");
	sxfer_result = ERROR_DB_TIMEOUT;
      }
      catch(const pqxx::sql_error &e) {
	log_warn(m_log, "SQL error in VaultTransferScore: %s\n", e.what());
      }
#endif
      log_msgs(m_log, "VAULT_SCORE_XFER %d from score %u to score %u%s\n",
	       msg->delta(), msg->dest_id(), msg->score_id(),
	       sxfer_result == NO_ERROR ? "" : " failed");

      u_char *sxfer_buf = new u_char[10];
      write16(sxfer_buf, 0, kAuth2Cli_ScoreTransferPointsReply);
      write32(sxfer_buf, 2, msg->reqid());
      write32(sxfer_buf, 6, sxfer_result);
      VaultPassthrough_BackendMessage *reply
	= new VaultPassthrough_BackendMessage(in->get_id1(),
					      in->get_id2(),
					      sxfer_buf, 10,
					      false, true);
      c->enqueue(reply);
    }
    break;
#endif /* !OLD_PROTOCOL */

  // XXX add new stuff here

  case VAULT_PASSTHRU:
    {
      VaultPassthrough_BackendMessage *msg
	= (VaultPassthrough_BackendMessage *)in;
      log_warn(m_log, "Unknown passthrough message type 0x%04x\n",
	       msg->uru_msgtype());
    }
    break;
  default:
    // unknown type
    log_warn(m_log, "Unknown message type 0x%08x\n", in->type());
    break;
  }
  return NO_SHUTDOWN;
}

Server::reason_t BackendServer::handle_admin(Connection *c,
					     BackendMessage *in) {
  switch (in->type()) {
  case ADMIN_HELLO:
    {
      Hello_BackendMessage *msg = (Hello_BackendMessage *)in;
      uint32_t peer_type = msg->peer_info();
      if (peer_type == 0) {
	// a dispatcher
	log_msgs(m_log, "ADMIN_HELLO from dispatcher %08x,%08x\n",
		 in->get_id1(), in->get_id2());
	gettimeofday(&c->m_timeout, NULL);
	c->m_interval = (3*BACKEND_KEEPALIVE_INTERVAL)+KEEPALIVE_INTERVAL;
	c->m_timeout.tv_sec += c->m_interval;
	// make sure we don't have duplicate entries
	for (std::vector<DispatcherInfo*>::iterator
	       iter = m_dispatchers.begin();
	       iter != m_dispatchers.end();
	       iter++) {
	  DispatcherInfo *disp = *iter;
	  if (disp->m_id1 == in->get_id1() && disp->m_id2 == in->get_id2()) {
	    log_net(m_log,
		    "Extra ADMIN_HELLO message from peer %08x,%08x type %d\n",
		    in->get_id1(), in->get_id2(), peer_type);
	    Connection *old_c = disp->m_conn;
	    if (old_c != c) {
	      disp->m_conn = c;
	      conn_shutdown(old_c, CLIENT_TIMEOUT);
	    }
	    return NO_SHUTDOWN;
	  }
	}
	// here, it's a new one
	DispatcherInfo *d = new DispatcherInfo(in->get_id1(),
					       in->get_id2(), c);
	m_dispatchers.push_back(d);
      }
      else {
	// auth or game
	log_msgs(m_log, "ADMIN_HELLO from %s %08x,%08x\n",
		 peer_type == TYPE_AUTH ? "auth"
		     : (peer_type == TYPE_GAME ? "game" : "gatekeeper"),
		 in->get_id1(), in->get_id2());
	ConnectionEntity *entity;
	HashKey key(in->get_id1(), in->get_id2());
	if (m_hash_table.find(key) != m_hash_table.end()) {
	  log_net(m_log,
		  "Extra ADMIN_HELLO message from peer %08x,%08x type %d\n",
		  in->get_id1(), in->get_id2(), peer_type);
	  entity = m_hash_table[key];
	  if (entity->type() != peer_type) {
	    log_err(m_log, "And we already had a peer of type %d!\n",
		    entity->type());
	    return PROTOCOL_ERROR;
	  }
	}
	else {
	  entity = new ConnectionEntity(c, peer_type);
	  m_hash_table[key] = entity;
	}
      }
      // send a reply with the backend server's max protocol version
      msg = new Hello_BackendMessage(in->get_id1(), in->get_id2(),
				     BACKEND_PROTOCOL_VERSION, false);
      c->enqueue(msg);
    }
    break;
  default:
    // unknown type
    log_warn(m_log, "Unknown message type 0x%08x\n", in->type());
  }
  return NO_SHUTDOWN;
}

Server::reason_t BackendServer::handle_track(Connection *c,
					     BackendMessage *in) {
  switch (in->type()) {
  case TRACK_PING:
    gettimeofday(&c->m_timeout, NULL);
    c->m_timeout.tv_sec += c->m_interval;
    break;
  case TRACK_SERVICE_TYPES:
    {
      TrackServiceTypes_BackendMessage *msg
	= (TrackServiceTypes_BackendMessage *)in;
      log_debug(m_log, "TRACK_SERVICE_TYPES: %08x,%08x accepts%s%s%s\n",
		in->get_id1(), in->get_id2(), msg->has_auth() ? " auth" : "",
		msg->has_file() ? " file" : "",
		msg->has_game() ? " game"
		    : ((msg->has_file() || msg->has_auth()) ? "" : " -none-"));
      std::vector<DispatcherInfo*>::iterator iter;
      DispatcherInfo *disp;
      for (iter = m_dispatchers.begin(); iter != m_dispatchers.end(); iter++) {
	disp = *iter;
	if (disp->m_id1 == in->get_id1() && disp->m_id2 == in->get_id2()) {
	  break;
	}
      }
      if (iter == m_dispatchers.end()) {
	// not found
	log_warn(m_log, "Could not find dispatcher info for peer %08x,%08x\n",
		 in->get_id1(), in->get_id2());
	disp = new DispatcherInfo(in->get_id1(), in->get_id2(), c);
	m_dispatchers.push_back(disp);
      }
      disp->m_accepting_new_game_servers = msg->has_game();
      // XXX if ever implemented, pay attention to message's
      // restrict_type() (means storing more data in DispatcherInfo)
      disp->m_handles_file_service = msg->has_file();
      disp->m_handles_auth_service = msg->has_auth();
      if (msg->has_file() || msg->has_auth()) {
	if (msg->addrtype() == TrackServiceTypes_BackendMessage::ST_HOSTNAME) {
	  disp->m_use_fa_hostname = true;
	  // we use the c_str() to force disp->m_fa_hostname to copy the
	  // string (the message's storage will go away)
	  disp->m_fa_hostname = msg->name()->c_str();
	}
	else {
	  disp->m_use_fa_hostname = false;
	  disp->m_fa_ipaddr = msg->address();
	}
      }
    }
    break;
  case TRACK_DISPATCHER_HELLO: // obsolete
    {
      log_debug(m_log, "TRACK_DISPATCHER_HELLO: %08x,%08x available\n",
		in->get_id1(), in->get_id2());
      std::vector<DispatcherInfo*>::iterator iter;
      for (iter = m_dispatchers.begin(); iter != m_dispatchers.end(); iter++) {
	DispatcherInfo *disp = *iter;
	if (disp->m_id1 == in->get_id1() && disp->m_id2 == in->get_id2()) {
	  disp->m_accepting_new_game_servers = true;
	  // XXX if ever implemented, pay attention to message's
	  // restrict_type() (means storing more data in DispatcherInfo)
	  disp->m_handles_file_service = false;
	  disp->m_handles_auth_service = false;
	  break;
	}
      }
      if (iter == m_dispatchers.end()) {
	// not found
	log_warn(m_log, "Could not find dispatcher info for peer %08x,%08x\n",
		 in->get_id1(), in->get_id2());
	DispatcherInfo *d = new DispatcherInfo(in->get_id1(),
					       in->get_id2(), c);
	d->m_accepting_new_game_servers = true;
	d->m_handles_file_service = false;
	d->m_handles_auth_service = false;
	m_dispatchers.push_back(d);
      }
    }
    break;
  case TRACK_DISPATCHER_BYE: // obsolete
    {
      log_debug(m_log, "TRACK_DISPATCHER_BYE: %08x,%08x unavailable\n",
		in->get_id1(), in->get_id2());
      std::vector<DispatcherInfo*>::iterator iter;
      for (iter = m_dispatchers.begin(); iter != m_dispatchers.end(); iter++) {
	DispatcherInfo *disp = *iter;
	if (disp->m_id1 == in->get_id1() && disp->m_id2 == in->get_id2()) {
	  disp->m_accepting_new_game_servers = false;
	  disp->m_handles_file_service = false;
	  disp->m_handles_auth_service = false;
	  break;
	}
      }
    }
    break;
  case TRACK_FIND_SERVICE:
    {
      TrackFindService_ToBackendMessage *msg
	= (TrackFindService_ToBackendMessage *)in;

      log_msgs(m_log, "TRACK_FIND_SERVICE: %08x,%08x asking for %s\n",
	       in->get_id1(), in->get_id2(),
	       msg->wants_file() ? "file" : "auth");

      bool got_one = false;
      DispatcherInfo *disp = NULL;
      TrackFindService_FromBackendMessage *reply;
      if (m_dispatchers.size() > 0) {
	if (msg->wants_file()) {
	  if (m_next_file >= m_dispatchers.size()) {
	    m_next_file = 0;
	  }
	  u_int stop_at = MIN(m_next_file, m_dispatchers.size());
	  do {
	    if (m_dispatchers[m_next_file]->m_handles_file_service) {
	      disp = m_dispatchers[m_next_file];
	      got_one = true;
	      break;
	    }
	    m_next_file++;
	    if (m_next_file >= m_dispatchers.size()) {
	      m_next_file = 0;
	    }
	  } while (m_next_file != stop_at);
	}
	else {
	  if (m_next_auth >= m_dispatchers.size()) {
	    m_next_auth = 0;
	  }
	  u_int stop_at = MIN(m_next_auth, m_dispatchers.size());
	  do {
	    if (m_dispatchers[m_next_auth]->m_handles_auth_service) {
	      disp = m_dispatchers[m_next_auth];
	      got_one = true;
	      break;
	    }
	    m_next_auth++;
	    if (m_next_auth >= m_dispatchers.size()) {
	      m_next_auth = 0;
	    }
	  } while (m_next_auth != stop_at);
	}
      }

      if (!got_one) {
	// no server available
	log_warn(m_log,
		 "Telling %08x,%08x there is currently no %s service!\n",
		 in->get_id1(), in->get_id2(),
		 msg->wants_file() ? "file" : "auth");
	reply = new TrackFindService_FromBackendMessage(in->get_id1(),
							in->get_id2(),
							msg->reqid(),
							msg->reqid2(),
							msg->wants_file());
      }
      else {
	// go to next one, since this one was just used
	if (msg->wants_file()) {
	  m_next_file++;
	}
	else {
	  m_next_auth++;
	}
	if (disp->m_use_fa_hostname) {
	  log_msgs(m_log,
		   "Telling %08x,%08x to get %s from %08x,%08x (%s)\n",
		   in->get_id1(), in->get_id2(),
		   msg->wants_file() ? "file" : "auth",
		   disp->m_id1, disp->m_id2, disp->m_fa_hostname.c_str());
	  reply = new TrackFindService_FromBackendMessage(in->get_id1(),
			in->get_id2(), msg->reqid(), msg->reqid2(),
			msg->wants_file(), disp->m_fa_hostname.c_str());
	}
	else {
	  log_msgs(m_log,
		   "Telling %08x,%08x to get %s from %08x,%08x (%08x)\n",
		   in->get_id1(), in->get_id2(),
		   msg->wants_file() ? "file" : "auth",
		   disp->m_id1, disp->m_id2, disp->m_fa_ipaddr);
	  reply = new TrackFindService_FromBackendMessage(in->get_id1(),
			in->get_id2(), msg->reqid(), msg->reqid2(),
			msg->wants_file(), disp->m_fa_ipaddr);
	}
      }
      c->enqueue(reply);
    }
    break;
  case TRACK_START_GAME:
    {
      TrackStartAge_ToBackendMessage *msg
	= (TrackStartAge_ToBackendMessage *)in;

      if (m_log && m_log->would_log_at(Logger::LOG_WARN)) {
	char uuid[UUID_STR_LEN];
	format_uuid(msg->age_uuid(), uuid);
	log_warn(m_log, "TRACK_START_GAME (reply): age UUID %s problem: %d\n",
		 uuid, (int)msg->problem());
      }

      if (msg->problem() != TrackStartAge_ToBackendMessage::NONE) {
	// the dispatcher says the game server cannot be started
	std::deque<TimerQueue::Timer*>::const_iterator w_iter;
	for (w_iter = m_timers->begin(); w_iter != m_timers->end(); w_iter++) {
	  Waiter *w = (Waiter*)(*w_iter);
	  if (w->cancelled()) {
	    continue;
	  }
	  if (!memcmp(w->m_ageuuid, msg->age_uuid(), UUID_RAW_LEN)) {
	    HashKey key(w->m_id1, w->m_id2);
	    if (m_hash_table.find(key) != m_hash_table.end()) {
	      ConnectionEntity *entity = m_hash_table[key];

	      log_warn(m_log, "Telling client connection %08x,%08x (kinum=%u) "
		       "we cannot start a game server\n",
		       w->m_id1, w->m_id2, w->m_kinum);
	      TrackAgeRequest_FromBackendMessage *none
		= new TrackAgeRequest_FromBackendMessage(w->m_id1,
							 w->m_id2,
							 w->m_reqid,
							 ERROR_INTERNAL);
	      entity->conn()->enqueue(none);
	    }
	    else {
	      // client gone?
	      log_debug(m_log, "Game server request failed for unknown "
			"connection %08x,%08x (kinum=%u)\n",
			w->m_id1, w->m_id2, w->m_kinum);
	    }
	    w->cancel();
	  }
	}
      }
    }
    break;
  case TRACK_GAME_HELLO:
    {
      TrackGameHello_BackendMessage *msg
	= (TrackGameHello_BackendMessage *)in;

      if (m_log && m_log->would_log_at(Logger::LOG_DEBUG)) {
	char uuid[UUID_STR_LEN];
	format_uuid(msg->age_uuid(), uuid);
	log_debug(m_log, "TRACK_GAME_HELLO: %s (%08x,%08x) available\n",
		  uuid, in->get_id1(), in->get_id2());
      }

      HashKey game(msg->get_id1(), msg->get_id2());
      ConnectionEntity *server = NULL;
      if (m_hash_table.find(game) == m_hash_table.end()) {
	// not found
	log_warn(m_log, "Could not find info for peer %08x,%08x\n",
		 in->get_id1(), in->get_id2());
	server = new ConnectionEntity(c, TYPE_GAME);
	m_hash_table[game] = server;
      }
      else {
	server = m_hash_table[game];
      }
      server->set_uuid(msg->age_uuid());
      server->set_server_id(msg->server_id());
      server->set_ipaddr(msg->ipaddr());

      // send all vault SDL if present
      status_code_t db_result = ERROR_INTERNAL;
      uint32_t age_node;
      uint32_t age_info;
      UruString age_fname;
#ifdef USE_PQXX
      try {
	my->C->perform(VaultGetAgeByUUID(msg->age_uuid(), age_node,
					 age_info, age_fname, db_result));
      }
      catch(const pqxx::in_doubt_error &e) {
	log_warn(m_log, "in_doubt getting age by UUID\n");
      }
      catch(const pqxx::broken_connection &e) {
	// pretty much fatal -- need to shut down or something
	log_err(m_log, "Connection to DB failed!\n");
	db_result = ERROR_DB_TIMEOUT;
      }
      catch(const pqxx::sql_error &e) {
	log_warn(m_log, "SQL error getting age by UUID: %s\n", e.what());
      }
#endif
      if (db_result != NO_ERROR) {
	char uuid[UUID_STR_LEN];
	format_uuid(msg->age_uuid(), uuid);
	log_warn(m_log, "DB request error getting age name for UUID %s\n",
		 uuid);
      }
      else {
	db_result = ERROR_INTERNAL;
	u_char *sdlbuf = NULL;
	u_int sdllen = 0;
	// Send the age's vault SDL first; the client does not write
	// timestamps to vault SDL, which means MOSS takes changes as newer
	// than anything else, but when creating a hood, the client writes
	// a node to the vault with *ALL* the state set (most to default).
	// This would override global SDL settings if it was sent after the
	// global SDL.
#ifdef USE_PQXX
	try {
	  my->C->perform(GetVaultSDL(age_info, age_fname, &sdlbuf, sdllen,
				     db_result));
	}
	catch(const pqxx::in_doubt_error &e) {
	  log_warn(m_log, "in_doubt getting age SDL\n");
	}
	catch(const pqxx::broken_connection &e) {
	  // pretty much fatal -- need to shut down or something
	  log_err(m_log, "Connection to DB failed!\n");
	  db_result = ERROR_DB_TIMEOUT;
	}
	catch(const pqxx::sql_error &e) {
	  log_warn(m_log, "SQL error getting age SDL: %s\n", e.what());
	}
#endif
	if (db_result != NO_ERROR) {
	  if (m_log && m_log->would_log_at(Logger::LOG_WARN)) {
	    char uuid[UUID_STR_LEN];
	    format_uuid(msg->age_uuid(), uuid);
	    log_warn(m_log, "DB request error getting age SDL for %s\n",
		     uuid);
	  }
	}
	else {
	  if (sdlbuf && sdllen > 0) {
	    // send the message
	    log_msgs(m_log, "Sending initial vault SDL to id %08x,%08x\n",
		     msg->get_id1(), msg->get_id2());
	    TrackSDLUpdate_BackendMessage *sdlmsg
	      = new TrackSDLUpdate_BackendMessage(msg->get_id1(),
						  msg->get_id2(),
						  0, m_ipaddr, m_id,
						  sdlbuf, sdllen,
			TrackSDLUpdate_BackendMessage::VAULT_SDL_LOAD);
	    c->enqueue(sdlmsg);
	  }
	}
	if (sdlbuf) {
	  delete[] sdlbuf;
	}
	// now send the global SDL
	db_result = ERROR_INTERNAL;
	sdlbuf = NULL;
	sdllen = 0;
#ifdef USE_PQXX
	try {
	  my->C->perform(GetGlobalSDL(age_fname, &sdlbuf, sdllen, db_result));
	}
	catch(const pqxx::in_doubt_error &e) {
	  log_warn(m_log, "in_doubt getting global SDL\n");
	}
	catch(const pqxx::broken_connection &e) {
	  // pretty much fatal -- need to shut down or something
	  log_err(m_log, "Connection to DB failed!\n");
	  db_result = ERROR_DB_TIMEOUT;
	}
	catch(const pqxx::sql_error &e) {
	  log_warn(m_log, "SQL error getting global SDL: %s\n", e.what());
	}
#endif
	if (db_result != NO_ERROR) {
	  log_warn(m_log, "DB request error getting global SDL for %s\n",
		   age_fname.c_str());
	}
	else {
	  if (sdlbuf && sdllen > 0) {
	    // send the message
	    log_msgs(m_log, "Sending global age SDL to id %08x,%08x\n",
		     msg->get_id1(), msg->get_id2());
	    TrackSDLUpdate_BackendMessage *sdlmsg
	      = new TrackSDLUpdate_BackendMessage(msg->get_id1(),
						  msg->get_id2(),
						  0, m_ipaddr, m_id,
						  sdlbuf, sdllen,
				TrackSDLUpdate_BackendMessage::GLOBAL_INIT);
	    c->enqueue(sdlmsg);
	  }
	}
	if (sdlbuf) {
	  delete[] sdlbuf;
	}
      }

      // find all clients waiting for this new server, and send the
      // request to register them with the game server
      struct timeval timeout;
      gettimeofday(&timeout, NULL);
      timeout.tv_sec += GAME_STARTUP_TIMEOUT;
      std::list<Waiter*> new_waiters;

      std::deque<TimerQueue::Timer*>::const_iterator w_iter;
      for (w_iter = m_timers->begin(); w_iter != m_timers->end(); w_iter++) {
	Waiter *w = (Waiter *)(*w_iter);
	if (w->cancelled()) {
	  continue;
	}
	if (!memcmp(w->m_ageuuid, msg->age_uuid(), UUID_RAW_LEN)) {
	  log_msgs(m_log, "Sending age registration for client (kinum=%u)\n",
		   w->m_kinum);
	  TrackAddPlayer_FromBackendMessage *add
	    = new TrackAddPlayer_FromBackendMessage(in->get_id1(),
						    in->get_id2(),
						    w->m_kinum,
						    w->m_name,
						    w->m_acctuuid);
	  c->enqueue(add);
	  // and reset the timeout just this once
	  Waiter *new_w = new Waiter(timeout, this, w->m_id1, w->m_id2,
				     w->m_reqid, w->m_kinum, w->m_name,
				     w->m_acctuuid, w->m_ageuuid, w->m_node);
	  w->cancel();
	  new_waiters.push_back(new_w);
	}
      }

      // now move the new waiters to the timer queue (doing it while
      // iterating through the timer queue is a bad plan: infinite loop
      // 'til you fall off the end of the queue and segfault)
      for (std::list<Waiter*>::iterator n_iter = new_waiters.begin();
	   n_iter != new_waiters.end();
	   n_iter++) {
	m_timers->insert(*n_iter);
      }
	
    }
    break;
  case TRACK_GAME_BYE:
    {
      TrackGameBye_ToBackendMessage *msg = (TrackGameBye_ToBackendMessage *)in;
      HashKey game(msg->get_id1(), msg->get_id2());
      if (m_hash_table.find(game) == m_hash_table.end()) {
	// not found!
	log_err(m_log, "Dropping TRACK_GAME_BYE from peer %08x,%08x which "
		"has not registered as a game server\n",
		msg->get_id1(), msg->get_id2());
	// just forget the message
      }
      else {
	ConnectionEntity *server = m_hash_table[game];
	log_debug(m_log, "TRACK_GAME_BYE from peer %08x,%08x final: %s\n",
		  msg->get_id1(), msg->get_id2(), msg->final() ? "yes" : "no");
	if (!msg->final()) {
	  // we have to not send new AddPlayer requests to that server
	  server->set_in_shutdown();

	  // we must send a message back so that the game server knows when
	  // it has drained the queue from us (tracking)
	  TrackGameBye_FromBackendMessage *marker
	    = new TrackGameBye_FromBackendMessage(msg->get_id1(),
						  msg->get_id2());
	  c->enqueue(marker);
	}
	else {
	  // At this point the only thing the game server has left to do
	  // should be exiting, freeing memory and closing connections. If we
	  // don't forget the game server now, and the old server hangs in
	  // shutdown, we will punt any waiting clients after their short
	  // timeout.

	  // If we happen to spin up a new server while the old one is
	  // shutting down, there is some potential for multiple simultaneous
	  // writes to the age's log file but that's an okay risk, because it
	  // won't break anything.

	  // XXX note that if we ever have multiple ConnectionEntities sharing
	  // a single Connection this is *wrong*
	  return PEER_SHUTDOWN;
	}
      }
    }
    break;
  case TRACK_FIND_GAME:
    // this handles a *client* request for a game server
    {
      TrackAgeRequest_ToBackendMessage *msg
	= (TrackAgeRequest_ToBackendMessage *)in;
#ifndef STANDALONE
#ifdef MULTIPLAYER_PHASE2
      // XXX first we have to make sure this is a valid age to be linking to
      // (how do I provide a list, and without having to restart the server
      // like Alcugs?)
      unimplemented;
      // XXX in general case, have dispatcher send list (wildcards allowed)
      // to tracking, have dispatcher maintain its list by checking on
      // conf reload
#endif
#endif
      if (m_log && m_log->would_log_at(Logger::LOG_DEBUG)) {
	char uuid[UUID_STR_LEN];
	format_uuid(msg->age_uuid(), uuid);
	log_debug(m_log, "TRACK_FIND_GAME: reqid %u age %s UUID %s\n",
		  msg->reqid(), msg->filename()->c_str(), uuid);
      }

      KillClient_BackendMessage::kill_reason_t why
	= handle_age_request(msg->age_uuid(), msg->filename(), false,
			     in->get_id1(), in->get_id2(), msg->reqid());
      if (why != KillClient_BackendMessage::UNKNOWN) {
	KillClient_BackendMessage *killit =
	  new KillClient_BackendMessage(in->get_id1(), in->get_id2(), why);
	c->enqueue(killit);
      }
    }
    break;
  case TRACK_ADD_PLAYER:
    // this is an ack
    {
      TrackAddPlayer_ToBackendMessage *msg
	= (TrackAddPlayer_ToBackendMessage *)in;
      
      HashKey game(msg->get_id1(), msg->get_id2());
      ConnectionEntity *server = NULL;
      if (m_hash_table.find(game) == m_hash_table.end()) {
	// not found
	log_err(m_log, "Dropping TRACK_ADD_PLAYER from peer %08x,%08x which "
		"has not registered as a game server\n",
		msg->get_id1(), msg->get_id2());
	// just forget the message
      }
      else {
	log_msgs(m_log, "TRACK_ADD_PLAYER from %08x,%08x: kinum=%u%s (%u)\n",
		 msg->get_id1(), msg->get_id2(), msg->kinum(),
		 msg->result() == NO_ERROR ? "" : " FAILED", msg->result());

	server = m_hash_table[game];

	// find the client
	std::deque<TimerQueue::Timer*>::const_iterator w_iter;
	for (w_iter = m_timers->begin(); w_iter != m_timers->end(); w_iter++) {
	  Waiter *w = (Waiter *)(*w_iter);
	  if (w->cancelled()) {
	    continue;
	  }
	  if (!memcmp(w->m_ageuuid, server->uuid(), UUID_RAW_LEN)) {
	    HashKey key(w->m_id1, w->m_id2);
	    if (m_hash_table.find(key) != m_hash_table.end()) {
	      ConnectionEntity *entity = m_hash_table[key];

	      log_msgs(m_log, "TRACK_FIND_GAME reply to %08x,%08x for client "
		       "reqid %u (kinum=%u)\n", w->m_id1, w->m_id2,
		       w->m_reqid, w->m_kinum);
	      TrackAgeRequest_FromBackendMessage *reply;
	      if (msg->result() == NO_ERROR) {
		reply
		  = new TrackAgeRequest_FromBackendMessage(w->m_id1,
							   w->m_id2,
							   w->m_reqid,
							   NO_ERROR,
							   server->uuid(),
							   server->server_id(),
							   w->m_node,
							   server->ipaddr());
		entity->conn()->enqueue(reply);
	      }
	      else if (msg->result() == ERROR_REMOTE_SHUTDOWN) {
		// ok, bad timing, let the server die and when it does
		// we'll create a new one; bump the timeout by making a new
		// one (this one is cancelled below)
		struct timeval new_t;
		gettimeofday(&new_t, NULL);
		new_t.tv_sec += GAME_STARTUP_TIMEOUT;
		Waiter *new_w = new Waiter(new_t, this, w->m_id1, w->m_id2,
					   w->m_reqid, w->m_kinum, w->m_name,
					   w->m_acctuuid, w->m_ageuuid,
					   w->m_node);
		// this insert is safe because we are going to stop iterating
		// over the timers list now
		m_timers->insert(new_w);
	      }
	      else {
		reply
		  = new TrackAgeRequest_FromBackendMessage(w->m_id1,
							   w->m_id2,
							   w->m_reqid,
							   msg->result());
		entity->conn()->enqueue(reply);
	      }
	    }
	    else {
	      // client timed out, I guess
	      log_debug(m_log, "Game server replied about unknown "
			"connection %08x,%08x (kinum=%u)\n",
			w->m_id1, w->m_id2, w->m_kinum);
	    }
	    w->cancel();
	    break;
	  }
	}
      }
    }
    break;
  case TRACK_GAME_PLAYERINFO:
    {
      TrackGamePlayerInfo_BackendMessage *msg
	= (TrackGamePlayerInfo_BackendMessage *)in;

      HashKey game(msg->get_id1(), msg->get_id2());
      if (m_hash_table.find(game) == m_hash_table.end()) {
	// not found
	log_err(m_log, "Dropping TRACK_GAME_PLAYERINFO from peer %08x,%08x "
		"which has not registered as a game server\n",
		msg->get_id1(), msg->get_id2());
	// just forget the message
      }
      else {
	log_msgs(m_log, "TRACK_GAME_PLAYERINFO from %08x,%08x: kinum=%u %s\n",
		 msg->get_id1(), msg->get_id2(), msg->kinum(),
		 msg->present() ? "here" : "left");

	ConnectionEntity *server = m_hash_table[game];
	// find auth ConnectionEntity for that KI number
	ConnectionEntity *auth = find_by_kinum(msg->kinum(), TYPE_AUTH);
	if (auth){
	  // found it, update local info
	  if (msg->present()) {
	    if (!(m_egg_mask & (1 << 1))) {
	      if (auth->egg1(auth->ipaddr() == msg->get_id1()
			     && auth->server_id() == msg->get_id2())) {
		// so it's a link to the same age -- in-game this can only
		// be Personal (with adminKI/CCR it could be a different age,
		// but I don't have the age name readily available and this
		// is just a silly easter egg!)
		uint32_t parent = 0, child = 0;
		status_code_t egg_status = ERROR_INTERNAL;
#ifdef USE_PQXX
		try {
		  my->C->perform(Egg1(msg->kinum(), parent, child,
				      egg_status));
		}
		catch(const pqxx::in_doubt_error &e) {
		  log_warn(m_log, "in_doubt in Egg1\n");
		  // oh well
		}
		catch(const pqxx::broken_connection &e) {
		  // pretty much fatal -- need to shut down or something
		  log_err(m_log, "Connection to DB failed!\n");
		  // do nothing
		}
		catch(const pqxx::sql_error &e) {
		  log_warn(m_log, "SQL error in Egg1: %s\n", e.what());
		}
#endif
		if (egg_status == NO_ERROR && parent != 0) {
		  // tell the client about the change
		  u_char *added_buf = new u_char[14];
		  write16(added_buf, 0, kAuth2Cli_VaultNodeAdded);
		  write32(added_buf, 2, parent);
		  write32(added_buf, 6, child);
		  write32(added_buf, 10, msg->kinum());
		  // the auth server's ipaddr() and server_id() are actually
		  // a game server's so I only have the info here (yuck)
		  std::map<HashKey,ConnectionEntity*>::iterator iter;
		  for (iter = m_hash_table.begin();
		       iter != m_hash_table.end();
		       iter++) {
		    if (iter->second == auth) {
		      VaultPassthrough_BackendMessage *reply
			= new VaultPassthrough_BackendMessage(
					iter->first.id1(), iter->first.id2(),
					added_buf, 14, false, true);
		      auth->conn()->enqueue(reply);
		      break;
		    }
		  }
		}
	      }
	    }
	    server->bump_count();
	    auth->set_ipaddr(msg->get_id1());
	    auth->set_server_id(msg->get_id2());
	  }
	  else {
	    server->drop_count();
	  }
	}
      }
    }
    break;
  case TRACK_INTERAGE_FWD:
    {
      TrackMsgForward_BackendMessage *msg
	= (TrackMsgForward_BackendMessage *)in;

      u_int recip_offset = msg->recips_offset();
      const u_char *msg_body = msg->fwd_msg();
      u_int msg_len = msg->fwd_msg_len();
      // the message should be correctness-checked by the game server though
      if (recip_offset < msg_len) {
	u_int recip_ct = msg_body[recip_offset++];
	// look for players in the list not at the game server this message
	// came from
	HashKey key(msg->get_id1(), msg->get_id2());
	if (m_hash_table.find(key) != m_hash_table.end()) {
	  ConnectionEntity *originator = m_hash_table[key];
	  if (originator->type() != TYPE_GAME) {
	    log_warn(m_log, "Received an interage Directed forward from non-"
		     "game server %08x,%08x\n", msg->get_id1(),
		     msg->get_id2());
	  }
	  else {
	    std::list<ConnectionEntity*> game_servers;
	    while (recip_ct > 0 && recip_offset+4 <= msg_len) {
	      kinum_t rki = read32(msg_body, recip_offset);
	      recip_offset += 4;
	      recip_ct--;
	      ConnectionEntity *who = find_by_kinum(rki, TYPE_AUTH);
	      if (who) {
		HashKey rkey(who->ipaddr(), who->server_id());
		if (m_hash_table.find(rkey) != m_hash_table.end()) {
		  ConnectionEntity *where = m_hash_table[rkey];
		  if (where != originator) {
		    game_servers.push_back(where);
		  }
		}
	      }
	    }
	    log_msgs(m_log, "TRACK_INTERAGE_FWD from %08x,%08x; forwarded "
		     "interage Directed message to %u servers\n",
		     msg->get_id1(), msg->get_id2(), game_servers.size());
	    if (game_servers.size() > 0) {
	      game_servers.sort();
	      game_servers.unique();
	      std::list<ConnectionEntity*>::iterator game;
	      for (game = game_servers.begin();
		   game != game_servers.end();
		   game++) {
		TrackMsgForward_BackendMessage *next_msg
		  = new TrackMsgForward_BackendMessage((*game)->ipaddr(),
						       (*game)->server_id(),
						       msg,
						       msg->recips_offset());
		(*game)->conn()->enqueue(next_msg);
	      }
	    }
	  }
	}
	else {
	  log_warn(m_log, "Received an interage Directed forward from unknown"
		   " server %08x,%08x\n", msg->get_id1(), msg->get_id2());
	  // drop message
	}
      }
      else {
	if (m_log && m_log->would_log_at(Logger::LOG_WARN)) {
	  log_warn(m_log, "Misformatted TRACK_INTERAGE_FWD from %08x,%08x\n",
		   msg->get_id1(), msg->get_id2());
	  m_log->dump_contents(Logger::LOG_WARN, msg->buffer(),
			       msg->message_len());
	}
      }
    }
    break;
  case TRACK_NEXT_GAMEID:
    {
      TrackNextGameID_BackendMessage *msg
	= (TrackNextGameID_BackendMessage *)in;

      uint32_t how_many = msg->how_many();
      log_msgs(m_log, "TRACK_NEXT_GAMEID requesting %u from %08x,%08x\n",
	       how_many, msg->get_id1(), msg->get_id2());

      msg = new TrackNextGameID_BackendMessage(msg->get_id1(), msg->get_id2(),
					       true, how_many, m_next_gameid);
      m_next_gameid += how_many;
      c->enqueue(msg);
    }
    break;
  default:
    // unknown type
    log_warn(m_log, "Unknown message type 0x%08x\n", in->type());
  }
  return NO_SHUTDOWN;
}

Server::reason_t BackendServer::handle_marker(Connection *c,
					      BackendMessage *in) {
  switch (in->type()) {
  case MARKER_NEWGAME:
    {
      MarkerGetGame_BackendMessage *msg = (MarkerGetGame_BackendMessage *)in;

      status_code_t mget_result = ERROR_INTERNAL;
      UruString game_name;
      uint32_t internal_id = 0;
      char game_type = -1;
      if (msg->exists()) {
#ifdef USE_PQXX
	try {
	  my->C->perform(MarkerGameFind_Request(msg->template_uuid(),
						game_name, internal_id,
						game_type, mget_result));
	}
	catch(const pqxx::in_doubt_error &e) {
	  log_warn(m_log, "in_doubt in MarkerGameFind_Request\n");
	  // this is relatively harmless; if we do nothing I believe
	  // the client will be fine and the user can re-open the game
	  // XXX check on that?
	  break;
	}
	catch(const pqxx::broken_connection &e) {
	  // pretty much fatal -- need to shut down or something
	  log_err(m_log, "Connection to DB failed!\n");
	  // do nothing
	  break;
	}
	catch(const pqxx::sql_error &e) {
	  log_warn(m_log, "SQL error in MarkerGameFind_Request: %s\n",
		   e.what());
	}
#endif
	if (m_log && m_log->would_log_at(Logger::LOG_MSGS)) {
	  char uuid[UUID_STR_LEN];
	  format_uuid(msg->template_uuid(), uuid);
	  if (mget_result == NO_ERROR || mget_result == ERROR_NODE_NOT_FOUND) {
	    log_msgs(m_log,
		     "MARKER_NEWGAME opening game %u uuid %s for %u%s\n",
		     internal_id, uuid, msg->player(),
		     mget_result == NO_ERROR ? "" : " MISSING");
	  }
	  else {
	    log_msgs(m_log, "MARKER_NEWGAME opening game %u uuid %s for %u: "
		     "error %u\n", internal_id, uuid, msg->player(),
		     mget_result);
	  }
	}
	if (mget_result == NO_ERROR || mget_result == ERROR_NODE_NOT_FOUND) {
	  MarkerGetGame_BackendMessage *reply
	    = new MarkerGetGame_BackendMessage(in->get_id1(), in->get_id2(),
					       true, msg->requester(),
					       (mget_result == NO_ERROR),
					       internal_id, game_type,
					       msg->template_uuid(),
					       &game_name);
	  c->enqueue(reply);
	}
	if (mget_result == NO_ERROR) {
	  // now fetch existing markers and forward them
	  std::vector<MarkerGame_MarkerInfo> allmarkers;
	  mget_result = ERROR_INTERNAL;
#ifdef USE_PQXX
	  try {
	    my->C->perform(MarkerGameMarkers_Request(internal_id,
						     mget_result,
						     allmarkers));
	  }
	  catch(const pqxx::in_doubt_error &e) {
	    log_warn(m_log, "in_doubt in MarkerGameMarkers_Request\n");
	    // XXX if we do nothing, the client will be told there are
	    // no markers
	  }
	  catch(const pqxx::broken_connection &e) {
	    // pretty much fatal -- need to shut down or something
	    log_err(m_log, "Connection to DB failed!\n");
	  }
	  catch(const pqxx::sql_error &e) {
	    log_warn(m_log, "SQL error in MarkerGameMarkers_Request: %s\n",
		     e.what());
	  }
#endif
	  log_msgs(m_log, "Sending MARKER_DUMP for game %u: %u markers%s\n",
		   internal_id, allmarkers.size(),
		   mget_result == NO_ERROR ? "" : " ERROR");
	  MarkersAll_BackendMessage *mreply =
	    new MarkersAll_BackendMessage(in->get_id1(), in->get_id2(),
					  internal_id, msg->requester(),
					  allmarkers.size());
	  if (mget_result == NO_ERROR && allmarkers.size() > 0) {
	    std::vector<MarkerGame_MarkerInfo>::iterator a_iter;
	    for (a_iter = allmarkers.begin();
		 a_iter != allmarkers.end();
		 a_iter++) {
	      if (a_iter->marker_id >= 0) {
		double x = a_iter->x, y = a_iter->y, z = a_iter->z;
		// we need to make sure these doubles are little-endian
		x = htoledouble(x); y = htoledouble(y); z = htoledouble(z);
		mreply->add_marker(a_iter->marker_id, x, y, z,
				   a_iter->marker_name, a_iter->age_name);
	      }
	    }
	  }
	  mreply->finalize();
	  // we have to send the reply even if there was an error so that
	  // the game server knows everything has happened
	  c->enqueue(mreply);

	  // now fetch captured markers
	  std::vector<MarkerGame_CapturedMarker> captured;
	  if (mget_result == NO_ERROR && allmarkers.size() > 0) {
	    mget_result = ERROR_INTERNAL;
#ifdef USE_PQXX
	    try {
	      my->C->perform(MarkerGameCaptured_Request(internal_id,
							msg->player(),
							mget_result,
							captured));
	    }
	    catch(const pqxx::in_doubt_error &e) {
	      log_warn(m_log, "in_doubt in MarkerGameCaptured_Request\n");
	      // XXX if we do nothing, the client will be told there are
	      // no captured markers
	    }
	    catch(const pqxx::broken_connection &e) {
	      // pretty much fatal -- need to shut down or something
	      log_err(m_log, "Connection to DB failed!\n");
	    }
	    catch(const pqxx::sql_error &e) {
	      log_warn(m_log, "SQL error in MarkerGameCaptured_Request: %s\n",
		       e.what());
	    }
#endif
	    log_msgs(m_log,
		     "Sending MARKER_STATE for game %u: %u markers%s\n",
		     internal_id, captured.size(),
		     mget_result == NO_ERROR ? "" : " ERROR");
	    MarkersCaptured_BackendMessage *creply =
	      new MarkersCaptured_BackendMessage(in->get_id1(), in->get_id2(),
						 internal_id,
						 msg->requester(),
						 captured.size());
	    if (mget_result == NO_ERROR && captured.size() > 0) {
	      std::vector<MarkerGame_CapturedMarker>::iterator c_iter;
	      for (c_iter = captured.begin();
		   c_iter != captured.end();
		   c_iter++) {
		if (c_iter->marker_id >= 0) {
		  creply->add_marker(c_iter->marker_id,
				     c_iter->capture_value);
		}
	      }
	    }
	    creply->finalize();
	    // we have to send the reply even if there was an error so that
	    // the game server knows everything has happened
	    c->enqueue(creply);
	  }
	}
      }
      else { /* game does not already exist */
	u_char game_uuid[UUID_RAW_LEN];
#ifdef USE_PQXX
	try {
	  my->C->perform(MarkerGameCreate_Request(msg->player(), msg->name(),
						  internal_id,
						  msg->game_type(), game_uuid,
						  mget_result));
	}
	catch(const pqxx::in_doubt_error &e) {
	  log_warn(m_log, "in_doubt in MarkerGameCreate_Request\n");
	  // this is relatively harmless; if we do nothing I believe
	  // the client will be fine and the user can re-open the game
	  // XXX check on that?
	  break;
	}
	catch(const pqxx::broken_connection &e) {
	  // pretty much fatal -- need to shut down or something
	  log_err(m_log, "Connection to DB failed!\n");
	  // do nothing
	  break;
	}
	catch(const pqxx::sql_error &e) {
	  log_warn(m_log, "SQL error in MarkerGameCreate_Request: %s\n",
		   e.what());
	}
#endif
	if (m_log && m_log->would_log_at(Logger::LOG_MSGS)) {
	  char uuid[UUID_STR_LEN];
	  format_uuid(game_uuid, uuid);
	  log_msgs(m_log, "MARKER_NEWGAME created game %u uuid %s for %u%s\n",
		   internal_id, uuid, msg->player(),
		   mget_result == NO_ERROR ? "" : " FAILED");
	}
	if (mget_result == NO_ERROR) {
	  MarkerGetGame_BackendMessage *reply
	    = new MarkerGetGame_BackendMessage(in->get_id1(), in->get_id2(),
					       true, msg->requester(), true,
					       internal_id, msg->game_type(),
					       game_uuid, msg->name());
	  c->enqueue(reply);
	}
      }
    }
    break;
  case MARKER_ADD:
    {
      MarkerAdd_BackendMessage *msg = (MarkerAdd_BackendMessage *)in;

      status_code_t madd_result = ERROR_INTERNAL;
      int32_t marker_num = -1;
      double x = msg->data()->x, y = msg->data()->y, z = msg->data()->z;
      // we need to make sure these doubles are in host order so they will
      // go into the DB correctly
      x = letohdouble(x); y = letohdouble(y); z = letohdouble(z); 
#ifdef USE_PQXX
      try {
	my->C->perform(MarkerGameAddMarker_Request(msg->localid(),
						   x, y, z, msg->name(),
						   msg->agename(),
						   marker_num, madd_result));
      }
      catch(const pqxx::in_doubt_error &e) {
	log_warn(m_log, "in_doubt in MarkerGameAddMarker_Request\n");
	// there is no way to know whether the transaction succeded
	// (short of looking up the next marker number first, and
	// comparing after the in_doubt)
	// failing to reply probably results in the client never setting
	// up the game? but upon link it will load what markers exist?
	// I don't think it's worth killing the client connection
	break;
      }
      catch(const pqxx::broken_connection &e) {
	// pretty much fatal -- need to shut down or something
	log_err(m_log, "Connection to DB failed!\n");
	// do nothing
	break;
      }
      catch(const pqxx::sql_error &e) {
	log_warn(m_log, "SQL error in MarkerGameAddMarker_Request: %s\n",
		 e.what());
      }
#endif
      if (madd_result == ERROR_NODE_NOT_FOUND) {
	log_warn(m_log, "MARKER_ADD attempted to add marker to non-existent "
		 "game %u (requesting GameMgr %08x,%08x %u)\n",
		 msg->localid(), in->get_id1(), in->get_id2(),
		 msg->requester());
      }
      else {
	log_msgs(m_log, "MARKER_ADD added marker %u to game %u%s\n",
		 marker_num, msg->localid(),
		 madd_result == NO_ERROR ? "" : " FAILED");
      }
      if (madd_result == NO_ERROR) {
	// reuse message
	msg->change_to_server();
	msg->set_number(marker_num);
	msg->add_ref();
	c->enqueue(msg);
      }
    }
    break;
  case MARKER_GAME_RENAME:
    {
      MarkerGameRename_BackendMessage *msg
	= (MarkerGameRename_BackendMessage *)in;

      status_code_t rename_result = ERROR_INTERNAL;
#ifdef USE_PQXX
      try {
	try {
	  my->C->perform(MarkerGameRename_Request(msg->localid(), msg->name(),
						  rename_result));
	}
	catch(const pqxx::in_doubt_error &e) {
	  log_warn(m_log, "in_doubt in MarkerGameRename_Request\n");
	  // this is completely harmless to retry
	  my->C->perform(MarkerGameRename_Request(msg->localid(), msg->name(),
						  rename_result));
	}
      }
      catch(const pqxx::in_doubt_error &e) {
	log_warn(m_log, "in_doubt again in MarkerGameRename_Request; "
		 "is something badly wrong with the DB?\n");
      }
      catch(const pqxx::broken_connection &e) {
	// pretty much fatal -- need to shut down or something
	log_err(m_log, "Connection to DB failed!\n");
      }
      catch(const pqxx::sql_error &e) {
	log_warn(m_log, "SQL error in MarkerGameRename_Request: %s\n",
		 e.what());
      }
#endif
      log_msgs(m_log, "MARKER_GAME_RENAME %sgame %u to %s%s\n",
	       rename_result == ERROR_NODE_NOT_FOUND ? "non-existent " : "",
	       msg->localid(), msg->name()->c_str(),
	       rename_result == ERROR_INTERNAL ? " FAILED" : "");
      if (rename_result == NO_ERROR) {
	msg->change_to_server();
	msg->add_ref();
	c->enqueue(msg);
      }
      else {
	// XXX I have no idea if the client is waiting for a reply so 
	// we need to send one, or if it will be fine hearing nothing. I
	// suspect the latter.
      }
    }
    break;
  case MARKER_GAME_DELETE:
    {
      MarkerGameDelete_BackendMessage *msg
	= (MarkerGameDelete_BackendMessage *)in;

      status_code_t delete_result = ERROR_INTERNAL;
#ifdef USE_PQXX
      try {
	try {
	  my->C->perform(MarkerGameDelete_Request(msg->localid(),
						  delete_result));
	}
	catch(const pqxx::in_doubt_error &e) {
	  log_warn(m_log, "in_doubt in MarkerGameDelete_Request\n");
	  my->C->perform(MarkerGameDelete_Request(msg->localid(),
						  delete_result));
	  if (delete_result == ERROR_NODE_NOT_FOUND) {
	    // assume the last attempt succeeded
	    delete_result = NO_ERROR;
	  }
	}
      }
      catch(const pqxx::in_doubt_error &e) {
	log_warn(m_log, "in_doubt again in MarkerGameDelete_Request; "
		 "is something badly wrong with the DB?\n");
      }
      catch(const pqxx::broken_connection &e) {
	// pretty much fatal -- need to shut down or something
	log_err(m_log, "Connection to DB failed!\n");
      }
      catch(const pqxx::sql_error &e) {
	log_warn(m_log, "SQL error in MarkerGameDelete_Request: %s\n",
		 e.what());
      }
#endif
      const char *resultstr = "";
      if (delete_result == ERROR_INTERNAL) {
	resultstr = " FAILED";
      }
      else if (delete_result == ERROR_INVALID_PARAM) {
	resultstr = " denied";
      }
      log_msgs(m_log, "MARKER_GAME_DELETE %sgame %u%s\n",
	       delete_result == ERROR_NODE_NOT_FOUND ? "non-existent " : "",
	       msg->localid(), resultstr);
      if (delete_result != NO_ERROR && delete_result != ERROR_INVALID_PARAM) {
	msg->clear_id();
      }
      msg->change_to_server();
      msg->add_ref();
      c->enqueue(msg);
    }
    break;
  case MARKER_RENAME:
    {
      MarkerGameRenameMarker_BackendMessage *msg
	= (MarkerGameRenameMarker_BackendMessage *)in;

      status_code_t mrename_result = ERROR_INTERNAL;
#ifdef USE_PQXX
      try {
	try {
	  my->C->perform(MarkerGameRenameMarker_Request(msg->localid(),
							msg->number(),
							msg->name(),
							mrename_result));
	}
	catch(const pqxx::in_doubt_error &e) {
	  log_warn(m_log, "in_doubt in MarkerGameRenameMarker_Request\n");
	  // this is completely harmless to retry
	  my->C->perform(MarkerGameRenameMarker_Request(msg->localid(),
							msg->number(),
							msg->name(),
							mrename_result));
	}
      }
      catch(const pqxx::in_doubt_error &e) {
	log_warn(m_log, "in_doubt again in MarkerGameRenameMarker_Request; "
		 "is something badly wrong with the DB?\n");
      }
      catch(const pqxx::broken_connection &e) {
	// pretty much fatal -- need to shut down or something
	log_err(m_log, "Connection to DB failed!\n");
      }
      catch(const pqxx::sql_error &e) {
	log_warn(m_log, "SQL error in MarkerGameRenameMarker_Request: %s\n",
		 e.what());
      }
#endif
      log_msgs(m_log, "MARKER_RENAME game %u marker %u to %s%s\n",
	       msg->localid(), msg->number(), msg->name()->c_str(),
	       mrename_result == NO_ERROR ? "" : " FAILED");
      if (mrename_result == NO_ERROR) {
	msg->change_to_server();
	msg->add_ref();
	c->enqueue(msg);
      }
      else {
	if (mrename_result == ERROR_NODE_NOT_FOUND) {
	  log_warn(m_log, "Attempted rename of non-existent marker "
		   "game %u marker %u\n", msg->localid(), msg->number());
	}
	// XXX I have no idea if the client is waiting for a reply so 
	// we need to send one, or if it will be fine hearing nothing. I
	// suspect the latter.
      }
    }
    break;
  case MARKER_DELETE:
    {
      MarkerGameDeleteMarker_BackendMessage *msg
	= (MarkerGameDeleteMarker_BackendMessage *)in;

      status_code_t mdelete_result = ERROR_INTERNAL;
#ifdef USE_PQXX
      try {
	try {
	  my->C->perform(MarkerGameDeleteMarker_Request(msg->localid(),
							msg->number(),
							mdelete_result));
	}
	catch(const pqxx::in_doubt_error &e) {
	  log_warn(m_log, "in_doubt in MarkerGameDeleteMarker_Request\n");
	  my->C->perform(MarkerGameDeleteMarker_Request(msg->localid(),
							msg->number(),
							mdelete_result));
	  if (mdelete_result == ERROR_NODE_NOT_FOUND) {
	    // assume the last attempt succeeded
	    mdelete_result = NO_ERROR;
	  }
	}
      }
      catch(const pqxx::in_doubt_error &e) {
	log_warn(m_log, "in_doubt again in MarkerGameDeleteMarker_Request; "
		 "is something badly wrong with the DB?\n");
      }
      catch(const pqxx::broken_connection &e) {
	// pretty much fatal -- need to shut down or something
	log_err(m_log, "Connection to DB failed!\n");
      }
      catch(const pqxx::sql_error &e) {
	log_warn(m_log, "SQL error in MarkerGameDeleteMarker_Request: %s\n",
		 e.what());
      }
#endif
      log_msgs(m_log, "MARKER_DELETE game %u marker %u%s\n",
	       msg->localid(), msg->number(),
	       mdelete_result == NO_ERROR ? "" : " FAILED");
      if (mdelete_result == NO_ERROR) {
	msg->change_to_server();
	msg->add_ref();
	c->enqueue(msg);
      }
      else {
	if (mdelete_result == ERROR_NODE_NOT_FOUND) {
	  log_warn(m_log, "Attempted delete of non-existent marker "
		   "game %u marker %u\n", msg->localid(), msg->number());
	}
	// XXX I have no idea if the client is waiting for a reply so 
	// we need to send one, or if it will be fine hearing nothing. I
	// suspect the latter.
      }
    }
    break;
  case MARKER_CAPTURE:
    {
      MarkerGameCaptureMarker_BackendMessage *msg
	= (MarkerGameCaptureMarker_BackendMessage *)in;

      status_code_t cap_result = ERROR_INTERNAL;
#ifdef USE_PQXX
      try {
	try {
	  my->C->perform(MarkerGameCaptureMarker_Request(msg->localid(),
							 msg->player(),
							 msg->number(),
							 msg->value(),
							 cap_result));
	}
	catch(const pqxx::in_doubt_error &e) {
	  log_warn(m_log, "in_doubt in MarkerGameCaptureMarker_Request\n");
	  // this is safe to retry, at worst we send a spurious captured
	  // message to the client for the case where the marker was already
	  // captured
	  my->C->perform(MarkerGameCaptureMarker_Request(msg->localid(),
							 msg->player(),
							 msg->number(),
							 msg->value(),
							 cap_result));
	  if (cap_result == ERROR_SCORE_EXISTS) {
	    // assume the last attempt succeeded
	    cap_result = NO_ERROR;
	  }
	}
      }
      catch(const pqxx::in_doubt_error &e) {
	log_warn(m_log, "in_doubt again in MarkerGameCaptureMarker_Request; "
		 "is something badly wrong with the DB?\n");
      }
      catch(const pqxx::broken_connection &e) {
	// pretty much fatal -- need to shut down or something
	log_err(m_log, "Connection to DB failed!\n");
      }
      catch(const pqxx::sql_error &e) {
	log_warn(m_log, "SQL error in MarkerGameCaptureMarker_Request: %s\n",
		 e.what());
      }
#endif
      log_msgs(m_log, "MARKER_CAPTURE game %u player %u marker %u%s\n",
	       msg->localid(), msg->player(), msg->number(),
	       cap_result == ERROR_INTERNAL ? " FAILED" : "");
      if (cap_result == NO_ERROR) {
	msg->change_to_server();
	msg->add_ref();
	c->enqueue(msg);
      }
      else if (cap_result == ERROR_NODE_NOT_FOUND) {
	// This is actually okay! This could happen legitimately if someone
	// is playing a user-created marker game and its owner deletes a
	// marker before the player captures it. Even if MOSS pushes marker
	// game changes to other clients, there's a race where the delete
	// could hit the DB while the capture message is already in flight.
	log_msgs(m_log, "Attempted capture of non-existent marker "
		 "game %u marker %u\n", msg->localid(), msg->number());
      }
      else {
	// either a DB error, or the marker was already captured; in the
	// latter case we intentionally send nothing, so in the former case
	// it will suffice to send nothing
      }
    }
    break;
  case MARKER_GAME_STOP:
    {
      MarkerGameStop_BackendMessage *msg = (MarkerGameStop_BackendMessage *)in;

      status_code_t stop_result = ERROR_INTERNAL;
#ifdef USE_PQXX
      try {
	try {
	  my->C->perform(MarkerGameStop_Request(msg->localid(), msg->player(),
						stop_result));
	}
	catch(const pqxx::in_doubt_error &e) {
	  log_warn(m_log, "in_doubt in MarkerGameStop_Request\n");
	  // this is safe to retry
	  my->C->perform(MarkerGameStop_Request(msg->localid(), msg->player(),
						stop_result));
	}
      }
      catch(const pqxx::in_doubt_error &e) {
	log_warn(m_log, "in_doubt again in MarkerGameStop_Request; "
		 "is something badly wrong with the DB?\n");
      }
      catch(const pqxx::broken_connection &e) {
	// pretty much fatal -- need to shut down or something
	log_err(m_log, "Connection to DB failed!\n");
      }
      catch(const pqxx::sql_error &e) {
	log_warn(m_log, "SQL error in MarkerGameStop_Request: %s\n",
		 e.what());
      }
#endif
      log_msgs(m_log, "MARKER_GAME_STOP game %u player %u%s\n",
	       msg->localid(), msg->player(),
	       stop_result == NO_ERROR ? "" : " FAILED");
    }
    break;
  default:
    // unknown type
    log_warn(m_log, "Unknown message type 0x%08x\n", in->type());
  }
  return NO_SHUTDOWN;
}

int BackendServer::init() {
  m_timers = new TimerQueue();
  m_conns.push_back(m_timers);
  try {
    my = new BackendObj(m_log, m_db_addr, m_db_port, m_db_params,
			m_db_user, m_db_passwd, m_db_name);
    if (my->connection_failed) {
      log_err(m_log, "Error connecting to database\n");
      return -1;
    }
  }
#ifdef USE_PQXX
  catch (const pqxx::broken_connection &e) {
    log_err(m_log, "DB connection failure: %s\n", e.what());
    return -1;
  }
  try {
    try {
      my->C->perform(Call_initvault());
    }
    catch (const pqxx::in_doubt_error &e) {
      // retry once; this is okay because if the previous one did succeed,
      // it will be detected and initvault() won't be run again
      log_warn(m_log, "in_doubt in Call_initvault; retrying\n");
      my->C->perform(Call_initvault());
    }
  }
  catch (const pqxx::in_doubt_error &e) {
    log_warn(m_log, "in_doubt again in Call_initvault; "
	     "is something badly wrong with the DB?\n");
    return -1;
  }
  catch(const pqxx::sql_error &e) {
    log_warn(m_log, "SQL error in Call_initvault: %s\n", e.what());
    return -1;
  }
  catch (const pqxx::broken_connection &e) {
    log_err(m_log, "DB connection failure: %s\n", e.what());
    return -1;
  }
#endif
  return 0;
}

Server::reason_t BackendServer::message_read(Server::Connection *c,
					     NetworkMessage *msg) {
  int msg_type = msg->type();

  if (msg_type == -1) {
    // unrecognized message
    log_err(m_log, "Unrecognized backend message received on "
	    "connection %d!\n", c->fd());
    if (m_log) {
      m_log->dump_contents(Logger::LOG_ERR, msg->buffer(), msg->message_len());
    }
    delete msg;
    return PROTOCOL_ERROR;
  }

  Server::reason_t ret;
  BackendMessage *in = (BackendMessage *)msg;

  if (msg_type & CLASS_AUTH) {
    ret = handle_auth(c, in);
  }
  else if (msg_type & CLASS_VAULT) {
    ret = handle_vault(c, in);
  }
  else if (msg_type & CLASS_ADMIN) {
    ret = handle_admin(c, in);
  }
  else if (msg_type & CLASS_TRACK) {
    ret = handle_track(c, in);
  }
  else if (msg_type & CLASS_MARKER) {
    ret = handle_marker(c, in);
  }
  else {
    log_err(m_log, "Unknown message type 0x%08x\n", msg_type);
    ret = NO_SHUTDOWN;
  }
  if (in->del_ref() < 1) {
    delete in;
  }
  return ret;
}

Server::reason_t BackendServer::conn_timeout(Server::Connection *c,
					     Server::reason_t why) {
  if (c == m_timers) {
    struct timeval now;
    gettimeofday(&now, NULL);
    m_timers->handle_timeout(now);
    return NO_SHUTDOWN;
  }
  else {
    log_warn(m_log, "Connection on %d timed out\n", c->fd());
    return conn_shutdown(c, why);
  }
}

Server::reason_t BackendServer::conn_shutdown(Server::Connection *c,
					      Server::reason_t why) {
  if (c == m_timers) {
    // hmm, this shouldn't happen
    // we must be shutting down the whole server or something
    return NO_SHUTDOWN;
  }

  for (std::vector<DispatcherInfo*>::iterator
	 d_iter = m_dispatchers.begin();
	 d_iter != m_dispatchers.end();
	 d_iter++) {
    DispatcherInfo *disp = *d_iter;
    if (disp->m_conn == c) {
      m_dispatchers.erase(d_iter);
      delete disp;
      break;
    }
  }
  // XXX not efficient!
  for (std::map<HashKey,ConnectionEntity*>::iterator
	 iter = m_hash_table.begin(); iter != m_hash_table.end(); iter++) {
    ConnectionEntity *leaver = iter->second;
    if (leaver->conn() == c) {
      m_hash_table.erase(iter);

      if (leaver->type() == TYPE_GAME) {
	// if there are any Waiters for this server, start a new one as this
	// one just shut down -- note that we have removed leaver from the list,
	// so handle_age_request won't just re-find the server that's gone
	std::deque<TimerQueue::Timer*>::const_iterator w_iter;
	for (w_iter = m_timers->begin(); w_iter != m_timers->end(); w_iter++) {
	  Waiter *w = (Waiter *)(*w_iter);
	  if (w->cancelled()) {
	    continue;
	  }
	  if (!memcmp(w->m_ageuuid, leaver->uuid(), UUID_RAW_LEN)) {
	    KillClient_BackendMessage::kill_reason_t why
	      = handle_age_request(leaver->uuid(), NULL, true,
				   w->m_id1, w->m_id2, w->m_reqid);
	    if (why == KillClient_BackendMessage::UNKNOWN) {
	      // only need one
	      break;
	    }
	  }
	}
	// if this age is a dynamically-created Bahro cave (eww!), delete it
	uint32_t age_node;
	uint32_t age_info;
	UruString age_fname;
	// use something not used by the DB routines
	status_code_t db_result = ERROR_NAME_LOOKUP;
#ifdef USE_PQXX
	try {
	  my->C->perform(VaultGetAgeByUUID(leaver->uuid(), age_node,
					   age_info, age_fname, db_result));
	  if (db_result == NO_ERROR) {
	    if (age_fname == "BahroCave" || age_fname == "LiveBahroCaves") {
	      if (m_log && m_log->would_log_at(Logger::LOG_DEBUG)) {
		char uuid[UUID_STR_LEN];
		format_uuid(leaver->uuid(), uuid);
		log_debug(m_log, "Trying to delete age %s, UUID %s\n",
			  age_fname.c_str(), uuid);
	      }
	      db_result = ERROR_NAME_LOOKUP;
	      my->C->perform(DeleteAge(age_info, db_result));
	    }
	  }
	}
	catch(const pqxx::in_doubt_error &e) {
	  log_warn(m_log, "in_doubt checking for/deleting Bahro cave\n");
	}
	catch(const pqxx::broken_connection &e) {
	  // pretty much fatal -- need to shut down or something
	  log_err(m_log, "Connection to DB failed!\n");
	}
	catch(const pqxx::sql_error &e) {
	  log_warn(m_log, "SQL error checking for/deleting Bahro cave: %s\n",
		   e.what());
	}
#endif
	// if db_result is still ERROR_NAME_LOOKUP, we just logged the
	// problem in the catch statements
	if (db_result != NO_ERROR && db_result != ERROR_NAME_LOOKUP) {
	  log_warn(m_log, "Error code %u checking for/deleting Bahro cave\n",
		   db_result);
	}
      }
      else if (leaver->type() == TYPE_AUTH) {
	// cancel any waiters there might be for this server
	std::deque<TimerQueue::Timer*>::const_iterator w_iter;
	for (w_iter = m_timers->begin(); w_iter != m_timers->end(); w_iter++) {
	  Waiter *w = (Waiter *)(*w_iter);
	  if (w->cancelled()) {
	    continue;
	  }
	  if (w->m_kinum == leaver->kinum()) {
	    w->cancel();
	  }
	}
	// kinum is 0 in StartUp
	if (leaver->kinum() != 0) {
	  // if the client is connected to any game server, tell the game
	  // server to drop the player
	  if (leaver->server_id() != 0 || leaver->ipaddr() != 0) {
	    HashKey key(leaver->ipaddr(), leaver->server_id());
	    if (m_hash_table.find(key) != m_hash_table.end()) {
	      ConnectionEntity *gameserver = m_hash_table[key];
	      if (gameserver->type() == TYPE_GAME) {
		KillClient_BackendMessage *killit
		  = new KillClient_BackendMessage(
				leaver->ipaddr(),
				leaver->server_id(),
				KillClient_BackendMessage::AUTH_DISCONNECT,
				leaver->kinum());
		gameserver->conn()->enqueue(killit);
	      }
	    }
	  }
	  // and mark the player offline in the vault
	  set_player_offline(leaver->kinum(), "disconnect");
	  log_debug(m_log, "Client kinum=%u has left the premises\n",
		    leaver->kinum());
	}
      }
      delete leaver;
      break;
    }
  }
  for (std::list<Connection*>::iterator
	 c_iter = m_conns.begin(); c_iter != m_conns.end(); c_iter++) {
    Connection *conn = *c_iter;
    if (conn == c) {
      m_conns.erase(c_iter);
      break;
    }
  }
  delete c;
  return NO_SHUTDOWN;
}

BackendServer::~BackendServer() {
  if (my) {
    delete my;
  }
  for (std::map<HashKey,ConnectionEntity*>::iterator
	 iter = m_hash_table.begin(); iter != m_hash_table.end(); iter++) {
    delete iter->second;
  }
}

bool BackendServer::shutdown(Server::reason_t reason) {
  // XXX !!!
  return true;
}

void BackendServer::add_client_conn(int fd, u_char first) {
  BackendConnection *conn = new BackendConnection(fd);
  m_conns.push_back(conn);
  conn->m_readbuf->buffer()[0] = first;
  conn->m_read_fill = 1;
}

void BackendServer::Waiter::callback() {
  // game server did not reply in time
  HashKey key(m_id1, m_id2);
  if (m_server->m_hash_table.find(key) != m_server->m_hash_table.end()) {
    ConnectionEntity *entity = m_server->m_hash_table[key];
    // XXX if we ever had a huge number of users, we want to do
    // a retry, and/or increase the timeout
    log_warn(m_server->m_log, "Telling client connection %08x,%08x (kinum=%u) "
	     "we did not hear back from a game server\n",
	     m_id1, m_id2, m_kinum);
    TrackAgeRequest_FromBackendMessage *none
      = new TrackAgeRequest_FromBackendMessage(m_id1,
					       m_id2,
					       m_reqid,
					       ERROR_NO_RESPONSE);
    entity->conn()->enqueue(none);
  }
  else {
    // client gone?
    log_debug(m_server->m_log, "Game server request timeout for unknown "
	      "connection %08x,%08x (kinum=%u)\n",
	      m_id1, m_id2, m_kinum);
  }
}

KillClient_BackendMessage::kill_reason_t
     BackendServer::handle_age_request(const u_char *age_uuid, 
				       UruString *filename,
				       bool force_new,
				       uint32_t user_id1, uint32_t user_id2,
				       uint32_t reqid) {
  // get the user info for this connection ID
  HashKey key(user_id1, user_id2);
  if (m_hash_table.find(key) == m_hash_table.end()) {
    log_warn(m_log, "Age requested for a client we don't know about!\n");
    return KillClient_BackendMessage::NO_STATE;
  }
  ConnectionEntity *user = m_hash_table[key];
  KillClient_BackendMessage::kill_reason_t result
    = KillClient_BackendMessage::UNKNOWN;

  // now get the age node ID; if it doesn't exist, stop now
  uint32_t age_node;
  uint32_t age_info_node;
  UruString age_fname;
  status_code_t db_result = ERROR_INTERNAL;
#ifdef USE_PQXX
  try {
    my->C->perform(VaultGetAgeByUUID(age_uuid, age_node, age_info_node,
				     age_fname, db_result));
  }
  catch(const pqxx::broken_connection &e) {
    // pretty much fatal -- need to shut down or something
    log_err(m_log, "Connection to DB failed!\n");
    db_result = ERROR_DB_TIMEOUT;
  }
  catch(const pqxx::sql_error &e) {
    log_warn(m_log, "SQL error in VaultGetAgeByUUID: %s\n", e.what());
    db_result = ERROR_INTERNAL;
  }
#endif
  if (db_result == ERROR_AGE_NOT_FOUND && filename) {
    const char *fname = filename->c_str();
    if (*filename == "BahroCave" || *filename == "LiveBahroCaves") {
      // special case -- the Bahro caves are created by the server each link
      // in response to the client sending a request with a random UUID
#ifdef USE_PQXX
      try {
	my->C->perform(VaultCreateAge_Request(fname, fname, fname, fname,
					      age_uuid, NULL,
					      age_node, age_info_node,
					      db_result));
      }
      catch(const pqxx::in_doubt_error &e) {
	log_warn(m_log, "in_doubt in CreateAge for Bahro cave\n");
	// this one, we really can't do much about
	return KillClient_BackendMessage::IN_DOUBT;
      }
      catch(const pqxx::broken_connection &e) {
	// pretty much fatal -- need to shut down or something
	log_err(m_log, "Connection to DB failed!\n");
	db_result = ERROR_DB_TIMEOUT;
      }
      catch(const pqxx::sql_error &e) {
	log_warn(m_log, "SQL error in VaultCreateNode for Bahro cave: %s\n",
		 e.what());
	db_result = ERROR_INTERNAL;
      }
#endif
      if (db_result == NO_ERROR) {
	age_fname = fname;
	// XXX for better efficiency later, keep track of what's
	// needed to delete the age so we don't have to query the DB
      }
    }
  }
  if (db_result != NO_ERROR) {
    TrackAgeRequest_FromBackendMessage *noage
      = new TrackAgeRequest_FromBackendMessage(user_id1, user_id2, reqid,
					       db_result);
    user->conn()->enqueue(noage);
    return result;
  }

  if (filename && (age_fname != *filename)) {
    // the age name the client gave us differs from what's in the DB
    char uuid[UUID_STR_LEN];
    format_uuid(age_uuid, uuid);
    log_warn(m_log, "Client requested age with UUID %s name %s but the name "
	     "is %s in the DB\n", uuid, filename->c_str(), age_fname.c_str());
    TrackAgeRequest_FromBackendMessage *badage
      = new TrackAgeRequest_FromBackendMessage(user_id1, user_id2, reqid,
					       ERROR_INVALID_DATA);
    user->conn()->enqueue(badage);
    return result;
  }

  struct timeval timeout;
  gettimeofday(&timeout, NULL);
  timeout.tv_sec += GAME_STARTUP_TIMEOUT;
  // XXX not efficient!
  std::map<HashKey,ConnectionEntity*>::iterator iter;
  for (iter = m_hash_table.begin(); iter != m_hash_table.end(); iter++) {
    if (!memcmp(iter->second->uuid(), age_uuid, UUID_RAW_LEN)) {
      // one already exists!
      ConnectionEntity *entity = iter->second;
      if (entity->type() != TYPE_GAME) {
	char uuid[UUID_STR_LEN];
	format_uuid(age_uuid, uuid);
	log_warn(m_log,
		 "Found an auth server with the requested game UUID %s!\n",
		 uuid);
	continue;
      }
      if (entity->in_shutdown()) {
	// if the server is shutting down, wait a bit for it to die
      }
      else {
	// make sure the server doesn't shut down while we are trying to
	// send a new client to it, and register the client's info with it
	log_debug(m_log, "Telling game server %08x,%08x a new client "
		  "(kinum=%u) is on the way\n",
		 iter->first.id1(), iter->first.id2(), user->kinum());
	TrackAddPlayer_FromBackendMessage *bump
	  = new TrackAddPlayer_FromBackendMessage(iter->first.id1(),
						  iter->first.id2(),
						  user->kinum(),
						  user->name(),
						  user->uuid());
	entity->conn()->enqueue(bump);
      }
      // and set a timeout
      if (force_new) {
	// this should never happen
	log_warn(m_log, "We're starting up a new game server because the "
		 "one we need quit, but there is still a game server of "
		 "that type!\n");
      }
      else {
	Waiter *w = new Waiter(timeout, this, user_id1, user_id2, reqid,
			       user->kinum(), user->name(), user->uuid(),
			       age_uuid, age_node);
	m_timers->insert(w);
      }
      // drop out of the loop, we've done what we need
      break;
    }
  }
  if (iter == m_hash_table.end()) {
    // need to make a new one, but maybe a request has been sent already
    bool need_new_one = force_new;
    // XXX the only way to tell is to search through the Waiter queue, this
    // information needs to be stored better!
    if (!force_new) {
      // assume we *do* need a new one
      need_new_one = true;
      std::deque<TimerQueue::Timer*>::const_iterator w_iter;
      for (w_iter = m_timers->begin(); w_iter != m_timers->end(); w_iter++) {
	Waiter *w = (Waiter*)(*w_iter);
	if (w->cancelled()) {
	  continue;
	}
	if (!memcmp(w->m_ageuuid, age_uuid, UUID_RAW_LEN)) {
	  // some other waiter wants that server
	  need_new_one = false;
	}
      }
    }
    if (!need_new_one) {
      // just set the timeout
      Waiter *w = new Waiter(timeout, this, user_id1, user_id2, reqid,
			     user->kinum(), user->name(), user->uuid(),
			     age_uuid, age_node);
      m_timers->insert(w);
      return result;
    }
    // here, we do indeed need to ask for a new server
    bool got_one = false;
    if (m_dispatchers.size() > 0) {
      if (m_next_dispatcher >= m_dispatchers.size()) {
	m_next_dispatcher = 0;
      }
      u_int stop_at = MIN(m_next_dispatcher, m_dispatchers.size());
      do {
	if (m_dispatchers[m_next_dispatcher]->m_accepting_new_game_servers) {
	  DispatcherInfo *disp = m_dispatchers[m_next_dispatcher];
	  // send a request to the dispatcher to start a new server, and
	  // register the client's info with it
	  log_debug(m_log,
		    "Telling dispatcher %08x,%08x to start a new %s server\n",
		    disp->m_id1, disp->m_id2, age_fname.c_str());
	  TrackStartAge_FromBackendMessage *start
	    = new TrackStartAge_FromBackendMessage(disp->m_id1, disp->m_id2,
						   new UruString(age_fname),
						   age_uuid);
	  disp->m_conn->enqueue(start);
	  // and set a timeout
	  if (!force_new) {
	    Waiter *w = new Waiter(timeout, this, user_id1, user_id2, reqid,
				   user->kinum(), user->name(), user->uuid(),
				   age_uuid, age_node);
	    m_timers->insert(w);
	  }
	  got_one = true;
	  break;
	}
	m_next_dispatcher++;
	if (m_next_dispatcher >= m_dispatchers.size()) {
	  m_next_dispatcher = 0;
	}
      } while (m_next_dispatcher != stop_at);
    }
    if (!got_one) {
      // no dispatchers available
      log_warn(m_log, "Telling client connection (kinum=%u) there "
	       "are no game servers to be had\n", user->kinum());
      TrackAgeRequest_FromBackendMessage *none
	= new TrackAgeRequest_FromBackendMessage(user_id1,
						 user_id2,
						 reqid,
						 ERROR_AGE_NOT_FOUND);
      user->conn()->enqueue(none);
    }
    else {
      // go to next one, since this one was just used
      m_next_dispatcher++;
    }
  }
  return result;
}

status_code_t BackendServer::set_player_offline(kinum_t ki, const char *why) {
      status_code_t offline = ERROR_INTERNAL;
      bool was_online = false;
      uint32_t player_node = 0;
#ifdef USE_PQXX
      try {
	try {
	  my->C->perform(SetPlayerOffline(ki, was_online,
					  player_node, offline));
	}
	catch(const pqxx::in_doubt_error &e) {
	  log_warn(m_log, "in_doubt in SetPlayerOffline for %s; retrying\n",
		   why);
	  my->C->perform(SetPlayerOffline(ki, was_online,
					  player_node, offline));
	}
      }
      catch(const pqxx::in_doubt_error &e) {
	log_err(m_log, "in_doubt again in SetPlayerOffline; "
		"is something badly wrong with the DB?\n");
      }
      catch(const pqxx::broken_connection &e) {
	// pretty much fatal -- need to shut down or something
	log_err(m_log, "Connection to DB failed!\n");
      }
      catch(const pqxx::sql_error &e) {
	log_warn(m_log, "SQL error in SetPlayerOffline for %s: %s\n",
		 why, e.what());
      }
#endif
#ifndef STANDALONE
      // we need to tell subscribers the node changed, but only 
      // if it changed; the player could already have been
      // set offline by the client, e.g. using Logout should do it
      // (use was_online value)
      if (was_online && offline == NO_ERROR && player_node != 0) {
	propagate_change_to_interested(player_node, NULL, false);
      }
#endif
      return offline;
}

void BackendServer::propagate_to_interested(BackendServer::prop_type_t t,
					    uint32_t nodeid, uint32_t child,
					    uint32_t ownerid,
					    const u_char *transuuid, 
					    bool check_age) {
  bool tell_all = false;
  // this is the game server, if the node is for a running age
  ConnectionEntity *game = NULL;
  // count messages sent
  size_t list_size = 0;

  status_code_t refer = ERROR_INTERNAL;
  std::vector<kinum_t> who;
#ifdef USE_PQXX
  // check if it's a player-related node
  try {
    my->C->perform(PlayersReferringTo(nodeid, refer, who));
  }
  catch(const pqxx::in_doubt_error &e) {
    log_err(m_log, "in_doubt in PlayersReferringTo\n");
  }
  catch(const pqxx::broken_connection &e) {
    // pretty much fatal -- need to shut down or something
    log_err(m_log, "Connection to DB failed!\n");
  }
  catch(const pqxx::sql_error &e) {
    log_warn(m_log, "SQL error in PlayersReferringTo: %s\n", e.what());
  }
#endif
  if (refer == ERROR_MAX_PLAYERS) {
    // global change, we're going to tell everyone
    tell_all = true;
    check_age = false;
    refer = NO_ERROR;
  }

  status_code_t age = (check_age ? ERROR_INTERNAL : ERROR_NODE_NOT_FOUND);
  u_char age_uuid[UUID_RAW_LEN];
#ifdef USE_PQXX
  // check if it's an age-related node
  if (check_age) {
    try {
      my->C->perform(AgeReferringTo(nodeid, age_uuid, age));
    }
    catch(const pqxx::in_doubt_error &e) {
      log_err(m_log, "in_doubt in AgeReferringTo\n");
    }
    catch(const pqxx::broken_connection &e) {
      // pretty much fatal -- need to shut down or something
      log_err(m_log, "Connection to DB failed!\n");
    }
    catch(const pqxx::sql_error &e) {
      log_warn(m_log, "SQL error in AgeReferringTo: %s\n", e.what());
    }
  }
#endif

  if (refer != NO_ERROR) {
    // who.size() better be 0
  }
  list_size = who.size();
  if (age == NO_ERROR) {
    // this means the node is in an age's tree; see if there is a server
    // for that age
    game = find_by_uuid(age_uuid, TYPE_GAME);
  }

  // XXX this is really DEBUG stuff, but consider changing to MSGS
  if (m_log && m_log->would_log_at(Logger::LOG_DEBUG)) {
    char uuid_formatted[UUID_STR_LEN];
    if (age == NO_ERROR) {
      format_uuid(age_uuid, uuid_formatted);
    }
    else {
      strcpy(uuid_formatted, "none");
    }
    log_debug(m_log, "propagate_to_interested %s node=%u child=%u\n",
	      (t == CHANGED ? "CHANGED" : (t == ADDED ? "ADDED" : "REMOVED")),
	      nodeid, child);
    log_debug(m_log, "result: age %s players ", uuid_formatted);
    size_t maxlist = MIN(10, list_size);
    for (size_t i = 0; i < maxlist; i++) {
      log_raw(Logger::LOG_DEBUG, m_log, "%d ", who[i]);
    }
    if (maxlist < list_size) {
      log_raw(Logger::LOG_DEBUG, m_log, "(and more)\n");
    }
    else {
      log_raw(Logger::LOG_DEBUG, m_log, "\n");
    }
  }

  if (list_size > 0 || game || tell_all) {
    // set up the message to the client
    u_char *changed_buf;
    size_t changed_len;
    switch (t) {
    case CHANGED:
      changed_len = 22;
      changed_buf = new u_char[changed_len];
      write16(changed_buf, 0, kAuth2Cli_VaultNodeChanged);
      write32(changed_buf, 2, nodeid);
      if (transuuid) {
	memcpy(changed_buf+6, transuuid, 16);
      }
      else {
	gen_uuid(changed_buf+6, 0);
      }
      break;
    case ADDED:
      changed_len = 14;
      changed_buf = new u_char[changed_len];
      write16(changed_buf, 0, kAuth2Cli_VaultNodeAdded);
      write32(changed_buf, 2, nodeid);
      write32(changed_buf, 6, child);
      write32(changed_buf, 10, ownerid);
      break;
    case REMOVED:
      changed_len = 10;
      changed_buf = new u_char[changed_len];
      write16(changed_buf, 0, kAuth2Cli_VaultNodeRemoved);
      write32(changed_buf, 2, nodeid);
      write32(changed_buf, 6, child);
      break;
    default:
      // can't happen
      return;
    }

    VaultPassthrough_BackendMessage *reply;
    for (std::map<HashKey,ConnectionEntity*>::iterator
	   iter = m_hash_table.begin(); iter != m_hash_table.end(); iter++) {
      const HashKey &key = iter->first;
      ConnectionEntity *entity = iter->second;
      if (entity->type() == TYPE_AUTH) {
	if (tell_all) {
	  reply = new VaultPassthrough_BackendMessage(key.id1(),
						      key.id2(),
						      changed_buf, changed_len,
						      false, false);
	  entity->conn()->enqueue(reply);
	}
	else if (game && game->ipaddr() == entity->ipaddr()
		 && game->server_id() == entity->server_id()) {
	  // send to this player because they're in the affected age
	  reply = new VaultPassthrough_BackendMessage(key.id1(),
						      key.id2(),
						      changed_buf, changed_len,
						      false, false);
	  entity->conn()->enqueue(reply);
	}
	else if (list_size > 0) {
	  // see if the player is on the "who" list
	  for (size_t i = 0; i < who.size(); i++) {
	    if (who[i] == entity->kinum()) {
	      reply = new VaultPassthrough_BackendMessage(key.id1(),
							  key.id2(),
							  changed_buf,
							  changed_len,
							  false, false);
	      entity->conn()->enqueue(reply);
	      list_size--;
	      break;
	    }
	  }
	}
      }
    }
    delete[] changed_buf;
  }
}

void BackendServer::propagate_player_delete_to_interested(
				std::multimap<kinum_t,uint32_t> &notify,
				uint32_t child) {
  u_char msgbuf[10];
  write16(msgbuf, 0, kAuth2Cli_VaultNodeRemoved);
  write32(msgbuf, 6, child);

#define stlcrud std::multimap<kinum_t,uint32_t>::iterator
  stlcrud mapiter;

  // XXX this is really DEBUG stuff, but consider changing to MSGS
  if (m_log && m_log->would_log_at(Logger::LOG_DEBUG)) {
    log_debug(m_log,
	      "propagate_player_delete_to_interested sending %u notifies\n",
	      notify.size());
    log_debug(m_log, "who,parent: ");
    u_int counter = 0;
    for (mapiter = notify.begin(); mapiter != notify.end(); mapiter++) {
      if (++counter >= 10) {
	log_raw(Logger::LOG_DEBUG, m_log, "(and more)");
	break;
      }
      kinum_t who = (*mapiter).first;
      uint32_t parent = (*mapiter).second;
      log_raw(Logger::LOG_DEBUG, m_log, "%u,%u ", (u_int)who, parent);
    }
    log_raw(Logger::LOG_DEBUG, m_log, "\n");
  }

  std::pair<stlcrud,stlcrud> range;
  for (std::map<HashKey,ConnectionEntity*>::iterator
	 iter = m_hash_table.begin(); iter != m_hash_table.end(); iter++) {
    const HashKey &key = iter->first;
    ConnectionEntity *entity = iter->second;
    if (entity->type() == TYPE_AUTH) {
      range = notify.equal_range(entity->kinum());
      for (mapiter = range.first; mapiter != range.second; mapiter++) {
	uint32_t parent = (*mapiter).second;
	write32(msgbuf, 2, parent);
	VaultPassthrough_BackendMessage *reply
	  = new VaultPassthrough_BackendMessage(key.id1(), key.id2(),
						msgbuf, 10, false, false);
	entity->conn()->enqueue(reply);
      }
    }
  }
#undef stlcrud
}

BackendServer::ConnectionEntity *
BackendServer::find_by_kinum(kinum_t ki, uint32_t type) {
  std::map<HashKey,ConnectionEntity*>::iterator iter;
  for (iter = m_hash_table.begin(); iter != m_hash_table.end(); iter++) {
    ConnectionEntity *candidate = iter->second;
    if (candidate->type() == type && candidate->kinum() == ki) {
      return candidate;
    }
  }
  return NULL;
}

BackendServer::ConnectionEntity *
BackendServer::find_by_uuid(const u_char *uuid, uint32_t type) {
  std::map<HashKey,ConnectionEntity*>::iterator iter;
  for (iter = m_hash_table.begin(); iter != m_hash_table.end(); iter++) {
    ConnectionEntity *candidate = iter->second;
    if (candidate->type() == type
	&& !memcmp(candidate->uuid(), uuid, UUID_RAW_LEN)) {
      return candidate;
    }
  }
  return NULL;
}
