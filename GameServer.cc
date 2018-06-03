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
#include <iostream>
#include <fstream>

#ifdef HAVE_OPENSSL_RC4
#include <openssl/rc4.h>
#else
#include "rc4.h"
#endif

#include "machine_arch.h"
#include "exceptions.h"
#include "typecodes.h"
#include "constants.h"
#include "protocol.h"
#include "msg_typecodes.h"
#include "backend_typecodes.h"
#include "util.h"
#include "UruString.h"
#include "PlKey.h"
#include "Buffer.h"

#include "Logger.h"
#include "SDL.h"
#include "NetworkMessage.h"
#include "BackendMessage.h"
#include "GameMessage.h"
#include "MessageQueue.h"

#include "moss_serv.h"
#include "GameState.h"
#include "GameServer.h"
#include "GameHandler.h"

GameServer::GameServer(const char *server_dir, bool is_a_thread,
		       struct sockaddr_in &vault_address,
		       const u_char *uuid, const char *filename,
		       uint32_t connect_ipaddr,
		       AgeDesc *age, std::list<SDLDesc*> &sdl)
  : Server(server_dir, is_a_thread),
    m_vault_addr(vault_address), m_vault(NULL), m_timed_shutdown(false),
    m_shutdown_timer(NULL), m_joiners(0), m_client_queue(NULL),
    m_fake_signal(0), m_filename(NULL), m_age(age), m_group_owner(0)
{
  m_ipaddr = connect_ipaddr;
  if (pthread_mutex_init(&m_client_queue_mutex, NULL)) {
    throw std::bad_alloc();
  }
  m_client_queue
    = new std::deque<std::pair<GameConnection*,NetworkMessage*> >();
  set_signal_data(&m_fake_signal, 1, &m_signal_processor);
  memcpy(m_age_uuid, uuid, UUID_RAW_LEN);
  m_filename = strdup(filename);
  // copy global SDL list (NOTE the SDLDesc* objects are shared!)
  m_game_state.m_allsdl.assign(sdl.begin(), sdl.end());
  // set up timeout
  m_timers = new TimerQueue();
  m_conns.push_back(m_timers);
  struct timeval when;
  gettimeofday(&when, NULL);
  when.tv_sec += m_age->linger_time();
  m_shutdown_timer = new ShutdownTimer(when, m_timed_shutdown);
  m_timers->insert(m_shutdown_timer);
  // stick a pointer for m_timers into m_game_state
  m_game_state.m_timers = m_timers;
}

GameServer::~GameServer() {
  // do not delete m_vault (it is in m_conns and deleted in ~Server)
  // same for m_timers
  log_debug(m_log, "deleting\n");
  pthread_mutex_destroy(&m_client_queue_mutex);
  std::deque<std::pair<GameConnection*,NetworkMessage*> >::iterator iter;
  for (iter = m_client_queue->begin(); iter != m_client_queue->end(); iter++) {
    GameConnection *c = iter->first;
    delete c;
    NetworkMessage *msg = iter->second;
    delete msg;
  }
  delete m_client_queue;
  if (m_filename) {
    free(m_filename);
  }
  delete m_age;
  // the SDLState objects must be deleted before the SDLDesc objects they
  // refer to
  std::list<SDLState*>::iterator state;
  for (state = m_game_state.m_sdl.begin();
       state != m_game_state.m_sdl.end();
       state++) {
    delete *state;
  }
  std::list<SDLDesc*>::iterator sdl;
  for (sdl = m_agesdl.begin(); sdl != m_agesdl.end(); sdl++) {
    delete *sdl;
  }
}

int GameServer::init() {
  // log my identity information
  char my_uuid[UUID_STR_LEN];
  format_uuid(m_age_uuid, my_uuid);
  log_info(m_log, "I'm a %s server, UUID %s, internal ID %08x,%08x\n",
	   m_filename, my_uuid, m_ipaddr, m_id);

  // XXX it is hard to open directories and files case-insensitively in
  // unix. You have to do a directory listing and match filenames case-
  // insensitively.

  // read in SDL, if present
  std::string sdldir = std::string(m_serv_dir) + PATH_SEPARATOR + "SDL"
		       + PATH_SEPARATOR + m_filename;
  int ret = SDLDesc::parse_directory(m_log, m_agesdl, sdldir, false, false);
  if (ret > 0) {
    // try a single file
    std::string sdlfile = sdldir + ".sdl";
    std::ifstream file(sdlfile.c_str(), std::ios_base::in);
    if (file.fail()) {
      log_debug(m_log, "No SDL found for age %s\n", m_filename);
      // this is not an error, some ages don't have SDL files
    }
    else {
      try {
	SDLDesc::parse_file(m_agesdl, file);
      }
      catch (const parse_error &e) {
	log_err(m_log, "Parse error, line %u: %s\n", e.lineno(), e.what());
	ret = -1;
      }
    }
  }
  if (ret < 0) {
    // forge on, but game mechanics will be broken
    log_warn(m_log, "Error reading SDL for age %s\n", m_filename);
  }
  if (m_agesdl.size() > 0) {
    // merge into allsdl list
    std::list<SDLDesc*>::iterator iter;
    // this loop just finds the place in the list to splice at, after the
    // most common SDLs
    for (iter = m_game_state.m_allsdl.begin();
	 iter != m_game_state.m_allsdl.end();
	 iter++) {
      const char *sdlname = (*iter)->name();
      if (!strcasecmp(sdlname, "physical")
	  || !strcasecmp(sdlname, "avatar")
	  // "avatar" covers "avatarPhysical"
	  || !strcasecmp(sdlname, "Layer")
	  || !strcasecmp(sdlname, "MorphSequence")
	  || !strcasecmp(sdlname, "clothing")) {
	// go on
      }
      else {
	break;
      }
    }
    std::list<SDLDesc*>::iterator here = iter;
    for (iter = m_agesdl.begin(); iter != m_agesdl.end(); iter++) {
      m_game_state.m_allsdl.insert(here, *iter);
    }
  }

  // read in stored SDL if present
  std::string statefile = std::string(m_serv_dir) + PATH_SEPARATOR + "state"
    + PATH_SEPARATOR + m_filename + PATH_SEPARATOR + my_uuid + PATH_SEPARATOR
    + "agestate.moss";
  std::ifstream savefile(statefile.c_str(), std::ios_base::in);
  if (!savefile.fail()) {
    log_debug(m_log, "Trying to read saved age state\n");
    if (!SDLState::load_file(savefile, m_game_state.m_sdl,
			     m_game_state.m_allsdl, m_log)) {
      log_warn(m_log, "Error while reading saved age state\n");
    }
  }
  // now, if there is an AgeSDLHook SDLDesc but no SDLState, make a default one
  std::list<SDLState*>::iterator iter;
  for (iter = m_game_state.m_sdl.begin();
       iter != m_game_state.m_sdl.end();
       iter++) {
    SDLState *s = *iter;
    if (s->name_equals(m_filename)
	&& s->key().m_name && *(s->key().m_name) == "AgeSDLHook") {
      break;
    }
  }
  if (iter == m_game_state.m_sdl.end()) {
    SDLDesc *d = SDLDesc::find_by_name(m_filename, m_game_state.m_allsdl);
    if (d) {
      log_debug(m_log, "Setting up new (default) AgeSDLHook\n");
      SDLState *s = new SDLState(d);
      uint32_t pageid = ((m_age->seq_prefix() + 1) << 16) | 0x1F;
      s->invent_age_key(pageid);
      s->expand();
      m_game_state.m_sdl.push_front(s);
    }
  }
  m_game_state.setup_filter();

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

bool GameServer::shutdown(reason_t reason) {
  log_info(m_log, "Shutdown started\n");

  char my_uuid[UUID_STR_LEN];
  format_uuid(m_age_uuid, my_uuid);
  std::string statefile = std::string(m_serv_dir) + PATH_SEPARATOR + "state"
    + PATH_SEPARATOR + m_filename + PATH_SEPARATOR + my_uuid + PATH_SEPARATOR;
  recursive_mkdir(statefile.c_str(), S_IRWXU|S_IRWXG);
  statefile = statefile + "agestate.moss";
  std::ofstream savefile(statefile.c_str(),
			 std::ios_base::out|std::ios_base::trunc);
  if (savefile.fail()) {
    log_warn(m_log, "Cannot open file %s to save age state\n",
	     statefile.c_str());
  }
  else {
    log_debug(m_log, "Trying to save age state\n");
    if (!SDLState::save_file(savefile, m_game_state.m_sdl)) {
      log_warn(m_log, "Error while saving age state\n");
    }
  }

  std::list<Connection*>::iterator iter;
  for (iter = m_conns.begin(); iter != m_conns.end(); ) {
    Connection *conn = *iter;
    if (conn == m_vault) {
      // don't clear the queue, it should have no more than TRACK_ADD_PLAYER
      // rejections and maybe a TRACK_PING
      iter++;
    }
    else {
      delete conn;
      iter = m_conns.erase(iter);
    }
  }

  TrackGameBye_ToBackendMessage *bye
    = new TrackGameBye_ToBackendMessage(m_ipaddr, m_id, true);
  // tell server we are shutting down
  // if shutdown does not finish, we still want the backend to know the
  // server is gone, so we do want to send this message even though in
  // normal (correct) circumstances the backend will know momentarily anyway
  m_vault->enqueue(bye);

  return false;
}

NetworkMessage *
GameServer::GameConnection::make_if_enough(const u_char *buf, size_t len,
					   int *want_len, bool become_owner) {
  NetworkMessage *msg = NULL;
  bool became_owner = false;

  if (m_state < NEGOTIATION_DONE) {
    *want_len = -1;
    msg = NegotiationMessage::make_if_enough(buf, len, TYPE_GAME);
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
    msg = GameMessage::make_if_enough(buf, len, want_len, become_owner);
    became_owner = true;
  }

  if (msg && become_owner && !became_owner) {
    // this should never happen
#ifdef DEBUG_ENABLE
    throw std::logic_error("GameConnection ownership of buffer not taken");
#endif
    delete[] buf;
  }
  return msg;
}

void GameServer::GameConnection::set_state(state_t s) {
  if (m_state != KILL_AFTER_QUEUE_EMPTY && (m_state != s)) {
    m_state = s;
  }
}

void GameServer::GameConnection::set_key(const PlKey &key) {
  m_key.delete_name();
  m_key = key;
  // copy the name so that if the clone message SDL is replaced or something,
  // we aren't referring to freed memory
  m_key.m_name = new UruString(*(key.m_name), true);
}

Server::reason_t GameServer::message_read(Connection *conn,
					  NetworkMessage *in) {
  if (conn == m_vault) {
    // retrofit (from old style)
    return backend_message(conn, (BackendMessage *)in);
  }

  kinum_t player = ((GameConnection *)conn)->kinum();
  if (in->type() == -1) {
    // unrecognized message
    if (in->message_len() <= 0) {
      log_net(m_log, "Game message with length %d (fd %d)\n",
	      in->message_len(), conn->fd());
      delete in;
      return PROTOCOL_ERROR;
    }
    log_net(m_log, "Unrecognized game message on %d\n", conn->fd());
    if (m_log) {
      m_log->dump_contents(Logger::LOG_NET, in->buffer(), in->message_len());
    }
  }
  else if (in->type() == kCli2Game_PropagateBuffer) {
    PropagateBufferMessage *prop = (PropagateBufferMessage *)in;
    propagate_handler *handler = get_propagate_handler(prop->subtype());
    if (!handler->msg_handled(prop)) {
      log_net(m_log,
	      "Dropping unhandled game message type 0x%04x (kinum=%u)\n",
	      prop->subtype(), player);
      if (m_log) {
	m_log->dump_contents(Logger::LOG_NET,
			     prop->buffer(), prop->message_len());
      }
    }
    else if (!handler->check_useable(prop)) {
      // protocol error
      log_warn(m_log, "Game message too short! (kinum=%u)\n", player);
      if (m_log) {
	m_log->dump_contents(Logger::LOG_WARN,
			     prop->buffer(), prop->message_len());
      }
      delete in;
      return PROTOCOL_ERROR;
    }
    else {
      std::list<Connection*>::iterator c_iter;
      // normal message handling
      if (handler->handle_message(prop, &m_game_state,
				  (GameConnection*)conn, m_log)) {
#ifndef STANDALONE
	// redistribute message to everyone
	bool did_timestamp = false;
	for (c_iter = m_conns.begin(); c_iter != m_conns.end(); c_iter++) {
	  Connection *c = *c_iter;
	  if (c != conn && c != m_vault && c != m_timers) {
	    GameConnection *gc = (GameConnection *)c;
	    if (gc->state() < STATE_REQUESTED) {
	      if (prop->subtype() == plNetMsgLoadClone) {
		// don't forward message, we'll get the clone in the
		// GameStateRequest
		continue;
	      }
	      else if (prop->subtype() == plNetMsgGameMessage) {
		uint16_t msgtype = ((PlNetMsgGameMessage*)prop)->msg_type();
		if (msgtype == plAvatarInputStateMsg) {
		  // not useful before the clone is loaded so why bother?
		  log_debug(m_log, "Dropping AvatarInputState to %u before "
			    "clone\n", gc->kinum());
		  continue;
		}
	      }
	    }
	    if (!did_timestamp) {
	      prop->make_own_copy();
	      prop->set_timestamp();
	      did_timestamp = true;
	    }
	    prop->add_ref();
#ifdef DO_PRIORITIES
	    // XXX we need to get the priority from handle_message, I guess
#endif
	    c->enqueue(prop);
	  }
	}
#endif
      }
      else {
	// either message is distributed to a subset of people, or it's
	// special some other way
	switch (prop->subtype()) {
	case plNetMsgMembersListReq:
	  {
	    ((GameConnection *)conn)->set_state(MEMBERS_REQUESTED);
	    PlNetMsgMembersMsg *list = new PlNetMsgMembersMsg(prop->kinum());
#ifndef STANDALONE
	    // walk list of connections and add them to the list
	    for (c_iter = m_conns.begin();
		 c_iter != m_conns.end();
		 c_iter++) {
	      Connection *c = *c_iter;
	      if (c != conn && c != m_vault && c != m_timers) {
		GameConnection *gc = (GameConnection *)c;
		if (gc->state() >= JOINED) {
		  // note that if the state is JOINED and not HAVE_CLONE,
		  // a "null" key will be sent (I think this must be right,
		  // because during link-in a "null" key is sent in
		  // NetMsgMemberUpdate and the real key shows up later in
		  // LoadClone, and that LoadClone will be redistributed to
		  // the incoming player when it arrives)
		  // we have the separate HAVE_CLONE state just in case
		  // that's wrong
		  list->addMember(gc->kinum(), &(gc->player_name()),
				  &(gc->plKey()), true);
		}
	      }
	    }
	    list->finalize(true);
#endif
	    conn->enqueue(list);
	  }
	  break;
#ifndef STANDALONE
	case plNetMsgGameMessageDirected:
	case plNetMsgVoice:
	  // subset
	  {
	    MessageQueue::priority_t pri = MessageQueue::NORMAL;
	    if (prop->subtype() == plNetMsgVoice) {
	      pri = MessageQueue::VOICE;
	    }
	    bool someone_missing = false;
	    // note, this depends on check_usable to prevent running off
	    // the end of the buffer
	    u_int recip_offset = prop->body_offset();
	    const u_char *msg_buf = prop->buffer();
	    if (pri == MessageQueue::VOICE) {
	      recip_offset += read16(msg_buf, recip_offset+2);
	      recip_offset += 4;
	    }
	    else {
	      recip_offset += read32(msg_buf, recip_offset+5);
	      recip_offset += 10;
	    }
	    u_int start_recips = recip_offset;
	    u_int recip_ct = msg_buf[recip_offset++];
	    // now we are at the recipients

	    bool did_timestamp = false;
	    for (u_int recip = 0; recip < recip_ct; recip++) {
	      kinum_t recip_ki = read32(msg_buf, recip_offset);
	      recip_offset += 4;

	      // look for that recipient
	      for (c_iter = m_conns.begin();
		   c_iter != m_conns.end();
		   c_iter++) {
		Connection *c = *c_iter;
		if (c != conn && c != m_vault && c != m_timers) {
		  GameConnection *gc = (GameConnection *)c;
		  if (gc->kinum() == recip_ki) {
		    // send to this one
		    if (pri == MessageQueue::VOICE
			&& (gc->state() < IN_GAME)) {
		      // except let's reduce link-in bandwidth a bit here
		      break;
		    }
		    // note we only exclude voice, let chat go through so
		    // it will be seen later

		    if (!did_timestamp) {
		      prop->make_own_copy();
		      prop->set_timestamp();
		      did_timestamp = true;
		    }
		    prop->add_ref();
		    c->enqueue(prop, pri);
		    break;
		  }
		}
	      } // for
	      if (!someone_missing && c_iter == m_conns.end()) {
		// recipient not present in the current age
		someone_missing = true;
	      }
	    }

	    if (someone_missing && pri != MessageQueue::VOICE) {
	      // Technically I believe that the message should only be
	      // forwarded if the interage flag is set, yet I know the
	      // UU servers forwarded all chat traffic regardless,
	      // and I suspect MOUL did as well.
	      // Probably it would be bad to forward a book-share message,
	      // but if I'm going to parse the message enough to check for
	      // that I can just parse the message to check for the interage
	      // flag. But a misbehaving client could set the interage flag
	      // anyway. So XXX to be proper, check for interage flag and
	      // that it's a pfKIMsg before forwarding to tracking.
	      if (1/*interage*/) {
		// forward to tracking
		if (!did_timestamp) {
		  prop->make_own_copy();
		}
		TrackMsgForward_BackendMessage *fwd
		  = new TrackMsgForward_BackendMessage(m_ipaddr, m_id,
						       prop, start_recips);
		m_vault->enqueue(fwd);
	      }
	    }
	  }
	  break;
#endif /* !STANDALONE */
	}
      }

      // now, we don't want to delete the incoming message if it's on
      // other queues, so return now
      if (prop->del_ref() < 1) {
	delete in;
      }
      return NO_SHUTDOWN;
    }
  }
  else if (in->type() == kCli2Game_GameMgrMsg) {
    GameMgrMessage *mgr = (GameMgrMessage *)in; 
    if (!mgr->check_useable()) {
      // protocol error
      log_warn(m_log, "Game message too short! (kinum=%u)\n", player);
      if (m_log) {
	m_log->dump_contents(Logger::LOG_WARN,
			     mgr->buffer(), mgr->message_len());
      }
      delete in;
      return PROTOCOL_ERROR;
    }

    if (mgr->is_setup()) {
      bool need_new_id;
      GameMgr *obj = m_game_state.setup_manager_for(player,
						    mgr->setup_uuid(),
						    need_new_id,
						    m_ipaddr, m_id);
      if (!obj) {
	if (m_log && m_log->would_log_at(Logger::LOG_NET)) {
	  char uuid[UUID_STR_LEN];
	  format_uuid(mgr->setup_uuid(), uuid);
	  log_net(m_log, "Dropping GameMgr setup request (kinum=%u) for "
		  "unhandled type %s\n", uuid, player);
	  m_log->dump_contents(Logger::LOG_NET,
			       mgr->buffer(), mgr->message_len());
	}
	// just drop it
      }
      else {
	log_msgs(m_log, "GameMgr setup request for %s (kinum=%u)\n",
		 GameMgr::type_str(obj->type()), player);
	if (need_new_id) {
	  log_msgs(m_log, "Sending new GameID request to backend\n");
	  TrackNextGameID_BackendMessage *id_req
	    = new TrackNextGameID_BackendMessage(m_ipaddr, m_id, false, 1);
	  m_vault->enqueue(id_req);
	}
	if (obj->id() == 0) {
	  // waiting for a game ID to be allocated
	  mgr->add_ref();
	  obj->save_setup_msg(mgr, player);
	}
	else if (!obj->initialize_game(mgr, player, this)) {
	  // protocol error
	  log_warn(m_log, "GameMgr setup message too short! (kinum=%u)\n",
		   player);
	  if (m_log) {
	    m_log->dump_contents(Logger::LOG_WARN,
				 mgr->buffer(), mgr->message_len());
	  }
	  if (mgr->del_ref() < 1) {
	    delete in;
	  }
	  return PROTOCOL_ERROR;
	}
      }
    }
    else {
      // not a setup message
      GameMgr *obj = m_game_state.get_manager_by_id(mgr->gameid());
      if (!obj) {
	log_net(m_log,
		"Received message for nonexistent GameMgr %u (kinum=%u)\n",
		mgr->gameid(), player);
	// just drop it
      }
      else {
	try {
	  if (!obj->got_message(mgr, player, this)) {
	    log_net(m_log, "Dropping unhandled GameMgr message type %u for %s "
		    "(kinum=%u)\n",
		    mgr->msgtype(), GameMgr::type_str(obj->type()), player);
	    if (m_log) {
	      m_log->dump_contents(Logger::LOG_NET,
				   mgr->buffer(), mgr->message_len());
	    }
	  }
	}
	catch (const truncated_message &e) {
	  log_warn(m_log, "GameMgr message too short! (kinum=%u)\n", player);
	  if (m_log) {
	    m_log->dump_contents(Logger::LOG_WARN,
				 mgr->buffer(), mgr->message_len());
	  }
	  if (mgr->del_ref() < 1) {
	    delete in;
	  }
	  return PROTOCOL_ERROR;
	}
      }
    }
    // now, we don't want to delete the incoming message if it's on
    // other queues, so return now
    if (mgr->del_ref() < 1) {
      delete in;
    }
    return NO_SHUTDOWN;
  }
  else if (in->type() == kCli2Game_JoinAgeRequest) {
    log_net(m_log, "Unexpected late JoinAgeRequest on fd %d\n", conn->fd());
    // this deletes the message
    return handle_join_request(conn, in);
  }
  else if (in->type() == kCli2Game_PingRequest) {
    conn->enqueue(in);
    // we do not want to delete the message, so skip the end
    return NO_SHUTDOWN;
  }
  else {
    log_net(m_log, "Unhandled client message type %d on fd %d\n",
	    in->type(), conn->fd());
  }
  delete in;
  return NO_SHUTDOWN;
}

Server::reason_t GameServer::backend_message(Connection *vault,
					     BackendMessage *in) {
  int msg_type = in->type();

  if (msg_type == -1) {
    // unrecognized message
    log_err(m_log, "Unrecognized backend message received on "
	    "connection %d!\n", vault->fd());
    if (m_log) {
      m_log->dump_contents(Logger::LOG_ERR, in->buffer(), in->message_len());
    }
    delete in;
    return PROTOCOL_ERROR;
  }

  if (msg_type & CLASS_MARKER) {
    Marker_BackendMessage *msg = (Marker_BackendMessage *)in;
    GameMgr *mgr = m_game_state.get_manager_by_id(msg->requester());
    if (!mgr) {
      // the manager has gone now, oh well
      log_debug(m_log,
		"Received backend message for now-gone marker manager %u\n",
		msg->requester());
    }
    else if (!mgr->process_backend_message(in, this)) {
      log_warn(m_log, "Unhandled backend message type 0x%08x\n", msg_type);
    }
    if (in->del_ref() < 1) {
      delete in;
    }
    return NO_SHUTDOWN;
  }

  msg_type &= ~FROM_SERVER;
  switch (msg_type) {
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
      KillClient_BackendMessage *msg = (KillClient_BackendMessage *)in;
      if (msg->why() != KillClient_BackendMessage::AUTH_DISCONNECT) {
	log_debug(m_log, "Backend sent ADMIN_KILL_CLIENT with reason %d\n",
		  (int)msg->why());
	break;
      }
      kinum_t kill_this_un = msg->kinum();
      std::list<Connection*>::iterator c_iter;
      for (c_iter = m_conns.begin(); c_iter != m_conns.end(); c_iter++) {
	Connection *c = *c_iter;
	if (c != m_vault && c != m_timers) {
	  GameConnection *gc = (GameConnection *)c;
	  if (gc->kinum() == kill_this_un) {
	    log_debug(m_log, "Force-dropping player kinum=%u on %d at "
		      "direction of tracking\n", kill_this_un, c->fd());
	    gc->set_in_shutdown(true);
	    gc->set_state(KILL_AFTER_QUEUE_EMPTY);
	    break;
	  }
	}
      }
      if (c_iter == m_conns.end()
	  && m_log && m_log->would_log_at(Logger::LOG_DEBUG)) {
	log_debug(m_log, "Tracking told us to drop player kinum=%u but no "
		  "such player is connected\n", kill_this_un);
      }
    }
    break;
  case TRACK_SDL_UPDATE:
    {
      TrackSDLUpdate_BackendMessage *msg
	= (TrackSDLUpdate_BackendMessage *)in;
      TrackSDLUpdate_BackendMessage::sdl_type_t utype = msg->update_type();
      const char *ustring = "???";
      switch (utype) {
      case TrackSDLUpdate_BackendMessage::INVALID:
	ustring = "INVALID";
	break;
      case TrackSDLUpdate_BackendMessage::GLOBAL_INIT:
	ustring = "global init";
	break;
      case TrackSDLUpdate_BackendMessage::GLOBAL_UPDATE:
	ustring = "global";
	break;
      case TrackSDLUpdate_BackendMessage::VAULT_SDL_UPDATE:
	ustring = "age update";
	break;
      case TrackSDLUpdate_BackendMessage::VAULT_SDL_LOAD:
	ustring = "age load";
	break;
      default:
	break;
      }
      if (utype == TrackSDLUpdate_BackendMessage::INVALID) {
	log_warn(m_log, "Dropping INVALID vault SDL update!\n");
	if (m_log && m_log->would_log_at(Logger::LOG_WARN)) {
	  m_log->dump_contents(Logger::LOG_WARN, msg->sdl_buf(),
			       msg->sdl_len());
	}
	break;
      }

      // see if the message is actually meant for this age
      UruString agename(msg->sdl_buf()+2, msg->sdl_len()-2,
			true, false, false);
      if (strcasecmp(agename.c_str(), m_filename)) {
	// the backend should not forward SDL updates except to the correct
	// game server, but the shortcut of forwarding them to the player's
	// current game server is still okay for STANDALONE
#ifdef STANDALONE
	if (utype != TrackSDLUpdate_BackendMessage::VAULT_SDL_UPDATE) {
#endif
	  log_warn(m_log, "Got %s vault SDL update for other age %s\n",
		   ustring, agename.c_str());
#ifdef STANDALONE
	}
	else {
	  // for VAULT_SDL_UPDATE it could be e.g. turning on a Relto
	  // page while in another age, or a clothing/morph change,
	  // so just ignore it
	}
#endif
	break;
      }

      // this message only makes sense for AgeSDLHook SDL
      SDLState *current = NULL;
      std::list<SDLState*>::iterator iter;
      for (iter = m_game_state.m_sdl.begin();
	   iter != m_game_state.m_sdl.end();
	   iter++) {
	SDLState *s = *iter;
	if (s->name_equals(m_filename)
	    && s->key().m_name && *(s->key().m_name) == "AgeSDLHook") {
	  current = s;
	  break;
	}
      }
      if (!current) {
	// there is no AgeSDLHook for this age, why are we
	// getting this message?
	log_err(m_log, "Got a %s vault SDL update for this age %s but "
		"there is no AgeSDLHook!\n", ustring, m_filename);
	break;
      }
      if (msg->sdl_len() <= 2) {
	log_net(m_log, "Empty %s vault SDL update message from backend\n",
		ustring);
	break;
      }

      // now parse the message
      SDLState *new_sdl = new SDLState();
      bool error = false;
      try {
	if (new_sdl->read_in(msg->sdl_buf()+2, msg->sdl_len()-2,
			     m_game_state.m_allsdl) < 0) {
	  // unrecognized, but we should never get here (bad version?)
	  log_warn(m_log, "Unrecognized %s vault SDL received\n", ustring);
	  error = true;
	}
      }
      catch (const truncated_message &e) {
	log_warn(m_log, "Truncated %s vault SDL received\n", ustring);
	error = true;
      }
      if (error) {
	if (m_log && m_log->would_log_at(Logger::LOG_WARN)) {
	  m_log->dump_contents(Logger::LOG_WARN, msg->sdl_buf(),
			       msg->sdl_len());
	}
      }
      else if (utype == TrackSDLUpdate_BackendMessage::VAULT_SDL_LOAD) {
	// when loading an age, the vault SDL *must* be first (it has no
	// timestamps), then the saved age SDL and global SDL
	// so, since we have already loaded the saved age SDL, swap the order
	// of doing things and then swap pointers to clean up
	log_msgs(m_log, "Incorporating vault SDL\n");
	new_sdl->expand();
	new_sdl->update_from(current, false/*swipe structure*/,
			     true/*use timestamps*/, true/*age load*/);
	std::list<SDLState*>::iterator iter;
	for (iter = m_game_state.m_sdl.begin();
	     iter != m_game_state.m_sdl.end();
	     iter++) {
	  if (*iter == current) {
	    // put the new_sdl object in the list instead
	    m_game_state.m_sdl.insert(iter, new_sdl);
	    m_game_state.m_sdl.erase(iter);
	    new_sdl = current; // so the right object is deleted
	    break;
	  }
	}
      }
      else {
	// when any vault SDL is updated (global or player), only records
	// that are both newer and different ought to be forwarded to clients;
	// to do that update_from has to modify new_sdl and we have to build
	// a new SDL message from it
	log_msgs(m_log, "Handling updated vault SDL\n");
	current->update_from(new_sdl, true,
		(utype != TrackSDLUpdate_BackendMessage::VAULT_SDL_UPDATE));

	// and forward to any players
	if (m_conns.size() > 2) {
	  PlNetMsgSDLState *new_msg = new PlNetMsgSDLState(new_sdl, false);
	  std::list<Connection*>::iterator c_iter;
	  for (c_iter = m_conns.begin(); c_iter != m_conns.end(); c_iter++) {
	    Connection *c = *c_iter;
	    if (c != m_vault && c != m_timers) {
	      new_msg->add_ref();
	      c->enqueue(new_msg);
	    }
	  }
	  if (new_msg->del_ref() < 1) {
	    delete new_msg;
	  }
	}
      }
      delete new_sdl;
    }
    break;
  case TRACK_ADD_PLAYER:
    {
      TrackAddPlayer_FromBackendMessage *msg
	= (TrackAddPlayer_FromBackendMessage *)in;
      log_msgs(m_log, "TRACK_ADD_PLAYER kinum=%u\n", msg->kinum());
      status_code_t result = NO_ERROR;
      if (m_timed_shutdown) {
	// XXX upon receiving this, the backend waits until the game server
	// closes the TCP connection anyway, after which it restarts the
	// server and re-adds the player, so maybe it is not needed to
	// handle this case at all -- in which case we don't even need the
	// shutdown handshake, we can just shut down, we don't even need
	// the TRACK_GAME_BYE message.....
	result = ERROR_REMOTE_SHUTDOWN;
      }
#ifndef STANDALONE
      if (result == NO_ERROR) {
	// register UUID/KI number to validate future client connections
	struct timeval then;
	gettimeofday(&then, NULL);
	then.tv_sec += 4*KEEPALIVE_INTERVAL; // wait for 2 whole minutes
	JoinTimer *newplayer = new JoinTimer(then, m_joiners, msg->kinum(),
					     msg->acct_uuid(),
					     msg->player_name());
	m_timers->insert(newplayer);
      }
#endif
      TrackAddPlayer_ToBackendMessage *reply
	= new TrackAddPlayer_ToBackendMessage(m_ipaddr, m_id,
					      msg->kinum(), result);
      vault->enqueue(reply);

      if (result == NO_ERROR) {
	// a connection we've accepted is incoming (in theory); don't shut down
	cancel_shutdown_timer();

#ifdef STANDALONE
	// In standalone mode we don't need to validate client connections
	// or track their names, so we don't bother, but this means we won't
	// time out future connections either. So we restart the shutdown
	// timer in case there are no client connections at all, otherwise an
	// uncompleted "future" connection prevents the server from ever
	// shutting down.
	maybe_start_shutdown_timer();
#endif
      }
    }
    break;
  case TRACK_GAME_BYE:
    log_msgs(m_log, "TRACK_GAME_BYE received\n");
    // do a clean shutdown now
    delete in;
    return SERVER_SHUTDOWN;
  case TRACK_INTERAGE_FWD:
    {
      TrackMsgForward_BackendMessage *msg
	= (TrackMsgForward_BackendMessage *)in;

      log_msgs(m_log, "TRACK_INTERAGE_FWD received\n");
      u_int recip_offset = msg->recips_offset();
      const u_char *msg_body = msg->fwd_msg();
      u_int msg_len = msg->fwd_msg_len();
      // the message should be correctness-checked by the game server though
      if (recip_offset < msg_len) {
	u_int recip_ct = msg_body[recip_offset++];
	PlNetMsgGameMessageDirected *fwd
	  = new PlNetMsgGameMessageDirected(msg);
	while (recip_ct > 0 && recip_offset+4 <= msg_len) {
	  kinum_t recip_ki = read32(msg_body, recip_offset);
	  recip_offset += 4;
	  recip_ct--;

	  // look for that recipient
	  std::list<Connection*>::iterator c_iter;
	  for (c_iter = m_conns.begin(); c_iter != m_conns.end(); c_iter++) {
	    Connection *c = *c_iter;
	    if (c != m_vault && c != m_timers) {
	      GameConnection *gc = (GameConnection *)c;
	      if (gc->kinum() == recip_ki) {
		// send to this one
		fwd->add_ref();
		c->enqueue(fwd);
		break;
	      }
	    }
	  } // for
	} // while
      }
      if (in->del_ref() >= 1) {
	// don't delete it, so return now
	return NO_SHUTDOWN;
      }
    }
    break;
  case TRACK_NEXT_GAMEID:
    {
      TrackNextGameID_BackendMessage *msg
	= (TrackNextGameID_BackendMessage *)in;
      // note, only one ID at a time is currently requested, so the game
      // server doesn't bother to save any extras that arrive (including
      // for now-departed GameMgrs)
      GameMgr *mgr = m_game_state.m_waiting_games.front();
      if (!mgr) {
	// the manager has gone now, oh well
	log_msgs(m_log, "Received new game ID for now-gone GameMgr\n");
      }
      else {
	log_msgs(m_log, "Received new game ID %u\n", msg->start_at());
	m_game_state.m_waiting_games.pop_front();
	mgr->assign_id(msg->start_at(), this);
      }
    }
    break;
  default:
    log_warn(m_log, "Unrecognized backend message type 0x%08x\n", in->type());
  }

  delete in;
  return NO_SHUTDOWN;
}

void GameServer::conn_completed(Connection *conn) {
  conn->set_in_connect(false);
  if (conn == m_vault) {
    conn->m_interval = BACKEND_KEEPALIVE_INTERVAL;
    gettimeofday(&conn->m_timeout, NULL);
    conn->m_timeout.tv_sec += conn->m_interval;

    Hello_BackendMessage *hello = new Hello_BackendMessage(m_ipaddr, m_id,
							   type());
    conn->enqueue(hello);
    TrackGameHello_BackendMessage *gamehello
      = new TrackGameHello_BackendMessage(m_ipaddr, m_id, m_age_uuid, m_id,
					  htole32(ntohl(m_ipaddr)));
    conn->enqueue(gamehello);
  }
  else {
    log_warn(m_log, "Unknown outgoing connection (fd %d) completed!\n",
	     conn->fd());
    conn->set_in_shutdown(true);
  }
}

Server::reason_t GameServer::conn_timeout(Connection *conn,
					  Server::reason_t why) {
  if (conn == m_vault) {
    TrackPing_BackendMessage *msg
      = new TrackPing_BackendMessage(m_ipaddr, m_id);
    m_vault->enqueue(msg);
    m_vault->m_timeout.tv_sec += m_vault->m_interval;
  }
  else if (conn == m_timers) {
    struct timeval now;
    gettimeofday(&now, NULL);
    m_timers->handle_timeout(now);
    if (m_timed_shutdown) {
      log_info(m_log, "Since I'm alone, and sad, I'm going to kill myself\n");
      // try to do a shutdown, but new arrivals could be on the way, so 
      // get confirmation first
      TrackGameBye_ToBackendMessage *bye
	= new TrackGameBye_ToBackendMessage(m_ipaddr, m_id, false);
      m_vault->enqueue(bye);
    }
#ifndef STANDALONE
    else {
      // see if we need to start the shutdown timer
      maybe_start_shutdown_timer();
    }
#endif
  }
  else {
    // client connection
    struct timeval now;
    gettimeofday(&now, NULL);
    now.tv_sec -= (3*KEEPALIVE_INTERVAL);
    if (timeval_lessthan(conn->m_lastread, now)) {
      // client timed out
      log_debug(m_log, "Client on %d timed out\n", conn->fd());
      why = conn_shutdown(conn, why);
      // if the last client just left us, conn_shutdown sets up
      // the shutdown timer
    }
    else {
      // not timed out, a message was received less than 3*KEEPALIVE_INTERVAL
      // ago; set timeout one KEEPALIVE_INTERVAL ahead and go on
      now.tv_sec += (4*KEEPALIVE_INTERVAL);
      conn->m_timeout = now;
    }
  }
  return NO_SHUTDOWN;
}

Server::reason_t GameServer::conn_shutdown(Connection *conn,
					   Server::reason_t why) {
  if (conn == m_vault) {
    // XXX this is only recoverable in very particular circumstances,
    // and I will do them later if I ever get to it

    if (why == CLIENT_CLOSE) {
      why = BACKEND_ERROR;
    }

    if (why != SERVER_SHUTDOWN) {
      // we have to clear the queue of any messages because otherwise they
      // will keep the server running
      m_vault->m_write_fill = 0;
      m_vault->msg_queue()->reset_head();
      m_vault->msg_queue()->clear_queue();
    }
    // if why == SERVER_SHUTDOWN, we want to do a nice shutdown and so
    // the messages are left on the queue to drain

    return why;
  }
  else {
    // client shutdown
    GameConnection *gconn = (GameConnection *)conn;
    kinum_t kinum = gconn->kinum();
    std::list<Connection*>::iterator c_iter;

    // if there's no KI number set, they did not get through join, and
    // we should not do most of the following
    if (!kinum) {
      for (c_iter = m_conns.begin(); c_iter != m_conns.end(); c_iter++) {
	if (conn == *c_iter) {
	  m_conns.erase(c_iter);
	  break;
	}
      }
      delete conn;

      // if the last client just left us, set up the shutdown timer
      maybe_start_shutdown_timer();

      return NO_SHUTDOWN;
    }

    // change GroupOwner
    if (kinum == m_group_owner) {
      for (c_iter = m_conns.begin(); c_iter != m_conns.end(); c_iter++) {
	Connection *c = *c_iter;
	if (c != conn && c != m_vault && c != m_timers) {
	  GameConnection *gc = (GameConnection *)c;
	  if (gc->state() >= JOINED) {
	    // we found one
	    PlNetMsgGroupOwner *owner = new PlNetMsgGroupOwner(true);
	    c->enqueue(owner);
	    m_group_owner = ((GameConnection *)c)->kinum();
	    break;
	  }
	}
      }
      if (c_iter == m_conns.end()) {
	// no other player found
	m_group_owner = 0;
      }
    }
    // change Game owners, maybe
    std::list<GameMgr*>::iterator g_iter;
    for (g_iter = m_game_state.m_age_games.begin();
	 g_iter != m_game_state.m_age_games.end();
	 g_iter++) {
      GameMgr *mgr = *g_iter;

      // the client seems not to know what to do with PlayerLeft (so what's
      // it meant for? or is it game type dependent? BlueSpiral and Heek are
      // known to be problematic, and we have no multiplayer Marker games)
      GameMgr_FourByte_Message *msg;
      msg = new GameMgr_FourByte_Message(mgr->id(), kGameCliPlayerLeftMsg,
					 kinum);
      mgr->send_to_all(msg, this);
      if (msg->del_ref() < 1) {
	delete msg;
      }

      // XXX this should be before send_to_all so it doesn't send to the
      // departing player, so why did I do it in this order?
      mgr->player_left(kinum, this);
    }
    m_game_state.player_left(kinum);

    // clean up clone, SDL
    std::vector<PlNetMsgLoadClone*> unload_msgs;
#ifndef STANDALONE
    PlNetMsgLoadClone *unload_msg = NULL;
#endif

    std::list<SDLState*>::iterator iter;
    for (iter = m_game_state.m_sdl.begin();
	 iter != m_game_state.m_sdl.end();
	 ) {
      SDLState *s = *iter;
      PlKey &key = s->key();
      if ((key.m_flags & 0x01) && (key.m_clientid == (uint32_t)kinum)) {
	// this discards everything with the player's Client ID
#ifndef STANDALONE
	// this includes quabs (and intentional object clones), so be more
	// discriminating
	if (s->name_equals("physical")) {
	  // this special case is for object clones, which have
	  // physical SDL (not avatarPhysical)
	  log_debug(m_log, "SDL cleanup: Keeping SDL %s(%u:%u) because it's "
		    "physical SDL\n",
		    key.m_name->c_str(), key.m_clientid, key.m_index);
	  iter++;
	  continue;
	}
	if (s->name_equals("CloneMessage")) {
	  const u_char *sdl_buf = s->vars()[0]->m_value[0].v_creatable;
	  if (!sdl_buf) {
	    log_err(m_log, "CloneMessage SDL is missing its data!\n");
	    // well, throw that one away, it's useless
	  }
	  else {
	    u_int clone_len = read32(sdl_buf, 0);
	    if (clone_len < 16) {
	      log_err(m_log, "CloneMessage submessage is truncated!\n");
	    }
	    else {
	      u_char is_player = sdl_buf[4];
	      uint16_t submsg_type = read16(sdl_buf, 14);

	      // I don't like these special casing the fireflies but I don't
	      // know what else to do
	      if ((submsg_type == plLoadAvatarMsg && is_player)
		  || (*(key.m_name) == "BugFlockingEmitTest")) {
		// player avatar and bugs
		// prepare to send unload to other clients
		log_debug(m_log, "SDL cleanup: Unloading %s (%u)\n",
			  key.m_name->c_str(), key.m_clientid);
		unload_msg = new PlNetMsgLoadClone(sdl_buf+5, clone_len,
						   key, kinum, false,
						   is_player);
		unload_msgs.push_back(unload_msg);
	      }
	      else if (submsg_type == plLoadAvatarMsg) {
		// quabs and NPC avatars
		// keep around, but only if there are other players
		// in the age (necessary for quabs)
		if (m_group_owner) {
		  log_debug(m_log, "SDL cleanup: Keeping avatar %s(%u:%u)\n",
			    key.m_name->c_str(), key.m_clientid,
			    key.m_index);
		  iter++;
		  continue;
		}
	      }
	      else {
		// keep object clones around
		log_debug(m_log, "SDL cleanup: Keeping object clone "
			  "%s(%u:%u)\n", key.m_name->c_str(), key.m_clientid,
			  key.m_index);
		iter++;
		continue;
	      }
	    }
	  }
	}
	// Now we have to handle Quab physicals specially; if we remove the
	// physical when the spawner links out, any new arrivals will not see
	// the quabs until someone else moves them and they will blip to the
	// actual location. I wonder if MOUL got this right because I
	// literally see no possible way to do this except by special-casing
	// it, because avatarPhysical messages have nothing to distinguish
	// player avatars and NPC avatars.
	else if (*(key.m_name) == "Quab") {
	  if (m_group_owner) {
	    log_debug(m_log, "SDL cleanup: Keeping Quab physical\n");
	    iter++;
	    continue;
	  }
	}
	log_debug(m_log, "SDL cleanup: dropping %s SDL %s(%u:%u)\n",
		  s->get_desc()->name(), key.m_name->c_str(),
		  key.m_clientid, key.m_index);
#endif
	iter = m_game_state.m_sdl.erase(iter);
	delete s;
      }
      else {
	iter++;
      }
    }

    // remove the player from the members (Age Players) list
#ifndef STANDALONE
    PlNetMsgMembersMsg *member_msg = new PlNetMsgMembersMsg(kinum);
    member_msg->addMember(kinum);
    member_msg->finalize(false);
#endif

    for (c_iter = m_conns.begin(); c_iter != m_conns.end(); ) {
      Connection *c = *c_iter;
      if (conn == c) {
	c_iter = m_conns.erase(c_iter);
#ifdef STANDALONE
	break;
#endif
      }
      else {
#ifndef STANDALONE
	if (c != m_vault && c != m_timers) {
	  // tell other clients this one is leaving
	  GameConnection *gc = (GameConnection *)c;
	  if (gc->state() >= STATE_REQUESTED && unload_msg) {
	    for (u_int i = 0; i < unload_msgs.size(); i++) {
	      unload_msg = unload_msgs[i];
	      unload_msg->add_ref();
	      c->enqueue(unload_msg);
	    }
	  }
	  if (gc->state() >= MEMBERS_REQUESTED) {
	    member_msg->add_ref();
	    c->enqueue(member_msg);
	  }
	}
#endif
	c_iter++;
      }
    }

#ifndef STANDALONE
    if (unload_msg) {
      for (u_int i = 0; i < unload_msgs.size(); i++) {
	unload_msg = unload_msgs[i];
	if (unload_msg->del_ref() < 1) {
	  delete unload_msg;
	}
      }
    }
    if (member_msg->del_ref() < 1) {
      delete member_msg;
    }
#endif

    // tell the backend this player is gone
    log_msgs(m_log, "Telling tracking player kinum=%u is gone\n", kinum);
    TrackGamePlayerInfo_BackendMessage *track
      = new TrackGamePlayerInfo_BackendMessage(m_ipaddr, m_id, kinum, false);
    m_vault->enqueue(track);

    delete conn;

    // if the last client just left us, set up the shutdown timer
    maybe_start_shutdown_timer();

    return NO_SHUTDOWN;
  }
}

Server::reason_t GameServer::handle_negotiation(GameConnection *c,
						const void *keydata,
						NetworkMessage *in,
						Logger *log,
						uint32_t &sid) {
  if (c->state() < NEGOTIATION_DONE) {
    if (in->type() == -1) {
      // unrecognized message
      log_net(log, "Unrecognized message during negotiation on %d\n",
	      c->fd());
      if (log) {
	log->dump_contents(Logger::LOG_NET, in->buffer(), in->message_len());
      }
      return PROTOCOL_ERROR;
    }
    if (in->check_useable()) {
      // I think we could do without one of these for every game connection in
      // the dispatcher log.
      if (log && log->would_log_at(Logger::LOG_MSGS)) {
	NegotiationMessage *msg = (NegotiationMessage *)in;
	char uuid[UUID_STR_LEN];
	format_uuid(msg->uuid(), uuid);
	log_msgs(log, "Client version: %u Release: %u UUID: %s\n",
		 msg->client_version(), msg->release_number(), uuid);
      }
    }
    else {
      // well, I don't *need* that info...
      log_warn(log, "Negotiation message on %d too short!\n", c->fd());
      if (log) {
	log->dump_contents(Logger::LOG_WARN, in->buffer(), in->message_len());
      }
    }
    c->set_state(NEGOTIATION_DONE);
  }
  else if (c->state() < NONCE_DONE) {
    if (in->type() == -1) {
      // unrecognized message
      log_net(log, "Unrecognized message during negotiation on %d\n", c->fd());
      if (log) {
	log->dump_contents(Logger::LOG_NET, in->buffer(), in->message_len());
      }
      return PROTOCOL_ERROR;
    }
    if (in->check_useable()) {
      // decrypt & set up key

      log_msgs(log, "Setting up session key (fd %d)\n", c->fd());
#if defined(USING_RSA) || defined(USING_DH)
      reason_t key_okay = c->setup_rc4_key(in->buffer()+1, in->message_len()-2,
					   keydata, c->fd(), log);
      if (key_okay != NO_SHUTDOWN) {
	// problem is already logged
	return key_okay;
      }
#endif
      c->set_state(NONCE_DONE);
    }
    else {
      log_warn(log, "Nonce message on %d too short!\n", c->fd());
      if (log) {
	log->dump_contents(Logger::LOG_WARN, in->buffer(), in->message_len());
      }
      return PROTOCOL_ERROR;
    }
  }

  /* from here is normal processing (after start-up) */

  else if (c->state() != NONCE_DONE) {
    // this is very bad -- we have two threads using the connection
    log_err(log,
	    "Game connection on %d must be passed to game server by now!\n",
	    c->fd());
    return FORGET_THIS_CONNECTION; // maybe this can spare us a server crash
  }
  else if (in->type() == kCli2Game_JoinAgeRequest) {
    if (!in->check_useable()) {
      // protocol error
      log_warn(log, "Game message on %d too short!\n", c->fd());
      if (log) {
	log->dump_contents(Logger::LOG_WARN, in->buffer(), in->message_len());
      }
      return PROTOCOL_ERROR;
    }
    // finally, here we know which game server to connect to
    GameJoinRequest *join = (GameJoinRequest *)in;
    c->set_state(JOIN_REQ);
    sid = join->server_id();
    log_msgs(log, "JoinAgeRequest for kinum %u on %d for server %08x\n",
	     join->kinum(), c->fd(), sid);
  }
  else {
    if (in->type() == -1) {
      log_net(log, "Unrecognized game message on %d\n", c->fd());
    }
    else {
      // something sent before connecting to correct game server
      if (in->type() == kCli2Game_PingRequest) {
	// PlasmaClient does this silly thing. We have to reply to the ping
	// before it will send the JoinAge. I think this is goofy. I like
	// abstraction and this breaks the obvious abstraction.
	log_msgs(log, "Ping received on %d before joining age\n", c->fd());
	// I don't want to requeue the message because otherwise I'll have to
	// do gymnastics to keep the caller from deleting the message while it
	// is on the queue. So just copy it.
	GamePingMessage *reply = new GamePingMessage(in->buffer(),
						     in->message_len());
	c->enqueue(reply);
	return NO_SHUTDOWN;
      }
      else {
	log_net(log, "Message type %d received on %d before joining age\n",
		in->type(), c->fd());
	if (in->message_len() <= 0) {
	  log_net(log, "Game message on %d with length %d\n",
		  c->fd(), in->message_len());
	}
	else {
	  if (log) {
	    log->dump_contents(Logger::LOG_NET, in->buffer(),
			       in->message_len());
	  }
	}
      }
    }
    return PROTOCOL_ERROR;
  }

  return NO_SHUTDOWN;
}

// convenience routine so dispatcher does not have to know about any message
// types
void GameServer::send_no_join(Connection *conn, const NetworkMessage *msg) {
  GameJoinRequest *join = (GameJoinRequest *)msg;
  GameJoinReply *nope = new GameJoinReply(join->reqid(), ERROR_AGE_NOT_FOUND);
  conn->enqueue(nope);
}

#ifndef FORK_GAME_TOO
void GameServer::queue_client_connection(GameConnection *conn,
					 NetworkMessage *msg) {
  pthread_mutex_lock(&m_client_queue_mutex);
  m_client_queue->push_back(
	std::pair<GameConnection*,NetworkMessage*>(conn, msg));
  m_fake_signal = 1;
  pthread_mutex_unlock(&m_client_queue_mutex);
}

void GameServer::get_queued_connections() {
  // swap queues so as to not hold the mutex, blocking the dispatcher
  std::deque<std::pair<GameConnection*,NetworkMessage*> >
    *new_queue, *newconns;
  new_queue = new std::deque<std::pair<GameConnection*,NetworkMessage*> >();

  // XXX consider std::list and splice() instead of std::deque and new
  pthread_mutex_lock(&m_client_queue_mutex);
  newconns = m_client_queue;
  m_client_queue = new_queue;
  m_fake_signal = 0;
  pthread_mutex_unlock(&m_client_queue_mutex);

  std::deque<std::pair<GameConnection*,NetworkMessage*> >::iterator iter;
  for (iter = newconns->begin(); iter != newconns->end(); iter++) {
    GameConnection *conn = iter->first;
    // it should not be possible to have the same connection passed over
    // more than once but be certain not to put it in m_conns more than once
    std::list<Connection*>::iterator c_iter;
    for (c_iter = m_conns.begin(); c_iter != m_conns.end(); c_iter++) {
      if (*c_iter == (Connection*)conn) {
	break;
      }
    }
    if (c_iter == m_conns.end()) {
      // normal code path
      m_conns.push_back(conn);
    }

    Server::reason_t result;
    NetworkMessage *msg = iter->second;
    if (msg->type() == kCli2Game_JoinAgeRequest) {
      // this is the normal, expected code path
      result = handle_join_request(conn, msg);

      if (result == NO_SHUTDOWN) {
	// If the client sent some other message after the JoinAgeRequest
	// then it could be read already. It will sit in the buffer unused
	// until the client sends something else, unless we handle it here.
	// If we don't handle it and this message is something the client is
	// waiting for, we'll have a deadlock (until the client is timed out).
	if (conn->m_read_off < conn->m_read_fill) {
	  // the following is based on code in the select loop, but the
	  // JoinAgeRequest is so short, conn->m_bigbuf must be NULL
	  if (conn->m_bigbuf) {
	    // this really, really shouldn't happen; who knows what's going
	    // on, so toss this back to the select loop to deal with properly
	  }
	  else {
	    log_debug(m_log, "Handling data sent by the client on fd %d "
		      "before receiving the JoinAgeReply\n", conn->fd());
	    Buffer *cbuf = conn->m_readbuf;
	    int to_read;
	    do {
	      try {
		msg = conn->make_if_enough(cbuf->buffer()+conn->m_read_off,
					   conn->m_read_fill-conn->m_read_off,
					   &to_read, false);
	      }
	      catch (const overlong_message &e) {
		log_net(m_log, "Message on %d too long: claimed %d bytes\n",
			conn->fd(), e.claimed_len());
		m_log->dump_contents(Logger::LOG_DEBUG,
				     cbuf->buffer()+conn->m_read_off,
				     conn->m_read_fill-conn->m_read_off);
		msg = NULL;
		result = PROTOCOL_ERROR;
	      }
	      if (msg) {
		conn->m_read_off += msg->message_len();
		result = message_read(conn, msg);
	      }
	    } while (msg && (conn->m_read_fill > conn->m_read_off)
		     && result == NO_SHUTDOWN);
	  }
	}
	else {
	  // normal code path (client sent only a join)
	  conn->m_read_off = conn->m_read_fill = 0; // not strictly necessary
	}
      }
    }
    else {
      // it is not possible for the message to be anything but JoinAgeRequest
      // (any other message does not contain the server ID and should be
      // handled/rejected by the dispatcher)
      log_err(m_log, "A message other than JoinAgeRequest on %d was "
	      "dispatched during age join (type %d)\n",
	      conn->fd(), msg->type());
      delete msg;
      result = INTERNAL_ERROR;
    }
    if (result != NO_SHUTDOWN) {
      // set up to drop the connection
      conn->set_in_shutdown(true);
      conn->set_state(KILL_AFTER_QUEUE_EMPTY);
    }
  }
  delete newconns;
}
#endif /* !FORK_GAME_TOO */

Server::reason_t GameServer::handle_join_request(Connection *conn,
						 NetworkMessage *in) {
    GameConnection *gconn = (GameConnection*)conn;
    GameJoinRequest *join = (GameJoinRequest*)in;
    status_code_t result = NO_ERROR;
    bool already_joined = true;
    UruString player_name("I am so lonely");
#ifndef STANDALONE
    // we need to check if this client is allowed to connect
    std::deque<TimerQueue::Timer*>::const_iterator t_iter;
    for (t_iter = m_timers->begin(); t_iter != m_timers->end(); t_iter++) {
      GameTimer *timer = (GameTimer *)*t_iter;
      if (timer->type() == GameTimer::CLIENT_JOIN) {
	JoinTimer *jt = (JoinTimer *)timer;
	if (jt->m_kinum == join->kinum()
	    && !memcmp(jt->m_acct_uuid, join->uuid(), UUID_RAW_LEN)) {
	  // it's a match
	  if (!jt->cancelled()) {
	    already_joined = false;
	    jt->cancel();
	    if (m_joiners > 0) {
	      m_joiners--;
	    }
	  }
	  // copy name
	  player_name = jt->m_name;
	  break;
	}
      }
    }
    if (t_iter == m_timers->end()) {
      // client not registered
      result = ERROR_AUTH_TOO_OLD;
      if (join->kinum() == gconn->kinum() && gconn->state() >= JOINED) {
	// Apparently, the client joined a while ago and the join timer has
	// expired. This is bad behavior but they can join as themselves
	// again if they like... if the KI number does not match, no go.
	result = NO_ERROR;
	already_joined = true;
      }
    }
#endif

    // send the JoinAgeReply
    log_info(m_log,
	     "Sending JoinAgeReply (result %u) for kinum %u on fd %d\n",
	     result, join->kinum(), conn->fd());
    GameJoinReply *reply = new GameJoinReply(join->reqid(), result);
    conn->enqueue(reply);

    // see if we're in the bad state where we failed to notice the player
    // left from a previous visit already
    if (result == NO_ERROR) {
      std::list<Connection*>::iterator c_iter;
      for (c_iter = m_conns.begin(); c_iter != m_conns.end(); c_iter++) {
	Connection *c = *c_iter;
	if (c != conn && c != m_vault && c != m_timers) {
	  GameConnection *gc = (GameConnection *)c;
	  if (gc->kinum() == join->kinum())  {
	    // bleah.
	    log_warn(m_log,
		     "Player kinum %u is arriving, but already present\n",
		     join->kinum());
	    conn_shutdown(c, PEER_SHUTDOWN);
	    // c_iter invalidated by conn_shutdown (besides, this very code
	    // should ensure we don't have > 1 "old" player)
	    break;
	  }
	}
      }
    }

    if (result != NO_ERROR) {
      // set up to drop the connection -- once we send an error result
      // the client sits at the black screen, so might as well boot it
      delete in;
      return PROTOCOL_ERROR;
    }
    if (already_joined) {
      // we already did all the following stuff, so skip it
    }
    else {
      gconn->set_state(JOINED);
      gconn->set_logger(m_log);
      gconn->set_kinum(join->kinum());
      gconn->set_uuid(join->uuid());
      gconn->player_name() = player_name;

      PlNetMsgGroupOwner *owner = new PlNetMsgGroupOwner(m_group_owner == 0);
      conn->enqueue(owner);
      if (m_group_owner == 0) {
	m_group_owner = join->kinum();
      }

      // Set timeout: timeouts are handled a little differently in the game
      // server because the client does not send PingRequests, so every
      // arriving message has to be counted. Instead of resetting the timeout
      // every message that arrives, we periodically wake up and if nothing
      // has arrived in a long enough interval (based on conn->m_lastread), we
      // time out the client. This makes the maximum time the client is gone
      // but not yet timed out up to one conn->m_interval more than if we did
      // set the timeout. But, since the client should send info at least
      // every 10 seconds instead of every KEEPALIVE_INTERVAL of 30 seconds,
      // it is quite reasonable to make the overall time shorter, so we will
      // punt the client if nothing has arrived in at least
      // 3*KEEPALIVE_INTERVAL instead of if nothing arrives in exactly
      // 4*KEEPALIVE_INTERVAL. To do that, we have to check every
      // KEEPALIVE_INTERVAL.
      struct timeval timeout;
      gettimeofday(&timeout, NULL);
      timeout.tv_sec += KEEPALIVE_INTERVAL;

      conn->m_interval = KEEPALIVE_INTERVAL;
      conn->m_timeout = timeout;

      // since we have a valid client connection, cancel the shutdown timer
      cancel_shutdown_timer();

      // tell the backend this player is here
      log_msgs(m_log, "Telling backend that player kinum=%u is here\n",
	       join->kinum());
      TrackGamePlayerInfo_BackendMessage *track
	= new TrackGamePlayerInfo_BackendMessage(m_ipaddr, m_id,
						 join->kinum(), true);
      m_vault->enqueue(track);

#ifndef STANDALONE
      // tell other players this one is here
      PlNetMsgMembersMsg *member_msg = new PlNetMsgMembersMsg(join->kinum());
      member_msg->addMember(join->kinum(), &(gconn->player_name()),
			    &(gconn->plKey()), true);
      member_msg->finalize(false);
      std::list<Connection*>::iterator c_iter;
      for (c_iter = m_conns.begin(); c_iter != m_conns.end(); c_iter++) {
	Connection *c = *c_iter;
	if (c != conn && c != m_vault && c != m_timers) {
	  GameConnection *gc = (GameConnection *)c;
	  if (gc->state() < MEMBERS_REQUESTED) {
	    // don't forward message, we'll get the member in the
	    // MemberListReq
	    continue;
	  }
	  member_msg->add_ref();
	  c->enqueue(member_msg);
	}
      }
      if (member_msg->del_ref() < 1) {
	delete member_msg;
      }
#endif
    }
    // and now we can get rid of the JoinRequest
    delete in;

    return NO_SHUTDOWN;
}

#ifdef FORK_GAME_TOO
NetworkMessage * 
GameServer::DispatcherConnection::make_if_enough(const u_char *buf,
						 size_t len,
						 int *want_len,
						 bool become_owner) {
}

void
GameServer::DispatcherConnection::forward_conn(GameConnection *game_conn) {
  // XXX forward 7 bytes of cached negotiation RC4 key, and *encrypted*
  // read buffer (which must be done by re-encrypting it)
  // XXX other choice is to forward decrypted read buffer, and 256 bytes of
  // RC4 state
}
#endif /* FORK_GAME_TOO */

Server::reason_t GameServer::GameSignalProcessor::signalled(int *todo,
							    Server *s) {
  GameServer *gs = (GameServer *)s;
  gs->get_queued_connections();
  return NO_SHUTDOWN;
}

void GameServer::cancel_shutdown_timer() {
  if (m_shutdown_timer && !m_timed_shutdown) {
    log_debug(m_log, "Shutdown timer was active, cancelling\n");
    m_shutdown_timer->cancel();
    m_shutdown_timer = NULL;
  }
  if (m_timed_shutdown) {
    // we were already shutting down, cancel that too
    // XXX can't be cancelled so don't try (revisit this)
    // XXX m_timed_shutdown = false;
    log_debug(m_log, "Cancel request for shutdown timer arrived, but we "
	      "have already started shutdown\n");
  }
}

void GameServer::maybe_start_shutdown_timer() {
  if (m_conns.size() == 2 && m_joiners == 0) {
    if (m_shutdown_timer) {
      if (m_timed_shutdown) {
	log_debug(m_log, "Maybe start shutdown timer arrived, "
		  "but we have already started shutdown\n");
      }
      return;
    }
    struct timeval when;
    gettimeofday(&when, NULL);
    when.tv_sec += m_age->linger_time();
    m_shutdown_timer = new ShutdownTimer(when, m_timed_shutdown);
    log_debug(m_log, "Shutdown timer was inactive, starting\n");
    m_timers->insert(m_shutdown_timer);
  }
}

bool GameServer::send_to_ki(kinum_t kinum, NetworkMessage *msg) {
  GameMgrMessage *gmm = (GameMgrMessage *)msg;
  std::list<Connection*>::iterator c_iter;
  for (c_iter = m_conns.begin(); c_iter != m_conns.end(); c_iter++) {
    Connection *c = *c_iter;
    if (c != m_vault && c != m_timers) {
      GameConnection *gc = (GameConnection *)c;
      if (gc->kinum() == kinum) {
	gmm->add_ref();
	c->enqueue(gmm);
	return true;
      }
    }
  }
  return false;
}

bool GameServer::send_to_vault(BackendMessage *msg) {
  msg->add_ref();
  m_vault->enqueue(msg);
  return true;
}

void GameServer::set_timer(Server::TimerQueue::Timer *timer) {
  m_timers->insert(timer);
}
