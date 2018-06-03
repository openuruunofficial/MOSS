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
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdarg.h>
#include <pthread.h>
#include <signal.h>
#include <iconv.h>

#include <sys/time.h>

#include <netinet/in.h>

#include <stdexcept>
#include <deque>
#include <list>
#include <vector>

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

/*
 * GameMgr game types
 */
// Heek: 9d83c2e2-7835-4477-9aaa-22254c59a753
static const u_char Heek_UUID[] = { 0xe2, 0xc2, 0x83, 0x9d, 0x35, 0x78,
				    0x77, 0x44, 0x9a, 0xaa,
				    0x22, 0x25, 0x4c, 0x59, 0xa7, 0x53 };
// BlueSpiral: 5ff98165-913e-4fd1-a2c2-9c7f31be2cc8
static const u_char BlueSpiral_UUID[] = { 0x65, 0x81, 0xf9, 0x5f, 0x3e, 0x91,
					  0xd1, 0x4f, 0xa2, 0xc2,
					  0x9c, 0x7f, 0x31, 0xbe, 0x2c, 0xc8 };
// VarSync (quab): 475c2e9b-a245-4106-a047-9b25d41ff333
static const u_char VarSync_UUID[] = { 0x9b, 0x2e, 0x5c, 0x47, 0x45, 0xa2,
				       0x06, 0x41, 0xa0, 0x47,
				       0x9b, 0x25, 0xd4, 0x1f, 0xf3, 0x33 };
// Marker: 000b2c39-0319-4be1-b06c-7a105b160fcf
static const u_char Marker_UUID[] = { 0x39, 0x2c, 0x0b, 0x00, 0x19, 0x03,
				      0xe1, 0x4b, 0xb0, 0x6c,
				      0x7a, 0x10, 0x5b, 0x16, 0x0f, 0xcf };
// ClimbingWall: 6224cdf4-3556-4740-b7cd-d637562d07be
static const u_char ClimbingWall_UUID[] = { 0xf4, 0xcd, 0x24, 0x62, 0x56,
					    0x35, 0x40, 0x47, 0xb7, 0xcd, 0xd6,
					    0x37, 0x56, 0x2d, 0x07, 0xbe };
// TicTacToe: a7236529-11d8-4758-9368-59cb43445a83
static const u_char TicTacToe_UUID[] = { 0x29, 0x65, 0x23, 0xa7, 0xd8, 0x11,
					 0x58, 0x47, 0x93, 0x68,
					 0x59, 0xcb, 0x43, 0x44, 0x5a, 0x83 };

GameState::~GameState() {
  // Note, be careful with the locks: if there are any pending ClearLockTimers
  // they'll access memory freed here. The GameServer object should not be
  // deleted if that's true (and the m_conns (thus Timers) should be deleted
  // before the embedded GameState member), so we should be good. But to be
  // certain we don't write to the freed space, even if everything else has
  // gone wrong, bump the lockseq before deleting. (We'd still read from the
  // freed memory, but if the memory has been reallocated, that's okay while
  // writing is not okay. There is still a problem in the unlikely chance the
  // reallocated memory has data there that matches the new lockseq but this
  // is all not supposed to happen in multiple ways already.)
  std::list<ObjectLock*>::iterator l_iter;
  for (l_iter = m_locks.begin(); l_iter != m_locks.end(); l_iter++) {
    ObjectLock *lock = *l_iter;
    lock->lockseq++;
    delete lock;
  }

  // GameMgrs
  std::list<GameMgr*>::iterator g_iter;
  for (g_iter = m_age_games.begin(); g_iter != m_age_games.end(); g_iter++) {
    delete *g_iter;
  }
  for (g_iter = m_marker_games.begin(); g_iter != m_marker_games.end();
       g_iter++) {
    delete *g_iter;
  }
}

SDLState * GameState::find_sdl_like(SDLState *new_sdl) const {
  const char *new_name = new_sdl->get_desc()->name();
  std::list<SDLState*>::const_iterator iter;
  for (iter = m_sdl.begin(); iter != m_sdl.end(); iter++) {
    SDLState *sdl = *iter;
    if (sdl->key() == new_sdl->key() && sdl->name_equals(new_name)) {
      return sdl;
    }
  }
  return NULL;
}

void GameState::add_sdl(SDLState *new_sdl) {
  new_sdl->expand();
  m_sdl.push_back(new_sdl);
}

void GameState::setup_filter() {
  std::list<SDLState*>::const_iterator iter;
  for (iter = m_sdl.begin(); iter != m_sdl.end(); iter++) {
    SDLState *sdl = *iter;
    if (sdl->name_equals("physical")) {
      // add to physicals list
      sdl_filter_t filter;
      filter.master = sdl;
      filter.switch_at.tv_sec = 0;
      filter.switch_at.tv_usec = 0;
      filter.from_who = 0;
      m_physicals.push_back(filter);
    }
  }
}

static struct timeval sdl_filter_timeout = {
  SDL_FILTER_TIME_SECS, SDL_FILTER_TIME_USECS
};
GameState::sdl_filter_t & GameState::get_filter(SDLState *new_sdl) {
  std::list<sdl_filter_t>::iterator iter;
  for (iter = m_physicals.begin(); iter != m_physicals.end(); iter++) {
    if (iter->master->key() == new_sdl->key()) {
      return *iter;
    }
  }
  // need to make a new one
  add_sdl(new_sdl);
  sdl_filter_t filter;
  filter.master = new_sdl;
  filter.switch_at.tv_sec = 0;
  filter.switch_at.tv_usec = 0;
  filter.from_who = 0;
  m_physicals.push_front(filter);
  return m_physicals.front();
}

GameState::ObjectLock::ObjectLock(PlKey &plkey)
  : who(0), lockseq(0)
{
  key = plkey; // will do a struct copy
  if (key.m_name) {
    // we must make our own UruString here, copying the pointer is no good
    key.m_name = new UruString(*key.m_name);
  }
}

#define GRANT_ALL_FOOTSTEPS

bool GameState::try_lock(PlKey &key, kinum_t ki) {
#ifdef GRANT_ALL_FOOTSTEPS
  if (key.m_name && strstr(key.m_name->c_str(), "Footstep")) {
    return true;
  }
#endif

  ObjectLock *thelock = NULL;
  std::list<ObjectLock*>::iterator l_iter;
  for (l_iter = m_locks.begin(); l_iter != m_locks.end(); l_iter++) {
    ObjectLock *lock = *l_iter;
    if (key == lock->key) {
      thelock = lock;
      break;
    }
  }
  if (!thelock) {
    // the lock has not been created yet; create it now
    thelock = new ObjectLock(key);
    m_locks.push_back(thelock);
  }

  // now test the lock
  if (thelock->who) {
    // already held
    return false;
  }
  else {
    // grant lock
    thelock->who = ki;
    thelock->lockseq++;
    // and set timeout
    struct timeval timeout;
    gettimeofday(&timeout, NULL);
    timeout.tv_sec += MAX_LOCK_TIME;
    ClearLockTimer *timer = new ClearLockTimer(timeout, thelock);
    m_timers->insert(timer);
    // success!
    return true;
  }
}

bool GameState::clear_lock(PlKey &key, kinum_t ki) {
#ifdef GRANT_ALL_FOOTSTEPS
  if (key.m_name && strstr(key.m_name->c_str(), "Footstep")) {
    return true;
  }
#endif

  std::list<ObjectLock*>::iterator l_iter;
  for (l_iter = m_locks.begin(); l_iter != m_locks.end(); l_iter++) {
    ObjectLock *lock = *l_iter;
    if (key == lock->key) {
      if (lock->who == ki) {
	lock->who = 0;
	return true;
      }
      else {
	// unlocking someone else's lock
	return false;
      }
    }
  }
  // if we got here, we haven't even heard of this lock before, so it's
  // certainly not held
  return false;
}

void GameState::ClearLockTimer::callback() {
  if (m_lock->who && m_lock->lockseq == m_lockseq) {
    // this means the timeout happened before the lock was released
    m_lock->who = 0;
  }
}


/*
 * General-purpose handler functions for PropagateBufferMessages
 */
static bool msg_not_handled(PropagateBufferMessage *msg) { return false; }
static bool msg_is_handled(PropagateBufferMessage *msg) { return true; }
static bool check_useable_none(PropagateBufferMessage *msg) { return true; }
static bool header_only_check_useable(PropagateBufferMessage *msg) {
  u_int msg_len = msg->message_len();
  if (msg_len < 16) {
    // header info
    return false;
  }
  if (msg_len < msg->body_offset()) {
    return false;
  }
  return true;
}
static bool bad_handler(PropagateBufferMessage *msg, GameState *state,
			GameServer::GameConnection *conn, Logger *log) {
  log_err(log, "handle_message should never be called for subtype 0x%04x\n",
	  msg->subtype());
  return false;
}
static bool ignore_handler(PropagateBufferMessage *msg, GameState *state,
			   GameServer::GameConnection *conn, Logger *log) {
  const char *msgtype;
  switch (msg->subtype()) {
  case plNetMsgPagingRoom:
    msgtype = " plNetMsgPagingRoom";
    break;
  case plNetMsgRelevanceRegions:
    msgtype = " plNetMsgRelevanceRegions";
    break;
  default:
    msgtype = "";
  }
  log_msgs(log, "Ignoring useless%s message, subtype 0x%04x\n",
	   msgtype, msg->subtype());
  return false;
}
static bool passthrough_handler(PropagateBufferMessage *msg, GameState *state,
				GameServer::GameConnection *conn,
				Logger *log) {
  log_msgs(log, "Redistributing message (from kinum=%u), subtype 0x%04x\n",
	   conn->kinum(), msg->subtype());
  return true;
}

/*
 * General-purpose handler structs
 */
static propagate_handler ph_no_handler = {
  msg_not_handled, msg_not_handled, bad_handler
};
static propagate_handler ph_ignore_it = {
  msg_is_handled, check_useable_none, ignore_handler
};
static propagate_handler ph_passthrough = {
  // XXX check_useable_none works okay for messages the server simply copies
  // to other clients and doesn't look at, but the server *should* validate
  // them to protect clients against a misbehaving one
  msg_is_handled, check_useable_none, passthrough_handler
};

/*
 * Message-specific handlers
 */
static bool members_list_handler(PropagateBufferMessage *msg,
				 GameState *state,
				 GameServer::GameConnection *conn,
				 Logger *log) {
  log_msgs(log, "plNetMsgMembersListReq (kinum=%u)\n", conn->kinum());
  // nothing to actually do here, has to be handled by GameServer
  return false;
}
static propagate_handler ph_members_list = {
  msg_is_handled, header_only_check_useable/*no body*/, members_list_handler
};

static bool state_request_check_useable(PropagateBufferMessage *msg) {
  u_int msg_len = msg->message_len();
  if (msg_len < 16) {
    // header info
    return false;
  }
  if (msg_len < msg->body_offset() + 4) {
    return false;
  }
  // NOTE not a full check, handler must verify everything after page count
  return true;
}
static bool state_request_handler(PropagateBufferMessage *msg,
				  GameState *state,
				  GameServer::GameConnection *conn,
				  Logger *log) {
  log_msgs(log, "plNetMsgGameStateRequest (kinum=%u)\n", conn->kinum());
  conn->set_state(GameServer::STATE_REQUESTED);
  // this message needs to queue all relevant game state on conn
  u_int state_count = 0;

  const u_char *buf = msg->buffer();
  u_int offset = msg->body_offset();
  uint32_t pages = read32(buf, offset);
  if (pages == 0) {
    // send all
    std::list<SDLState*>::const_iterator iter;
    for (iter = state->sdl_begin(); iter != state->sdl_end(); iter++) {
      SDLState *sdl = *iter;
      PlKey &key = sdl->key();
      // NOTE we have to make sure to send clones before SDL that pertains
      // to them
#ifdef STANDALONE
      // just send everything that hasn't got a client ID in the key (gets
      // around clone ordering, Yeesha avatar, firefly clones, etc. issues)
      if (key.m_flags & 0x01) {
	continue;
      }
#else
      // filter needs to be more discriminating in multiplayer
      if (sdl->name_equals("CloneMessage")) {
	// clones are handled differently
	const u_char *sdl_buf = sdl->vars()[0]->m_value[0].v_creatable;
	if (!sdl_buf) {
	  log_err(log, "CloneMessage SDL is missing its data!\n");
	  // well, throw that one away, it's useless
	}
	else {
	  u_int clone_len = read32(sdl_buf, 0);
	  u_char is_player = sdl_buf[4];
	  if (is_player && key.m_clientid == conn->kinum()) {
	    // the client loads the clone before asking for the age state,
	    // so don't send the player's own clone back
	    continue;
	  }
	  else {
	    // quabs arrive with "is_player" zero, but the MOUL server
	    // sent them to new arrivals with the value as 1
	    // (perhaps this flag is actually "hidden")
	    // how do I know what to do without this special case?
	    if (*(key.m_name) == "Quab") {
	      is_player = 1;
	    }
	    PlNetMsgLoadClone *load_msg
	      = new PlNetMsgLoadClone(sdl_buf+5, clone_len,
				      key, key.m_clientid, true, is_player);
	    conn->enqueue(load_msg);
	    state_count++;
	  }
	}
	continue;
      }
#endif
      conn->enqueue(new PlNetMsgSDLState(sdl, true));
      state_count++;

      // XXX For scalability there should be a cap on how many messages are
      // sent, and a timer set to send more after other processing has
      // been allowed to happen.
      // Once we have that, we shuld send all the avatarPhysicals last, and
      // not send any new ones received until that time (to cut link-in
      // downloads). Or, we should send them all even later in the
      // link-in process if possible.
    }
  }
  else {
    // send only that which matches the following pages
    offset += 4;

    if (pages > 200) {
      // actually, any pages != 1 is fishy, but this code is here to make
      // sure we don't try to allocate too much (e.g. pages is actually -1)
      pages = 200;
    }
    uint32_t pageids[pages];
    u_int top = 0;
    // when traversing the list, make sure we don't read off the end of
    // the buffer
    u_int bufend = msg->message_len();
    while (top < pages) {
      if (bufend < offset+8) {
	log_net(log, "Bad GameStateRequest message (kinum=%u): %u pages "
		"listed but message too short\n", conn->kinum(), (int)pages);
	break;
      }
      pageids[top++] = read32(buf, offset);
      // I don't see why I need the page type or name, so skip them
      offset += 6;
      uint16_t str_len = read16(buf, offset);
      offset += 2+(str_len & 0x0FFF);
    }

    std::list<SDLState*>::const_iterator iter;
    for (iter = state->sdl_begin(); iter != state->sdl_end(); iter++) {
      SDLState *sdl = *iter;
      for (u_int i = 0; i < top; i++) {
	if (sdl->key().m_pageid == pageids[i]) {
	  conn->enqueue(new PlNetMsgSDLState(sdl, true));
	  state_count++;
	}
      }
    }
  }

  // send the message saying how many state messages were sent
  conn->enqueue(new PlNetMsgInitialAgeStateSent(state_count));
  return false;
}
static propagate_handler ph_state_request = {
  msg_is_handled, state_request_check_useable, state_request_handler
};

static bool test_and_set_handler(PropagateBufferMessage *msg,
				 GameState *state,
				 GameServer::GameConnection *conn,
				 Logger *log) {
  kinum_t ki = conn->kinum();
  const u_char *buf = msg->buffer();
  u_int offset = msg->body_offset();
  u_int buflen = msg->message_len();
  PlKey key;
  try {
    offset += key.read_in(buf+offset, buflen-offset);
  }
  catch (const parse_error &e) {
    // message truncated
    log_warn(log, "plNetMsgTestAndSet message too short (kinum=%u)\n", ki);
    key.delete_name();
    return false;
  }
  const char *lockname = (key.m_name ? key.m_name->c_str() : "");
  const char *action = NULL;

  // now there is a bunch more, make sure not to read off end of message
  u_int claimed_msglen = 0, submsg_offset = 0; // shut up compiler
  u_char from_state = 0, to_state = 0; // shut up compiler
  if (buflen < offset+9) {
    goto test_and_set_truncated;
  }
  offset += 5; // no idea what this data is
  claimed_msglen = read32(buf, offset);
  offset += 4;
  submsg_offset = offset;
  if (buflen < offset+claimed_msglen) {
    log_warn(log, "plNetMsgTestAndSet message shorter (%u) than claimed (%u) "
	     "(kinum=%u) lock '%s'\n", buflen-offset, claimed_msglen, ki,
	     lockname);
    goto test_and_set_truncated;
  }
  // the embedded message length suggests the next data is all another
  // type that could be treated as a submessage, but as I see nowhere else
  // a parser for it would be used, there's little point
  if (buflen < offset+2) {
    goto test_and_set_truncated;
  }
  {
    UruString str(buf+offset, buflen-offset, true, false, false);
    offset += str.arrival_len();
    if (str != "TrigState") {
      // whoa!
      log_net(log, "Unknown type of lock '%s' in plNetMsgTestAndSet "
	      "(kinum=%u) lock '%s'!\n", str.c_str(), ki, lockname);
      if (log) {
	log->dump_contents(Logger::LOG_NET, buf+submsg_offset,
			   buflen-submsg_offset);
      }
      // unsupported lock, wild guess on what to do
      conn->enqueue(new PlServerReplyMsg(false, key));
      key.delete_name();
      return false;
    }
  }
  if (buflen < offset+7) {
    goto test_and_set_truncated;
  }
  offset += 4; // no idea what this is
  from_state = buf[offset++];
  {
    UruString str2(buf+offset, buflen-offset, true, false, false);
    offset += str2.arrival_len();
    if (str2 != "Triggered") {
      // ???
      log_net(log, "Unknown TrigState '%s' in plNetMsgTestAndSet "
	      "(kinum=%u) lock '%s'!\n", str2.c_str(), ki, lockname);
      if (log) {
	log->dump_contents(Logger::LOG_NET, buf+submsg_offset,
			   buflen-submsg_offset);
      }
      key.delete_name();
      return false;
    }
  }
  if (buflen < offset+2) {
    goto test_and_set_truncated;
  }
  offset++; // no idea what this 0x2 is
  to_state = buf[offset++];
  // no idea what the rest is

  if (from_state + to_state != 1) {
    // don't know what that means...
    log_net(log, "plNetMsgTestAndSet unexpected state1: %u state2: %u "
	    "(kinum=%u) lock '%s'\n", from_state, to_state, ki, lockname);
    key.delete_name();
    return false;
  }

#ifdef STANDALONE
  if (to_state == 1) {
    action = "granted";
    conn->enqueue(new PlServerReplyMsg(true, key));
  }
  else {
    action = "released";
  }
#else
  if (to_state == 1) {
    if (state->try_lock(key, ki)) {
      action = "granted";
      conn->enqueue(new PlServerReplyMsg(true, key));
    }
    else {
      action = "rejected";
      conn->enqueue(new PlServerReplyMsg(false, key));
    }
  }
  else {
    if (state->clear_lock(key, ki)) {
      action = "released";
    }
    else {
      log_net(log, "plNetMsgTestAndSet (kinum=%u) lock '%s' release "
	      "requested but lock not held\n", ki, lockname);
    }
  }
#endif
  if (action) {
    log_debug(log, "plNetMsgTestAndSet (kinum=%u) lock '%s' %s\n",
	      ki, lockname, action);
  }
  key.delete_name();
  return false;

 test_and_set_truncated:
    // message too short
  log_warn(log, "plNetMsgTestAndSet message too short (kinum=%u) lock '%s'\n",
	   ki, lockname);

  key.delete_name();
  return false;
}
static propagate_handler ph_test_and_set = {
  msg_is_handled, header_only_check_useable, test_and_set_handler
};

static bool sdl_handler(PropagateBufferMessage *msg,
			GameState *state,
			GameServer::GameConnection *conn,
			Logger *log) {
  kinum_t ki = conn->kinum();
  conn->set_state(GameServer::IN_GAME);
  const u_char *buf = msg->buffer();
  u_int offset = msg->body_offset();
  u_int buflen = msg->message_len();

  SDLState *sdl = new SDLState();
  int readlen = 0;
  bool retval = true, known = true;
  bool bcast = (msg->subtype() == plNetMsgSDLStateBCast);
  try {
    readlen = sdl->read_msg(buf+offset, buflen-offset, state->sdl_descs());
  }
  catch (const parse_error &pe) {
    log_warn(log, "Parse error for SDL message (kinum=%u): %s\n",
	     ki, pe.what());
    retval = false;
  }
  catch (const truncated_message &tm) {
    log_warn(log, "Truncated SDL message (kinum=%u)\n", ki);
    retval = false;
  }
  catch (const std::bad_alloc &e) {
    log_err(log, "Could not allocate for SDL state\n");
    retval = false;
  }
  if (readlen <= 0) {
    // unknown SDL
    known = false;
    if (bcast) {
      log_debug(log, "Redistributing unknown SDL (kinum=%u)\n", ki);
    }
  }

  if (retval && known) {
    // if we get here, it's a message we recognize
    if (log && log->would_log_at(Logger::LOG_MSGS)) {
      char tmpstr[25];
      tmpstr[0] = '\0';
      if (sdl->key().m_flags & 0x01) {
	snprintf(tmpstr, 25, "(%u:%u)", sdl->key().m_clientid,
		 sdl->key().m_index);
      }
      log_msgs(log, "plNetMsgSDLState%s %s %s%s (kinum=%u)\n",
	       bcast ? "BCast" : "", sdl->get_desc()->name(),
	       sdl->key().m_name ? sdl->key().m_name->c_str() : "(noname)",
	       tmpstr, ki);
    }
#ifndef STANDALONE
    if (sdl->name_equals("physical")) {
      // kickable: need to do filtering
      GameState::sdl_filter_t &filter = state->get_filter(sdl);
      struct timeval now;
      gettimeofday(&now, NULL);
      if (filter.master == sdl) {
	// new object
	filter.from_who = ki;
	filter.switch_at = now;
	timeval_add(filter.switch_at, sdl_filter_timeout);
	// this is the first message for this object, so the SDL object was
	// put in the list, so don't delete the SDL here
	sdl = NULL;
      }
      else if (filter.from_who == ki) {
	filter.switch_at = now;
	timeval_add(filter.switch_at, sdl_filter_timeout);
	filter.master->update_from(sdl);
	// leave retval true
      }
      else if (timeval_lessthan(filter.switch_at, now)) {
	// use this one instead of waiting more
	filter.from_who = ki;
	filter.switch_at = now;
	timeval_add(filter.switch_at, sdl_filter_timeout);
	filter.master->update_from(sdl);
	// leave retval true
      }
      else {
	// not time to use someone else's yet
	retval = false;
      }
    }
    else {
#endif
      // all other messages we take as they come
      SDLState *master = state->find_sdl_like(sdl);
      if (master) {
	master->update_from(sdl);
      }
      else {
	state->add_sdl(sdl);
	sdl = NULL; // don't delete it
      }
      // leave retval true
#ifdef STANDALONE
      (void)sdl_filter_timeout; // make compiler happy
      retval = false; // no one to redistribute to so don't bother
#else
    }
#endif
  }

  if (sdl) {
    delete sdl;
  }
  return (bcast ? retval : false);
}
static propagate_handler ph_sdl = {
  msg_is_handled, header_only_check_useable, sdl_handler
};

#ifndef STANDALONE
static bool directed_check_useable(PropagateBufferMessage *msg) {
  u_int msg_len = msg->message_len();
  if (msg_len < 16) {
    // header info
    return false;
  }
  u_int offset = msg->body_offset();
  if (msg_len < offset + 9) {
    return false;
  }
  const u_char *buf = msg->buffer();
  offset += 10 + read32(buf, offset+5); // 10 includes "end thing"
  if (msg_len < offset+1) {
    return false;
  }
  u_char recip_ct = buf[offset++];
  if (msg_len < offset+(4*recip_ct)) {
    return false;
  }

  // does not verify contents *parses* correctly
  return true;
}
static bool directed_handler(PropagateBufferMessage *msg,
			     GameState *state,
			     GameServer::GameConnection *conn,
			     Logger *log) {
  log_msgs(log, "Directed message (from kinum=%u)\n", conn->kinum());
  return false;
}
static propagate_handler ph_directed = {
  msg_is_handled, directed_check_useable, directed_handler
};

static bool voice_check_useable(PropagateBufferMessage *msg) {
  u_int msg_len = msg->message_len();
  if (msg_len < 16) {
    // header info
    return false;
  }
  u_int offset = msg->body_offset();
  if (msg_len < offset + 5) {
    return false;
  }
  const u_char *buf = msg->buffer();
  offset += 4 + read16(buf, offset+2);
  if (msg_len < offset+1) {
    return false;
  }
  u_char recip_ct = buf[offset++];
  if (msg_len < offset+(4*recip_ct)) {
    return false;
  }

  // does not verify contents *parses* correctly
  return true;
}
static bool voice_handler(PropagateBufferMessage *msg,
			  GameState *state,
			  GameServer::GameConnection *conn,
			  Logger *log) {
  log_msgs(log, "Voice message (from kinum=%u)\n", conn->kinum());
  return false;
}
static propagate_handler ph_voice = {
  msg_is_handled, voice_check_useable, voice_handler
};

static bool load_clone_check_useable(PropagateBufferMessage *msg) {
  u_int msg_len = msg->message_len();
  if (msg_len < 16) {
    // header info
    return false;
  }
  u_int offset = msg->body_offset();
  if (msg_len < offset + 9) {
    return false;
  }
  const u_char *buf = msg->buffer();
  // submessage length
  offset += 10 + read32(buf, offset+5); // 10 includes submessage "end thing"
  PlKey obj;
  try {
    offset += obj.read_in(buf+offset, msg_len-offset);
    obj.delete_name();
  }
  catch (const truncated_message &tm) {
    obj.delete_name();
    return false;
  }
  if (msg_len < offset+3) {
    return false;
  }

  // does not verify contents *parses* correctly
  return true;
}
static bool load_clone_handler(PropagateBufferMessage *msg,
			       GameState *state,
			       GameServer::GameConnection *conn,
			       Logger *log) {
  const u_char *buf = msg->buffer();
  u_int offset = msg->body_offset();
  u_int msg_start = offset;
  offset += 10 + read32(buf, offset+5); // 10 includes submessage "end thing"
  u_int msg_end = offset;
  
  // okay, it looks like we can keep this submessage wholesale, we don't
  // even need to parse it

  const SDLDesc *clone_desc = SDLDesc::find_by_name("CloneMessage",
						    state->sdl_descs());
  if (!clone_desc) {
    // we have a serious problem
    log_err(log, "No CloneMessage SDL found! Clones will be very broken\n");
    // at least send it on to those already present
    return true;
  }
  SDLState *sdl = new SDLState(clone_desc);
  try {
    offset += sdl->key().read_in(buf+offset, msg->message_len()-offset);
  }
  catch (const truncated_message &tm) {
    log_err(log, "check_useable() failed for this LoadClone\n");
    if (log) {
      log->dump_contents(Logger::LOG_ERR, buf, msg->message_len());
    }
    delete sdl;
    return true;
  }
  u_char is_player = buf[offset++];
  // we don't get unloads from clients any more in MOUL, but just in case
  if (buf[offset] == 0) {
    log_net(log, "Got a LoadClone *un*load message (kinum=%u)\n",
	    msg->kinum());
    delete sdl;
    return true;
  }

  // update connection state
  if (conn->state() < GameServer::HAVE_CLONE) {
    conn->set_key(sdl->key());
    conn->set_state(GameServer::HAVE_CLONE);
  }

  // now write the clone contents to the SDL's CREATABLE
  log_msgs(log, "plNetMsgLoadClone (kinum=%u)\n", msg->kinum());
  sdl->expand();
  sdl->vars()[0]->m_value = new SDLDesc::Variable::data_t[1];
  u_int submsg_len = msg_end-msg_start;
  u_char *saved = new u_char[submsg_len+5];
  sdl->vars()[0]->m_value[0].v_creatable = saved;
  write32(saved, 0, submsg_len);
  saved[4] = is_player;
  memcpy(saved+5, buf+msg_start, submsg_len);

  SDLState *master = state->find_sdl_like(sdl);
  if (master) {
    master->update_from(sdl);
    delete sdl;
  }
  else {
    state->add_sdl(sdl);
  }
  return true;
}
static propagate_handler ph_load_clone = {
  msg_is_handled, load_clone_check_useable, load_clone_handler
};
#endif /* !STANDALONE */

propagate_handler * get_propagate_handler(uint16_t subtype) {
  switch(subtype) {
  case plNetMsgMembersListReq:
    return &ph_members_list;
  case plNetMsgGameStateRequest:
    return &ph_state_request;
  case plNetMsgTestAndSet:
    return &ph_test_and_set;
  case plNetMsgPagingRoom:
    // AFAICT this message has no purpose, it's just leftovers
    return &ph_ignore_it;
  case plNetMsgGameMessage:
    // XXX I believe these are all broadcast messages but it must be verified
  case plNetMsgPlayerPage:
    return &ph_passthrough;
  case plNetMsgSDLState:
  case plNetMsgSDLStateBCast:
    return &ph_sdl;
#ifdef STANDALONE
  case plNetMsgLoadClone:
  case plNetMsgRelevanceRegions:
  case plNetMsgVoice:
  case plNetMsgGameMessageDirected:
    return &ph_ignore_it;
#else
  case plNetMsgVoice:
    return &ph_voice;
  case plNetMsgGameMessageDirected:
    return &ph_directed;
  case plNetMsgLoadClone:
    return &ph_load_clone;
  case plNetMsgRelevanceRegions:
#ifdef MULTIPLAYER_PHASE2 /* more like phase 10 */
    unimplemented;
#else
    return &ph_ignore_it;
#endif
#endif /* !STANDALONE */
  case plSetNetGroupIDMsg: // XXX don't have any idea what this is for
    return &ph_passthrough;
  default:
    return &ph_no_handler;
  }
}


/*
 * GameMgr types
 */
class VarSyncGameMgr : public GameMgr {
public:
  VarSyncGameMgr(uint32_t id) : GameMgr(id, VarSync) { }
  virtual ~VarSyncGameMgr() { }

  bool initialize_game(const GameMgrMessage *msg, kinum_t player,
		       GameServer *server);
  bool got_message(GameMgrMessage *msg, kinum_t player, GameServer *server);
  void player_left(kinum_t player, GameServer *server);

protected:
  class Var {
  public:
    UruString name;
    double val; // always little-endian
    // not strictly required, I don't think
    // u_int index;
    Var() { }
    Var(const Var &other) : val(other.val) {
      name = other.name;
    }
    Var & operator=(const Var &other) {
      if (this != &other) {
	name = other.name;
	val = other.val;
      }
      return *this;
    }
  };
  std::vector<Var> m_vars;
};

class MarkerGameMgr : public GameMgr {
public:
  MarkerGameMgr(uint32_t id, uint32_t server_id1, uint32_t server_id2)
    : GameMgr(id, Marker), m_sid1(server_id1), m_sid2(server_id2),
      m_game_name(NULL), m_template(NULL), m_private_id(0), m_state(INIT),
      m_elapsed_time(0)
  { }
  virtual ~MarkerGameMgr() {
    if (m_game_name) delete m_game_name;
    if (m_template) delete m_template;
  }

  bool initialize_game(const GameMgrMessage *msg, kinum_t player,
		       GameServer *server);
  bool got_message(GameMgrMessage *msg, kinum_t player, GameServer *server);

  // marker game-specific function for receiving data from the backend
  bool process_backend_message(NetworkMessage *in, GameServer *server);

protected:
  typedef enum {
    // the order matters here; the code expects DEAD,INIT,START,LIST_WAIT
    // all are < READY which is < PLAYING
    INIT = 0,
    START = 1,
    LIST_WAIT = 2,
    //CAPTURED_WAIT = 3,
    READY = 4,
    PLAYING = 5,
    //PAUSED = 6,
    DEAD = -1
  } game_state_t;

  uint32_t m_sid1, m_sid2;
  // time limit not used in quest games apparently; 677 ms isn't very long
  u_int m_time_limit;
  u_char m_game_type;
  UruString *m_game_name;
  UruString *m_template;
  // for tracking game state
  u_int m_private_id;
  game_state_t m_state;
  struct timeval m_start_time;
  // XXX elapsed time has to go into the DB if games that actually
  // care about the time ever exist
  // XXX also, this is not *actually* elapsed time so all code working with
  // it could be wrong
  u_int m_elapsed_time;
};

class BlueSpiralGameMgr : public GameMgr {
public:
  BlueSpiralGameMgr(uint32_t id)
    : GameMgr(id, BlueSpiral), m_started(false), m_timer(NULL) { }
  virtual ~BlueSpiralGameMgr() { if (m_timer) m_timer->cancel(); }

  bool initialize_game(const GameMgrMessage *msg, kinum_t player,
		       GameServer *server);
  bool got_message(GameMgrMessage *msg, kinum_t player, GameServer *server);
  void player_left(kinum_t player, GameServer *server);

protected:
  void start_game(GameServer *server);

  class DoorTimer : public Server::TimerQueue::Timer {
  public:
    typedef enum {
      TurnDoor,
      GameDone
    } action_t;
    DoorTimer(struct timeval &when, BlueSpiralGameMgr *mgr,
	      GameServer *server, action_t why)
      : Timer(when), m_who(mgr), m_server(server), m_action(why) { }
    virtual ~DoorTimer() { }
    virtual void callback();
  protected:
    BlueSpiralGameMgr *m_who;
    GameServer *m_server;
    action_t m_action;
  };
  void handle_timeout(DoorTimer::action_t why, GameServer *server);

  u_char m_order[7];
  u_int m_next;
  bool m_started;
  bool m_rotating;
  DoorTimer *m_timer; // do not delete; the TimerQueue does that

private:
  static const int turn_delta = 15;
  static const int game_delta = 60;
  // close is client-side and occurs 1 second after GameOver arrives or the
  // door finishes opening (whichever is later)
  // close_delta is used only for STANDALONE, so make it something modest
  // so the one player has a good chance of making it
  static const int close_delta = 14;
};

class HeekGameMgr : public GameMgr {
public:
  HeekGameMgr(uint32_t id);
  virtual ~HeekGameMgr();

  bool initialize_game(const GameMgrMessage *msg, kinum_t player,
		       GameServer *server);
  bool got_message(GameMgrMessage *msg, kinum_t player, GameServer *server);
  void player_left(kinum_t player, GameServer *server);

protected:
  typedef enum {
    // order matters!
    IDLE = 0,
    IN_GAME = 1,
    COUNTDOWN = 2,
    STOP_WAIT = 3,
    ANIM_WAIT = 4,
    WINNER = 5,
    WIN_WAIT = 6
  } game_state_t;

#ifdef DEBUG_HEEK_STATE
  const char * statename() {
    switch(m_state) {
    case IDLE:
      return "IDLE";
    case IN_GAME:
      return "IN_GAME";
    case COUNTDOWN:
      return "COUNTDOWN";
    case STOP_WAIT:
      return "STOP_WAIT";
    case ANIM_WAIT:
      return "ANIM_WAIT";
    case WINNER:
      return "WINNER";
    case WIN_WAIT:
      return "WIN_WAIT";
    default:
      return "(unknown)";
    }
  }
#endif

  // lots of helper functions
  void tell_all_sitters(GameMgrMessage *send, GameServer *server);
  int get_player_index(kinum_t player) {
    for (u_int i = 0; i < 5; i++) {
      if (m_sitting[i] && m_sitting[i]->m_ki == player) { return i; }
    }
    return -1;
  }
  void reset_game() {
    m_current_game++;
    m_point_pool = 0;
  }
  void reset_choices() {
    m_choice_ct = 0;
    for (u_int i = 0; i < 5; i++) {
      if (m_sitting[i]) { m_sitting[i]->m_choice = -1; }
    }
  }
  void countdown_done(GameServer *server, bool early);
  void handle_round(GameServer *server);
  void handle_winner(GameServer *server);
  void countdown_idle(GameServer *server);
  void handle_departure(int position, GameServer *server);
  void send_drop(GameServer *server);

  class HeekTimer : public Server::TimerQueue::Timer {
  public:
    HeekTimer(struct timeval &when, HeekGameMgr *mgr, GameServer *server)
      : Timer(when), m_who(mgr), m_server(server) { }
    virtual ~HeekTimer() { }
    virtual void callback() { m_who->handle_timeout(m_server); }
  protected:
    HeekGameMgr *m_who;
    GameServer *m_server;
  };
  void handle_timeout(GameServer *server);

  // this object contains all the state for a given player
  class Sitter {
  public:
    kinum_t m_ki;
    int32_t m_score;
    char m_choice;
    char m_wins[3];
    u_int m_current_game;
    bool m_pending_winner;
    Sitter(kinum_t player, int32_t score)
      : m_ki(player), m_score(score), m_choice(-1), m_current_game(0),
	m_pending_winner(false)
    {
      reset_wins();
    }
    void reset_wins() {
      m_wins[0] = m_wins[1] = m_wins[2] = 0;
      m_pending_winner = false;
    }
  };
  std::list<Sitter*> m_all;

  game_state_t m_state;
  // sitter_t::m_current_game is initialized from this, which is incremented
  // every heek game so we can tell whether the player played during the
  // current game
  u_int m_current_game;
  // when anyone first starts playing a game, a point is preemptively given up
  u_int m_point_pool;

  Sitter *m_sitting[5];
  u_int m_sitting_ct;
  u_int m_choice_ct; // number of choices received this round
  u_int m_pending_winner_ct;
  // this is used only if the game owner leaves while sitting
  int m_cleanup;

  HeekTimer *m_timer;
  static const int choice_delta = 7;
  // the three following timeouts are in case of a misbehaving owner, and
  // shouldn't fire in normal situations
  // (these are 1 second greater than the real animation times)
  static const int stop_delta = 1;
  static const int anim_delta = 11;
  static const int win_delta = 6;
};

bool VarSyncGameMgr::initialize_game(const GameMgrMessage *msg,
				     kinum_t player, GameServer *server) {
  if (m_owner == 0) {
    m_owner = player;
  }
  //const u_char *buf = msg->buffer();
  u_int len = msg->message_len();
  u_int off = msg->setup_data();
  if (off+1 < len) {
    return false;
  }
  // XXX I do not know what any values in this message are for, so we aren't
  // using them

  add_player(player);
  send_setup_reply(msg, player, server);
  if (m_owner == player) {
    // it doesn't make sense to me that the order this stuff is sent depends
    // on whether you're owner, but let us try
    send_join(player, server);
  }
  // send all the vars
  for (u_int idx = 0; idx < m_vars.size(); idx++) {
    GameMgr_VarSync_VarCreated_Message *vmsg
      = new GameMgr_VarSync_VarCreated_Message(m_gameid, idx+1,
						 m_vars[idx].name,
						 m_vars[idx].val);
    server->send_to_ki(player, vmsg);
    if (vmsg->del_ref() < 1) {
      delete vmsg; // wasn't queued
    }
  }
  GameMgr_Simple_Message *smsg
    = new GameMgr_Simple_Message(m_gameid, kVarSyncAllVarsSent);
  server->send_to_ki(player, smsg);
  if (smsg->del_ref() < 1) {
    delete smsg; // wasn't queued
  }
  if (m_owner != player) {
    // it doesn't make sense to me that the order this stuff is sent depends
    // on whether you're owner, but let us try
    send_join(player, server);
  }
  return true;
}

bool VarSyncGameMgr::got_message(GameMgrMessage *msg, kinum_t player,
				 GameServer *server) {
  Logger *log = server->log();
  if (player != m_owner) {
    log_warn(log, "Player %u sent a VarSync message but owner is %u\n",
	     player, m_owner);
    return true;
  }
  const u_char *buf = msg->buffer();
  u_int off = msg->body_data();
  switch (msg->msgtype()) {
  case kVarSyncNumericVarCreate:
    if (msg->message_len() < off+520) {
      throw truncated_message("VarSync NumericVarCreate too short");
    }
    else {
      // need to make sure the string is copied
      UruString varname(buf+off, 512, false, true, true);
      off += 512;
      // check that we don't have one of these already
      for (u_int idx = 0; idx < m_vars.size(); idx++) {
	if (varname == m_vars[idx].name) {
	  // hmm...
	  log_warn(log, "VarSync NumericVarCreate request for existing "
		   "name %s (kinum=%u)\n", varname.c_str(), player);
	  GameMgr_VarSync_VarCreated_Message *vmsg
	    = new GameMgr_VarSync_VarCreated_Message(m_gameid, idx+1,
						     m_vars[idx].name,
						     m_vars[idx].val);
	  if (!server->send_to_ki(player, vmsg)) {
	    // wow, if we get here we don't even know about the owner!
	    log_err(log, "Whoa! Got a message from a VarSync game owner who "
		    "isn't connected (kinum=%u)\n", player);
	  }
	  if (vmsg->del_ref() < 1) {
	    delete vmsg;
	  }
	  return true;
	}
      }
      // if we got here, the var doesn't already exist
      Var newvar;
      newvar.name = varname;
      newvar.val = read_double(buf, off);
      m_vars.push_back(newvar);
      log_msgs(log, "VarSync NumericVarCreate -> var %s (kinum=%u)\n",
	       newvar.name.c_str(), player);
      // and tell everyone about it
      GameMgr_VarSync_VarCreated_Message *vmsg
	= new GameMgr_VarSync_VarCreated_Message(m_gameid, m_vars.size(),
						 newvar.name, newvar.val);
      send_to_all(vmsg, server);
      if (vmsg->del_ref() < 1) {
	// shouldn't happen (zero players)
	delete vmsg;
      }
    }
    return true;
  case kVarSyncNumericVarChange:
    if (msg->message_len() < off+12) {
      throw truncated_message("VarSync NumericVarChange too short");
    }
    else {
      u_int idx = read32(buf, off);
      off += 4;
      if (idx > 0 && idx <= m_vars.size()) {
	m_vars[idx-1].val = read_double(buf, off);
	log_msgs(log, "VarSync NumericVarChange var %u (kinum=%u)\n",
		 idx, player);
      }
      else {
	log_warn(log, "Received VarSync change message for unknown "
		 "index %u (kinum=%u)\n", idx, player);
      }
    }
    // since, of course, Cyan didn't make
    // NumericVarChanged == NumericVarChange, we have to twiddle the
    // buffer, but after that we can redistribute this one, at least
    msg->make_own_copy();
    msg->clobber_msgtype(kVarSyncNumericVarChanged);
    send_to_all(msg, server);
    return true;
  default:
    return false;
  }
}

void VarSyncGameMgr::player_left(kinum_t player, GameServer *server) {
  // Because of the buggy Python for quab games, owner handoff is a
  // nightmare: exception-fest galore. Since the game is broken anyway,
  // just break it preemptively by not transferring the owner.

  // We can't leave the owner as the player who left, because they may return
  // to the age. We can't set the owner to zero because that means the next
  // to link in will be assigned the owner. Setting it to 1 (which is not a
  // valid KI number) works around these problems. Using -1 feels like it
  // could trip a special case in client code.
  m_owner = 1;
  GameMgr::player_left(player, server);
  if (m_players.size() == 0) {
    // we can revive the game next time someone arrives, so fix up the owner
    // back to "no owner"
    m_owner = 0;
    // age is now empty -- throw out the variables
    m_vars.clear();
  }
}

bool MarkerGameMgr::initialize_game(const GameMgrMessage *msg,
				    kinum_t player, GameServer *server) {
  m_owner = player;
  const u_char *buf = msg->buffer();
  u_int len = msg->message_len();
  u_int off = msg->setup_data();
  if (off+5+516+160 < len) {
    return false;
  }

  // here the message is known to be long enough
  m_time_limit = read32(buf, off);
  off += 4;
  m_game_type = buf[off++];
  // name
  m_game_name = new UruString(buf+off, 516, false, true, true);
  off += 516;
  m_template = new UruString(buf+off, 160, false, true, true);

  add_player(player);
  send_setup_reply(msg, player, server);

  // now, if the template was blank, this is a new game being created
  if (m_template->strlen() == 0) {
    MarkerGetGame_BackendMessage *get_game
      = new MarkerGetGame_BackendMessage(m_sid1, m_sid2, false, m_gameid,
					 false, (uint32_t)player, m_game_type,
					 NULL, m_game_name);
    server->send_to_vault(get_game);
    if (get_game->del_ref() < 1) {
      // shouldn't happen
      delete get_game;
    }
  }
  else {
    // convert template UUID from widestring to "raw" UUID
    u_char uuid[UUID_RAW_LEN];
    if (uuid_string_to_bytes(uuid, UUID_RAW_LEN, m_template->c_str(),
			     m_template->strlen(), true, true)) {
      // XXX format error in string from client
    }
    else {
      MarkerGetGame_BackendMessage *get_game
	= new MarkerGetGame_BackendMessage(m_sid1, m_sid2, false, m_gameid,
					   true, (uint32_t)player,
					   m_game_type, uuid, m_game_name);
      server->send_to_vault(get_game);
      if (get_game->del_ref() < 1) {
	// shouldn't happen
	delete get_game;
      }
    }
  }

  // we have to wait to hear back from the backend before sending more
  m_state = START;
  return true;
}

bool MarkerGameMgr::got_message(GameMgrMessage *msg, kinum_t player,
				GameServer *server) {
  Logger *log = server->log();
  if (player != m_owner) {
    log_warn(log, "Player %u sent a Marker message but owner is %u\n",
	     player, m_owner);
    return true;
  }
  if (m_state == DEAD) {
    log_debug(log, "Received marker message type %u while in state DEAD "
	      "(kinum=%u)\n", msg->msgtype(), player);
    return true;
  }
  const u_char *buf = msg->buffer();
  u_int off = msg->body_data();

  // XXX What happens if someone adds or deletes a marker while another
  // is playing the game? Or renames one? Is that propagated to all current
  // players? Blargh!

  switch(msg->msgtype()) {
  case kMarkerMarkerAdd:
    if (msg->message_len() < off+24+512+160) {
      throw truncated_message("kMarkerMarkerAdd message too short");
    }
    else if (m_state < READY) {
      log_warn(log, "Client (kinum=%u) added a marker before being told "
	       "about the whole game!\n", player);
    }
    else {
      log_msgs(log, "MarkerAdd request (kinum=%u) -> backend\n", player);
      double x, y, z;
      x = read_double(buf, off);
      off += 8;
      y = read_double(buf, off);
      off += 8;
      z = read_double(buf, off);
      off += 8;
      UruString marker_name(buf+off, 512, false, true, false);
      off += 512;
      UruString age_name(buf+off, 160, false, true, false);
      MarkerAdd_BackendMessage *add
	= new MarkerAdd_BackendMessage(m_sid1, m_sid2, false, m_gameid,
				       m_private_id, x, y, z, marker_name,
				       age_name);
      server->send_to_vault(add);
      if (add->del_ref() < 1) {
	// shouldn't happen
	delete add;
      }
    }
    break;
  case kMarkerGameStart:
    if (m_state < READY) {
      log_warn(log, "Client (kinum=%u) started a game before being told "
	       "about the whole game!\n", player);
    }
    else if (m_state == PLAYING) {
      log_msgs(log, "MarkerGameStart (kinum=%u) (already started)\n",
	       player);
      // ignore it
    }
    else {
      log_msgs(log, "MarkerGameStart (kinum=%u)\n", player);
      gettimeofday(&m_start_time, NULL);
      m_state = PLAYING;

      // In MOUL when the client sent lots of adds followed by a start,
      // the server replied with its start after replying to the adds.
      // MOSS does not hit the DB with a start, so it will reply to the
      // start immediately, likely before any adds.
      GameMgr_Simple_Message *reply
	= new GameMgr_Simple_Message(m_gameid, kMarkerGameStarted);
      server->send_to_ki(player, reply);
      if (reply->del_ref() < 1) {
	// shouldn't happen
	delete reply;
      }
    }
    break;
  case kMarkerGamePause:
    // pause is sent when you click "Stop Game" AND when you click
    // "Reset Game", before the kMarkerGameReset is sent
    if (m_state < READY) {
      log_warn(log, "Client (kinum=%u) paused the game in unexpected "
	       "state %d\n", player, m_state);
    }
    else if (m_state == READY /*|| m_state == PAUSED*/) {
      log_msgs(log, "MarkerGamePause (kinum=%u) (ignored)\n", player);
      // ignore it
    }
    else { // m_state == PLAYING
      log_msgs(log, "MarkerGamePause (kinum=%u)\n", player);
      struct timeval now;
      gettimeofday(&now, NULL);
      timeval_subtract(now, m_start_time);
      m_elapsed_time += now.tv_sec * 1000;
      m_elapsed_time += now.tv_usec / 1000;

      m_state = READY; // game is actually *stopped*
      GameMgr_FourByte_Message *reply
	= new GameMgr_FourByte_Message(m_gameid, kMarkerGamePaused,
				       m_elapsed_time);
      server->send_to_ki(player, reply);
      if (reply->del_ref() < 1) {
	// shouldn't happen
	delete reply;
      }
    }
    break;
  case kMarkerGameResetReq:
    // reset means: clear the captured markers (and presumably reset the
    // elapsed time), but keep playing
    if (m_state < READY) {
      log_warn(log, "Client (kinum=%u) reset the game in unexpected "
	       "state %d\n", player, m_state);
    }
    else {
      log_msgs(log, "MarkerGameResetReq (kinum=%u)\n", player);
      m_elapsed_time = 0;
      m_state = READY;
      MarkerGameStop_BackendMessage *stop
	= new MarkerGameStop_BackendMessage(m_sid1, m_sid2, false,
					    m_gameid, m_private_id, player);
      server->send_to_vault(stop);
      if (stop->del_ref() < 1) {
	// shouldn't happen
	delete stop;
      }
      GameMgr_Simple_Message *reply
	= new GameMgr_Simple_Message(m_gameid, kMarkerGameReset);
      server->send_to_ki(player, reply);
      if (reply->del_ref() < 1) {
	// shouldn't happen
	delete reply;
      }
    }
    break;
  case kMarkerGameNameChange:
    if (msg->message_len() < off+512) {
      throw truncated_message("kMarkerGameNameChange message too short");
    }
    if (m_state < READY) {
      log_warn(log, "Client (kinum=%u) changed the game name in unexpected "
	       "state %d\n", player, m_state);
    }
    if (m_state > START) {
      log_msgs(log, "MarkerGameNameChange request (kinum=%u) -> backend\n",
	       player);
      UruString new_name(buf+off, 512, false, true, false);
      MarkerGameRename_BackendMessage *rename
	= new MarkerGameRename_BackendMessage(m_sid1, m_sid2, false, m_gameid,
					      m_private_id, new_name);
      server->send_to_vault(rename);
      if (rename->del_ref() < 1) {
	// shouldn't happen
	delete rename;
      }
    }
    break;
  case kMarkerGameDelete:
    if (m_state < READY) {
      log_warn(log, "Client (kinum=%u) deleted the game in unexpected "
	       "state %d\n", player, m_state);
    }
    if (m_state > START) {
      // marker games other than CGZ are deleted by the vault
      bool isCGZ = (m_game_type == kMarkerGameCGZ);
      log_msgs(log, "MarkerGameDelete request (kinum=%u) %s\n",
	       player, isCGZ ? "-> backend" : "(not CGZ)");
      if (isCGZ) {
	MarkerGameDelete_BackendMessage *del
	  = new MarkerGameDelete_BackendMessage(m_sid1, m_sid2, false,
						m_gameid, m_private_id);
	server->send_to_vault(del);
	if (del->del_ref() < 1) {
	  // shouldn't happen
	  delete del;
	}
      }
      else {
	// send success to the client
	GameMgr_OneByte_Message *reply =
	  new GameMgr_OneByte_Message(m_gameid, kMarkerGameDeleted, true);
	server->send_to_ki(m_owner, reply);
	if (reply->del_ref() < 1) {
	  // shouldn't happen
	  delete reply;
	}
      }
    }
    break;
  case kMarkerMarkerDelete:
    if (msg->message_len() < off+4) {
      throw truncated_message("kMarkerMarkerDelete message too short");
    }
    if (m_state < READY) {
      log_warn(log, "Client (kinum=%u) deleting marker before being told "
	       "about the whole game!\n", player);
    }
    else {
      log_msgs(log, "MarkerMarkerDelete (kinum=%u) -> backend\n", player);
      MarkerGameDeleteMarker_BackendMessage *del
	= new MarkerGameDeleteMarker_BackendMessage(m_sid1, m_sid2, false,
						    m_gameid, m_private_id,
						    read32(buf, off));
      server->send_to_vault(del);
      if (del->del_ref() < 1) {
	// shouldn't happen
	delete del;
      }
    }
    break;
  case kMarkerMarkerNameChange:
    if (msg->message_len() < off+4+512) {
      throw truncated_message("kMarkerMarkerNameChange message too short");
    }
    if (m_state < READY) {
      log_warn(log, "Client (kinum=%u) changing marker before being told "
	       "about the whole game!\n", player);
    }
    else {
      log_msgs(log, "MarkerMarkerNameChange (kinum=%u) -> backend\n", player);
      UruString new_name(buf+off+4, 512, false, true, false);
      MarkerGameRenameMarker_BackendMessage *rename
	= new MarkerGameRenameMarker_BackendMessage(m_sid1, m_sid2, false,
						    m_gameid, m_private_id,
						    read32(buf, off),
						    new_name);
      server->send_to_vault(rename);
      if (rename->del_ref() < 1) {
	// shouldn't happen
	delete rename;
      }
    }
    break;
  case kMarkerMarkerCapture:
    // XXX ideally we would track captured markers locally so repeated
    // captures (which do happen) don't all have to hit the backend and DB
    // (also track them when receiving MARKER_STATE from backend)
    if (msg->message_len() < off+4) {
      throw truncated_message("kMarkerMarkerCapture message too short");
    }
    if (m_state < READY) {
      log_warn(log, "Client kinum=%u captured marker before being told about "
	       "the whole game!\n", player);
    }
    else {
      log_msgs(log, "MarkerMarkerCapture (kinum=%u) -> backend\n", player);
      MarkerGameCaptureMarker_BackendMessage *capture
	= new MarkerGameCaptureMarker_BackendMessage(m_sid1, m_sid2, false,
						     m_gameid, m_private_id,
						     player, read32(buf, off),
						     1);
      server->send_to_vault(capture);
      if (capture->del_ref() < 1) {
	// shouldn't happen
	delete capture;
      }
    }
    break;
  default:
    return false;
  }
  return true;
}

bool MarkerGameMgr::process_backend_message(NetworkMessage *in,
					    GameServer *server) {
  // here it is assumed that the message is destined for *this* manager,
  // and the usual assumption that BackendMessages are correct applies

  Logger *log = server->log();
  switch(in->type()) {
  case MARKER_NEWGAME|FROM_SERVER:
    if (m_state != START) {
      // whoa!
      log_err(log, "MarkerMgr %u: Backend sent a MARKER_NEWGAME while "
	      "this game (internal ID %u) was in state %d!\n",
	      m_gameid, m_private_id, m_state);
    }
    else {
      MarkerGetGame_BackendMessage *msg = (MarkerGetGame_BackendMessage *)in;
      if (!msg->exists()) {
	// this should not happen, let's see just how wrong it is...
	if (m_template->strlen() == 0) {
	  // DB failed to create a *new* game
	  log_err(log, "MarkerMgr %u: Backend failed to create a new game!\n",
		  m_gameid);
	}
	else {
	  // client requested a non-existent game
	  log_warn(log, "MarkerMgr %u: Client (kinum=%u) requested a "
		   "non-existent game %s\n", m_gameid, m_owner,
		   m_template->c_str());
	}
	m_state = DEAD;
      }
      else {
	// we're good, proceed!
	bool isnew = (m_template->strlen() == 0);
	log_msgs(log, "MarkerMgr %u: MARKER_NEWGAME (%s) -> client kinum=%u\n",
		 m_gameid, isnew ? "new" : "existing", m_owner);
	m_private_id = msg->localid();
	if ((m_game_name->strlen() != msg->name()->strlen())
	    || strcmp(m_game_name->c_str(), msg->name()->c_str())) {
	  // keep our version of the name correct
	  delete m_game_name;
	  m_game_name = new UruString(*msg->name(), true);
	}
	m_game_type = msg->game_type();

	if (isnew) {
	  // created a new game, tell the client all about it
	  m_state = READY;

	  GameMgr_Marker_GameCreated_Message *created
	    = new GameMgr_Marker_GameCreated_Message(m_gameid,
						     msg->template_uuid());
	  server->send_to_ki(m_owner, created);
	  if (created->del_ref() < 1) {
	    // shouldn't happen
	    delete created;
	  }
#if 1
	  GameMgr_OneByte_Message *reply
	    = new GameMgr_OneByte_Message(m_gameid, kMarkerGameType,
					  m_game_type);
	  server->send_to_ki(m_owner, reply);
	  if (reply->del_ref() < 1) {
	    // shouldn't happen
	    delete reply;
	  }
#endif
	  GameMgr_Marker_GameNameChanged_Message *name
	    = new GameMgr_Marker_GameNameChanged_Message(m_gameid,
							 msg->name());
	  server->send_to_ki(m_owner, name);
	  if (name->del_ref() < 1) {
	    // shouldn't happen
	    delete name;
	  }
#if 1
	  reply = new GameMgr_OneByte_Message(m_gameid, kMarkerTeamAssigned,
					      1);
	  server->send_to_ki(m_owner, reply);
	  if (reply->del_ref() < 1) {
	    // shouldn't happen
	    delete reply;
	  }
	  send_join(m_owner, server);
#endif

	  // send kMarkerTemplateCreated
	  // send kMarkerGameType
	  // send kMarkerGameNameChanged
	  // send kMarkerTeamAsssigned, kGameCliPlayerJoinedMsg,
	  //      kGameCliOwnerChangeMsg
	}
	else {
	  // starting an existing game
	  m_state = LIST_WAIT;
#if 1
	  GameMgr_OneByte_Message *reply
	    = new GameMgr_OneByte_Message(m_gameid, kMarkerTeamAssigned, 1);
	  server->send_to_ki(m_owner, reply);
	  if (reply->del_ref() < 1) {
	    // shouldn't happen
	    delete reply;
	  }
	  send_join(m_owner, server);
	  reply = new GameMgr_OneByte_Message(m_gameid, kMarkerGameType,
					      m_game_type);
	  server->send_to_ki(m_owner, reply);
	  if (reply->del_ref() < 1) {
	    // shouldn't happen
	    delete reply;
	  }
#endif

	  // send kMarkerTeamAsssigned, kGameCliPlayerJoinedMsg,
	  //      kGameCliOwnerChangeMsg
	  // send kMarkerGameType
	}
#if 0
	// I am trying sending the messages in a slightly different order,
	// hopefully it will work fine XXX
	GameMgr_OneByte_Message *reply
	  = new GameMgr_OneByte_Message(m_gameid, kMarkerGameType,
					m_game_type);
	server->send_to_ki(m_owner, reply);
	if (reply->del_ref() < 1) {
	  // shouldn't happen
	  delete reply;
	}
	reply = new GameMgr_OneByte_Message(m_gameid, kMarkerTeamAssigned, 1);
	server->send_to_ki(m_owner, reply);
	if (reply->del_ref() < 1) {
	  // shouldn't happen
	  delete reply;
	}
	send_join(m_owner, server);
#endif
      }
    }
    break;
  case MARKER_DUMP|FROM_SERVER:
    if (m_state != LIST_WAIT) {
      log_err(log, "MarkerMgr %u: Backend sent a MARKER_DUMP while "
	      "this game (internal ID %u) was in state %d!\n",
	      m_gameid, m_private_id, m_state);
    }
    else {
      log_msgs(log, "MarkerMgr %u: MARKER_DUMP -> client kinum=%u\n",
	       m_gameid, m_owner);
      MarkersAll_BackendMessage *msg = (MarkersAll_BackendMessage *)in;
      size_t num_markers = msg->size();
      if (num_markers > 0) {
	// send messages to client
	GameMgr_Marker_MarkerAdded_Message *addmsg;
	for (u_int i = 0; i < num_markers; i++) {
	  addmsg = new GameMgr_Marker_MarkerAdded_Message(m_gameid,
							  msg->data(),
							  msg->name(),
							  msg->agename(),
							  msg);
	  server->send_to_ki(m_owner, addmsg);
	  if (addmsg->del_ref() < 1) {
	    // shouldn't happen
	    delete addmsg;
	  }
	  msg->advance_index();
	}
      }
      GameMgr_Marker_GameNameChanged_Message *name
	= new GameMgr_Marker_GameNameChanged_Message(m_gameid, m_game_name);
      server->send_to_ki(m_owner, name);
      if (name->del_ref() < 1) {
	// shouldn't happen
	delete name;
      }
      m_state = READY;
    }
    break;
  case MARKER_STATE|FROM_SERVER:
    if (m_state < READY) {
      log_err(log, "MarkerMgr %u: Backend sent a MARKER_STATE while "
	      "this game (internal ID %u) was in state %d!\n",
	      m_gameid, m_private_id, m_state);
    }
    else {
      log_msgs(log, "MarkerMgr %u: MARKER_STATE -> client kinum=%u\n",
	       m_gameid, m_owner);
      MarkersCaptured_BackendMessage *msg
	= (MarkersCaptured_BackendMessage *)in;
      size_t num_markers = msg->size();
      if (num_markers > 0) {
	// send messages to client
	GameMgr_Marker_MarkerCaptured_Message *captured;
	const int32_t *list = (int32_t*)msg->list();
	for (u_int i = 0; i < num_markers; i++) {
	  captured = new GameMgr_Marker_MarkerCaptured_Message(m_gameid,
							       list[2*i],
							       list[(2*i)+1]);
	  server->send_to_ki(m_owner, captured);
	  if (captured->del_ref() < 1) {
	    // shouldn't happen
	    delete captured;
	  }
	}
      }
    }
    break;
  case MARKER_ADD|FROM_SERVER:
    if (m_state == INIT || m_state == START || m_state == DEAD) {
      log_err(log, "MarkerMgr %u: Backend sent a MARKER_ADD while this "
	      "game (internal ID %u) was in state %d!\n",
	      m_gameid, m_private_id, m_state);
    }
    else {
      log_msgs(log, "MarkerMgr %u: MARKER_ADD -> client kinum=%u\n",
	       m_gameid, m_owner);
      MarkerAdd_BackendMessage *msg = (MarkerAdd_BackendMessage *)in;
      GameMgr_Marker_MarkerAdded_Message *reply
	= new GameMgr_Marker_MarkerAdded_Message(m_gameid, msg->data(),
						 msg->name(), msg->agename(),
						 msg);
      server->send_to_ki(m_owner, reply);
      if (reply->del_ref() < 1) {
	// shouldn't happen
	delete reply;
      }
    }
    break;
  case MARKER_GAME_RENAME|FROM_SERVER:
    if (m_state == INIT || m_state == START || m_state == DEAD) {
      log_err(log, "MarkerMgr %u: Backend sent a MARKER_GAME_RENAME while "
	      "this game (internal ID %u) was in state %d!\n",
	      m_gameid, m_private_id, m_state);
    }
    else {
      log_msgs(log, "MarkerMgr %u: MARKER_GAME_RENAME -> client kinum=%u\n",
	       m_gameid, m_owner);
      MarkerGameRename_BackendMessage *msg
	= (MarkerGameRename_BackendMessage *)in;
      GameMgr_Marker_GameNameChanged_Message *reply
	= new GameMgr_Marker_GameNameChanged_Message(m_gameid, msg->name());
      server->send_to_ki(m_owner, reply);
      if (reply->del_ref() < 1) {
	// shouldn't happen
	delete reply;
      }
    }
    break;
  case MARKER_GAME_DELETE|FROM_SERVER:
    if (m_state == INIT || m_state == START || m_state == DEAD) {
      log_err(log, "MarkerMgr %u: Backend sent a MARKER_GAME_DELETE while "
	      "this game (internal ID %u) was in state %d!\n",
	      m_gameid, m_private_id, m_state);
    }
    else {
      log_msgs(log, "MarkerMgr %u: MARKER_GAME_DELETE -> client kinum=%u\n",
	       m_gameid, m_owner);
      MarkerGameDelete_BackendMessage *msg
	= (MarkerGameDelete_BackendMessage *)in;
      bool success = (msg->localid() != 0);
      GameMgr_OneByte_Message *reply =
	new GameMgr_OneByte_Message(m_gameid, kMarkerGameDeleted, success);
      server->send_to_ki(m_owner, reply);
      if (reply->del_ref() < 1) {
	// shouldn't happen
	delete reply;
      }
      if (success) {
	m_state = DEAD;
      }
      else {
	log_warn(log,
		 "MarkerMgr %u: deletion of game (internal ID %u) failed\n",
		 m_gameid, m_private_id);
      }
    }
    break;
  case MARKER_RENAME|FROM_SERVER:
    if (m_state == INIT || m_state == START || m_state == DEAD) {
      log_err(log, "MarkerMgr %u: Backend sent a MARKER_RENAME while "
	      "this game (internal ID %u) was in state %d!\n",
	      m_gameid, m_private_id, m_state);
    }
    else {
      log_msgs(log, "MarkerMgr %u: MARKER_RENAME -> client kinum=%u\n",
	       m_gameid, m_owner);
      MarkerGameRenameMarker_BackendMessage *msg
	= (MarkerGameRenameMarker_BackendMessage *)in;
      GameMgr_Marker_MarkerNameChanged_Message *reply
	= new GameMgr_Marker_MarkerNameChanged_Message(m_gameid,
						       msg->number(),
						       msg->name());
      server->send_to_ki(m_owner, reply);
      if (reply->del_ref() < 1) {
	// shouldn't happen
	delete reply;
      }
    }
    break;
  case MARKER_DELETE|FROM_SERVER:
    if (m_state == INIT || m_state == START || m_state == DEAD) {
      log_err(log, "MarkerMgr %u: Backend sent a MARKER_DELETE while "
	      "this game (internal ID %u) was in state %d!\n",
	      m_gameid, m_private_id, m_state);
    }
    else {
      log_msgs(log, "MarkerMgr %u: MARKER_DELETE -> client kinum=%u\n",
	       m_gameid, m_owner);
      MarkerGameDeleteMarker_BackendMessage *msg
	= (MarkerGameDeleteMarker_BackendMessage *)in;
      GameMgr_FourByte_Message *reply
	= new GameMgr_FourByte_Message(m_gameid, kMarkerMarkerDeleted,
				       (uint32_t)msg->number());
      server->send_to_ki(m_owner, reply);
      if (reply->del_ref() < 1) {
	// shouldn't happen
	delete reply;
      }
    }
    break;
  case MARKER_CAPTURE|FROM_SERVER:
    if (m_state < READY) {
      log_err(log, "MarkerMgr %u: Backend sent a MARKER_CAPTURE while "
	      "this game (internal ID %u) was in state %d!\n",
	      m_gameid, m_private_id, m_state);
    }
    else {
      log_msgs(log, "MarkerMgr %u: MARKER_CAPTURE -> client kinum=%u\n",
	       m_gameid, m_owner);
      MarkerGameCaptureMarker_BackendMessage *msg
	= (MarkerGameCaptureMarker_BackendMessage *)in;
      GameMgr_Marker_MarkerCaptured_Message *reply
	= new GameMgr_Marker_MarkerCaptured_Message(m_gameid,
						    msg->number(),
						    msg->value());
      server->send_to_ki(m_owner, reply);
      if (reply->del_ref() < 1) {
	// shouldn't happen
	delete reply;
      }
    }
    break;
  default:
    return false; // message not handled!
  }

  return true;
}

bool BlueSpiralGameMgr::initialize_game(const GameMgrMessage *msg,
					kinum_t player, GameServer *server) {
  if (m_owner == 0) {
    m_owner = player;
  }
  //const u_char *buf = msg->buffer();
  u_int len = msg->message_len();
  u_int off = msg->setup_data();
  if (off+1 < len) {
    return false;
  }
  // XXX I do not know what any values in this message are for, so we aren't
  // using them

  add_player(player);
  send_setup_reply(msg, player, server);
  send_join(player, server);

  return true;
}

bool BlueSpiralGameMgr::got_message(GameMgrMessage *msg, kinum_t player,
				    GameServer *server) {
  Logger *log = server->log();
  const u_char *buf = msg->buffer();
  u_int off = msg->body_data();
  switch (msg->msgtype()) {
  case kBlueSpiralGameStart:
    if (player != m_owner) {
      log_warn(log, "Player %u sent a BlueSpiralGameStart but owner is %u\n",
	       player, m_owner);
    }
    else {
      log_msgs(log, "BlueSpiral GameStart request (kinum=%u)\n", player);
      if (m_started) {
	// one can touch the door while a game is running; stop the previous
	// game before starting a new one
	if (m_timer) {
	  m_timer->cancel();
	}
	GameMgr_Simple_Message *stop
	  = new GameMgr_Simple_Message(m_gameid, kBlueSpiralGameOver);
	send_to_all(stop, server);
	if (stop->del_ref() < 1) {
	  delete stop; // shouldn't happen
	}
	// XXX ideally we would wait some short amount of time before
	// starting the next time, to give the door time to rotate back if it
	// is moving -- even more ideally it would be proportional to the
	// amount of time the door has been moving
      }
#ifdef STANDALONE
      // since I'm not putting in a game timeout, make "start" a toggle
      // so the door can be stopped
      if (m_started) {
	m_started = false;
	m_timer = NULL;
      }
      else
#endif
	start_game(server);
    }
    break;
  case kBlueSpiralClothHit:
    if (msg->message_len() < off+1) {
      throw truncated_message("BlueSpiral ClothHit too short");
    }
    else {
      // I guess the game logic goes here
      if (m_started) {
	log_msgs(log, "BlueSpiral ClothHit %u from kinum=%u; next is %u\n",
		 buf[off], player, m_order[m_next]);
	GameMgr_Simple_Message *reply;
	if (m_order[m_next] == buf[off]) {
	  m_next++;
	  // send succesful to owner
	  reply = new GameMgr_Simple_Message(m_gameid,
					     kBlueSpiralSuccessfulHit);
	  if (!server->send_to_ki(m_owner, reply)) {
	    log_warn(log, "BlueSpiral tried to send message to owner "
		     "(kinum=%u) who isn't connected\n", m_owner);
	  }
	  if (reply->del_ref() < 1) {
	    delete reply;
	  }
	  if (m_next > 6) {
	    // game is done!
	    m_started = false;
	    reply = new GameMgr_Simple_Message(m_gameid, kBlueSpiralGameWon);
	    // looks like sent only to owner
	    server->send_to_ki(m_owner, reply);
	    if (reply->del_ref() < 1) {
	      delete reply; // shouldn't happen
	    }
#ifdef STANDALONE
	    // since I have no overall timeout in STANDALONE mode, set a
	    // shorter one here so the door still closes eventually
	    struct timeval timeout;
	    gettimeofday(&timeout, NULL);
	    timeout.tv_sec += close_delta;
	    m_timer = new DoorTimer(timeout, this, server,
				    DoorTimer::GameDone);
	    server->set_timer(m_timer);
#endif
	  }
	}
	else {
	  m_started = false;
	  if (m_timer) {
	    m_timer->cancel();
	    m_timer = NULL;
	  }
	  // send game over to all
	  reply = new GameMgr_Simple_Message(m_gameid, kBlueSpiralGameOver);
	  send_to_all(reply, server);
	  if (reply->del_ref() < 1) {
	    delete reply; // shouldn't happen
	  }
	}
      }
      else {
	log_msgs(log, "Ignoring BlueSpiralClothHit (kinum=%u) because "
		 "game not in progress\n", player);
      }
    }
    break;
  default:
    return false; // message not handled!
  }
  return true;
}

void BlueSpiralGameMgr::player_left(kinum_t player, GameServer *server) {
  GameMgr::player_left(player, server);
  if (m_owner == 0) {
    // age is now empty
    m_started = false;
  }
}

void BlueSpiralGameMgr::start_game(GameServer *server) {
  m_started = true;
  m_next = 0;
  // create new cloth order
  uint16_t data[8];
  get_random_data((u_char*)&data, 16);
  // The way this works is, m_order[i] is assigned to the number of values
  // in the array r that are greater than r[i]. (If there are two equal
  // values, the second one is "greater".) This basically means m_order[i]
  // is the index number of r[i] in a sorted r, and since there is a strict
  // ordering, we know the numbers are unique and cover the range 0:6.
  uint16_t *r = (uint16_t*)data;
  for (u_int i = 0; i < 7; i++) {
    u_char val = 0;
    for (u_int j = 0; j < 7; j++) {
      if (i != j && (r[j] > r[i] || (r[j] == r[i] && j > i))) {
	val++;
      }
    }
    m_order[i] = val;
  }
  log_debug(server->log(), "BlueSpiral cloth order: %u %u %u %u %u %u %u\n",
	    m_order[0], m_order[1], m_order[2], m_order[3], m_order[4], 
	    m_order[5], m_order[6]);

  // set a timer to rotate the door
  struct timeval timeout;
  gettimeofday(&timeout, NULL);
  timeout.tv_sec += turn_delta;
  m_timer = new DoorTimer(timeout, this, server, DoorTimer::TurnDoor);
  server->set_timer(m_timer);

  // now broadcast the info
  GameMgr_BlueSpiral_ClothOrder_Message *order
    = new GameMgr_BlueSpiral_ClothOrder_Message(m_gameid, m_order);
  send_to_all(order, server);
  if (order->del_ref() < 1) {
    // shouldn't happen!
    delete order;
  }
  GameMgr_OneByte_Message *start
    = new GameMgr_OneByte_Message(m_gameid, kBlueSpiralGameStarted, 0);
  send_to_all(start, server);
  if (start->del_ref() < 1) {
    // shouldn't happen!
    delete start;
  }
}

void BlueSpiralGameMgr::DoorTimer::callback() {
  m_who->handle_timeout(m_action, m_server);
}

void
BlueSpiralGameMgr::handle_timeout(BlueSpiralGameMgr::DoorTimer::action_t why,
				  GameServer *server) {
  if (why == DoorTimer::TurnDoor) {
    GameMgr_OneByte_Message *start
      = new GameMgr_OneByte_Message(m_gameid, kBlueSpiralGameStarted, 1);
    server->send_to_ki(m_owner, start);
    if (start->del_ref() < 1) {
      delete start;
    }
#ifndef STANDALONE
    struct timeval timeout;
    gettimeofday(&timeout, NULL);
    timeout.tv_sec += game_delta;
    m_timer = new DoorTimer(timeout, this, server, DoorTimer::GameDone);
    server->set_timer(m_timer);
#else
    // there is no timeout
    m_timer = NULL;
#endif
  }
  else { // why == GameDone
    // game timed out
    log_debug(server->log(), "BlueSpiral time over\n");
    m_started = false;
    m_timer = NULL;
    GameMgr_Simple_Message *done
      = new GameMgr_Simple_Message(m_gameid, kBlueSpiralGameOver);
    send_to_all(done, server);
    if (done->del_ref() < 1) {
      delete done;
    }
  }
}

HeekGameMgr::HeekGameMgr(uint32_t id)
  : GameMgr(id, Heek), m_state(IDLE), m_current_game(0), m_point_pool(0),
    m_sitting_ct(0), m_choice_ct(0), m_pending_winner_ct(0), m_cleanup(-1),
    m_timer(NULL) {
  for (u_int i = 0; i < 5; i++) {
    m_sitting[i] = NULL;
  }
}

HeekGameMgr::~HeekGameMgr() {
  std::list<Sitter*>::iterator iter;
  for (iter = m_all.begin(); iter != m_all.end(); iter++) {
    delete *iter;
  }
}

bool HeekGameMgr::initialize_game(const GameMgrMessage *msg, kinum_t player,
				  GameServer *server) {
  if (m_owner == 0) {
    m_owner = player;
  }
  // no extra payload in this setup, so no need to do a length test
  add_player(player);
  send_setup_reply(msg, player, server);
  send_join(player, server);

  if (m_cleanup >= 0 && m_owner == player) {
    // previously the last player left while sitting at the table, and now
    // that we have a new owner we should have him clean up
    send_drop(server);
  }
  return true;
}

bool HeekGameMgr::got_message(GameMgrMessage *msg, kinum_t player,
			      GameServer *server) {
  Logger *log = server->log();
  const u_char *buf = msg->buffer();
  u_int off = msg->body_data();
  switch (msg->msgtype()) {
  case kHeekPlayGameReq:
    if (msg->message_len() < off+5+512) {
      throw truncated_message("HeekPlayGameReq too short");
    }
    else if (m_sitting_ct >= 5) {
      log_err(log, "Player kinum=%u is sitting at Heek but there are "
	      "already %u at the table!\n", player, m_sitting_ct);
      // I can't do much but ignore it
    }
    else {
      // position is 0-based
      u_char position = buf[off++];
      if (m_sitting[position]) {
	log_err(log, "Player kinum=%u is sitting at Heek position %u but "
		"%u is already there!\n", player, position,
		m_sitting[position]->m_ki);
      }
      else {
	log_msgs(log,
		 "Player kinum=%u sat at Heek position %u, %u now sitting\n",
		 player, position, m_sitting_ct+1);
	int32_t score = read32(buf, off);
	off += 4;
	Sitter *this_guy = NULL;
	std::list<Sitter*>::iterator iter;
	for (iter = m_all.begin(); iter != m_all.end(); iter++) {
	  Sitter *that_guy = *iter;
	  if (that_guy->m_ki == player) {
	    this_guy = that_guy;
#ifdef DEBUG_HEEK_STATE
	    log_debug(log, "Player kinum=%u game=%u current_game=%u\n",
		      player, this_guy->m_current_game, m_current_game);
#endif
	    if (this_guy->m_current_game == m_current_game
		&& this_guy->m_score != score) {
	      log_warn(log, "Player kinum=%u is playing this game but has "
		       "claimed his score is now %d instead of %d!\n",
		       player, score, this_guy->m_score);
	    }
	    else {
	      this_guy->m_score = score;
	    }
	    if (this_guy->m_current_game != m_current_game) {
#ifdef DEBUG_HEEK_STATE
	      log_debug(log, "Resetting wins for player kinum=%u\n", player);
#endif
	      this_guy->reset_wins();
	    }
	    break;
	  }
	}
	if (!this_guy) {
	  this_guy = new Sitter(player, score);
	  m_all.push_back(this_guy);
	}
	else if (this_guy->m_choice != -1) {
	  // choice should always be -1 already (see handle_departure())
	  log_err(log, "Sitting player %u has choice %d\n",
		  player, this_guy->m_choice);
	  this_guy->m_choice = -1;
	}
	m_sitting_ct++;
	m_sitting[position] = this_guy;

	GameMgr_Heek_PlayGame_Message *playgame
	  = new GameMgr_Heek_PlayGame_Message(m_gameid, true/*XXXever false?*/,
			(m_sitting_ct == 1) /*single*/,
			(m_sitting_ct > 1 && m_state < COUNTDOWN) /*enable*/);
	server->send_to_ki(player, playgame);
	if (playgame->del_ref() < 1) {
	  delete playgame; // wasn't queued
	}

	// now, is this enabling the game?
	if (m_sitting_ct == 2 && m_state < COUNTDOWN) {
	  // previously there was one player
	  GameMgr_OneByte_Message *enable
	    = new GameMgr_OneByte_Message(m_gameid, kHeekInterfaceState, 1);
	  for (u_int i = 0; i < 5; i++) {
	    if (m_sitting[i] && m_sitting[i] != this_guy) {
	      server->send_to_ki(m_sitting[i]->m_ki, enable);
	    }
	  }
	  if (enable->del_ref() < 1) {
	    delete enable; // wasn't queued
	  }
	}

	// I hope I don't have to keep around the avatar name long term
	UruString avatar_name(buf+off, 512, false, true, false);
	// announce the new player
	GameMgr_Heek_Welcome_Message *welcome
	  = new GameMgr_Heek_Welcome_Message(m_gameid, this_guy->m_score,
					     1, avatar_name);
	tell_all_sitters(welcome, server);
	if (welcome->del_ref() < 1) {
	  delete welcome; // wasn't queued
	}
      }
    }
    return true;
  case kHeekChoice:
    if (msg->message_len() < off+1) {
      throw truncated_message("HeekChoice too short");
    }
    else if (m_sitting_ct < 2) {
      // this could have been sent immediately before someone got up, or just
      // before the choice round ended, so ignore it
      log_msgs(log, "Ignoring old HeekChoice (kinum=%u)\n", player);
    }
    else {
      log_msgs(log, "HeekChoice %u from kinum=%u\n", buf[off], player);
      if (m_state == IDLE) {
	// start a new game
	log_debug(log, "Starting a new round of Heek\n");
#ifdef DEBUG_HEEK_STATE
	log_debug(log, "HEEK IDLE -> IN_GAME\n");
#endif
	m_state = IN_GAME;
	reset_game();
      }
      if (m_state == IN_GAME) {
	m_state = COUNTDOWN;
#ifdef DEBUG_HEEK_STATE
	log_debug(log, "HEEK IN_GAME -> COUNTDOWN\n");
#endif
	reset_choices();
	// tell owner about the countdown
	GameMgr_OneByte_Message *countdown
	  = new GameMgr_OneByte_Message(m_gameid, kHeekCountdownState,
					kHeekCountdownStart);
	server->send_to_ki(m_owner, countdown);
	if (countdown->del_ref() < 1) {
	  delete countdown; // wasn't queued
	}
	// start the choice timeout
	struct timeval timeout;
	gettimeofday(&timeout, NULL);
	timeout.tv_sec += choice_delta;
	m_timer = new HeekTimer(timeout, this, server);
	server->set_timer(m_timer);
      }

      if (m_state == COUNTDOWN) {
	// finally we get to register the choice
	if (buf[off] > kHeekGameChoiceScissors) {
	  log_warn(log, "Player (kinum=%u) sent invalid Heek choice %u\n",
		   player, buf[off]);
	}
	else {
	  int idx = get_player_index(player);
	  if (idx < 0) {
	    log_warn(log, "Got Heek choice from non-sitting player kinum=%u\n",
		     player);
	  }
	  else {
	    if (m_sitting[idx]->m_current_game != m_current_game) {
#ifdef DEBUG_HEEK_STATE
	      log_debug(log, "Heek: player %u is starting this game for the "
			"first time\n", m_sitting[idx]->m_ki);
#endif
	      m_sitting[idx]->m_current_game = m_current_game;
	      m_sitting[idx]->reset_wins();
	      // proactively subtract a point
	      m_sitting[idx]->m_score--;
	      m_point_pool++;
	      // and send the message
	      GameMgr_Heek_PointUpdate_Message *points
		= new GameMgr_Heek_PointUpdate_Message(m_gameid, false,
						       m_sitting[idx]->m_score,
						       1);
	      server->send_to_ki(m_sitting[idx]->m_ki, points);
	      if (points->del_ref() < 1) {
		delete points; // wasn't queued
	      }
	    }
#ifdef DEBUG_HEEK_STATE
	    else {
	      log_debug(log, "Heek: player %u is continuing this game\n",
			m_sitting[idx]->m_ki);
	    }
#endif
	    // if m_choice is >= 0 the player is just changing the choice,
	    // so don't increment the total count
	    if (m_sitting[idx]->m_choice < 0) {
	      m_choice_ct++;
#ifdef DEBUG_HEEK_STATE
	      log_debug(log, "Heek: total choices %u\n", m_choice_ct);
#endif
	    }
	    m_sitting[idx]->m_choice = (char)buf[off];

	    // now, if all choices were received we stop the countdown
	    if (m_choice_ct >= m_sitting_ct) {
#ifdef DEBUG_HEEK_STATE
	      log_debug(log, "Heek: all choices received, stop countdown\n");
#endif
	      if (m_timer) {
		m_timer->cancel();
		m_timer = NULL;
	      }
	      countdown_done(server, true);
	    }
	  }
	}
      }
      else {
	// simply ignore it; may have been sent just before the state changed
#ifdef DEBUG_HEEK_STATE
	log_debug(log, "Heek: ignoring choice\n");
#endif
      }
    }
    return true;
  case kHeekAnimationFinished:
    if (msg->message_len() < off+1) {
      throw truncated_message("HeekAnimationFinished too short");
    }
    else if (player != m_owner) {
      log_warn(log, "Player %u sent a HeekAnimationFinished message but "
	       "owner is %u\n", player, m_owner);
    }
    else {
      log_msgs(log, "HeekAnimationFinished (kinum=%u)\n", player);
      if (buf[off] == kHeekGameSeqCountdown) {
	// the client sends this more than once so take care
	if (m_state == STOP_WAIT) {
#ifdef DEBUG_HEEK_STATE
	  log_debug(log, "Heek: Countdown animation finished\n");
#endif
	  if (m_timer) {
	    m_timer->cancel();
	    m_timer = NULL;
	  }
	  handle_round(server);
	}
#ifdef DEBUG_HEEK_STATE
	else {
	  log_debug(log, "Heek: late Countdown animation finished message\n");
	}
#endif
      }
      else if (buf[off] == kHeekGameSeqChoiceAnim) {
#ifdef DEBUG_HEEK_STATE
	log_debug(log, "Heek: Choice animation finished\n");
#endif
	if (m_state == ANIM_WAIT || m_state == WINNER) {
	  if (m_timer) {
	    m_timer->cancel();
	    m_timer = NULL;
	  }
	  if (m_state == ANIM_WAIT) {
	    countdown_idle(server);
	  }
	  else {
	    handle_winner(server);
	  }
	}
      }
      else if (buf[off] == kHeekGameSeqGameWinAnim) {
#ifdef DEBUG_HEEK_STATE
	log_debug(log, "Heek: Win animation finished\n");
#endif
	if (m_state == WIN_WAIT) {
	  if (m_timer) {
	    m_timer->cancel();
	    m_timer = NULL;
	  }
	  countdown_idle(server);
#ifdef DEBUG_HEEK_STATE
	  log_debug(log, "HEEK WIN_WAIT -> IDLE\n");
#endif
	  m_state = IDLE;
	}
      }
    }
    return true;
  case kHeekGoodbyeReq:
    {
      int idx = get_player_index(player);
      if (idx < 0) {
	log_warn(log,
		 "Got Heek goodbye from non-sitting player kinum=%u\n",
		 player);
      }
      else {
	log_msgs(log, "HeekGoodbye from kinum=%u\n", player);
	// the score has already been decremented, if it's going to be
	bool fake_win = false;

	if (m_sitting_ct == 1) {
	  // this is the last person getting up; they "win"
#ifdef DEBUG_HEEK_STATE
	  log_debug(log, "Heek: last person leaving gets the %u point%s\n",
		    m_point_pool, m_point_pool == 1 ? "" : "s");
#endif
	  m_sitting[idx]->m_score += m_point_pool;
	  if (m_point_pool > 1) {
	    fake_win = true;
	  }
	}

	GameMgr_Heek_PointUpdate_Message *points
	  = new GameMgr_Heek_PointUpdate_Message(m_gameid, fake_win,
						 m_sitting[idx]->m_score, 1);
	server->send_to_ki(player, points);
	if (points->del_ref() < 1) {
	  delete points; // wasn't queued
	}
	GameMgr_Simple_Message *bye
	  = new GameMgr_Simple_Message(m_gameid, kHeekGoodbye);
	server->send_to_ki(player, bye);
	if (bye->del_ref() < 1) {
	  delete bye; // wasn't queued
	}

	handle_departure(idx, server);
      }
    }
    return true;
  default:
    return false;
  }
}

void HeekGameMgr::player_left(kinum_t player, GameServer *server) {
  int idx = get_player_index(player);
  if (idx >= 0) {
    // if this is the last player, they can't get the point pool because
    // they're already gone

    // if the departing player was sitting at the table, the server has to
    // send a kHeekDrop message to the owner for position idx, so that the
    // table state will be cleaned up
    if (player == m_owner) {
      // but this player *is* the owner, so keep track for the new owner
      m_cleanup = idx;
    }
    else {
      m_cleanup = idx;
      send_drop(server);
    }

    handle_departure(idx, server);
  }
  // since the player is leaving the whole age, remove them from m_all
  std::list<Sitter*>::iterator iter;
  for (iter = m_all.begin(); iter != m_all.end(); iter++) {
    Sitter *p = *iter;
    if (p->m_ki == player) {
      delete p;
    }
    m_all.erase(iter);
    break;
  }
  GameMgr::player_left(player, server);
  // if the person leaving was owner and we have a new owner now, tell the
  // new owner to drop the one leaving
  if (m_cleanup >= 0 && m_owner != 0) {
    send_drop(server);
  }
}

// This strategy for handling kHeekDrop will fail if more than one player
// departs at once unless the owner is never one of them. If the owner is
// already gone at the time the another player's departure is processed (and
// the owner's departure is processed later), m_cleanup will be set to -1 and
// then the next departing player's ID, losing the first. There is not an
// easy or even somewhat complicated way to handle it; we would have to track
// all drops persistently until the current owner sends something else,
// proving aliveness. Not worth the trouble, really.
void HeekGameMgr::send_drop(GameServer *server) {
  if (m_cleanup >= 0 && m_owner != 0) {
    GameMgr_OneByte_Message *msg
      = new GameMgr_OneByte_Message(m_gameid, kHeekDrop, m_cleanup);
    server->send_to_ki(m_owner, msg);
    if (msg->del_ref() < 1) {
      delete msg; // wasn't queued
    }
    m_cleanup = -1;
  }
}

void HeekGameMgr::tell_all_sitters(GameMgrMessage *send, GameServer *server) {
  for (u_int i = 0; i < 5; i++) {
    if (m_sitting[i]) {
      server->send_to_ki(m_sitting[i]->m_ki, send);
    }
  }
}

void HeekGameMgr::countdown_done(GameServer *server, bool early) {
#ifdef DEBUG_HEEK_STATE
  log_debug(server->log(), "Heek: sending countdown stop\n");
#endif
  GameMgr_OneByte_Message *stop
    = new GameMgr_OneByte_Message(m_gameid, kHeekCountdownState,
				  kHeekCountdownStop);
  server->send_to_ki(m_owner, stop);
  if (stop->del_ref() < 1) {
    delete stop; // wasn't queued
  }
  // wait for animations
#ifdef DEBUG_HEEK_STATE
  log_debug(server->log(), "HEEK %s -> STOP_WAIT\n", statename());
#endif
  m_state = STOP_WAIT;
  struct timeval timeout;
  gettimeofday(&timeout, NULL);
  timeout.tv_sec += stop_delta;
  m_timer = new HeekTimer(timeout, this, server);
  server->set_timer(m_timer);
}

void HeekGameMgr::handle_round(GameServer *server) {
  GameMgr_OneByte_Message *state
    = new GameMgr_OneByte_Message(m_gameid, kHeekInterfaceState, 0);
  // XXX we may have to only tell sitters who currently have
  // the interface enabled - if someone sat during this round
  // their interface is already disabled; find out whether the
  // client will draw it re-disabling or ignore a disable nicely
  tell_all_sitters(state, server);
  if (state->del_ref() < 1) {
    delete state; // wasn't queued
  }

  u_int i;
  // keep track of what to do next
  game_state_t next_state = ANIM_WAIT;

  // distribute points if any
  u_int rocks = 0, papers = 0, scissors = 0;
  for (i = 0; i < 5; i++) {
    if (m_sitting[i]) {
      switch (m_sitting[i]->m_choice) {
      case kHeekGameChoiceRock: /* 0 */
	rocks++;
	break;
      case kHeekGameChoicePaper: /* 1 */
	papers++;
	break;
      case kHeekGameChoiceScissors: /* 2 */
	scissors++;
	break;
      default:
	break;
      }
    }
  }
  u_int total = rocks + papers + scissors;
  if (total <= 1) {
    // do nothing
#ifdef DEBUG_HEEK_STATE
    log_debug(server->log(), "One or fewer choices, no winner\n");
#endif
    next_state = IN_GAME;
  }
  else {
    // whee, this is so much fun!
    char totals[5];
    int max = -5;
    // rules as described in
    // http://www.guildofgreeters.com/images/stories/pdf/Ahyoheek_Rules.pdf
    // except of course it doesn't mention any of the special cases, which
    // both fall out as having everyone's score == 0 (all choose the same,
    // or the three-way tie of R, P, and S)
    for (i = 0; i < 5; i++) {
      if (m_sitting[i]) {
	switch (m_sitting[i]->m_choice) {
	case kHeekGameChoiceRock:
	  totals[i] = scissors - papers;
	  max = MAX(max, totals[i]);
	  break;
	case kHeekGameChoicePaper:
	  totals[i] = rocks - scissors;
	  max = MAX(max, totals[i]);
	  break;
	case kHeekGameChoiceScissors:
	  totals[i] = papers - rocks;
	  max = MAX(max, totals[i]);
	  break;
	default:
	  totals[i] = -5;
	}
      }
    }
    u_int game_winners = 0;
    GameMgr_Heek_WinLose_Message *winlose;
    for (i = 0; i < 5; i++) {
      if (m_sitting[i] && m_sitting[i]->m_choice >= 0) {
	winlose = new GameMgr_Heek_WinLose_Message(m_gameid,
				(totals[i] > 0 && totals[i] == max),
				m_sitting[i]->m_choice);
	server->send_to_ki(m_sitting[i]->m_ki, winlose);
	if (winlose->del_ref() < 1) {
	  delete winlose; // wasn't queued
	}

	if (totals[i] > 0 && totals[i] == max) {
	  // this player is a round winner
	  u_int choice = m_sitting[i]->m_choice;
	  if (++(m_sitting[i]->m_wins[choice]) > 2) {
	    // and maybe a game winner
	    if (m_pending_winner_ct == 0) {
	      // we aren't in sudden-death mode, call this one a pending
	      // winner
	      m_sitting[i]->m_pending_winner = true;
	    }
	    game_winners++;
	    
	    // if there were two lights already, don't send a LightState
	    // message; either the player is a winner, which we don't know
	    // yet, and will get messages to flash the lights, or the player
	    // didn't win and gets no light changes
	  }
	  else {
	    // send a LightState for the point just acquired
	    u_int light = 2*choice;
	    light += m_sitting[i]->m_wins[choice] - 1;
	    GameMgr_Heek_Lights_Message *lightmsg
	      = new GameMgr_Heek_Lights_Message(m_gameid, light,
					GameMgr_Heek_Lights_Message::On);
	    server->send_to_ki(m_sitting[i]->m_ki, lightmsg);
	    if (lightmsg->del_ref() < 1) {
	      delete lightmsg; // wasn't queued
	    }
	  }
	}
      }
    }
    // now figure out data for whether there's a whole-game winner
    if (game_winners == 1 && m_pending_winner_ct == 0) {
      // we have one winner this round
    }
    else if (game_winners > 0 || m_pending_winner_ct > 0) {
      // we have multiple winners this round and/or we're in sudden death
      max = 0;
      for (i = 0; i < 5; i++) {
	if (m_sitting[i] && m_sitting[i]->m_pending_winner) {
	  // either we're in sudden death and this player is a candidate
	  // or multiple players just got a third point this round
	  totals[i] = m_sitting[i]->m_wins[0] + m_sitting[i]->m_wins[1]
		      + m_sitting[i]->m_wins[2];
	  max = MAX(max, totals[i]);
	}
      }
      // now find those who have the max
      game_winners = 0;
      for (i = 0; i < 5; i++) {
	if (m_sitting[i] && m_sitting[i]->m_pending_winner) {
	  if (totals[i] != max) {
	    // this player isn't a winner after all
	    if (m_pending_winner_ct > 0) {
	      if (m_pending_winner_ct < 2) {
		// yikes!
		log_err(server->log(),
			"Not enough pending winners in Heek sudden death!\n");
	      }
	      else {
		m_sitting[i]->m_pending_winner = false;
		m_pending_winner_ct--;
	      }
	    }
	    else {
	      m_sitting[i]->m_pending_winner = false;
	    }
	  }
	  else {
	    game_winners++;
	  }
	}
      }
    }

    if (m_pending_winner_ct == 0 && game_winners > 1) {
      // multiple winners, now enter sudden-death mode
      m_pending_winner_ct = game_winners;
    }
    else if (m_pending_winner_ct > 1) {
      // we were in sudden-death mode and still are
    }
    else if (game_winners == 1) {
      // yay, we have a winner!
      m_pending_winner_ct = 0;
      for (i = 0; i < 5; i++) {
	if (m_sitting[i] && m_sitting[i]->m_pending_winner) {
	  // send a LightState message to flash both lights
	  u_int light = 2*(int)m_sitting[i]->m_choice;
	  GameMgr_Heek_Lights_Message *lightmsg
	    = new GameMgr_Heek_Lights_Message(m_gameid, light,
					GameMgr_Heek_Lights_Message::Flash);
	  server->send_to_ki(m_sitting[i]->m_ki, lightmsg);
	  if (lightmsg->del_ref() < 1) {
	    delete lightmsg; // wasn't queued
	  }
	  light++;
	  lightmsg = new GameMgr_Heek_Lights_Message(m_gameid, light,
					GameMgr_Heek_Lights_Message::Flash);
	  server->send_to_ki(m_sitting[i]->m_ki, lightmsg);
	  if (lightmsg->del_ref() < 1) {
	    delete lightmsg; // wasn't queued
	  }

	  // the player's points are m_point_pool, which is everyone else's
	  // contribution plus this player's returned to him
	  m_sitting[i]->m_score += m_point_pool;
	  m_point_pool = 0;
	  break;
	}
	// everyone else's score has already been decremented up front
      }
      next_state = WINNER;
    }
  }

  // now, wait for the animations
  if (next_state == ANIM_WAIT || next_state == WINNER) {
#ifdef DEBUG_HEEK_STATE
    log_debug(server->log(), "HEEK %s -> %s\n", statename(),
	      next_state == ANIM_WAIT ? "ANIM_WAIT" : "WINNER");
#endif
    m_state = next_state;
    struct timeval timeout;
    gettimeofday(&timeout, NULL);
    timeout.tv_sec += anim_delta;
    m_timer = new HeekTimer(timeout, this, server);
    server->set_timer(m_timer);
  }
  else {
#ifdef DEBUG_HEEK_STATE
    log_debug(server->log(), "Heek: handle_round: no animation\n");
#endif
    countdown_idle(server);
  }
}

void HeekGameMgr::handle_winner(GameServer *server) {
  for (int i = 0; i < 5; i++) {
    if (m_sitting[i]) {
      if (m_sitting[i]->m_pending_winner) {
	m_sitting[i]->m_pending_winner = false;
	GameMgr_OneByte_Message *winmsg
	  = new GameMgr_OneByte_Message(m_gameid, kHeekGameWin,
					m_sitting[i]->m_choice);
	server->send_to_ki(m_owner, winmsg);
	if (winmsg->del_ref() < 1) {
	  delete winmsg; // wasn't queued
	}
      }
      if (m_sitting[i]->m_current_game == m_current_game) {
	GameMgr_Heek_PointUpdate_Message *update
	  = new GameMgr_Heek_PointUpdate_Message(m_gameid, true,
						 m_sitting[i]->m_score, 1);
	server->send_to_ki(m_sitting[i]->m_ki, update);
	if (update->del_ref() < 1) {
	  delete update; // wasn't queued
	}
      }
    }
  }

  // now wait for animation
#ifdef DEBUG_HEEK_STATE
  log_debug(server->log(), "HEEK %s -> WIN_WAIT\n", statename());
#endif
  m_state = WIN_WAIT;
  struct timeval timeout;
  gettimeofday(&timeout, NULL);
  timeout.tv_sec += win_delta;
  m_timer = new HeekTimer(timeout, this, server);
  server->set_timer(m_timer);
}

void HeekGameMgr::countdown_idle(GameServer *server) {
#ifdef DEBUG_HEEK_STATE
  log_debug(server->log(), "HEEK %s -> IN_GAME\n", statename());
#endif
  m_state = IN_GAME;
  // tell the owner about the idle state
  GameMgr_OneByte_Message *msg
    = new GameMgr_OneByte_Message(m_gameid, kHeekCountdownState,
				  kHeekCountdownIdle);
  server->send_to_ki(m_owner, msg);
  if (msg->del_ref() < 1) {
    delete msg; // wasn't queued
  }
  if (m_sitting_ct > 1) {
    msg = new GameMgr_OneByte_Message(m_gameid, kHeekInterfaceState, 1);
    tell_all_sitters(msg, server);
    if (msg->del_ref() < 1) {
      delete msg; // wasn't queued
    }
  }
}

void HeekGameMgr::handle_departure(int position, GameServer *server) {
  if (m_sitting_ct == 1) {
    // last player, reset the game
#ifdef DEBUG_HEEK_STATE
    log_debug(server->log(), "Heek: last player gone\n");
#endif
    reset_game();
    if (m_state == COUNTDOWN) {
      // could happen if two stand up in quick succession during countdown
      countdown_done(server, true);
    }
    else {
#ifdef DEBUG_HEEK_STATE
      log_debug(server->log(), "HEEK %s -> IDLE\n", statename());
#endif
      m_state = IDLE;
    }
  }
  if (m_sitting[position]->m_choice >= 0) {
    if (m_state > IN_GAME && m_choice_ct > 0) {
      m_choice_ct--;
#ifdef DEBUG_HEEK_STATE
      log_debug(server->log(), "Heek: %u choice%s now\n",
		m_choice_ct, m_choice_ct == 1 ? "" : "s");
#endif
    }
    m_sitting[position]->m_choice = -1;
  }
  // disable the interface if necessary
  // (it's not enabled if state >= ANIM_WAIT)
  if (m_state < ANIM_WAIT) {
    GameMgr_OneByte_Message *state
      = new GameMgr_OneByte_Message(m_gameid, kHeekInterfaceState, 0);
    // if there is only one at the table, the interface is already disabled
    if (m_sitting_ct < 2) {
    }
    // if there are two at the table, disable everyone's interface because
    // there will only be one now
    else if (m_sitting_ct == 2) {
      for (int i = 0; i < 5; i++) {
	if (m_sitting[i]) {
	  server->send_to_ki(m_sitting[i]->m_ki, state);
	}
      }
    }
    // if there are more than two at the table, only disable the departing
    // player's interface
    else if (m_sitting_ct > 2) {
      server->send_to_ki(m_sitting[position]->m_ki, state);
    }
    if (state->del_ref() < 1) {
      delete state;
    }
  }
  if (m_sitting[position]->m_pending_winner) {
    // a winner no more
    m_sitting[position]->m_pending_winner = false;
    if (m_pending_winner_ct > 0) {
      // ouch, and he just lost all the points
      m_pending_winner_ct--;
    }
  }
  m_sitting[position] = NULL;
  if (m_sitting_ct > 0) {
    m_sitting_ct--;
  }
  else {
    // XXX WHOA! shouldn't ever happen
  }
#ifdef DEBUG_HEEK_STATE
  log_debug(server->log(), "Heek: number sitting now %u\n", m_sitting_ct);
#endif
}

void HeekGameMgr::handle_timeout(GameServer *server) {
  if (m_state == COUNTDOWN) {
#ifdef DEBUG_HEEK_STATE
    log_debug(server->log(), "Heek: timeout in COUNTDOWN\n");
#endif
    if (m_choice_ct > 1) {
      countdown_done(server, false);
    }
    else {
      // only one person participated, go to idle
      countdown_idle(server);
    }
  }
  else if (m_state == STOP_WAIT) {
#ifdef DEBUG_HEEK_STATE
    log_debug(server->log(), "Heek: timeout in STOP_WAIT\n");
#endif
    m_timer = NULL;
    handle_round(server);
  }
  else if (m_state == ANIM_WAIT) {
#ifdef DEBUG_HEEK_STATE
    log_debug(server->log(), "Heek: timeout in ANIM_WAIT\n");
#endif
    m_timer = NULL;
    countdown_idle(server);
  }
  else if (m_state == WINNER) {
#ifdef DEBUG_HEEK_STATE
    log_debug(server->log(), "Heek: timeout in WINNER\n");
#endif
    handle_winner(server);
  }
  else if (m_state == WIN_WAIT) {
#ifdef DEBUG_HEEK_STATE
    log_debug(server->log(), "Heek: timeout in WIN_WAIT\n");
#endif
    m_timer = NULL;
    countdown_idle(server);
#ifdef DEBUG_HEEK_STATE
    log_debug(server->log(), "HEEK %s -> IDLE (game complete)\n",
	      statename());
#endif
    m_state = IDLE;
  }
}

GameMgr * GameState::setup_manager_for(kinum_t player, const u_char *uuid,
				       bool &needs_new_id,
				       uint32_t id1, uint32_t id2) {
  needs_new_id = true;
  std::list<GameMgr*>::iterator iter;
  if (!memcmp(uuid, VarSync_UUID, UUID_RAW_LEN)) {
    // use global game
    for (iter = m_age_games.begin(); iter != m_age_games.end(); iter++) {
      GameMgr *mgr = *iter;
      if (mgr->type() == VarSync) {
	// this is the one
	needs_new_id = false;
	return mgr;
      }
    }
    // here we have to make a new game
    GameMgr *mgr = new VarSyncGameMgr(0);
    m_age_games.push_back(mgr);
    m_waiting_games.push_back(mgr);
    return mgr;
  }
  else if (!memcmp(uuid, Marker_UUID, UUID_RAW_LEN)) {
    // clear out any previous games for this player
    for (iter = m_marker_games.begin(); iter != m_marker_games.end(); ) {
      GameMgr *mgr = *iter;
      if (mgr->owner() == player) {
	m_waiting_games.remove(mgr);
	delete mgr;
	iter = m_marker_games.erase(iter);
      }
      else {
	iter++;
      }
    }
    // here we have to make a new game
    MarkerGameMgr *mmgr = new MarkerGameMgr(0, id1, id2);
    m_marker_games.push_back(mmgr);
    m_waiting_games.push_back(mmgr);
    return mmgr;
  }
  else if (!memcmp(uuid, BlueSpiral_UUID, UUID_RAW_LEN)) {
    // use global game
    for (iter = m_age_games.begin(); iter != m_age_games.end(); iter++) {
      GameMgr *mgr = *iter;
      if (mgr->type() == BlueSpiral) {
	// this is the one
	needs_new_id = false;
	return mgr;
      }
    }
    // here we have to make a new game
    GameMgr *mgr = new BlueSpiralGameMgr(0);
    m_age_games.push_back(mgr);
    m_waiting_games.push_back(mgr);
    return mgr;
  }
  else if (!memcmp(uuid, Heek_UUID, UUID_RAW_LEN)) {
    // use global game
    for (iter = m_age_games.begin(); iter != m_age_games.end(); iter++) {
      GameMgr *mgr = *iter;
      if (mgr->type() == Heek) {
	// this is the one
	needs_new_id = false;
	return mgr;
      }
    }
    // here we have to make a new game
    GameMgr *mgr = new HeekGameMgr(0);
    m_age_games.push_back(mgr);
    m_waiting_games.push_back(mgr);
    return mgr;
  }
  else {
    // unsupported game type
    return NULL;
  }
}

GameMgr * GameState::get_manager_by_id(uint32_t game_id) {
  std::list<GameMgr*>::iterator iter;
  for (iter = m_age_games.begin(); iter != m_age_games.end(); iter++) {
    GameMgr *mgr = *iter;
    if (mgr->id() == game_id) {
      // this is the one
      return mgr;
    }
  }
  for (iter = m_marker_games.begin(); iter != m_marker_games.end(); iter++) {
    GameMgr *mgr = *iter;
    if (mgr->id() == game_id) {
      // this is the one
      return mgr;
    }
  }
  return NULL;
}

void GameState::player_left(kinum_t player) {
  std::list<GameMgr*>::iterator iter;
  for (iter = m_marker_games.begin(); iter != m_marker_games.end(); ) {
    MarkerGameMgr *mmgr = (MarkerGameMgr *)*iter;
    if (mmgr->owner() == player) {
      m_waiting_games.remove(mmgr);
      delete mmgr;
      iter = m_marker_games.erase(iter);
    }
    else {
      iter++;
    }
  }
}

const char * GameMgr::type_str(const game_type_t type) {
  switch(type) {
  case VarSync:
    return "VarSync";
  case Marker:
    return "Marker";
  case BlueSpiral:
    return "BlueSpiral";
  case Heek:
    return "Heek";
  case Invalid:
    return "Invalid";
  default:
    return "Unknown";
  }
}

void GameMgr::player_left(kinum_t player, GameServer *server) {
  remove_player(player);
  if (player == m_owner) {
    find_new_owner(server);
  }
}

void GameMgr::save_setup_msg(GameMgrMessage *msg, kinum_t player) {
  msg->make_own_copy();
  m_setups.push_back(std::pair<GameMgrMessage*,kinum_t>(msg, player));
}

void GameMgr::assign_id(uint32_t new_id, GameServer *server) {
  m_gameid = new_id;
  std::list<std::pair<GameMgrMessage*,kinum_t> >::iterator iter;
  for (iter = m_setups.begin(); iter != m_setups.end(); iter++) {
    GameMgrMessage *mgr = iter->first;
    initialize_game(mgr, iter->second, server);
    if (mgr->del_ref() < 1) {
      delete mgr;
    }
  }
  // this is not strictly necessary, as the list destructor will clean up,
  // but just in case we reuse the list somehow, clear it now
  m_setups.clear();
}

void GameMgr::send_setup_reply(const GameMgrMessage *msg, kinum_t player,
			       GameServer *server) {
  GameMgr_Setup_Reply *rmsg = new GameMgr_Setup_Reply(m_gameid, msg->reqid(),
						      m_owner,
						      msg->setup_uuid());
  server->send_to_ki(player, rmsg);
  if (rmsg->del_ref() < 1) {
    delete rmsg;
  }
}

void GameMgr::send_join(kinum_t player, GameServer *server) {
  GameMgr_FourByte_Message *msg
    = new GameMgr_FourByte_Message(m_gameid, kGameCliPlayerJoinedMsg, player);
  send_to_all(msg, server);
  if (msg->del_ref() < 1) {
    delete msg; // wasn't queued
  }
  msg = new GameMgr_FourByte_Message(m_gameid, kGameCliOwnerChangeMsg,
				     m_owner);
  server->send_to_ki(player, msg);
  if (msg->del_ref() < 1) {
    delete msg; // wasn't queued
  }
}

void GameMgr::add_player(kinum_t player) {
  std::list<kinum_t>::iterator iter;
  for (iter = m_players.begin(); iter != m_players.end(); iter++) {
    if (*iter == player) {
      return;
    }
  }
  m_players.push_back(player);
}

void GameMgr::remove_player(kinum_t player) {
  std::list<kinum_t>::iterator iter;
  for (iter = m_players.begin(); iter != m_players.end(); iter++) {
    if (*iter == player) {
      m_players.erase(iter);
      return;
    }
  }
}

void GameMgr::find_new_owner(GameServer *server) {
  if (m_players.size() == 0) {
    m_owner = 0;
  }
  else {
    m_owner = m_players.front();
    log_msgs(server->log(), "Announcing new owner kinum=%u for GameMgr %u\n",
	     m_owner, m_gameid);
    // now announce the new owner
    GameMgr_FourByte_Message *msg
      = new GameMgr_FourByte_Message(m_gameid, kGameCliOwnerChangeMsg,
				     m_owner);
    send_to_all(msg, server);
    if (msg->del_ref() < 1) {
      delete msg;
    }
  }
}

void GameMgr::send_to_all(NetworkMessage *msg, GameServer *server) {
  std::list<kinum_t>::iterator iter;
  for (iter = m_players.begin(); iter != m_players.end(); iter++) {
    server->send_to_ki(*iter, msg);
  }
}
