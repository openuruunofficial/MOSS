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
 * This file contains the data structures used in the game server for
 * handling state coming from clients.
 */

#ifndef _GAME_HANDLER_H_
#define _GAME_HANDLER_H_

//#include <list>
//
//#include "Logger.h"
//
//#include "GameMessage.h"
//
//#include "GameState.h"
//#include "GameServer.h"

/*
 * This struct is just a container for function pointers for each
 * PropagateBufferMessage subtype that is handled. The functions are
 * called by the GameServer.
 */
typedef struct {
  // This should return true when the message is fully handled,
  // INCLUDING correctness checking.
  bool (*msg_handled)(PropagateBufferMessage *msg);

  // To prevent serious server bugs, a message must be fully checked for
  // correctness (primarily but not exclusively that it is not truncated),
  // or, if the useable check is sparse, the parser must be able to handle
  // truncated messages without running off the end of the buffer.
  bool (*check_useable)(PropagateBufferMessage *msg);

  // This function is called if the useability check succeeds, and should
  // modify GameState if necessary, even the contents of the buffer if a
  // modified version should be kept around. If the message is kept around,
  // don't forget use add_ref(). If a message is to be sent back to the
  // client, queue it on the connection. Return true if the message (as it
  // is now) should be redistributed to all other clients. This will result
  // in the Timestamp being set in the message, if present.
  bool (*handle_message)(PropagateBufferMessage *msg,
			 GameState *state,
			 GameServer::GameConnection *conn,
			 Logger *log);
} propagate_handler;

// called to get a struct pointer based on the type
propagate_handler *get_propagate_handler(uint16_t subtype);


/*
 * The GameMgr class represents a given "game" instance, and keeps all data
 * required for that game. Subclasses will represent each game type.
 */
typedef enum {
  Invalid = 0,
  VarSync = 1,
  Marker = 2,
  BlueSpiral = 3,
  Heek = 4
} game_type_t;

class GameMgr {
public:
  // this is called after a setup message is received
  // returns false if the message was too short
  virtual bool initialize_game(const GameMgrMessage *msg, kinum_t player,
			       GameServer *server) = 0;
  // this is called when a message is received
  // returns false if the message is not handled, throws truncated_message
  virtual bool got_message(GameMgrMessage *msg, kinum_t player,
			   GameServer *server) = 0;
  // this is called when any player leaves the age
  // returns true if this player was the owner
  virtual void player_left(kinum_t player, GameServer *server);
  // function for receiving data from the backend (currently only used for
  // marker games)
  virtual bool process_backend_message(NetworkMessage *in,
				       GameServer *server) { return false; }
  // this function is called when the GameMgr doesn't have a unique ID yet
  virtual void save_setup_msg(GameMgrMessage *msg, kinum_t player);
  // this function is called to assign the game ID to a game currently
  // with none (in which case id() returns 0)
  virtual void assign_id(uint32_t new_id, GameServer *server);
  // send a message to all currently joined to this game
  virtual void send_to_all(NetworkMessage *msg, GameServer *server);

  virtual ~GameMgr() { };

  uint32_t id() const { return m_gameid; }
  game_type_t type() const { return m_type; }
  kinum_t owner() const { return m_owner; }

  static const char * type_str(const game_type_t type);

protected:
  GameMgr(uint32_t gameid, game_type_t type)
    : m_gameid(gameid), m_type(type), m_owner(0)
  { }

  uint32_t m_gameid;
  game_type_t m_type;
  kinum_t m_owner;
  std::list<kinum_t> m_players;

  // saved setup messages (waiting for unique gameid)
  std::list<std::pair<GameMgrMessage*,kinum_t> > m_setups;

  // subclass initialize_game functions can use these
  virtual void send_setup_reply(const GameMgrMessage *msg, kinum_t player,
				GameServer *server);
  virtual void send_join(kinum_t player, GameServer *server);
  void add_player(kinum_t player);
  // player_left functions can use these
  void remove_player(kinum_t player);
  virtual void find_new_owner(GameServer *server);
};

#endif /* _GAME_HANDLER_H_ */
