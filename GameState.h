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
 * The purpose of this file is to logically separate the game state from
 * all the connection goo.
 */

#ifndef _GAME_STATE_H_
#define _GAME_STATE_H_

//#include <sys/time.h>
//
//#include <list>
//
//#include "PlKey.h"
//
//#include "SDL.h"
//
//#include "moss_serv.h"

// forward declarations
class GameMgr;

/*
 * There is one of these per game server. Nearly all the dynamic state from
 * clients is kept here.
 */
class GameState {
  friend class GameServer;

public:
  GameState() { }
  ~GameState();

  /*
   * SDL
   */
  const std::list<SDLDesc*> & sdl_descs() const { return m_allsdl; }
  std::list<SDLState*>::const_iterator sdl_begin() { return m_sdl.begin(); }
  std::list<SDLState*>::const_iterator sdl_end() { return m_sdl.end(); }
  // returns NULL if not found
  SDLState * find_sdl_like(SDLState *new_sdl) const;
  void add_sdl(SDLState *new_sdl);

  /*
   * Kickables
   */
#define SDL_FILTER_TIME_SECS 1
#define SDL_FILTER_TIME_USECS 150000
  typedef struct {
    SDLState *master;
    struct timeval switch_at;
    kinum_t from_who;
    // other stuff for more advanced filtering?
    // e.g. newest message not from from_who, to use after a timeout
  } sdl_filter_t;
  // call this at init time, after the age state is loaded
  void setup_filter();
  // this returns the filter object, creating a new one (and putting the
  // state in the regular SDL list) if necessary
  sdl_filter_t & get_filter(SDLState *new_sdl);

  /*
   * Server-mediated synchronization locks
   */
  bool try_lock(PlKey &key, kinum_t ki);
  bool clear_lock(PlKey &key, kinum_t ki);

  /*
   * GameMgr stuff -- Heek, Quabs, Markers, Blue Spiral, etc.
   */
  // this returns NULL if the game type is not supported
  GameMgr * setup_manager_for(kinum_t player, const u_char *uuid,
			      bool &needs_new_id,
			      /* next two for marker games */
			      uint32_t id1, uint32_t id2);
  // this returns NULL if there isn't a manager with that ID
  GameMgr * get_manager_by_id(uint32_t game_id);
  // this is called when a player leaves the age (for cleanup of marker games)
  void player_left(kinum_t player);

protected:
  std::list<SDLDesc*> m_allsdl; // do not delete contents!
  std::list<SDLState*> m_sdl; // do not delete contents!

  /*
   * Keep extra information for kickables so we can do filtering
   */
  std::list<sdl_filter_t> m_physicals;

  /*
   * Manage region/object locks (plNetMsgTestAndSet)
   */
  class ObjectLock {
  public:
    PlKey key;
    kinum_t who;
    u_int lockseq;
    ObjectLock(PlKey &plkey);
    ~ObjectLock() { key.delete_name(); }
  };
  std::list<ObjectLock*> m_locks;
  class ClearLockTimer : public Server::TimerQueue::Timer {
  public:
    ClearLockTimer(struct timeval &when, ObjectLock *lock)
      : Timer(when), m_lock(lock), m_lockseq(lock->lockseq) { }
    void callback();
  protected:
    ObjectLock *m_lock;
    u_int m_lockseq;
  };
  // GameServer's timer queue
  Server::TimerQueue *m_timers; // do not delete!

  /*
   * GameMgr
   */
  std::list<GameMgr*> m_age_games; // typically only one for a given age
  std::list<GameMgr*> m_marker_games;
  std::list<GameMgr*> m_waiting_games; // those needing a new ID
};

#endif /* _GAME_STATE_H_ */
