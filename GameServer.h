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
 * GameServer is the class representing a game server. It has a backend
 * connection to the vault/tracking server, and (possibly) multiple client
 * connections.
 */

#ifndef _GAME_SERVER_H_
#define _GAME_SERVER_H_

//#include <sys/time.h>
//
//#include <netinet/in.h>
//
//#include <deque>
//#include <list>
//
//#include "Buffer.h"
//
//#include "Logger.h"
//#include "SDL.h"
//#include "GameMessage.h"
//#include "BackendMessage.h"
//
//#include "moss_serv.h"
//#include "GameState.h"

class GameServer : public Server {
public:
  GameServer(const char *server_dir, bool is_a_thread,
	     struct sockaddr_in &vault_address,
	     const u_char *uuid, const char *filename,
	     uint32_t connect_ipaddr,
	     AgeDesc *age, std::list<SDLDesc*> &sdl);
  virtual ~GameServer();

  int type() const { return TYPE_GAME; }
  const char * type_name() const { return "game"; }

  int init();
  bool shutdown(reason_t reason);

  reason_t message_read(Connection *conn, NetworkMessage *msg);

  void conn_completed(Connection *conn);

  reason_t conn_timeout(Connection *conn, reason_t why);
  reason_t conn_shutdown(Connection *conn, reason_t why);

  // protocol info
  typedef enum {
    START = 0,
    NEGOTIATION_DONE = 1,
    NONCE_DONE = 2,
    JOIN_REQ = 3,
    JOINED = 4,
    HAVE_CLONE = 5,
    MEMBERS_REQUESTED = 6,
    STATE_REQUESTED = 7,
    IN_GAME = 8,
    KILL_AFTER_QUEUE_EMPTY = 255
  } state_t;

  class GameConnection : public Server::Connection {
  public:
    GameConnection(int the_fd, Logger *log)
      : Connection(the_fd), m_state(START), m_kinum(0), m_log(log)
    {
      m_interval = KEEPALIVE_INTERVAL*4;
      gettimeofday(&m_timeout, NULL);
      m_timeout.tv_sec += m_interval;
      memset(m_client_uuid, 0, UUID_RAW_LEN);
      m_key.make_null();
    }
    virtual ~GameConnection() { m_key.delete_name(); }
    state_t state() const { return m_state; }
    void set_state(state_t s);
    NetworkMessage * make_if_enough(const u_char *buf, size_t len,
				    int *want_len, bool become_owner=false);
    void set_logger(Logger *log) { m_log = log; }

    /*
     * Additional accessors
     */
    const u_char * client_uuid() const { return m_client_uuid; }
    kinum_t kinum() const { return m_kinum; }
    const PlKey & plKey() const { return m_key; }
    UruString & player_name() { return m_player_name; }

    void set_kinum(kinum_t ki) { m_kinum = ki; }
    void set_uuid(const u_char *uuid) {
      memcpy(m_client_uuid, uuid, UUID_RAW_LEN);
    }
    void set_key(const PlKey &key);

  protected:
    state_t m_state;

    u_char m_client_uuid[UUID_RAW_LEN];
    kinum_t m_kinum;
    UruString m_player_name;
    PlKey m_key;

  private:
    Logger *m_log;
  };

  /*
   * Game server-specific functionality
   */
  // the following three are called only by the dispatcher, as it needs to
  // handle connections until it is known which game server to pass them
  // to, and then pass them on
  static reason_t handle_negotiation(GameConnection *conn,
				     const void *keydata, NetworkMessage *in,
				     Logger *log, uint32_t &sid);
  static void send_no_join(Connection *conn, const NetworkMessage *msg);
#ifndef FORK_GAME_TOO
  void queue_client_connection(GameConnection *conn, NetworkMessage *msg);
  // this is called by the GameSignalProcessor to complete the handoff
  void get_queued_connections();
#else
  // this connection is used for both ends of the socket-based protocol
  // between the dispatcher and game servers, which is why it's defined
  // here
  class DispatcherConnection : public Server::Connection {
  public:
    DispatcherConnection(int the_fd, Logger *log, int other_fd=-1)
      : Connection(the_fd), m_log(log), m_other_fd(other_fd) { }
    NetworkMessage * make_if_enough(const u_char *buf, size_t len,
				    int *want_len, bool become_owner=false);
    virtual ~DispatcherConnection() { if (m_other_fd >= 0) close(m_other_fd); }
    // this function will arrange to forward all necessary connection state to
    // the game server, before deleting game_conn
    void forward_conn(GameConnection *game_conn);
  protected:
    int m_other_fd;
  };
#endif /* !FORK_GAME_TOO */

  // the following two functions should only be called by GameMgrs with
  // GameMgrMessages; the functions call msg->add_ref() for each
  // connection, and return false if the message was not queued
  bool send_to_ki(kinum_t kinum, NetworkMessage *msg);
  bool send_to_vault(BackendMessage *msg);
  // the following is also intended for GameMgrs
  void set_timer(TimerQueue::Timer *timer);

protected:
  // backend connection(s)
  struct sockaddr_in m_vault_addr;
  Connection *m_vault;

  reason_t backend_message(Connection *conn, BackendMessage *msg);

  /*
   * timers
   */
  TimerQueue *m_timers;
  class GameTimer : public TimerQueue::Timer {
  public:
    typedef enum {
      SHUTDOWN = 0,
      CLIENT_JOIN = 1
    } timer_type_t;
    GameTimer(struct timeval &when, timer_type_t type)
      : Timer(when), m_type(type) { }
    timer_type_t type() const { return m_type; }
  protected:
    timer_type_t m_type;
  };

  // the ShutdownTimer is for shutting down the game server after it is
  // idle for LingerTime
  bool m_timed_shutdown;
  class ShutdownTimer : public GameTimer {
  public:
    ShutdownTimer(struct timeval &when, bool &do_shutdown)
      : GameTimer(when, SHUTDOWN), m_shutdown(do_shutdown) { }
    void callback() { m_shutdown = true; }
  protected:
    bool &m_shutdown;
  };
  // be careful accessing this: only dereference it if it is not NULL *and*
  // m_timed_shutdown is false (if it's true, the timer has fired and this
  // is a dangling pointer!)
  ShutdownTimer *m_shutdown_timer;
  // functions for manipulating the shutdown timer
  void cancel_shutdown_timer();
  void maybe_start_shutdown_timer();

  /*
   * new connection state tracking
   */
#ifndef STANDALONE
  // we have to keep track of the clients tracking is sending our way so
  // that we can validate them when we connect, and so that we know their
  // avatar names, plus we need to time the "future" connections out if they
  // never happen
  class JoinTimer : public GameTimer {
  public:
    JoinTimer(struct timeval &when, u_int &server_joiners,
	      kinum_t kinum, const u_char *uuid, UruString *str)
      : GameTimer(when, CLIENT_JOIN), m_kinum(kinum), m_name(*str),
	m_joiners(server_joiners)
    {
      m_joiners++;
      memcpy(m_acct_uuid, uuid, UUID_RAW_LEN);
    }
    // as the timer itself represents the registration of the client, the
    // "registration" is automatically deleted after this when the timer is
    // deleted -- the only thing is, we may need to start the shutdown timer
    void callback() { if (m_joiners > 0) m_joiners--; }

    kinum_t m_kinum;
    u_char m_acct_uuid[UUID_RAW_LEN];
    UruString m_name;
  protected:
    u_int &m_joiners;
  };
#endif /* !STANDALONE */
  u_int m_joiners;

#ifndef FORK_GAME_TOO
  // this little dance is to allow new connections to be added asynchronously
  // by the dispatcher, without requiring adding locking to m_conns; instead
  // we lock this m_client_queue and so we only need to grab locks in the
  // process of adding a game client instead of every time we look at the
  // connection list
  pthread_mutex_t m_client_queue_mutex;
  std::deque<std::pair<GameConnection*,NetworkMessage*> > *m_client_queue;
  int m_fake_signal;
  class GameSignalProcessor : public SignalProcessor {
  public:
    reason_t signalled(int *todo, Server *s);
  };
  GameSignalProcessor m_signal_processor;
#endif /* !FORK_GAME_TOO */

  /*
   * per-age data
   */
  u_char m_age_uuid[16];
  char *m_filename;
  AgeDesc *m_age;
  std::list<SDLDesc*> m_agesdl;

  // dynamic per-age data
  kinum_t m_group_owner;
  GameState m_game_state;
};

#endif /* _GAME_SERVER_H_ */
