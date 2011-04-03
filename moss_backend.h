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
 * BackendServer is the class for a backend server. There are three kinds
 * of backend server: auth, vault, and tracking.
 *
 * At the moment all three are handled by one server, but they could be
 * split up.
 */

//#include <sys/time.h>
//
//#include <stdexcept>
//#include <map>
//#include <vector>
//
//#include "backend_typecodes.h"
//#include "UruString.h"
//
//#include "BackendMessage.h"
//
//#include "moss_serv.h"

#ifndef _MOSS_BACKEND_H_
#define _MOSS_BACKEND_H_

// the definition of this is in db_requests.h because I was trying to
// keep all the DB-specific stuff there
class BackendObj;

class BackendServer : public Server {
public:
  BackendServer(int listen_fd, uint32_t ipaddr,
		const char *db_address, const int db_port,
		const char *db_user, const char *db_password,
		const char *db_name, const char *db_params,
		const u_int &egg_mask)
    : Server(listen_fd, ipaddr), my(NULL), m_egg_mask(egg_mask),
      m_db_addr(db_address), m_db_port(db_port), m_db_params(db_params),
      m_db_user(db_user), m_db_passwd(db_password), m_db_name(db_name),
      m_next_dispatcher(0), m_next_file(0), m_next_auth(0),
      m_timers(NULL), m_next_gameid(100) { }
  virtual ~BackendServer();

  int type() const { return CLASS_AUTH|CLASS_VAULT|CLASS_TRACK|CLASS_ADMIN; }
  const char * type_name() const { return "Backend"; }

  int init();
  bool shutdown(reason_t reason);

  reason_t message_read(Connection *conn, NetworkMessage *msg);

  void add_client_conn(int fd, u_char first);
  reason_t conn_timeout(Connection *conn, reason_t why);
  reason_t conn_shutdown(Connection *conn, reason_t why);

protected:
  BackendObj *my;
  const u_int &m_egg_mask;

  // "arguments"
  const char *m_db_addr;
  const int m_db_port;
  const char *m_db_params;
  const char *m_db_user;
  const char *m_db_passwd;
  const char *m_db_name; // database name


  // this is the key for the connection ID hash table
  class HashKey {
  public:
    HashKey(uint32_t id1, uint32_t id2)
      : m_key((((uint64_t)id1) << 32) | id2) { }
    HashKey(const HashKey &other) : m_key(other.m_key) { }
    HashKey() : m_key(0) { }
    HashKey & operator=(const HashKey &other) {
      if (this != &other) m_key = other.m_key;
      return *this;
    }
    bool operator<(const HashKey &other) const {
      return (m_key < other.m_key);
    }
    uint32_t id1() const { return (uint32_t)(m_key >> 32); }
    uint32_t id2() const { return (uint32_t)(m_key & 0xffffffff); }
  private:
    uint64_t m_key;
  };
  // this is the per-connection entity state; note that a "connection entity"
  // does not necessarily have a 1:1 mapping to a Connection object from the
  // select loop (in theory groups of frontend servers can use a single TCP
  // connection) so the pointer for that is stored in this object
  class ConnectionEntity {
  public:
    ConnectionEntity(Connection *c, uint32_t type)
      : m_conn(c), m_type(type), m_kinum(0),
	m_id(0), m_ipaddr(0), m_shutdown(false), m_players(0) {
      
      memset(m_uuid, 0, UUID_RAW_LEN);
    }

    // where do I queue messages?
    Connection * conn() const { return m_conn; }
    // type of server
    uint32_t type() const { return m_type; }
    // for auth, game connections
    void set_uuid(const u_char *uuid) {
      memcpy(m_uuid, uuid, UUID_RAW_LEN);
    }
    const u_char * uuid() const { return m_uuid; }

    // this data is for *game* servers -- if it's a game connection it's
    // the server's ID, but if it's an auth connection, it's the game
    // server's ID for where the player most recently joined
    uint32_t ipaddr() const { return m_ipaddr; }
    void set_ipaddr(uint32_t ipaddr) { m_ipaddr = ipaddr; }
    uint32_t server_id() const { return m_id; }
    void set_server_id(uint32_t id) { m_id = id; }

    // for auth connections only
    void set_kinum(kinum_t kinum) { m_kinum = kinum; }
    kinum_t kinum() const { return m_kinum; }
    UruString &name() { return m_name; }
    // fnord
    bool egg1(bool yesno) {
      if (yesno && ++m_players == 3) return true;
      if (!yesno && m_players) m_players = 0;
      return false;
    }

    // for game connections only
    bool in_shutdown() const { return m_shutdown; }
    void set_in_shutdown() { m_shutdown = true; }
    u_int player_count() const { return m_players; }
    void bump_count() { m_players++; }
    void drop_count() { if (m_players > 0) m_players--; }

  protected:
    Connection *m_conn;
    uint32_t m_type;
    u_char m_uuid[UUID_RAW_LEN];
    kinum_t m_kinum;
    UruString m_name;
    uint32_t m_id;
    uint32_t m_ipaddr; // host order
    bool m_shutdown;
    u_int m_players;
  private:
    ConnectionEntity() { };
  };

  /*
   * keep track of all the state from different connection entities
   */
  // XXX this should be a hash_map but that's nonstandard; unordered_map is
  // up-and-coming but let's just use map for now
  std::map<HashKey,ConnectionEntity*> m_hash_table;
  // more to come -- vault refs tree cache

  /*
   * tracking server state
   *
   * XXX Right now the tracking server is very ad-hoc and inefficient,
   * because the inefficiency is really not an issue for single-player.
   * Really we should maintain a second hash table going from UUID to
   * ConnectionEntity, we should maintain a two-way mapping of
   * auth<->game servers, the method of choosing the next dispatcher
   * should be handled much better, etc.
   */
  class DispatcherInfo {
  public:
    DispatcherInfo(uint32_t id1, uint32_t id2, Connection *conn)
      : m_id1(id1), m_id2(id2), m_conn(conn),
	m_accepting_new_game_servers(false),
	m_handles_file_service(false), m_handles_auth_service(false),
	m_use_fa_hostname(true), m_fa_ipaddr(0) { }
    uint32_t m_id1, m_id2;
    Connection *m_conn;
    // statistics (TRACK_STATUS) here, if we ever care about load-balancing
    bool m_accepting_new_game_servers;
    bool m_handles_file_service, m_handles_auth_service;
    bool m_use_fa_hostname;
    uint32_t m_fa_ipaddr;
    UruString m_fa_hostname;
  };
  std::vector<DispatcherInfo*> m_dispatchers;
  u_int m_next_dispatcher, m_next_file, m_next_auth;
  KillClient_BackendMessage::kill_reason_t
       handle_age_request(const u_char *age_uuid, UruString *filename,
			  bool force_new, uint32_t user_id1, uint32_t user_id2,
			  uint32_t reqid);
  class Waiter : public TimerQueue::Timer {
  public:
    Waiter(struct timeval &timeout, BackendServer *me,
	   uint32_t id1, uint32_t id2, uint32_t reqid, kinum_t ki,
	   UruString &name, const u_char *acctuuid, const u_char *age_uuid,
	   uint32_t nodeid)
      : Timer(timeout), m_server(me),
	m_id1(id1), m_id2(id2), m_reqid(reqid), m_kinum(ki), m_node(nodeid)
    {
      // make sure the Waiter has a copy in case the ConnectionEntity
      // goes away
      m_name = name.c_str();
      memcpy(m_acctuuid, acctuuid, UUID_RAW_LEN);
      memcpy(m_ageuuid, age_uuid, UUID_RAW_LEN);
    }
    void callback();

    BackendServer *m_server;
    uint32_t m_id1, m_id2;
    uint32_t m_reqid;
    kinum_t m_kinum;
    UruString m_name;
    u_char m_acctuuid[UUID_RAW_LEN];
    uint32_t m_node;
    u_char m_ageuuid[UUID_RAW_LEN];
  };
  TimerQueue *m_timers;

  // utility functions
  status_code_t set_player_offline(kinum_t ki, const char *why);
  // the node change/add/remove functions are currently (inlined) wrappers
  // around one workhorse; this is just meant to make code easier to read,
  // while allowing for them to change if necessary
  typedef enum {
    CHANGED,
    ADDED,
    REMOVED
  } prop_type_t;
  void propagate_change_to_interested(uint32_t nodeid,
				      // if transuuid is NULL one is generated
				      const u_char *transuuid,
				      bool check_age) {
    propagate_to_interested(CHANGED, nodeid, 0, 0, transuuid, check_age);
  }
  void propagate_add_to_interested(uint32_t parent, uint32_t child,
				   uint32_t ownerid, bool check_age) {
    propagate_to_interested(ADDED, parent, child, ownerid, NULL, check_age);
  }
  void propagate_remove_to_interested(uint32_t parent, uint32_t child,
				      bool check_age) {
    propagate_to_interested(REMOVED, parent, child, 0, NULL, check_age);
  }
  void propagate_to_interested(prop_type_t t, uint32_t nodeid,
			       uint32_t child, uint32_t ownerid,
			       const u_char *transuuid, bool check_age);
  // we have a special function for player delete, because the relative
  // complexity of what updates need to be sent has been put into the DB
  void propagate_player_delete_to_interested(
				std::multimap<kinum_t,uint32_t> &notify,
				uint32_t child);

  // operations on our inefficient data structure
  ConnectionEntity * find_by_kinum(kinum_t ki, uint32_t type);
  ConnectionEntity * find_by_uuid(const u_char *uuid, uint32_t type);

  // for GameMgrs
  u_int m_next_gameid;

  /*
   * helper functions
   */
  reason_t handle_auth(Connection *c, BackendMessage *in);
  reason_t handle_vault(Connection *c, BackendMessage *in);
  reason_t handle_admin(Connection *c, BackendMessage *in);
  reason_t handle_track(Connection *c, BackendMessage *in);
  reason_t handle_marker(Connection *c, BackendMessage *in);


  /*
   * If the backend server talks to a database or any other kind of service,
   * the socket used for communication has to be managed by the select loop.
   */
  /*
   * Currently UNUSED. We are using synchronous DB access. This will be
   * chnged only if we actually need to do so.
   */
  class DBConnection : public Connection {
  public:
    // XXX
    virtual NetworkMessage * make_if_enough(const u_char *buf, size_t len,
					    int *want_len,
					    bool become_owner=false);
  };
};

#endif /* _MOSS_BACKEND_H_ */
