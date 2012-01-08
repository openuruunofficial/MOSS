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
 * Encoding of objects used to get results from the DB, and the DB-dependent
 * routines to fill them in.
 */

//#ifdef USE_POSTGRES
//#ifdef USE_PQXX
//#include <pqxx/pqxx>
//#include <pqxx/binarystring>
//#else
//#include <libpq-fe.h>
//#endif
//#endif
//
//#include <stdio.h>
//#include <string.h>
//
//#include <list>
//#include <vector>
//#include <sstream>
//#include <map>
//
//#include "protocol.h"
//#include "machine_arch.h"
//#include "util.h"
//#include "UruString.h"
//#include "VaultNode.h"
//
//#include "Logger.h"

#ifndef _DB_REQUESTS_H_
#define _DB_REQUESTS_H_

/*
 * This is the object that keeps track of the connection to the DB.
 */
class BackendObj {
public:
  bool connection_failed;
#ifdef USE_POSTGRES
#ifdef USE_PQXX
  pqxx::connection *C;
#else
  PGconn *C;
#endif
#endif
  BackendObj(Logger *logger,
	     const char *db_address, const int db_port, const char *db_params,
	     const char *db_user, const char *db_password, const char *db_name)
    : connection_failed(false), C(NULL) {
#ifdef USE_POSTGRES
    std::stringstream connstr;
    connstr << "dbname=" << db_name;

    if (db_address && db_address[0] != '\0') {
      connstr << " host=" << db_address;
    }
    if (db_port > 0) {
      connstr << " port=" << db_port;
    }
    if (db_user && db_user[0] != '\0') {
      connstr << " user=" << db_user;
    }
    if (db_password && db_password[0] != '\0') {
      connstr << " password=" << db_password;
    }
    if (db_params && db_params[0] != '\0') {
      connstr << " " << db_params;
    }

#ifdef USE_PQXX
    // XXX note, throws an exception either now or later if connection fails
    C = new pqxx::connection(connstr.str());
    // XXX C->trace(FILE *); // enable tracing to a given output stream
#else
    C = PQconnectdb(connstr.str().c_str());
    if (C == NULL) {
      log_err(log, "Failed to allocate DB connection data!!\n");
      connection_failed = true;
    }
    else {
      ConnStatusType status = PQstatus(C);
      if (status == CONNECTION_OK) {
	// only CONNECTION_OK and CONNECTION_BAD should be present
	// with synchronous connection

	// XXX PQtrace(c, FILE *); // enable tracing to a given output stream
	// NOTE: see commentary on Windows at 
	// http://www.postgresql.org/docs/8.2/interactive/libpq-control.html
      }
      else {
	connection_failed = true;
	log_err(log, "DB connection error: %s", PQerrorMessage(C));
      }
    }
#endif
#endif
  }
#if defined(USE_POSTGRES) && !defined(USE_PQXX)
  bool restart_connection() {
    PQreset(C);
    ConnStatusType status = PQstatus(C);
    if (status != CONNECTION_OK) {
      connection_failed = true;
    }
    else {
      connection_failed = false;
    }
    return !connection_failed;
  }
#endif
  ~BackendObj() {
#ifdef USE_POSTGRES
    // XXX at present, since transactions are blocking, we should never
    // execute the destructor with a transaction open; if we could, we have
    // to handle the transaction first
    if (C) {
#ifdef USE_PQXX
      delete C;
#else
      PQfinish(C);
#endif
    }
#endif
  }
};


#ifdef USE_PQXX
// Use a #define to reduce clutter due to different libpqxx versions having
// different quoting functionality.
#ifdef PQXX_TRANS_ESC
#define ESC_STR(T, s) (T).esc(s)
#define ESC_BIN(T, s, len) (T).esc_raw(s, len)
#else
#define ESC_STR(T, s) pqxx::sqlesc(s)
#define ESC_BIN(T, s, len) pqxx::escape_binary(s, len)
#endif
#endif /* USE_PQXX */


#define MIN_NODEVAL 100


/*
 * Vault/DB maintenance
 */

#ifdef USE_PQXX
class Call_initvault : public pqxx::transactor<> {
public:
  void operator()(argument_type &T) {
    pqxx::result R(T.exec("SELECT initvault()"));
    // returns 1 if the nodes existed already, 0 otherwise
  }
};
#endif


/*
 * Auth operations
 */

class AuthAcctLogin_AcctQuery_Result {
public:
  status_code_t result_code;
  std::string user_class;
  u_char hash[20];
  u_char uuid[UUID_RAW_LEN];
  bool is_visitor;
  
  AuthAcctLogin_AcctQuery_Result()
    : result_code(ERROR_LOGIN_DENIED), user_class(""), is_visitor(false)
  {
    memset(uuid, 0, UUID_RAW_LEN);
  }

  AuthAcctLogin_AcctQuery_Result(AuthAcctLogin_AcctQuery_Result &other)
    : result_code(other.result_code), user_class(other.user_class),
      is_visitor(other.is_visitor)
  {
    memcpy(hash, other.hash, 20);
    memcpy(uuid, other.uuid, UUID_RAW_LEN);
  }

  AuthAcctLogin_AcctQuery_Result&
    operator=(const AuthAcctLogin_AcctQuery_Result &other)
  {
    if (this != &other) {
      result_code = other.result_code;
      user_class = other.user_class;
      memcpy(hash, other.hash, 20);
      memcpy(uuid, other.uuid, UUID_RAW_LEN);
      is_visitor = other.is_visitor;
    }
    return *this;
  }
};
#ifdef USE_POSTGRES
#ifdef USE_PQXX
class AuthAcctLogin_AcctQuery : public pqxx::transactor<> {
public:
  AuthAcctLogin_AcctQuery(const char *name,
			  AuthAcctLogin_AcctQuery_Result &result)
    : pqxx::transactor<>("AuthAcctLogin_AcctQuery"),
      m_name(name), m_result(result)
  { }

  AuthAcctLogin_AcctQuery(const AuthAcctLogin_AcctQuery &other) 
    : pqxx::transactor<>("AuthAcctLogin_AcctQuery"),
      m_name(other.m_name), m_result(other.m_result)
  { }

  void operator()(argument_type &T) {
    pqxx::result R(T.exec("SELECT hash,class,id,visitor,banned FROM accounts "
			  "WHERE name=lower('" + ESC_STR(T, m_name) + "')"));
    if (R.size() == 0) {
      m_result.result_code = ERROR_ACCT_NOT_FOUND;
      return;
    }
    if (R.size() == 1 && R.columns() == 5) {
      bool banned = false;
      R[0]["banned"].to(banned);
      if (banned) {
	m_result.result_code = ERROR_BANNED;
	return;
      }
      pqxx::result::field F = R[0]["hash"];
      char hash[41];
      if (strlen(F.c_str()) != 40) {
	m_result.result_code = ERROR_INVALID_PARAM;
	return;
      }
      memcpy(hash, F.c_str(), 41);
      for (int i = 19; i >= 0; i--) {
	// if we sscanf four bytes at a time, we have to byte-swap to big-endian
	unsigned int data;
	if (sscanf(hash+(2*i), "%x", &data) != 1) {
	  m_result.result_code = ERROR_INVALID_PARAM;
	  return;
	}
	m_result.hash[i] = (u_char)(data & 0xFF);
	hash[2*i] = '\0';
      }
      F = R[0]["class"];
      if (F.is_null()) {
	m_result.user_class = "default";
      }
      else {
	F.to(m_result.user_class);
      }
      F = R[0]["id"];
      if (F.is_null()
	  || uuid_string_to_bytes(m_result.uuid, UUID_RAW_LEN,
				  F.c_str(), strlen(F.c_str()),
				  1, 1)) {
	memset(m_result.uuid, 0, UUID_RAW_LEN);
      }
      // if visitor is null, to() doesn't set the value, so it defaults
      R[0]["visitor"].to(m_result.is_visitor);
      m_result.result_code = NO_ERROR;
    }
  }

  void on_commit() {
  }

private:
  const char *m_name;
  // I think we are okay to NOT keep a local copy of the result object,
  // because the result_code will only be set to non-default upon success.
  // If this query actually wrote to the DB we would need to delay until
  // on_commit().
  AuthAcctLogin_AcctQuery_Result &m_result;
};
#else /* ! USE_PQXX */
void AuthAcctLogin_AcctQuery(BackendObj *conn, char *name,
			     AuthAcctLogin_AcctQuery_Result &result);
#endif /* USE_PQXX */
#endif /* USE_POSTGRES */

class AuthAcctLogin_PlayerQuery_Player {
public:
  AuthAcctLogin_PlayerQuery_Player()
    : kinum(0), name(), gender(), explorer_type(GUEST_CUSTOMER) { };

  AuthAcctLogin_PlayerQuery_Player(const
				   AuthAcctLogin_PlayerQuery_Player &other)
    : kinum(other.kinum), name(other.name), gender(other.gender),
      explorer_type(other.explorer_type) { }

  kinum_t kinum;
  UruString name;
  UruString gender;
  customer_type_t explorer_type;
};
#ifdef USE_PQXX
class AuthAcctLogin_PlayerQuery : public pqxx::transactor<pqxx::nontransaction> {
public:
  AuthAcctLogin_PlayerQuery(u_char *uuid,
			    std::list<AuthAcctLogin_PlayerQuery_Player> &l)
    : pqxx::transactor<pqxx::nontransaction>("AuthAcctLogin_PlayerQuery"),
      m_uuid(uuid), m_results(l)
  { }

  AuthAcctLogin_PlayerQuery(const AuthAcctLogin_PlayerQuery &other) 
    : pqxx::transactor<pqxx::nontransaction>("AuthAcctLogin_PlayerQuery"),
      m_uuid(other.m_uuid), m_results(other.m_results)
  { }

  void operator()(argument_type &T) {
    char uuid_str[UUID_STR_LEN];

    uuid_bytes_to_string((u_char*)uuid_str, UUID_STR_LEN, m_uuid, UUID_RAW_LEN,
			 1, 1);

    pqxx::result R(T.exec("SELECT * FROM acctplayerinfo('" + 
			  /*severe paranoia*/ESC_STR(T, uuid_str) + "')"));
    if (m_results.size() != 0) {
      // this should not happen
      throw std::runtime_error("We appear to have restarted what should be a "
			  "nontransaction which only sets local state after "
			  "the entire DB interaction succeeds!");
    }

    for (pqxx::result::const_iterator row = R.begin(); row != R.end(); row++) {
      AuthAcctLogin_PlayerQuery_Player result;
      row["v_ki"].to(result.kinum);
      std::string tempstr;
      row["v_name"].to(tempstr);
      result.name = tempstr;
      row["v_gender"].to(tempstr);
      result.gender = tempstr;
      int exptype;
      row["v_type"].to(exptype);
      result.explorer_type = (customer_type_t)exptype;
      m_results.push_front(result);
    }
  }

protected:
  u_char *m_uuid;
  std::list<AuthAcctLogin_PlayerQuery_Player> &m_results;
};

class AuthValidateKI : public pqxx::transactor<pqxx::nontransaction> {
public:
  AuthValidateKI(const u_char *uuid, kinum_t kinum, status_code_t &result,
		 UruString &name)
    : pqxx::transactor<pqxx::nontransaction>("AuthValidateKI"),
      m_uuid(uuid), m_kinum(kinum), m_result(result), m_name(name) 
  { }

  AuthValidateKI(const AuthValidateKI &other) 
    : pqxx::transactor<pqxx::nontransaction>("AuthValidateKI"),
      m_uuid(other.m_uuid), m_kinum(other.m_kinum), m_result(other.m_result),
      m_name(other.m_name)
  { }

  void operator()(argument_type &T) {
    char uuid_str[UUID_STR_LEN];

    uuid_bytes_to_string((u_char*)uuid_str, UUID_STR_LEN, m_uuid, UUID_RAW_LEN,
			 1, 1);
    std::stringstream qstr;
    qstr << "SELECT v_name FROM acctplayerinfo('"
	 << /*severe paranoia*/ESC_STR(T, uuid_str)
	 << "') where v_ki = "
	 << m_kinum;

    pqxx::result R(T.exec(qstr));
			  
    if (R.size() == 0) {
      m_result = ERROR_PLAYER_NOT_FOUND;
    }
    else {
      m_result = NO_ERROR;
      m_name = R[0][0].c_str();
    }
  }

protected:
  const u_char *m_uuid;
  kinum_t m_kinum;
  status_code_t &m_result;
  UruString &m_name;
};

class AuthChangePassword : public pqxx::transactor<> {
public:
  AuthChangePassword(const u_char *uuid, const char *name,
		     const char *newhash, status_code_t &result)
    : pqxx::transactor<>("AuthChangePassword"),
      m_uuid(uuid), m_name(name), m_hash(newhash), m_result(result),
      my_result(ERROR_INTERNAL)
  { }

  AuthChangePassword(const AuthChangePassword &other) 
    : pqxx::transactor<>("AuthChangePassword"),
      m_uuid(other.m_uuid), m_name(other.m_name), m_hash(other.m_hash),
      m_result(other.m_result), my_result(other.my_result)
  { }

  void operator()(argument_type &T) {
    char uuid_str[UUID_STR_LEN];

    uuid_bytes_to_string((u_char*)uuid_str, UUID_STR_LEN, m_uuid, UUID_RAW_LEN,
			 1, 1);
    pqxx::result R(T.exec("UPDATE accounts SET hash='" +
			  /*severe paranoia*/ESC_STR(T, m_hash) +
			  "' WHERE id='" + 
			  /*severe paranoia*/ESC_STR(T, uuid_str) +
			  "' and name='" + ESC_STR(T, m_name) + "'"));
    if (R.affected_rows() == 0) {
      my_result = ERROR_ACCT_NOT_FOUND;
      return;
    }
    else {
      my_result = NO_ERROR;
    }
  }

  void on_commit() {
    m_result = my_result;
  }

protected:
  const u_char *m_uuid;
  const char *m_name;
  const char *m_hash;
  status_code_t &m_result;
  status_code_t my_result;
};

class AuthVerifyPassword : public pqxx::transactor<pqxx::nontransaction> {
public:
  AuthVerifyPassword(const u_char *uuid, const char *name,
		     const char *hash, status_code_t &result)
    : pqxx::transactor<pqxx::nontransaction>("AuthVerifyPassword"),
      m_uuid(uuid), m_name(name), m_hash(hash), m_result(result)
  { }

  AuthVerifyPassword(const AuthVerifyPassword &other) 
    : pqxx::transactor<pqxx::nontransaction>("AuthVerifyPassword"),
      m_uuid(other.m_uuid), m_name(other.m_name), m_hash(other.m_hash),
      m_result(other.m_result)
  { }

  void operator()(argument_type &T) {
    char uuid_str[UUID_STR_LEN];

    uuid_bytes_to_string((u_char*)uuid_str, UUID_STR_LEN, m_uuid, UUID_RAW_LEN,
			 1, 1);
    pqxx::result R(T.exec("SELECT hash FROM accounts WHERE id='" + 
			  /*severe paranoia*/ESC_STR(T, uuid_str) +
			  "' and name='" + ESC_STR(T, m_name) + "'"));
    if (R.size() == 0) {
      m_result = ERROR_ACCT_NOT_FOUND;
      return;
    }
    else {
      const char *dbhash = R[0]["hash"].c_str();
      if (strncmp(m_hash, dbhash, 40)) {
	m_result = ERROR_BAD_PASSWD;
      }
      else {
	m_result = NO_ERROR;
      }
    }
  }

protected:
  const u_char *m_uuid;
  const char *m_name;
  const char *m_hash;
  status_code_t &m_result;
};


/*
 * Vault management
 */

class VaultPlayerCreate_Request : public pqxx::transactor<> {
public:
  VaultPlayerCreate_Request(const u_char *uuid, const char *name,
		    const char *gender,
		    AuthAcctLogin_PlayerQuery_Player &new_player,
		    uint32_t &neighbors_list, uint32_t &player_info)
    : pqxx::transactor<>("VaultPlayerCreate_Request"),
      m_uuid(uuid), m_name(name), m_gender(gender), m_player(new_player),
      m_neighbors(neighbors_list), m_player_info(player_info)
  {
    my_player.kinum = ERROR_INTERNAL;
  }

  VaultPlayerCreate_Request(const VaultPlayerCreate_Request &other) 
    : pqxx::transactor<>("VaultPlayerCreate_Request"),
      m_uuid(other.m_uuid), m_name(other.m_name), m_gender(other.m_gender),
      m_player(other.m_player), m_neighbors(other.m_neighbors),
      m_player_info(other.m_player_info), my_player(other.my_player)
  { }

  void operator()(argument_type &T) {
    char uuid_str[UUID_STR_LEN];

    uuid_bytes_to_string((u_char*)uuid_str, UUID_STR_LEN, m_uuid, UUID_RAW_LEN,
			 1, 1);

    pqxx::result R(T.exec("SELECT * FROM createplayer('" + 
			  ESC_STR(T, m_name) + "', '" +
			  ESC_STR(T, m_gender) + "', '" + 
			  /*severe paranoia*/ESC_STR(T, uuid_str) + "')"));
    if (R.size() != 1) {
      my_player.kinum = ERROR_INTERNAL;
    }
    else {
      R[0]["v_ki"].to(my_player.kinum);
    }
    if (my_player.kinum >= MIN_NODEVAL) {
      std::string tempstr;
      R[0]["v_name"].to(tempstr);
      my_player.name = tempstr;
      R[0]["v_gender"].to(tempstr);
      my_player.gender = tempstr;
      int exptype;
      R[0]["v_type"].to(exptype);
      my_player.explorer_type = (customer_type_t)exptype;
      pqxx::result::field Fn = R[0]["v_neighbors"];
      pqxx::result::field Fp = R[0]["v_playerinfonode"];
      if (Fn.is_null() || Fp.is_null()) {
	// this shouldn't happen but it's relatively minor thing
	m_neighbors = 0;
	m_player_info = 0;
      }
      else {
	Fn.to(m_neighbors);
	Fp.to(m_player_info);
      }
    }
    else {
      // there was a problem somewhere
    }
  }

  void on_commit() {
    m_player = my_player;
  }

protected:
  const u_char *m_uuid;
  const char *m_name;
  const char *m_gender;
  AuthAcctLogin_PlayerQuery_Player &m_player;
  uint32_t &m_neighbors, &m_player_info;
  AuthAcctLogin_PlayerQuery_Player my_player;
};
class VaultPlayerRequest_Verify
  : public pqxx::transactor<pqxx::nontransaction> {
public:
  VaultPlayerRequest_Verify(const u_char *uuid, const char *name,
			    AuthAcctLogin_PlayerQuery_Player &result)
    : pqxx::transactor<pqxx::nontransaction>("VaultPlayerRequest_Verify"),
      m_uuid(uuid), m_name(name), m_result(result)
  {
    m_result.kinum = ERROR_INTERNAL;
  }

  VaultPlayerRequest_Verify(const VaultPlayerRequest_Verify &other) 
    : pqxx::transactor<pqxx::nontransaction>("VaultPlayerRequest_Verify"),
      m_uuid(other.m_uuid), m_name(other.m_name), m_result(other.m_result)
  { }

  void operator()(argument_type &T) {
    char uuid_str[UUID_STR_LEN];

    uuid_bytes_to_string((u_char*)uuid_str, UUID_STR_LEN, m_uuid, UUID_RAW_LEN,
			 1, 1);

    pqxx::result R(T.exec("SELECT * FROM acctplayerinfo('" +
			  /*severe paranoia*/ESC_STR(T, uuid_str) +
			  "') where v_name = '" + ESC_STR(T, m_name) + "'"));
    if (R.size() == 0) {
      m_result.kinum = ERROR_PLAYER_NOT_FOUND;
    }
    else if (R.size() != 1) {
      m_result.kinum = ERROR_INTERNAL;
    }
    else {
      m_result.kinum = NO_ERROR;
    }
    if (m_result.kinum >= MIN_NODEVAL) {
      std::string tempstr;
      R[0]["v_name"].to(tempstr);
      m_result.name = tempstr;
      R[0]["v_gender"].to(tempstr);
      m_result.gender = tempstr;
      int exptype;
      R[0]["v_type"].to(exptype);
      exptype = (customer_type_t)m_result.explorer_type;
    }
    else {
      // there was a problem somewhere
    }
  }

protected:
  const u_char *m_uuid;
  const char *m_name;
  AuthAcctLogin_PlayerQuery_Player &m_result;
};

class VaultPlayerDelete_Request : public pqxx::transactor<> {
public:
  VaultPlayerDelete_Request(kinum_t kinum, status_code_t &result,
			    std::multimap<kinum_t,uint32_t> &tell_who,
			    uint32_t &player_info)
    : pqxx::transactor<>("VaultPlayerDelete_Request"),
      m_kinum(kinum), m_result(result), m_tell_who(tell_who),
      m_player_info(player_info), my_result(ERROR_INTERNAL)
  { }

  VaultPlayerDelete_Request(const VaultPlayerDelete_Request &other) 
    : pqxx::transactor<>("VaultPlayerDelete_Request"),
      m_kinum(other.m_kinum), m_result(other.m_result),
      m_tell_who(other.m_tell_who), m_player_info(other.m_player_info),
      my_result(other.my_result)
  { }

  void operator()(argument_type &T) {
    std::stringstream qstr;
    qstr << "SELECT * FROM deleteplayer(" << m_kinum << ")";
    pqxx::result R(T.exec(qstr));
    // Note that we don't get much worked up over a failure in delete.
    // If the delete failed entirely, then the player can try again.
    // If zero rows are returned, there will be stale state until everyone
    // logs out and in again (not harmful to the system).
    // As such we're a bit sloppy with the returned multimap, writing to it
    // here. If for some reason some data is put in it, then this function
    // throws an exception, and the transaction is restarted, and we get here
    // again, we'll lose the earlier data (but it should be returned
    // again...). This will be fine. Actually I think the transactor local
    // state thing is really for multi-query state tracking and all of MOSS's
    // single-query DB transactors could be equally sloppy.
    // In any case, the caller is still expected to test the result before 
    // using the data.
    m_tell_who.clear();
    if (R.size() > 0) {
      pqxx::result::field Fn = R[0]["v_child"];
      if (Fn.is_null()) {
	// this shouldn't happen
	my_result = ERROR_NODE_NOT_FOUND;
	return;
      }
      Fn.to(m_player_info);
    }
    my_result = NO_ERROR;
    for (pqxx::result::const_iterator row = R.begin(); row != R.end(); row++) {
      uint32_t parent, notify;
      row["v_parent"].to(parent);
      row["v_notify"].to(notify);
      m_tell_who.insert(std::pair<kinum_t,uint32_t>((kinum_t)notify, parent));
    }
  }

  void on_commit() {
    m_result = my_result;
  }

protected:
  kinum_t m_kinum;
  status_code_t &m_result;
  std::multimap<kinum_t,uint32_t> &m_tell_who;
  uint32_t &m_player_info;
  uint32_t my_neighbors;
  status_code_t my_result;
};
#endif /* USE_PQXX */

typedef struct {
  uint32_t parent;
  uint32_t child;
  uint32_t owner;
} VaultFetchRefs_VaultRef;

#ifdef USE_PQXX
static bool string_output(pqxx::transaction_base &T,
			  std::ostream &ostr, const VaultNode *node,
			  VaultNode::datatype_t type, vault_bitfield_t bit) {
  switch (type) {
  case VaultNode::INT:
  case VaultNode::UINT:
    ostr << node->num_val(bit);
    break;
  case VaultNode::UUID:
    {
      char uuid_str[UUID_STR_LEN];
      uuid_bytes_to_string((u_char*)uuid_str, UUID_STR_LEN,
			   node->const_uuid_ptr(bit), UUID_RAW_LEN,
			   1, 1);
      ostr << "'" << /*severe paranoia*/ESC_STR(T, uuid_str) << "'";
    }
    break;
  case VaultNode::STRING:
    {
      const u_char *str_data = node->const_data_ptr(bit);
      u_int str_len = read32(str_data, 0);
      UruString str(str_data+4, str_len, false, true, false);
      ostr << "'" << ESC_STR(T, str.c_str()) << "'";
    }
    break;
  case VaultNode::BLOB:
    {
      const u_char *blob_data = node->const_data_ptr(bit);
      u_int blob_len = read32(blob_data, 0);
      ostr << "E'" << ESC_BIN(T, blob_data, blob_len+4) << "'";
    }
    break;
  default:
    // programmer error

    // the query will almost certainly blow up anyway
    ostr << "''";
    return false;
  }
  return true;
}

class VaultFetchRefs_Request : public pqxx::transactor<pqxx::nontransaction> {
public:
  VaultFetchRefs_Request(uint32_t root_node, status_code_t &result,
			 std::vector<VaultFetchRefs_VaultRef> &reflist)
    : pqxx::transactor<pqxx::nontransaction>("VaultFetchRefs_Request"),
      m_node(root_node), m_result(result), m_list(reflist)
  { }

  VaultFetchRefs_Request(const VaultFetchRefs_Request &other) 
    : pqxx::transactor<pqxx::nontransaction>("VaultFetchRefs_Request"),
      m_node(other.m_node), m_result(other.m_result), m_list(other.m_list)
  { }

  void operator()(argument_type &T) {
    std::stringstream qstr;
    qstr << "SELECT * FROM fetchnoderefs("
	 << m_node
	 << ")";
    pqxx::result R(T.exec(qstr));

    m_result = NO_ERROR;
    if (R.size() == 0) {
      // this just means there are no refs
      return;
    }
    if (m_list.size() != 0) {
      // this should not happen
      throw std::runtime_error("We appear to have restarted what should be a "
			  "nontransaction which only sets local state after "
			  "the entire DB interaction succeeds!");
    }
    m_list.reserve(R.size());
    for (pqxx::result::const_iterator row = R.begin(); row != R.end(); row++) {
      VaultFetchRefs_VaultRef ref;
      row["parent"].to(ref.parent);
      row["child"].to(ref.child);
      row["ownerid"].to(ref.owner);
      m_list.push_back(ref);
    }
  }

protected:
  uint32_t m_node;
  status_code_t &m_result;
  std::vector<VaultFetchRefs_VaultRef> &m_list;
};

class VaultFindNode_Request : public pqxx::transactor<pqxx::nontransaction> {
public:
  VaultFindNode_Request(uint32_t node, status_code_t &result,
			uint32_t &val)
    : pqxx::transactor<pqxx::nontransaction>("VaultFindNode_Request"),
      m_owner(node), m_result(result), m_val(val)
  { }

  VaultFindNode_Request(const VaultFindNode_Request &other) 
    : pqxx::transactor<pqxx::nontransaction>("VaultFindNode_Request"),
      m_owner(other.m_owner), m_result(other.m_result), m_val(other.m_val)
  { }

  void operator()(argument_type &T) {
    std::stringstream qstr;
    qstr << "SELECT nodeid FROM playerinfo INNER JOIN noderefs ON "
	 << "playerinfo.nodeid = noderefs.child where noderefs.parent = "
	 << m_owner;
    pqxx::result R(T.exec(qstr));

    if (R.size() > 1) {
      m_result = ERROR_INVALID_DATA;
      R[0]["nodeid"].to(m_val);
    }
    else if (R.size() > 0) {
      m_result = NO_ERROR;
      R[0]["nodeid"].to(m_val);
    }
    else {
      m_result = ERROR_NODE_NOT_FOUND;
    }
  }

protected:
  uint32_t m_owner;
  status_code_t &m_result;
  uint32_t &m_val;
};

class VaultFindNode_Generic : public pqxx::transactor<pqxx::nontransaction> {
public:
  VaultFindNode_Generic(const VaultNode *node, status_code_t &result,
			std::vector<uint32_t> &found, Logger *log)
    : pqxx::transactor<pqxx::nontransaction>("VaultFindNode_Generic"),
      m_node(node), m_result(result), m_found(found), m_log(log)
  { }

  VaultFindNode_Generic(const VaultFindNode_Generic &other) 
    : pqxx::transactor<pqxx::nontransaction>("VaultFindNode_Generic"),
      m_node(other.m_node), m_result(other.m_result), m_found(other.m_found),
      m_log(other.m_log)
  { }

  void operator()(argument_type &T) {
    if (m_found.size() != 0) {
      // this should not happen
      throw std::runtime_error("We appear to have restarted what should be a "
			  "nontransaction which only sets local state after "
			  "the entire DB interaction succeeds!");
    }

    VaultNode::vault_nodetype_t ntype = m_node->type();
    if (ntype == VaultNode::InvalidNode) {
      // we do not allow * queries
      log_warn(m_log, "Denying a VaultNodeFind without the node type!\n");
      m_result = ERROR_FORBIDDEN;
      return;
    }

    std::stringstream qstr;
    qstr << "SELECT nodeid FROM " << VaultNode::tablename_for_type(ntype)
	 << " WHERE ";
    uint32_t bits = VaultNode::all_bits_for_type(ntype);
    // the DB at the moment has separate tables for each node type, so
    // we don't put the node type into the query 
    bits &= ~NodeType;
    uint32_t findbits = m_node->bitfield1();
    // we don't let users manage CreateTime and ModifyTime
    findbits &= ~(CreateTime|ModifyTime);
    if ((findbits & ~NodeType) == 0) {
      // we do not allow queries for all of a given node type
      log_warn(m_log, "Denying a VaultNodeFind for only the node type!\n");
      m_result = ERROR_FORBIDDEN;
      return;
    }
    bool first = true;
    const VaultNode::ColumnSpec *col;
    for (u_int i = 0; i < 32; i++) {
      vault_bitfield_t bit = (vault_bitfield_t)(1 << i);
      if (findbits & bit) {
	if (bits & bit) {
	  col = VaultNode::get_spec(ntype, bit);
	  if (first) {
	    first = false;
	  }
	  else {
	    qstr << " and ";
	  }
	  qstr << " " << col->col_name << "=";
	  if (!string_output(T, qstr, m_node, col->datatype, bit)) {
	    log_err(m_log, "Unhandled vault node field type!\n");
	  }
	}
	else if (bit == NodeType) {
	}
	else {
	  // we really weren't expecting that!
	  log_net(m_log, "Field 0x%08x was present in vault node find "
		  "of type %d!\n", (uint32_t)bit, ntype);
	  log_net(m_log, "If this field is allowed to be present, edit the "
		  "VaultNode ColumnSpec; if not, this client is "
		  "misbehaving.\n");
	}
      }
    }

    pqxx::result R(T.exec(qstr));

    m_result = NO_ERROR;
    if (R.size() == 0) {
      // no node found
      m_result = ERROR_NODE_NOT_FOUND;
      return;
    }
    m_found.reserve(R.size());
    for (u_int i = 0; i < R.size(); i++) {
      uint32_t val;
      R[i][0].to(val);
      m_found[i] = val;
    }
  }

protected:
  const VaultNode *m_node;
  status_code_t &m_result;
  std::vector<uint32_t> &m_found;
  Logger *m_log;
};

class VaultFetchNode_Request : public pqxx::transactor<pqxx::nontransaction> {
public:
  VaultFetchNode_Request(uint32_t nodeid, status_code_t &result,
			 VaultNode &node, Logger *log)
    : pqxx::transactor<pqxx::nontransaction>("VaultFetchNode_Request"),
      m_id(nodeid), m_result(result), m_node(node), m_log(log)
  { }

  VaultFetchNode_Request(const VaultFetchNode_Request &other) 
    : pqxx::transactor<pqxx::nontransaction>("VaultFetchNode_Request"),
      m_id(other.m_id), m_result(other.m_result), m_node(other.m_node),
      m_log(other.m_log)
  { }

  void operator()(argument_type &T) {
    std::stringstream qstr;
    qstr << "SELECT * FROM fetchnode("
	 << m_id
	 << ")";
    pqxx::result R(T.exec(qstr));

    if (R.size() > 1) {
      m_result = ERROR_INTERNAL;
      return;
    }
    else if (R.size() == 0) {
      // appears to not happen, see next test
      m_result = ERROR_NODE_NOT_FOUND;
      return;
    }
    else if (R[0]["v_nodetype"].is_null()) {
      m_result = ERROR_NODE_NOT_FOUND;
      return;
    }
    else {
      m_result = NO_ERROR;
    }

    int type;
    R[0]["v_nodetype"].to(type);
    VaultNode::vault_nodetype_t ntype = (VaultNode::vault_nodetype_t)type;
    uint32_t bits = VaultNode::all_bits_for_type(ntype);

    m_node.num_ref(NodeID) = htole32(m_id);
    const VaultNode::ColumnSpec *col;
    for (u_int i = 1; i < 32; i++) {
      vault_bitfield_t bit = (vault_bitfield_t)(1 << i);
      if (bits & bit) {
	col = VaultNode::get_spec(ntype, bit);
	pqxx::result::field F = R[0][col->fetch_name];
	if (F.is_null()) {
	  if (col->fetch_required) {
	    log_net(m_log, "Field 0x%08x was expected from vault node %d "
		    "fetch of type %d, yet it is not present in the DB!\n",
		    (uint32_t)bit, m_id, type);
	    log_net(m_log, "If this field is allowed to be null, edit the "
		    "VaultNode ColumnSpec; if not, investigate the missing "
		    "data.\n");
	    // but, go on anyway
	  }
	}
	else {
	  switch (col->datatype) {
	  case VaultNode::INT:
	    {
	      int32_t val;
	      F.to(val);
	      m_node.num_ref(bit) = htole32(val);
	    }
	    break;
	  case VaultNode::UINT:
	    {
	      uint32_t val;
	      F.to(val);
	      m_node.num_ref(bit) = htole32(val);
	    }
	    break;
	  case VaultNode::UUID:
	    if (uuid_string_to_bytes(m_node.uuid_ptr(bit), UUID_RAW_LEN,
				     F.c_str(), strlen(F.c_str()),
				     1, 1)) {
	      memset(m_node.uuid_ptr(bit), 0, UUID_RAW_LEN);
	    }
	    break;
	  case VaultNode::STRING:
	    {
	      UruString str((const u_char*)F.c_str(), strlen(F.c_str())+1,
			    false, false, false/* unneeded*/);
	      size_t str_len = str.send_len(false, true, true);
	      memcpy(m_node.data_ptr(bit, str_len),
		     str.get_str(false, true, true), str_len);
	    }
	    break;
	  case VaultNode::BLOB:
	    {
	      pqxx::binarystring blob(F);
	      size_t blob_len = read32(blob.data(), 0);
	      if (blob_len+4 != blob.length()) {
		// the data from the vault is wrong
		log_err(m_log, "Length mismatch in blob from DB! Data claims "
			"%d, DB claims %d\n", blob_len+4, blob.length());
		if (blob_len+4 > blob.length()) {
		  blob_len = blob.length() - 4;
		}
	      }
	      memcpy(m_node.data_ptr(bit, blob_len), blob.data()+4, blob_len);
	    }
	    break;
	  default:
	    // programmer error
	    log_err(m_log, "Unhandled vault node field type!\n");
	    break;
	  }
	}
      }
    }
  }

protected:
  uint32_t m_id;
  status_code_t &m_result;
  VaultNode &m_node;
  Logger *m_log;
};

class VaultSaveNode_Request : public pqxx::transactor<> {
public:
  VaultSaveNode_Request(uint32_t nodeid, const VaultNode *node,
			status_code_t &result, Logger *log)
    : pqxx::transactor<>("VaultSaveNode_Request"),
      m_id(nodeid), m_node(node), m_result(result), m_log(log)
  { }

  VaultSaveNode_Request(const VaultSaveNode_Request &other) 
    : pqxx::transactor<>("VaultSaveNode_Request"),
      m_id(other.m_id), m_node(other.m_node), m_result(other.m_result),
      m_log(other.m_log)
  { }

  void operator()(argument_type &T) {
    VaultNode::vault_nodetype_t ntype = m_node->type();
    if (ntype == VaultNode::InvalidNode) {
      // hrm...
      std::stringstream backup_qstr;
      backup_qstr << "select type from nodes where nodeid = " << m_id; // XXX
      pqxx::result BR(T.exec(backup_qstr));
      if (BR.size() != 1) {
	// wow, we can't update this anyway
	m_result = ERROR_NODE_NOT_FOUND;
	return;
      }
      int32_t ntype_int;
      BR[0][0].to(ntype_int);
      ntype = (VaultNode::vault_nodetype_t)ntype_int;
    }

    std::stringstream qstr;
    qstr << "UPDATE " << VaultNode::tablename_for_type(ntype) << " SET";
    uint32_t bits = VaultNode::all_bits_for_type(ntype);
    // the DB at the moment has separate tables for each node type, so
    // we don't put the node type into the query 
    bits &= ~NodeType;
    // we don't let users manage CreateTime and ModifyTime
    bits &= ~(CreateTime|ModifyTime);
    uint32_t savebits = m_node->bitfield1();
#ifdef OLD_PROTOCOL
    if ((savebits & ~NodeType) == 0) {
      // not sure what this is about... looks like the MOUL server ignored
      // them, as do we in effect, but instead of throwing an SQL error,
      // we can just stop now
      m_result = ERROR_INVALID_PARAM;
      return;
    }
#endif
    bool first = true;
    const VaultNode::ColumnSpec *col;
    for (u_int i = 0; i < 32; i++) {
      vault_bitfield_t bit = (vault_bitfield_t)(1 << i);
      if (savebits & bit) {
	if (bits & bit) {
	  col = VaultNode::get_spec(ntype, bit);
	  if (first) {
	    first = false;
	  }
	  else {
	    qstr << ",";
	  }
	  qstr << " " << col->col_name << "=";
	  if (!string_output(T, qstr, m_node, col->datatype, bit)) {
	    log_err(m_log, "Unhandled vault node field type!\n");
	  }
	}
	else if (bit == NodeType) {
	}
	else {
	  // we really weren't expecting that!
	  log_net(m_log, "Field 0x%08x was present in vault node %d save "
		  "of type %d!\n", (uint32_t)bit, m_id, ntype);
	  log_net(m_log, "If this field is allowed to be present, edit the "
		  "VaultNode ColumnSpec; if not, this client is "
		  "misbehaving.\n");
	}
      }
    }
    qstr << ", modifytime=now() WHERE nodeid=" << m_id;

    T.exec(qstr);
    m_result = NO_ERROR;
  }

protected:
  uint32_t m_id;
  const VaultNode *m_node;
  status_code_t &m_result;
  Logger *m_log;
};

class VaultCreateNode_Request : public pqxx::transactor<> {
public:
  VaultCreateNode_Request(const VaultNode *node, const u_char *acctid,
			  const kinum_t id, uint32_t &nodeid, Logger *log)
    : pqxx::transactor<>("VaultCreateNode_Request"),
      m_node(node), m_creatoracctid(acctid), m_creatorid(id),
      m_id(nodeid), my_id(ERROR_INTERNAL), m_log(log)
 { }

  VaultCreateNode_Request(const VaultCreateNode_Request &other) 
    : pqxx::transactor<>("VaultCreateNode_Request"),
      m_node(other.m_node), m_creatoracctid(other.m_creatoracctid),
      m_creatorid(other.m_creatorid), m_id(other.m_id), my_id(other.my_id),
      m_log(other.m_log)
 { }

  void operator()(argument_type &T) {
    my_id = (uint32_t)ERROR_INTERNAL;
    VaultNode::vault_nodetype_t ntype = m_node->type();
    if (ntype == VaultNode::InvalidNode) {
      // no can do without a type!
      my_id = (uint32_t)ERROR_INVALID_DATA;
      return;
    }

    std::stringstream qstr;
    qstr << "SELECT * FROM newnodeid("
	 << (uint32_t)ntype
	 << ")";
    pqxx::result R(T.exec(qstr));
    if (R.size() != 1) {
      return; // leaves my_id set to ERROR_INTERNAL
    }
    else {
      R[0][0].to(my_id);
    }
    char acct_str[UUID_STR_LEN];
    uuid_bytes_to_string((u_char*)acct_str, UUID_STR_LEN,
			 m_creatoracctid, UUID_RAW_LEN, 1, 1);

    std::stringstream cols, vals;
    cols << " (nodeid, createtime, modifytime, creatoracctid, creatorid";
    vals << " (" << my_id << ", now(), now(), '" << ESC_STR(T, acct_str)
	 << "', " << m_creatorid;
    uint32_t bits = VaultNode::all_bits_for_type(ntype);
    // the DB at the moment has separate tables for each node type, so
    // we don't put the node type into the query 
    bits &= ~NodeType;
    uint32_t savebits = m_node->bitfield1();
    const VaultNode::ColumnSpec *col;
    for (u_int i = 0; i < 32; i++) {
      vault_bitfield_t bit = (vault_bitfield_t)(1 << i);
      if (savebits & bit) {
	if ((bits & bit)
	    || ((bit == CreateAgeName || bit == CreateAgeUUID)
		&& (ntype == VaultNode::ChronicleNode
		    || ntype == VaultNode::FolderNode
		    || ntype == VaultNode::ImageNode
		    || ntype == VaultNode::SDLNode
		    || ntype == VaultNode::TextNoteNode
		    || ntype == VaultNode::AgeLinkNode
		    || ntype == VaultNode::MarkergameNode
		    ))) {
	  col = VaultNode::get_spec(ntype, bit);
	  cols << ", " << col->col_name;
	  vals << ", ";
	  if (!string_output(T, vals, m_node, col->datatype, bit)) {
	    log_err(m_log, "Unhandled vault node field type!\n");
	  }
	}
	else if (bit == NodeType) {
	}
	else {
	  // we really weren't expecting that!
	  log_net(m_log, "Field 0x%08x was present in vault node create "
		  "of type %d!\n", (uint32_t)bit, ntype);
	  log_net(m_log, "If this field is allowed to be present, edit the "
		  "VaultNode ColumnSpec; if not, this client is "
		  "misbehaving.\n");
	}
      }
    }

    std::stringstream qstr2;

    qstr2 << "INSERT INTO "
	  << VaultNode::tablename_for_type(ntype)
	  << cols.str()
	  << ") VALUES "
	  << vals.str()
	  << ")";

    T.exec(qstr2);
  }

  void on_commit() {
    m_id = my_id;
  }

protected:
  const VaultNode *m_node;
  const u_char *m_creatoracctid;
  kinum_t m_creatorid;
  uint32_t &m_id;
  uint32_t my_id;
  Logger *m_log;
};

class VaultAddRef_Request : public pqxx::transactor<> {
public:
  VaultAddRef_Request(uint32_t parent, uint32_t child, uint32_t owner,
		      status_code_t &result)
    : pqxx::transactor<>("VaultAddRef_Request"),
      m_parent(parent), m_child(child), m_owner(owner), m_result(result),
      my_result(result)
  { }

  VaultAddRef_Request(const VaultAddRef_Request &other) 
    : pqxx::transactor<>("VaultAddRef_Request"),
      m_parent(other.m_parent), m_child(other.m_child),
      m_owner(other.m_owner), m_result(other.m_result),
      my_result(other.my_result)
  { }

  void operator()(argument_type &T) {
    std::stringstream qstr;
    qstr << "SELECT * FROM addnode(" << m_parent << ", " << m_child
	 << ", " << m_owner << ")";

    pqxx::result R(T.exec(qstr));
    if (R.size() != 1) {
      my_result = ERROR_INTERNAL;
    }
    else {
      int query_result;
      R[0][0].to(query_result);
      if (query_result == 0) {
	my_result = NO_ERROR;
      }
      else if (query_result == 1) {
	my_result = ERROR_INVALID_DATA;
      }
      else {
	my_result = ERROR_NODE_NOT_FOUND;
      }
    }
  }

  void on_commit() {
    m_result = my_result;
  }

protected:
  uint32_t m_parent;
  uint32_t m_child;
  uint32_t m_owner;
  status_code_t &m_result;
  status_code_t my_result;
};

class VaultRemoveRef_Request : public pqxx::transactor<> {
public:
  VaultRemoveRef_Request(uint32_t parent, uint32_t child,
			 int &node_ct)
    : pqxx::transactor<>("VaultRemoveRef_Request"),
      m_parent(parent), m_child(child), m_count(node_ct), my_count(0)
  { }

  VaultRemoveRef_Request(const VaultRemoveRef_Request &other) 
    : pqxx::transactor<>("VaultRemoveRef_Request"),
      m_parent(other.m_parent), m_child(other.m_child),
      m_count(other.m_count), my_count(other.my_count)
  { }

  void operator()(argument_type &T) {
    std::stringstream qstr;
    qstr << "SELECT * FROM removenode(" << m_parent << ", " << m_child << ")";

    pqxx::result R(T.exec(qstr));
    if (R.size() != 1) {
      my_count = -1;
    }
    else {
      R[0][0].to(my_count);
    }
  }

  void on_commit() {
    m_count = my_count;
  }

protected:
  uint32_t m_parent;
  uint32_t m_child;
  int &m_count;
  int my_count;
};

class VaultCreateAge_Request : public pqxx::transactor<> {
public:
  VaultCreateAge_Request(const char *filename, const char *instance,
			 const char *user_defined, const char *display,
			 const u_char *createuuid, const u_char *parentuuid,
			 uint32_t &age_node, uint32_t &age_info_node,
			 status_code_t &result)
    : pqxx::transactor<>("VaultCreateAge_Request"),
      m_filename(filename), m_instance(instance), m_userdef(user_defined),
      m_display(display), m_createuuid(createuuid), m_parentuuid(parentuuid),
      m_age_node(age_node), m_age_info_node(age_info_node), m_result(result),
      my_age_node(0), my_age_info_node(0), my_result(result)
 { }

  VaultCreateAge_Request(const VaultCreateAge_Request &other) 
    : pqxx::transactor<>("VaultCreateAge_Request"),
      m_filename(other.m_filename), m_instance(other.m_instance),
      m_userdef(other.m_userdef), m_display(other.m_display),
      m_createuuid(other.m_createuuid), m_parentuuid(other.m_parentuuid),
      m_age_node(other.m_age_node), m_age_info_node(other.m_age_info_node),
      m_result(other.m_result), my_age_node(other.my_age_node),
      my_age_info_node(other.my_age_info_node), my_result(other.my_result)
 { }

  void operator()(argument_type &T) {
    char uuid1[UUID_STR_LEN], uuid2[UUID_STR_LEN];
    uuid_bytes_to_string((u_char*)uuid1, UUID_STR_LEN,
			 m_createuuid, UUID_RAW_LEN, 1, 1);
    if (m_parentuuid) {
      uuid_bytes_to_string((u_char*)uuid2, UUID_STR_LEN,
			   m_parentuuid, UUID_RAW_LEN, 1, 1);
    }
    else {
      strcpy(uuid2, "null");
    }
    std::stringstream qstr;
    qstr << "SELECT * FROM createage('"
	 << ESC_STR(T, m_filename)
	 << "', '"
	 << ESC_STR(T, m_instance)
	 << "', '"
	 << ESC_STR(T, m_userdef)
	 << "', '"
	 << ESC_STR(T, m_display)
	 << "', '"
	 << /*severe paranoia*/ESC_STR(T, uuid1)
	 << "', '"
	 << /*severe paranoia*/ESC_STR(T, uuid2)
	 << "')";

    pqxx::result R(T.exec(qstr));
    if (R.size() != 1) {
      my_result = ERROR_INTERNAL;
    }
    else {
      my_result = NO_ERROR;
      pqxx::result::field F = R[0]["v_agenode"];
      if (F.is_null()) {
	my_result = ERROR_INTERNAL;
      }
      else {
	F.to(my_age_node);
      }
      F = R[0]["v_ageinfonode"];
      if (F.is_null()) {
	my_result = ERROR_INTERNAL;
      }
      else {
	F.to(my_age_info_node);
      }
    }
  }

  void on_commit() {
    m_age_node = my_age_node;
    m_age_info_node = my_age_info_node;
    m_result = my_result;
  }

protected:
  const char *m_filename;
  const char *m_instance;
  const char *m_userdef;
  const char *m_display;
  const u_char *m_createuuid;
  const u_char *m_parentuuid;
  uint32_t &m_age_node;
  uint32_t &m_age_info_node;
  status_code_t &m_result;
  uint32_t my_age_node;
  uint32_t my_age_info_node;
  status_code_t my_result;
};
#endif /* USE_PQXX */

typedef struct {
  u_char uuid[UUID_RAW_LEN];
  UruString instance_name;
  UruString user_defined;
  UruString display_name;
  u_int instance_num;
  u_int num_owners;
} VaultAgeList_AgeInfo;

#ifdef USE_PQXX
class VaultAgeList_Request : public pqxx::transactor<pqxx::nontransaction> {
public:
  VaultAgeList_Request(UruString &filename, status_code_t &result,
		       std::vector<VaultAgeList_AgeInfo> &ages)
    : pqxx::transactor<pqxx::nontransaction>("VaultAgeList_Request"),
      m_filename(filename), m_list(ages), m_result(result)
  { }

  VaultAgeList_Request(const VaultAgeList_Request &other) 
    : pqxx::transactor<pqxx::nontransaction>("VaultAgeList_Request"),
      m_filename(other.m_filename), m_list(other.m_list),
      m_result(other.m_result)
 { }

  void operator()(argument_type &T) {
    std::stringstream qstr;
    qstr << "SELECT * FROM getpublicagelist('"
	 << ESC_STR(T, m_filename.c_str())
	 << "')";
    pqxx::result R(T.exec(qstr));

    m_result = NO_ERROR;
    if (R.size() == 0) {
      return;
    }
    if (m_list.size() != 0) {
      // this should not happen
      throw std::runtime_error("We appear to have restarted what should be a "
			  "nontransaction which only sets local state after "
			  "the entire DB interaction succeeds!");
    }
    m_list.reserve(R.size());
    for (pqxx::result::const_iterator row = R.begin(); row != R.end(); row++) {
      VaultAgeList_AgeInfo age;
      pqxx::result::field F = row["v_uuid"];
      if (F.is_null()
	  || uuid_string_to_bytes(age.uuid, UUID_RAW_LEN, F.c_str(),
				  strlen(F.c_str()), 1, 1)) {
	memset(age.uuid, 0, UUID_RAW_LEN);
      }
      F = row["v_instance_name"];
      if (!F.is_null()) {
	age.instance_name = F.c_str();
      }
      F = row["v_user_defined"];
      if (!F.is_null()) {
	age.user_defined = F.c_str();
      }
      F = row["v_display_name"];
      if (!F.is_null()) {
	age.display_name = F.c_str();
      }
      F = row["v_instance_num"];
      if (!F.is_null()) {
	F.to(age.instance_num);
      }
      else {
	age.instance_num = 0;
      }
      F = row["v_numowners"];
      if (!F.is_null()) {
	F.to(age.num_owners);
      }
      else {
	age.num_owners = 0;
      }
      m_list.push_back(age);
    }
  }

protected:
  UruString &m_filename;
  std::vector<VaultAgeList_AgeInfo> &m_list;
  status_code_t &m_result;
};

class VaultSendNode_Request : public pqxx::transactor<> {
public:
  VaultSendNode_Request(kinum_t player, uint32_t nodeid, kinum_t sender,
			status_code_t &result, uint32_t &inboxid)
    : pqxx::transactor<>("VaultSendNode_Request"),
      m_player(player), m_node(nodeid), m_sender(sender), m_result(result),
      m_inbox(inboxid), my_result(result), my_inbox(0)
  { }

  VaultSendNode_Request(const VaultSendNode_Request &other) 
    : pqxx::transactor<>("VaultSendNode_Request"),
      m_player(other.m_player), m_node(other.m_node),
      m_sender(other.m_sender), m_result(other.m_result),
      m_inbox(other.m_inbox), my_result(other.my_result),
      my_inbox(other.my_inbox)
  { }

  void operator()(argument_type &T) {
    std::stringstream qstr;
    qstr << "SELECT * FROM sendnode(" << m_player << ", " << m_node << ", "
    << m_sender << ")";

    pqxx::result R(T.exec(qstr));
    if (R.size() != 1) {
      my_result = ERROR_INTERNAL;
    }
    else {
      int query_result;
      R[0]["v_inbox"].to(my_inbox);
      R[0]["v_result"].to(query_result);
      if (query_result == 0) {
	my_result = NO_ERROR;
      }
      else if (query_result == 1) {
	my_result = ERROR_INVALID_DATA;
      }
      else {
	my_result = ERROR_NODE_NOT_FOUND;
      }
    }
  }

  void on_commit() {
    m_result = my_result;
    m_inbox = my_inbox;
  }

protected:
  uint32_t m_player;
  uint32_t m_node;
  uint32_t m_sender;
  status_code_t &m_result;
  uint32_t &m_inbox;
  status_code_t my_result;
  uint32_t my_inbox;
};

class VaultSetAgePublic_Request : public pqxx::transactor<> {
public:
  VaultSetAgePublic_Request(uint32_t nodeid, bool to_public,
			    status_code_t &result)
    : pqxx::transactor<>("VaultSetAgePublic_Request"),
      m_node(nodeid), m_public(to_public), m_result(result), my_result(result)
  { }

  VaultSetAgePublic_Request(const VaultSetAgePublic_Request &other) 
    : pqxx::transactor<>("VaultSetAgePublic_Request"),
      m_node(other.m_node), m_public(other.m_public),
      m_result(other.m_result), my_result(other.my_result)
  { }

  void operator()(argument_type &T) {
    std::stringstream qstr;
    // when setting to private, the value must be 0, not null, or the
    // client won't update the Nexus GUI to say (and do) "Make Public"
    qstr << "UPDATE ageinfo SET int32_2=" << (m_public ? "1" : "0")
	 << ", modifytime=now() WHERE nodeid=" << m_node;
    T.exec(qstr);
    my_result = NO_ERROR;
  }

  void on_commit() {
    m_result = my_result;
  }

protected:
  uint32_t m_node;
  bool m_public;
  status_code_t &m_result;
  status_code_t my_result;
};

class VaultGetScore_Request : public pqxx::transactor<pqxx::nontransaction> {
public:
  VaultGetScore_Request(const uint32_t holder, UruString *name,
			uint32_t &score_id, int32_t &create_time,
			uint32_t &score_type, int32_t &score_value,
			status_code_t &result)
    : pqxx::transactor<pqxx::nontransaction>("VaultGetScore_Request"),
      m_score_holder(holder), m_score_name(name), m_score_id(score_id),
      m_timestamp(create_time), m_score_type(score_type),
      m_score_value(score_value), m_result(result)
  { }

  VaultGetScore_Request(const VaultGetScore_Request &other)
    : pqxx::transactor<pqxx::nontransaction>("VaultGetScore_Request"),
      m_score_holder(other.m_score_holder), m_score_name(other.m_score_name),
      m_score_id(other.m_score_id), m_timestamp(other.m_timestamp),
      m_score_type(other.m_score_type), m_score_value(other.m_score_value),
      m_result(other.m_result)
  { }

  void operator()(argument_type &T) {
    std::stringstream qstr;
    qstr << "SELECT * FROM getscore(" << m_score_holder << ", '"
	 << ESC_STR(T, m_score_name->c_str()) << "')";
    pqxx::result R(T.exec(qstr));

    if (R.size() != 1) {
      m_result = ERROR_INTERNAL;
    }
    else {
      pqxx::result::field F = R[0]["v_id"];
      if (F.is_null()) {
	m_result = ERROR_NO_SCORE;
      }
      else {
	m_result = NO_ERROR;
	F.to(m_score_id);
	F = R[0]["v_createtime"];
	if (F.is_null()) {
	  // shouldn't happen
	  m_result = ERROR_INTERNAL;
	  return;
	}
	F.to(m_timestamp);
	F = R[0]["v_type"];
	if (F.is_null()) {
	  // shouldn't happen
	  m_result = ERROR_INTERNAL;
	  return;
	}
	F.to(m_score_type);
	F = R[0]["v_score"];
	if (F.is_null()) {
	  // shouldn't happen
	  m_result = ERROR_INTERNAL;
	  return;
	}
	F.to(m_score_value);
      }
    }
  }

protected:
  kinum_t m_score_holder;
  UruString *m_score_name;
  uint32_t &m_score_id;
  int32_t &m_timestamp;
  uint32_t &m_score_type;
  int32_t &m_score_value;
  status_code_t &m_result;
};

class VaultCreateScore_Request : public pqxx::transactor<> {
public:
  VaultCreateScore_Request(const uint32_t holder, UruString *name,
			   uint32_t score_type, int32_t score_value,
			   uint32_t &score_id, int32_t &create_time,
			   status_code_t &result)
    : pqxx::transactor<>("VaultCreateScore_Request"),
      m_score_holder(holder), m_score_name(name), m_score_type(score_type),
      m_score_value(score_value), m_score_id(score_id),
      m_timestamp(create_time), m_result(result), my_score_id(0),
      my_timestamp(0), my_result(result)
  { }

  VaultCreateScore_Request(const VaultCreateScore_Request &other)
    : pqxx::transactor<>("VaultCreateScore_Request"),
      m_score_holder(other.m_score_holder), m_score_name(other.m_score_name),
      m_score_type(other.m_score_type), m_score_value(other.m_score_value),
      m_score_id(other.m_score_id), m_timestamp(other.m_timestamp),
      m_result(other.m_result), my_score_id(other.my_score_id),
      my_timestamp(other.my_timestamp), my_result(other.my_result)
  { }

  void operator()(argument_type &T) {
    std::stringstream qstr;
    qstr << "SELECT * FROM newscore(" << m_score_holder << ", '"
	 << ESC_STR(T, m_score_name->c_str()) << "', "
	 << m_score_type << ", " << m_score_value << ")";
    pqxx::result R(T.exec(qstr));

    if (R.size() != 1) {
      my_result = ERROR_INTERNAL;
    }
    else {
      pqxx::result::field F = R[0]["v_id"];
      F.to(my_score_id);
      if (my_score_id == 0) {
	my_result = ERROR_SCORE_EXISTS;
      }
      else if (my_score_id == 1) {
	my_result = ERROR_BAD_SCORE_TYPE;
      }
      else {
	my_result = NO_ERROR;
	F = R[0]["v_createtime"];
	F.to(my_timestamp);
      }
    }
  }

  void on_commit() {
    m_score_id = my_score_id;
    m_timestamp = my_timestamp;
    m_result = my_result;
  }

protected:
  kinum_t m_score_holder;
  UruString *m_score_name;
  uint32_t m_score_type;
  int32_t m_score_value;
  uint32_t &m_score_id;
  int32_t &m_timestamp;
  status_code_t &m_result;
  uint32_t my_score_id;
  int32_t my_timestamp;
  status_code_t my_result;
};

class VaultAddToScore_Request : public pqxx::transactor<> {
public:
  VaultAddToScore_Request(uint32_t score_id, int32_t delta,
			  status_code_t &result)
    : pqxx::transactor<>("VaultAddToScore_Request"),
      m_score_id(score_id), m_delta(delta), m_result(result), my_result(result)
  { }

  VaultAddToScore_Request(const VaultAddToScore_Request &other)
    : pqxx::transactor<>("VaultAddToScore_Request"),
      m_score_id(other.m_score_id), m_delta(other.m_delta),
      m_result(other.m_result), my_result(other.my_result)
  { }

  void operator()(argument_type &T) {
    std::stringstream qstr;
    qstr << "SELECT * FROM addtoscore(" << m_score_id << ", "
	 << m_delta << ")";
    pqxx::result R(T.exec(qstr));
    if (R.size() != 1) {
      my_result = ERROR_INTERNAL;
    }
    else {
      int query_result;
      R[0][0].to(query_result);
      if (query_result == 0) {
	my_result = NO_ERROR;
      }
      else if (query_result == 1) {
	my_result = ERROR_BAD_SCORE_TYPE;
      }
      else {
	my_result = ERROR_NO_SCORE;
      }
    }
  }

  void on_commit() {
    m_result = my_result;
  }

protected:
  uint32_t m_score_id;
  int32_t m_delta;
  status_code_t &m_result;
  status_code_t my_result;
};

class VaultTransferScore_Request : public pqxx::transactor<> {
public:
  VaultTransferScore_Request(uint32_t score_id, uint32_t dest_id,
			     int32_t delta, status_code_t &result)
    : pqxx::transactor<>("VaultTransferScore_Request"),
      m_score_id(score_id), m_dest_id(dest_id), m_delta(delta),
      m_result(result), my_result(result)
  { }

  VaultTransferScore_Request(const VaultTransferScore_Request &other)
    : pqxx::transactor<>("VaultTransferScore_Request"),
      m_score_id(other.m_score_id), m_dest_id(other.m_dest_id),
      m_delta(other.m_delta),
      m_result(other.m_result), my_result(other.my_result)
  { }

  void operator()(argument_type &T) {
    std::stringstream qstr;
    qstr << "SELECT * FROM transferscore(" << m_score_id << ", "
	 << m_dest_id << ", " << m_delta << ")";
    pqxx::result R(T.exec(qstr));
    if (R.size() != 1) {
      my_result = ERROR_INTERNAL;
    }
    else {
      int query_result;
      R[0][0].to(query_result);
      if (query_result == 0) {
	my_result = NO_ERROR;
      }
      else if (query_result == 1) {
	my_result = ERROR_BAD_SCORE_TYPE;
      }
      else if (query_result == 2) {
	my_result = ERROR_NO_SCORE;
      }
      else {
	my_result = ERROR_SCORE_TOO_SMALL;
      }
    }
  }

  void on_commit() {
    m_result = my_result;
  }

protected:
  uint32_t m_score_id;
  uint32_t m_dest_id;
  int32_t m_delta;
  status_code_t &m_result;
  status_code_t my_result;
};

class MarkerGameCreate_Request : public pqxx::transactor<> {
public:
  MarkerGameCreate_Request(kinum_t owner, UruString *game_name,
			   uint32_t &internal_id, char game_type,
			   u_char *game_uuid, status_code_t &result)
    : pqxx::transactor<>("MarkerGameCreate_Request"),
      m_owner(owner), m_game_name(game_name), m_type(game_type),
      m_game_id(internal_id), m_uuid(game_uuid), m_result(result),
      my_game_id(0), my_result(result)
  {
    memset(my_uuid, 0, UUID_RAW_LEN);
  }

  MarkerGameCreate_Request(const MarkerGameCreate_Request &other)
    : pqxx::transactor<>("MarkerGameCreate_Request"),
      m_owner(other.m_owner), m_game_name(other.m_game_name),
      m_type(other.m_type), m_game_id(other.m_game_id), m_uuid(other.m_uuid),
      m_result(other.m_result), my_game_id(other.my_game_id),
      my_result(other.my_result)
  {
    memcpy(my_uuid, other.my_uuid, UUID_RAW_LEN);
  }

  void operator()(argument_type &T) {
    std::stringstream qstr;
    qstr << "SELECT * FROM createmarkergame(" << m_owner << ", "
	 << m_type << ", '" << ESC_STR(T, m_game_name->c_str()) << "')";
    pqxx::result R(T.exec(qstr));
    if (R.size() != 1) {
      my_result = ERROR_INTERNAL;
    }
    else {
      my_result = NO_ERROR;
      pqxx::result::field F = R[0]["v_uuid"];
      if (F.is_null()
	  || uuid_string_to_bytes(my_uuid, UUID_RAW_LEN, F.c_str(),
				  strlen(F.c_str()), 1, 1)) {
	my_result = ERROR_INTERNAL;
	memset(my_uuid, 0, UUID_RAW_LEN);
      }
      F = R[0]["v_gameid"];
      if (F.is_null()) {
	// shouldn't happen
	my_result = ERROR_INTERNAL;
      }
      else {
	F.to(my_game_id);
      }
    }
  }

  void on_commit() {
    m_game_id = my_game_id;
    memcpy(m_uuid, my_uuid, UUID_RAW_LEN);
    m_result = my_result;
  }

protected:
  kinum_t m_owner;
  UruString *m_game_name;
  int m_type;
  uint32_t &m_game_id;
  u_char *m_uuid;
  status_code_t &m_result;
  uint32_t my_game_id;
  u_char my_uuid[UUID_RAW_LEN];
  status_code_t my_result;
};

class MarkerGameFind_Request : public pqxx::transactor<pqxx::nontransaction> {
public:
  MarkerGameFind_Request(const u_char *game_uuid, UruString &game_name,
			 uint32_t &internal_id, char &game_type,
			 status_code_t &result)
    : pqxx::transactor<pqxx::nontransaction>("MarkerGameFind_Request"),
      m_uuid(game_uuid), m_game_name(game_name), m_game_id(internal_id),
      m_type(game_type), m_result(result)
  { }

  MarkerGameFind_Request(const MarkerGameFind_Request &other)
    : pqxx::transactor<pqxx::nontransaction>("MarkerGameFind_Request"),
      m_uuid(other.m_uuid), m_game_name(other.m_game_name),
      m_game_id(other.m_game_id), m_type(other.m_type),
      m_result(other.m_result)
  { }

  void operator()(argument_type &T) {
    char uuid[UUID_STR_LEN];
    if (m_uuid) {
      uuid_bytes_to_string((u_char*)uuid, UUID_STR_LEN,
			   m_uuid, UUID_RAW_LEN, 1, 1);
    }
    else {
      m_result = ERROR_INVALID_PARAM;
      return;
    }
    pqxx::result R(T.exec("SELECT * FROM getmarkergame('" +
			  /*severe paranoia*/ESC_STR(T, uuid) + "')"));
    if (R.size() != 1) {
      m_result = ERROR_INTERNAL;
    }
    else {
      pqxx::result::field F = R[0]["v_gameid"];
      if (F.is_null()) {
	// game does not exist
	m_result = ERROR_NODE_NOT_FOUND;
      }
      else {
	m_result = NO_ERROR;
	F.to(m_game_id);
	F = R[0]["v_name"];
	if (!F.is_null()) {
	  m_game_name = F.c_str();
	}
	F = R[0]["v_type"];
	if (F.is_null()) {
	  m_type = -1;
	}
	else {
	  int intval;
	  F.to(intval);
	  m_type = intval & 0xFF;
	}
      }
    }
  }

protected:
  const u_char *m_uuid;
  UruString &m_game_name;
  uint32_t &m_game_id;
  char &m_type;
  status_code_t &m_result;
};

class MarkerGameRename_Request : public pqxx::transactor<> {
public:
  MarkerGameRename_Request(uint32_t internal_id, UruString *game_name,
			   status_code_t &result)
    : pqxx::transactor<>("MarkerGameRename_Request"),
      m_game_id(internal_id), m_game_name(game_name), m_result(result),
      my_result(result)
  { }

  MarkerGameRename_Request(const MarkerGameRename_Request &other)
    : pqxx::transactor<>("MarkerGameRename_Request"),
      m_game_id(other.m_game_id), m_game_name(other.m_game_name),
      m_result(other.m_result), my_result(other.my_result)
  { }

  void operator()(argument_type &T) {
    std::stringstream qstr;
    qstr << "SELECT * FROM renamemarkergame(" << m_game_id << ", '"
	 << ESC_STR(T, m_game_name->c_str()) << "')";
    pqxx::result R(T.exec(qstr));
    if (R.size() != 1) {
      my_result = ERROR_INTERNAL;
    }
    else {
      int query_result;
      R[0][0].to(query_result);
      if (query_result == 0) {
	my_result = NO_ERROR;
      }
      else {
	my_result = ERROR_NODE_NOT_FOUND;
      }
    }
  }

  void on_commit() {
    m_result = my_result;
  }

protected:
  uint32_t m_game_id;
  UruString *m_game_name;
  status_code_t &m_result;
  status_code_t my_result;
};

class MarkerGameDelete_Request : public pqxx::transactor<> {
public:
  MarkerGameDelete_Request(uint32_t internal_id, status_code_t &result)
    : pqxx::transactor<>("MarkerGameDelete_Request"),
      m_game_id(internal_id), m_result(result), my_result(result)
  { }

  MarkerGameDelete_Request(const MarkerGameDelete_Request &other)
    : pqxx::transactor<>("MarkerGameDelete_Request"),
      m_game_id(other.m_game_id), m_result(other.m_result),
      my_result(other.my_result)
  { }

  void operator()(argument_type &T) {
    std::stringstream qstr;
    qstr << "SELECT * FROM deletemarkergame(" << m_game_id << ")";
    pqxx::result R(T.exec(qstr));
    if (R.size() != 1) {
      my_result = ERROR_INTERNAL;
    }
    else {
      int result;
      R[0][0].to(result);
      if (result == 0) {
	my_result = NO_ERROR;
      }
      else if (result == 1) {
	my_result = ERROR_INVALID_PARAM;
      }
      else {
	my_result = ERROR_NODE_NOT_FOUND;
      }
    }
  }

  void on_commit() {
    m_result = my_result;
  }

protected:
  uint32_t m_game_id;
  status_code_t &m_result;
  status_code_t my_result;
};

class MarkerGameAddMarker_Request : public pqxx::transactor<> {
public:
  MarkerGameAddMarker_Request(uint32_t internal_id, double x, double y,
			      double z, UruString *marker_name,
			      UruString *age, int32_t &marker_num,
			      status_code_t &result)
    : pqxx::transactor<>("MarkerGameAddMarker_Request"),
      m_game_id(internal_id), m_x(x), m_y(y), m_z(z), m_name(marker_name),
      m_age(age), m_marker(marker_num), m_result(result),
      my_marker(-1), my_result(result)
  { }

  MarkerGameAddMarker_Request(const MarkerGameAddMarker_Request &other)
    : pqxx::transactor<>("MarkerGameAddMarker_Request"),
      m_game_id(other.m_game_id), m_x(other.m_x), m_y(other.m_y),
      m_z(other.m_z), m_name(other.m_name), m_age(other.m_age),
      m_marker(other.m_marker), m_result(other.m_result),
      my_marker(other.my_marker), my_result(other.my_result)
  { }

  void operator()(argument_type &T) {
    std::stringstream qstr;
    qstr << "SELECT * FROM addmarker(" << m_game_id << ", " << m_x << ", "
	 << m_y << ", " << m_z << ", '" << ESC_STR(T, m_name->c_str())
	 << "', '" << ESC_STR(T, m_age->c_str()) << "')";
    pqxx::result R(T.exec(qstr));
    if (R.size() != 1) {
      my_result = ERROR_INTERNAL;
    }
    else {
      R[0][0].to(my_marker);
      if (my_marker < 0) {
	my_result = ERROR_NODE_NOT_FOUND;
      }
      else {
	my_result = NO_ERROR;
      }
    }
  }

  void on_commit() {
    m_marker = my_marker;
    m_result = my_result;
  }

protected:
  uint32_t m_game_id;
  double m_x, m_y, m_z;
  UruString *m_name;
  UruString *m_age;
  int32_t &m_marker;
  status_code_t &m_result;
  int32_t my_marker;
  status_code_t my_result;
};

class MarkerGameRenameMarker_Request : public pqxx::transactor<> {
public:
  MarkerGameRenameMarker_Request(uint32_t internal_id, int marker_num,
				 UruString *marker_name, status_code_t &result)
    : pqxx::transactor<>("MarkerGameRenameMarker_Request"),
      m_game_id(internal_id), m_marker(marker_num), m_name(marker_name),
      m_result(result), my_result(result)
  { }

  MarkerGameRenameMarker_Request(const MarkerGameRenameMarker_Request &other)
    : pqxx::transactor<>("MarkerGameRenameMarker_Request"),
      m_game_id(other.m_game_id), m_marker(other.m_marker),
      m_name(other.m_name), m_result(other.m_result),
      my_result(other.my_result)
  { }

  void operator()(argument_type &T) {
    std::stringstream qstr;
    qstr << "SELECT * FROM renamemarker(" << m_game_id << ", "
	 << m_marker << ", '" << ESC_STR(T, m_name->c_str()) << "')";
    pqxx::result R(T.exec(qstr));
    if (R.size() != 1) {
      my_result = ERROR_INTERNAL;
    }
    else {
      int query_result;
      R[0][0].to(query_result);
      if (query_result) {
	my_result = ERROR_NODE_NOT_FOUND;
      }
      else {
	my_result = NO_ERROR;
      }
    }
  }

  void on_commit() {
    m_result = my_result;
  }

protected:
  uint32_t m_game_id;
  int m_marker;
  UruString *m_name;
  status_code_t &m_result;
  status_code_t my_result;
};

class MarkerGameDeleteMarker_Request : public pqxx::transactor<> {
public:
  MarkerGameDeleteMarker_Request(uint32_t internal_id, int marker_num,
				 status_code_t &result)
    : pqxx::transactor<>("MarkerGameDeleteMarker_Request"),
      m_game_id(internal_id), m_marker(marker_num), m_result(result),
      my_result(result)
  { }

  MarkerGameDeleteMarker_Request(const MarkerGameDeleteMarker_Request &other)
    : pqxx::transactor<>("MarkerGameDeleteMarker_Request"),
      m_game_id(other.m_game_id), m_marker(other.m_marker),
      m_result(other.m_result), my_result(other.my_result)
  { }

  void operator()(argument_type &T) {
    std::stringstream qstr;
    qstr << "SELECT * FROM deletemarker(" << m_game_id << ", "
	 << m_marker << ")";
    pqxx::result R(T.exec(qstr));
    if (R.size() != 1) {
      my_result = ERROR_INTERNAL;
    }
    else {
      int query_result;
      R[0][0].to(query_result);
      if (query_result) {
	my_result = ERROR_NODE_NOT_FOUND;
      }
      else {
	my_result = NO_ERROR;
      }
    }
  }

  void on_commit() {
    m_result = my_result;
  }

protected:
  uint32_t m_game_id;
  int m_marker;
  status_code_t &m_result;
  status_code_t my_result;
};
#endif /* USE_PQXX */

typedef struct {
  int32_t marker_id;
  double x;
  double y;
  double z;
  UruString marker_name;
  UruString age_name;
} MarkerGame_MarkerInfo;

typedef struct {
  int32_t marker_id;
  int32_t capture_value;
} MarkerGame_CapturedMarker;

#ifdef USE_PQXX
class MarkerGameMarkers_Request
  : public pqxx::transactor<pqxx::nontransaction> {
public:
  MarkerGameMarkers_Request(uint32_t internal_id, status_code_t &result,
			    std::vector<MarkerGame_MarkerInfo> &markerlist)
    : pqxx::transactor<pqxx::nontransaction>("MarkerGameMarkers_Request"),
      m_game_id(internal_id), m_list(markerlist), m_result(result)
  { }

  MarkerGameMarkers_Request(const MarkerGameMarkers_Request &other)
    : pqxx::transactor<pqxx::nontransaction>("MarkerGameMarkers_Request"),
      m_game_id(other.m_game_id), m_list(other.m_list),
      m_result(other.m_result)
  { }

  void operator()(argument_type &T) {
    std::stringstream qstr;
    qstr << "SELECT * FROM getmarkers(" << m_game_id << ")";
    pqxx::result R(T.exec(qstr));

    m_result = NO_ERROR;
    if (R.size() == 0) {
      return;
    }
    if (m_list.size() != 0) {
      // this should not happen
      throw std::runtime_error("We appear to have restarted what should be a "
			  "nontransaction which only sets local state after "
			  "the entire DB interaction succeeds!");
    }
    m_list.reserve(R.size());
    for (pqxx::result::const_iterator row = R.begin(); row != R.end(); row++) {
      MarkerGame_MarkerInfo marker;
      pqxx::result::field F = row["v_id"];
      if (F.is_null()) {
	marker.marker_id = -1;
      }
      else {
	F.to(marker.marker_id);
      }
      F = row["v_x"];
      if (!F.is_null()) {
	F.to(marker.x);
      }
      F = row["v_y"];
      if (!F.is_null()) {
	F.to(marker.y);
      }
      F = row["v_z"];
      if (!F.is_null()) {
	F.to(marker.z);
      }
      F = row["v_name"];
      if (!F.is_null()) {
	marker.marker_name = F.c_str();
      }
      F = row["v_age"];
      if (!F.is_null()) {
	marker.age_name = F.c_str();
      }
      m_list.push_back(marker);
    }
  }

protected:
  uint32_t m_game_id;
  std::vector<MarkerGame_MarkerInfo> &m_list;
  status_code_t &m_result;
};

class MarkerGameCaptured_Request
  : public pqxx::transactor<pqxx::nontransaction> {
public:
  MarkerGameCaptured_Request(uint32_t internal_id, kinum_t player,
			     status_code_t &result,
			     std::vector<MarkerGame_CapturedMarker> &markers)
    : pqxx::transactor<pqxx::nontransaction>("MarkerGameCaptured_Request"),
      m_game_id(internal_id), m_player(player), m_list(markers),
      m_result(result)
  { }

  MarkerGameCaptured_Request(const MarkerGameCaptured_Request &other)
    : pqxx::transactor<pqxx::nontransaction>("MarkerGameCaptured_Request"),
      m_game_id(other.m_game_id), m_player(other.m_player),
      m_list(other.m_list), m_result(other.m_result)
  { }

  void operator()(argument_type &T) {
    std::stringstream qstr;
    qstr << "SELECT * FROM capturedmarkers(" << m_game_id << ", "
	 << m_player << ")";
    pqxx::result R(T.exec(qstr));

    m_result = NO_ERROR;
    if (R.size() == 0) {
      return;
    }
    if (m_list.size() != 0) {
      // this should not happen
      throw std::runtime_error("We appear to have restarted what should be a "
			  "nontransaction which only sets local state after "
			  "the entire DB interaction succeeds!");
    }
    m_list.reserve(R.size());
    for (pqxx::result::const_iterator row = R.begin(); row != R.end(); row++) {
      MarkerGame_CapturedMarker marker;
      pqxx::result::field F = row["v_id"];
      if (F.is_null()) {
	marker.marker_id = -1;
      }
      else {
	F.to(marker.marker_id);
      }
      F = row["v_value"];
      if (F.is_null()) {
	marker.capture_value = 0;
      }
      else {
	F.to(marker.capture_value);
      }
      m_list.push_back(marker);
    }
  }

protected:
  uint32_t m_game_id;
  kinum_t m_player;
  std::vector<MarkerGame_CapturedMarker> &m_list;
  status_code_t &m_result;
};

class MarkerGameCaptureMarker_Request : public pqxx::transactor<> {
public:
  MarkerGameCaptureMarker_Request(uint32_t internal_id, kinum_t player,
				  int marker_num, int capture_value,
				  status_code_t &result)
    : pqxx::transactor<>("MarkerGameCaptureMarker_Request"),
      m_game_id(internal_id), m_player(player), m_marker(marker_num),
      m_value(capture_value), m_result(result), my_result(result)
  { }

  MarkerGameCaptureMarker_Request(const MarkerGameCaptureMarker_Request &other)
    : pqxx::transactor<>("MarkerGameCaptureMarker_Request"),
      m_game_id(other.m_game_id), m_player(other.m_player),
      m_marker(other.m_marker), m_value(other.m_value),
      m_result(other.m_result), my_result(other.my_result)
  { }

  void operator()(argument_type &T) {
    std::stringstream qstr;
    qstr << "SELECT * FROM setmarkerto(" << m_game_id << ", "
	 << m_player << ", " << m_marker << ", " << m_value << ")";
    pqxx::result R(T.exec(qstr));
    if (R.size() != 1) {
      my_result = ERROR_INTERNAL;
    }
    else {
      int query_result;
      R[0][0].to(query_result);
      if (query_result < 0) {
	my_result = ERROR_NODE_NOT_FOUND;
      }
      else if (query_result == 0) {
	my_result = NO_ERROR;
      }
      else {
	// this is kind of a bogus error, but it's not sent over the wire,
	// so whatever
	my_result = ERROR_SCORE_EXISTS;
      }
    }
  }

  void on_commit() {
    m_result = my_result;
  }

protected:
  uint32_t m_game_id;
  kinum_t m_player;
  int m_marker;
  int m_value;
  status_code_t &m_result;
  status_code_t my_result;
};

class MarkerGameStop_Request : public pqxx::transactor<> {
public:
  MarkerGameStop_Request(uint32_t internal_id, kinum_t player,
			 status_code_t &result)
    : pqxx::transactor<>("MarkerGameStop_Request"),
      m_game_id(internal_id), m_player(player),
      m_result(result), my_result(result)
  { }

  MarkerGameStop_Request(const MarkerGameStop_Request &other)
    : pqxx::transactor<>("MarkerGameStop_Request"),
      m_game_id(other.m_game_id), m_player(other.m_player),
      m_result(other.m_result), my_result(other.my_result)
  { }

  void operator()(argument_type &T) {
    std::stringstream qstr;
    qstr << "SELECT stopmarkergame(" << m_game_id << ", "
	 << m_player << ")";
    pqxx::result R(T.exec(qstr));
    my_result = NO_ERROR;
  }

  void on_commit() {
    m_result = my_result;
  }

protected:
  uint32_t m_game_id;
  kinum_t m_player;
  status_code_t &m_result;
  status_code_t my_result;
};

class VaultGetAgeByUUID : public pqxx::transactor<pqxx::nontransaction> {
public:
  VaultGetAgeByUUID(const u_char *uuid, uint32_t &age_node,
		    uint32_t &age_info, UruString &filename,
		    status_code_t &result)
    : pqxx::transactor<pqxx::nontransaction>("VaultGetAgeByUUID"),
      m_uuid(uuid), m_age_node(age_node), m_age_info(age_info),
      m_age_name(filename), m_result(result)
 { }

  VaultGetAgeByUUID(const VaultGetAgeByUUID &other) 
    : pqxx::transactor<pqxx::nontransaction>("VaultGetAgeByUUID"),
      m_uuid(other.m_uuid), m_age_node(other.m_age_node),
      m_age_info(other.m_age_info), m_age_name(other.m_age_name),
      m_result(other.m_result)
 { }

  void operator()(argument_type &T) {
    char uuid[UUID_STR_LEN];
    uuid_bytes_to_string((u_char*)uuid, UUID_STR_LEN,
			 m_uuid, UUID_RAW_LEN, 1, 1);

    pqxx::result R(T.exec("SELECT * FROM getagebyuuid('" +
			  /*severe paranoia*/ESC_STR(T, uuid) + "')"));
    m_age_node = 0;
    if (R.size() != 1) {
      m_result = ERROR_INTERNAL;
    }
    else {
      m_result = NO_ERROR;
      pqxx::result::field F = R[0]["v_agenode"];
      if (F.is_null()) {
	m_result = ERROR_INTERNAL;
      }
      else {
	F.to(m_age_node);
	if (m_age_node == 0) {
	  m_result = ERROR_AGE_NOT_FOUND;
	}
      }
      F = R[0]["v_ageinfo"];
      if (F.is_null()) {
	m_age_info = 0;
      }
      else {
	F.to(m_age_info);
      }
      F = R[0]["v_filename"];
      m_age_name = F.c_str();
    }
  }

protected:
  const u_char *m_uuid;
  uint32_t &m_age_node;
  uint32_t &m_age_info;
  UruString &m_age_name;
  status_code_t &m_result;
};

class SetPlayerOffline : public pqxx::transactor<> {
public:
  SetPlayerOffline(kinum_t kinum, bool &was_online, uint32_t &info_node,
		   status_code_t &result)
    : pqxx::transactor<>("SetPlayerOffline"), m_kinum(kinum),
      m_online(was_online), m_node(info_node), m_result(result),
      my_online(true), my_node(0), my_result(ERROR_INTERNAL)
  { }

  SetPlayerOffline(const SetPlayerOffline &other)
    : pqxx::transactor<>("SetPlayerOffline"), m_kinum(other.m_kinum),
      m_online(other.m_online), m_node(other.m_node),
      m_result(other.m_result), my_online(other.my_online),
      my_node(other.my_node), my_result(other.my_result)
  { }

  void operator()(argument_type &T) {
    std::stringstream qstr;
    qstr << "SELECT * FROM setplayeroffline(" << m_kinum << ")";
    pqxx::result R(T.exec(qstr));
    if (R.size() != 1) {
      my_result = ERROR_INTERNAL;
    }
    else {
      my_result = NO_ERROR;
      pqxx::result::field F = R[0]["v_online"];
      if (F.is_null()) {
	my_online = false;
      }
      else {
	int online;
	F.to(online);
	my_online = (online != 0 ? true : false);
      }
      F = R[0]["v_node"];
      if (F.is_null()) {
	my_result = ERROR_NODE_NOT_FOUND;
      }
      else {
	F.to(my_node);
      }
    }
  }

  void on_commit() {
    m_online = my_online;
    m_node = my_node;
    m_result = my_result;
  }

protected:    
  kinum_t m_kinum;
  bool &m_online;
  uint32_t &m_node;
  status_code_t &m_result;
  bool my_online;
  uint32_t my_node;
  status_code_t my_result;
};

class SetPlayerConnected : public pqxx::transactor<> {
public:
  SetPlayerConnected(kinum_t kinum, status_code_t &result)
    : pqxx::transactor<>("SetPlayerConnected"), m_kinum(kinum),
      m_result(result), my_result(ERROR_INTERNAL)
  { }

  SetPlayerConnected(const SetPlayerConnected &other)
    : pqxx::transactor<>("SetPlayerConnected"), m_kinum(other.m_kinum),
      m_result(other.m_result), my_result(other.my_result)
  { }

  void operator()(argument_type &T) {
    std::stringstream qstr;
    qstr << "SELECT setplayerconnected(" << m_kinum << ")";
    T.exec(qstr);
    my_result = NO_ERROR;
  }

  void on_commit() {
    m_result = my_result;
  }

protected:    
  kinum_t m_kinum;
  status_code_t &m_result;
  status_code_t my_result;
};

class PlayersReferringTo : public pqxx::transactor<pqxx::nontransaction> {
public:
  PlayersReferringTo(uint32_t node, status_code_t &result,
		     std::vector<kinum_t> &players)
    : pqxx::transactor<pqxx::nontransaction>("PlayersReferringTo"),
      m_node(node), m_result(result), m_list(players),
      my_result(ERROR_INTERNAL)
  { }

  PlayersReferringTo(const PlayersReferringTo &other) 
    : pqxx::transactor<pqxx::nontransaction>("PlayersReferringTo"),
      m_node(other.m_node), m_result(other.m_result), m_list(other.m_list),
      my_result(other.my_result)
  { }

  void operator()(argument_type &T) {
    std::stringstream qstr;
    qstr << "SELECT * FROM notifyplayers(" << m_node << ")";
    pqxx::result R(T.exec(qstr));

    my_result = NO_ERROR;
    if (R.size() == 0) {
      // there are no players with a ref to this node
      return;
    }
    if (m_list.size() != 0) {
      // this should not happen
      throw std::runtime_error("We appear to have restarted what should be a "
			  "nontransaction which only sets local state after "
			  "the entire DB interaction succeeds!");
    }
    // check for -1 special case
    if (R.size() == 1) {
      int32_t value;
      R[0][0].to(value);
      if (value == -1) {
	// not realy an error but meh.
	my_result = ERROR_MAX_PLAYERS;
      }
      else {
	// we can skip the for loop since we already have all the info
	m_list.push_back((kinum_t)value);
      }
      return;
    }
    m_list.reserve(R.size());
    for (pqxx::result::const_iterator row = R.begin(); row != R.end(); row++) {
      uint32_t ki;
      row[0].to(ki);
      m_list.push_back((kinum_t)ki);
    }
  }

  void on_commit() {
    m_result = my_result;
  }

protected:
  uint32_t m_node;
  status_code_t &m_result;
  std::vector<kinum_t> &m_list;
  status_code_t my_result;
};

class AgeReferringTo : public pqxx::transactor<pqxx::nontransaction> {
public:
  AgeReferringTo(uint32_t node, u_char *uuid, status_code_t &result)
    : pqxx::transactor<pqxx::nontransaction>("AgeReferringTo"),
      m_node(node), m_uuid(uuid), m_result(result), my_result(ERROR_INTERNAL)
  {
    memset(my_uuid, 0, UUID_RAW_LEN);
  }

  AgeReferringTo(const AgeReferringTo &other) 
    : pqxx::transactor<pqxx::nontransaction>("AgeReferringTo"),
      m_node(other.m_node), m_uuid(other.m_uuid), m_result(other.m_result),
      my_result(other.my_result)
  {
    memcpy(my_uuid, other.my_uuid, UUID_RAW_LEN);
  }

  void operator()(argument_type &T) {
    std::stringstream qstr;
    qstr << "SELECT * FROM notifyage(" << m_node << ")";
    pqxx::result R(T.exec(qstr));

    if (R.size() == 0) {
      // there is no age with a ref to this node
      my_result = ERROR_NODE_NOT_FOUND;
      return;
    }
    else {
      my_result = NO_ERROR;
      pqxx::result::field F = R[0][0];
      if (F.is_null()
	  || uuid_string_to_bytes(my_uuid, UUID_RAW_LEN, F.c_str(),
				  strlen(F.c_str()), 1, 1)) {
	my_result = ERROR_INTERNAL;
	memset(my_uuid, 0, UUID_RAW_LEN);
      }
    }
  }

  void on_commit() {
    if (my_result == NO_ERROR) {
      memcpy(m_uuid, my_uuid, UUID_RAW_LEN);
    }
    m_result = my_result;
  }

protected:
  uint32_t m_node;
  u_char *m_uuid;
  status_code_t &m_result;
  u_char my_uuid[UUID_RAW_LEN];
  status_code_t my_result;
};

class DeleteAge : public pqxx::transactor<> {
public:
  DeleteAge(uint32_t ageinfo_node, status_code_t &result)
    : pqxx::transactor<>("DeleteAge"), m_age(ageinfo_node),
      m_result(result), my_result(ERROR_INTERNAL)
  { }

  DeleteAge(const DeleteAge &other)
    : pqxx::transactor<>("DeleteAge"), m_age(other.m_age),
      m_result(other.m_result), my_result(other.my_result)
  { }

  void operator()(argument_type &T) {
    std::stringstream qstr;
    qstr << "SELECT deleteage(" << m_age << ")";
    T.exec(qstr);
    my_result = NO_ERROR;
  }

  void on_commit() {
    m_result = my_result;
  }

protected:    
  uint32_t m_age;
  status_code_t &m_result;
  status_code_t my_result;
};

class GetGlobalSDL : public pqxx::transactor<pqxx::nontransaction> {
public:
  // *outbuf must be set NULL by caller
  GetGlobalSDL(UruString &filename, u_char **outbuf, u_int &buflen,
	       status_code_t &result)
    : pqxx::transactor<pqxx::nontransaction>("GetGlobalSDL"),
      m_filename(filename), m_outbuf(outbuf), m_buflen(buflen),
      m_result(result)
  { }

  GetGlobalSDL(const GetGlobalSDL &other)
    : pqxx::transactor<pqxx::nontransaction>("GetGlobalSDL"),
      m_filename(other.m_filename), m_outbuf(other.m_outbuf),
      m_buflen(other.m_buflen), m_result(other.m_result)
  { }

  void operator()(argument_type &T) {
    pqxx::result R(T.exec("SELECT * FROM getglobalsdlbyname('" +
			  ESC_STR(T, m_filename.c_str()) + "')"));
    if (*m_outbuf) {
      // this should not happen
      throw std::runtime_error("We appear to have restarted what should be a "
			  "nontransaction which only sets local state after "
			  "the entire DB interaction succeeds!");
    }
    pqxx::result::field F = R[0]["v_sdl"];
    if (F.is_null()) {
      // node simply not there, or no data
      m_result = NO_ERROR;
      return;
    }
    pqxx::binarystring blob(F);
    m_buflen = read32(blob.data(), 0);
    if (m_buflen+4 != blob.length()) {
      // the data from the vault is wrong
      m_result = ERROR_INVALID_DATA;
      return;
    }
    *m_outbuf = new u_char[m_buflen];
    memcpy(*m_outbuf, blob.data()+4, m_buflen);
    m_result = NO_ERROR;
  }

protected:    
  UruString &m_filename;
  u_char **m_outbuf;
  u_int &m_buflen;
  status_code_t &m_result;
};

class GetVaultSDL : public pqxx::transactor<pqxx::nontransaction> {
public:
  // *outbuf must be set NULL by caller
  GetVaultSDL(uint32_t ageinfo, UruString &filename,
	      u_char **outbuf, u_int &buflen, status_code_t &result)
    : pqxx::transactor<pqxx::nontransaction>("GetVaultSDL"),
      m_age(ageinfo), m_filename(filename), m_outbuf(outbuf),
      m_buflen(buflen), m_result(result)
  { }

  GetVaultSDL(const GetVaultSDL &other)
    : pqxx::transactor<pqxx::nontransaction>("GetVaultSDL"),
      m_age(other.m_age), m_filename(other.m_filename),
      m_outbuf(other.m_outbuf), m_buflen(other.m_buflen),
      m_result(other.m_result)
  { }

  void operator()(argument_type &T) {
    std::stringstream qstr;
    qstr << "SELECT * FROM getagesdl(" << m_age << ", '"
	 << ESC_STR(T, m_filename.c_str()) + "')";
    pqxx::result R(T.exec(qstr));

    if (*m_outbuf) {
      // this should not happen
      throw std::runtime_error("We appear to have restarted what should be a "
			  "nontransaction which only sets local state after "
			  "the entire DB interaction succeeds!");
    }
    pqxx::result::field F = R[0]["v_sdl"];
    if (F.is_null()) {
      // node simply not there, or no data
      m_result = NO_ERROR;
      return;
    }
    pqxx::binarystring blob(F);
    m_buflen = read32(blob.data(), 0);
    if (m_buflen+4 != blob.length()) {
      // the data from the vault is wrong
      m_result = ERROR_INVALID_DATA;
      return;
    }
    *m_outbuf = new u_char[m_buflen];
    memcpy(*m_outbuf, blob.data()+4, m_buflen);
    m_result = NO_ERROR;
  }

protected:    
  uint32_t m_age;
  UruString &m_filename;
  u_char **m_outbuf;
  u_int &m_buflen;
  status_code_t &m_result;
};

class GetAgeUUIDFor : public pqxx::transactor<pqxx::nontransaction> {
public:
  GetAgeUUIDFor(uint32_t childnode, u_char *uuid, status_code_t &result)
    : pqxx::transactor<pqxx::nontransaction>("GetAgeUUIDFor"),
      m_node(childnode), m_uuid(uuid), m_result(result)
  { }

  GetAgeUUIDFor(const GetAgeUUIDFor &other)
    : pqxx::transactor<pqxx::nontransaction>("GetAgeUUIDFor"),
      m_node(other.m_node), m_uuid(other.m_uuid), m_result(other.m_result)
  { }

  void operator()(argument_type &T) {
    std::stringstream qstr;
    qstr << "SELECT * FROM getuuidforsdl(" << m_node << ")";
    pqxx::result R(T.exec(qstr));

    pqxx::result::field F = R[0][0];
    if (F.is_null()) {
      // empty result
      m_result = ERROR_NODE_NOT_FOUND;
    }
    else if (uuid_string_to_bytes(m_uuid, UUID_RAW_LEN, F.c_str(),
			     strlen(F.c_str()), 1, 1)) {
      m_result = ERROR_INVALID_PARAM;
    }
    else {
      m_result = NO_ERROR;
    }
  }

protected:
  uint32_t m_node;
  u_char *m_uuid;
  status_code_t &m_result;
};

class Egg1 : public pqxx::transactor<> {
public:
  Egg1(kinum_t kinum, uint32_t &parent, uint32_t &child, status_code_t &result)
    : pqxx::transactor<>("Egg1"),
      m_kinum(kinum), m_parent(parent), m_child(child), m_result(result),
      my_parent(0), my_child(0), my_result(ERROR_INTERNAL)
  { }

  Egg1(const Egg1 &other)
    : pqxx::transactor<>("Egg1"),
      m_kinum(other.m_kinum), m_parent(other.m_parent), m_child(other.m_child),
      m_result(other.m_result), my_parent(other.my_parent),
      my_child(other.my_child), my_result(other.my_result)
  { }

  void operator()(argument_type &T) {
    std::stringstream qstr;
    qstr << "SELECT * FROM egg1award(" << m_kinum << ")";
    pqxx::result R(T.exec(qstr));

    if (R.size() != 1) {
      my_result = ERROR_INTERNAL;
    }
    else {
      pqxx::result::field F = R[0]["v_parent"];
      if (!F.is_null()) {
	F.to(my_parent);
	if (my_parent == 0) {
	  my_child = 0;
	  my_result = NO_ERROR;
	}
	else {
	  F = R[0]["v_child"];
	  if (!F.is_null()) {
	    F.to(my_child);
	    if (my_child != 0) {
	      my_result = NO_ERROR;
	    }
	  }
	}
      }
    }
  }

  void on_commit() {
    if (my_parent != 0) {
      m_parent = my_parent;
      m_child = my_child;
    }
    else {
      m_parent = 0;
      m_child = 0;
    }
    m_result = my_result;
  }

protected:
  kinum_t m_kinum;
  uint32_t &m_parent;
  uint32_t &m_child;
  status_code_t &m_result;
  uint32_t my_parent;
  uint32_t my_child;
  status_code_t my_result;
};

#endif /* USE_PQXX */

#endif /* _DB_REQUESTS_H_ */
