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

#include <stdarg.h>
#include <iconv.h>

#include <exception>
#include <list>
#include <string>
#include <sstream>
#include <iomanip>

#ifdef USE_POSTGRES
#ifdef USE_PQXX
#include <pqxx/pqxx>
#include <pqxx/binarystring>
#else
#include <libpq-fe.h>
#endif
#endif

#include "machine_arch.h"
#include "protocol.h"
#include "util.h"
#include "UruString.h"
#include "VaultNode.h"

#include "Logger.h"

#include "db_requests.h"


#ifdef USE_POSTGRES

#ifdef USE_PQXX
std::string ESC_BIN(pqxx::transaction_base &T, const u_char *s, u_int len) {
  std::stringstream res;
  res << std::oct << std::setfill('0');
  for (u_int i = 0; i < len; i++) {
    res << std::setw(2) << "\\\\" << std::setw(3) << (int)s[i];
  }
  // copying is fun!
  return res.str();
}
#endif

#ifndef USE_PQXX
void AuthAcctLogin_AcctQuery(BackendObj *conn, char *name,
			     AuthAcctLogin_AcctQuery_Result &result) {
  static int tries = 0;
  // if using PQexec instead, use PQescapeStringConn on name
  PGresult *res = PQexecParams(conn->C,
			       "SELECT hash,class,id,visitor,banned "
			       "FROM accounts WHERE name=$1;",
			       1, NULL, &name, NULL, NULL, 0);
  if (!res) {
    result.result_code = ERROR_INTERNAL;
    // XXX do this instead when exceptions are right
    //throw std::bad_alloc("NULL result from PQexecParams"
    //			 "in AuthAcctLogin_AuthQuery");
    return;
  }
  
  ExecStatusType exec_status = PQresultStatus(res);
  if (exec_status == PGRES_FATAL_ERROR) {
    log_err(conn->log, "DB fatal error: %s", PQresultErrorMessage(res));
    if (PQstatus(conn->C) == CONNECTION_BAD) {
      if (tries == 0) {
	log_info(conn->log, "attempting to reconnect to DB\n");
      }
      if (tries == 3) {
	// XXX pretty much fatal -- need to shut down or something
	log_err(conn->log, "Connection to DB failed!\n");
	result.result_code = ERROR_DB_TIMEOUT;
      }
      else {
	if (conn->restart_connection()) {
	  tries++;
	  AuthAcctLogin_AcctQuery(conn, name, pw_hash, result);
	  tries--;
	}
	else {
	  result.result_code = ERROR_DB_TIMEOUT;
	}
      }
    }
    else {
      result.result_code = ERROR_INTERNAL;
    }
  }
  else if (exec_status == PGRES_BAD_RESPONSE) {
    result.result_code = ERROR_INTERNAL;
  }
//  else if (exec_status == PGRES_NONFATAL_ERROR) {
//    // ???
//  }
  else {
    int ntuples = PQntuples(res);
    if (ntuples == 0) {
      result.result_code = ERROR_ACCT_NOT_FOUND;
    }
    else if (ntuples == 1 && PQnfields(res) == 5) {
      result.result_code = NO_ERROR;
      int colnum = PQfnumber(res, "banned");
      char *value;
      if (!PQgetisnull(res, 0, colnum)) {
	value = PQgetvalue(res, 0, colnum);
	if (value[0] == 't' || value[0] == 'T') {
	  result.result_code = ERROR_BANNED;
	}
      }
      if (result.result_code == NO_ERROR) {
	colnum = PQfnumber(res, "hash");
	value = PQgetvalue(res, 0, colnum);
	if (strlen(value) != 40) {
	  result.result_code = ERROR_INVALID_PARAM;
	}
	else {
	  int i;
	  unsigned int data;
	  for (i = 19; i >= 0; i--) {
	    /* if we sscanf four bytes at a time, we have to byte-swap
	       to big-endian */
	    if (sscanf(value+(2*i), "%x", &data) != 1) {
	      result.result_code = ERROR_INVALID_PARAM;
	      break;
	    }
	    result.hash[i] = (u_char)(data & 0xFF);
	    hash[2*i] = '\0';
	  }
	}
	if (result.result_code == NO_ERROR) {
	  colnum = PQfnumber(res, "class");
	  if (PQgetisnull(res, 0, colnum)) {
	    result.user_class = "default";
	  }
	  else {
	    result.user_class = PQgetvalue(res, 0, colnum);
	  }
	  colnum = PQfnumber(res, "id");
	  value = PQgetvalue(res, 0, colnum);
	  // NOTE: if I use the uuid native type and provide 1 (get binary
	  // data) as the last argument to PQexecParams, the uuid comes
	  // back as 16-byte binary encoded, though I would still have to
	  // byte-swap it to Uru format
	  if (PQgetisnull(res, 0, colnum)
	      || uuid_string_to_bytes(result.uuid, UUID_RAW_LEN, value,
				      strlen(value), 1, 1)) {
	    memset(result.uuid, 0, UUID_RAW_LEN);
	  }
	  colnum = PQfnumber(res, "visitor");
	  value = PQgetvalue(res, 0, colnum);
	  if (value[0] == 'f' || value[0] == 'F') {
	    result.is_visitor = false;
	  }
	  else {
	    result.is_visitor = true;
	  }
	}
      }
    }
  }
  PQclear(res);
}
#endif
#endif
