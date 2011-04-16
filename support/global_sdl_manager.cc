/*
  MOSS - A server for the Myst Online: Uru Live client/protocol
  Copyright (C) 2009,2011  a'moaca'

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

/*
 * This program allows manipulation of SDL nodes in the MOSS vault. It
 * connects directly to the DB to do it. Changes made are not propagated
 * to clients.
 *
 * This is like a poor man's VaultManager and only a very small subset of it
 * at that.
 *
 * If propagation is needed, the best thing would be to instead connect
 * through the auth server (requiring: auth server to allow vault operations
 * without python download first, auth server to check whether an account is
 * allowed to do this (new column in accounts table, new backend message),
 * and some way to indicate it's a manager, not a client, connection.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <iconv.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <getopt.h>
#include <dirent.h>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <stdexcept>
#include <list>
#include <vector>

#include "machine_arch.h"
#include "protocol.h"
#include "exceptions.h"
#include "util.h"
#include "UruString.h"
#include "PlKey.h"
#include "Logger.h"
#include "SDL.h"

#ifdef USE_POSTGRES
#ifdef USE_PQXX
#include <pqxx/pqxx>
#include <pqxx/binarystring>
#else
#include <libpq-fe.h>
#endif
#endif
#include "VaultNode.h"
#include "db_requests.h"

// DB queries
#ifdef USE_PQXX
class GetFolder : public pqxx::transactor<pqxx::nontransaction> {
public:
  GetFolder(u_int &folder) 
    : pqxx::transactor<pqxx::nontransaction>("GetFolder"),
      m_folder(folder)
  { }

  GetFolder(const GetFolder &other) 
    : pqxx::transactor<pqxx::nontransaction>("GetFolder"),
      m_folder(other.m_folder)
  { }

  void operator()(argument_type &T) {
    pqxx::result R(T.exec("SELECT nodeid FROM folder WHERE TYPE = 20"));
    if (R.size() == 0) {
      fprintf(stderr, "No AllAgeGlobalSDLNodes folder found in DB!\n");
      m_folder = 0;
    }
    else {
      R[0][0].to(m_folder);
    }
  }

protected:
  u_int &m_folder;
};
#endif

void print_state(SDLState *st, int indent=0);
void print_data_by_type(SDLDesc::Variable::data_t *data, u_int count,
			SDLDesc::sdl_type_t type);
int get_all_sdls(const char *dirname, std::list<SDLDesc*> &sdls,
		 bool die_on_error);
SDLState * read_state(VaultNode *node, std::list<SDLDesc*> &sdls);
bool update_sdl(SDLState *sdl, u_int idx, std::stringstream &in);

int main(int argc, char *argv[]) {
  static struct option options[] = {
    { "host", required_argument, 0, 'h' },
    { "user", required_argument, 0, 'U' },
    { "password", required_argument, 0, 'p' },
    { "dbname", required_argument, 0, 'd' },
    { "options", required_argument, 0, 'o' },
    { 0, 0, 0, 0 }
  };
  static const char *usage = "Usage: %s [-h <DB addr[:port]>] [-U <DB username>] [-p <DB password>] [-d <DB name>] [-o <DB options>] <top level SDL directory (unencrypted)>\n";
  char c;
  opterr = 0;
  char *addrspec = NULL, *username = NULL, *password = NULL, *db_name = NULL;
  char *db_opts = NULL;
  while ((c = getopt_long(argc, argv, "h:U:p:d:o:", options, NULL)) != -1) {
    switch (c) {
    case 'h':
      addrspec = strdup(optarg);
      break;
    case 'U':
      username = strdup(optarg);
      break;
    case 'p':
      password = strdup(optarg);
      break;
    case 'd':
      db_name = strdup(optarg);
      break;
    case 'o':
      db_opts = strdup(optarg);
      break;
    default:
      fprintf(stderr, usage, argv[0]);
      return 1;
    }
  }
  int i = optind;
  if (i >= argc) {
    fprintf(stderr, usage, argv[0]);
    return 1;
  }

  std::list<SDLDesc*> sdls;
  struct stat s;  
  int ret = stat(argv[i], &s);
  if (ret < 0) {
    fprintf(stderr, "%s does not exist\n", argv[i]);
    return -1;
  }

  // read in SDL files
  if (get_all_sdls(argv[i], sdls, true)) {
    return -1;
  }
  if (sdls.size() == 0) {
    // we can be of no use like this
    fprintf(stderr, "No SDL data loaded\n");
    return -1;
  }

  // connect to DB, and get AllAgeGlobalSDLNodes folder
  int port = 0;
  if (addrspec) {
    char *cp = strchr(addrspec, ':');
    if (cp) {
      *cp++ = '\0';
      int num = sscanf(cp, "%u", &port);
      if (num != 1) {
	fprintf(stderr, "Cannot parse %s as a port number\n", cp);
      }
    }
  }
  BackendObj *db = NULL;
  try {
    db = new BackendObj(/*Logger*/NULL,
			addrspec, port, db_opts, username, password,
			db_name ? db_name : "moss");
    if (db->connection_failed) {
      fprintf(stderr, "Error connecting to database\n");
      delete db;
      return -1;
    }
  }
  catch (const pqxx::broken_connection &e) {
    fprintf(stderr, "DB connection failure: %s\n", e.what());
    delete db;
    return -1;
  }
  uint32_t folder;
  std::vector<VaultFetchRefs_VaultRef> agelist;
  std::vector<VaultNode*> sdlnodes;
  try {
    db->C->perform(GetFolder(folder));
    if (folder == 0) {
      delete db;
      return -1;
    }
    // get contents
    status_code_t result = NO_ERROR;
    db->C->perform(VaultFetchRefs_Request(folder, result, agelist));
    if (result != NO_ERROR) {
      fprintf(stderr, "Bad result %d fetching node list\n", result);
      delete db;
      return -1;
    }
    for (std::vector<VaultFetchRefs_VaultRef>::iterator
	   riter = agelist.begin(); riter != agelist.end(); riter++) {
      if (riter->parent != folder) {
	continue;
      }
      VaultNode *f_node = new VaultNode();
      db->C->perform(VaultFetchNode_Request(riter->child, result,
					    *f_node, NULL));
      if (result == NO_ERROR) {
	if (f_node->type() != VaultNode::SDLNode) {
	  fprintf(stderr, "Node %u has unexpected type %u\n",
		  riter->child, f_node->type());
	}
	else {
	  sdlnodes.push_back(f_node);
	}
      }
      else {
	// yikes
	fprintf(stderr, "The vault is unhappy, nodeid %u returned as ref\n"
		"but it couldn't be fetched\n", riter->child);
	delete db;
	return -1;
      }
    }
  }
  catch(const pqxx::in_doubt_error &e) {
    fprintf(stderr, "in_doubt error from DB?!\n");
    delete db;
    return -1;
  }
  catch(const pqxx::broken_connection &e) {
    fprintf(stderr, "Connection to DB failed!\n");
    delete db;
    return -1;
  }
  catch(const pqxx::sql_error &e) {
    fprintf(stderr, "SQL error: %s\n", e.what());
    delete db;
    return -1;
  }

  // now enter command loop
  std::string input;
  std::string cmd;
  std::string agename("");
  VaultNode *current_node = NULL;
  SDLState *current_state = NULL;
  bool modified = false, new_node = false;
  while (1) {
    std::getline(std::cin, input);
    if (!std::cin.good()) {
      break;
    }
    std::stringstream in(input);
    std::getline(in, cmd, ' ');
    if (!in.fail()) {
      if (cmd[0] == 'h' || cmd[0] == 'H') {
	printf("\th\t\t\thelp\n"
	       "\ta <name>\t\tfocus on age <name>\n"
	       "\td\t\t\tprint state\n"
	       "\tc\t\t\tcreate a new SDL node (not saved to DB)\n"
	       "\tm <name> <value>\tmodify state (not saved to DB)\n"
	       "\tw\t\t\twrite (save) state to DB\n"
	       "\tq\t\t\tquit\n");
      }
      else if (cmd[0] == 'q') {
	if (modified) {
	  printf("There are unsaved changes, quit anyway? ");
	  std::getline(std::cin, input);
	  if (!std::cin.good()) {
	    break;
	  }
	  if (input[0] == 'y' || input[0] == 'Y') {
	    break;
	  }
	}
	else {
	  break;
	}
      }
      else if (cmd[0] == '#') {
	continue;
      }
      else if (cmd[0] == 'a') {
	std::string new_agename;
	std::getline(in, new_agename, ' ');
	if (in.fail()) {
	  printf("'a' requires a name argument\n");
	}
	else {
	  std::vector<VaultNode*>::iterator iter;
	  for (iter = sdlnodes.begin(); iter != sdlnodes.end(); iter++) {
	    VaultNode *node = *iter;
	    if (node->bitfield1() & String64_1) {
	      const u_char *data = node->const_data_ptr(String64_1);
	      UruString name(data+4, read32(data, 0), false, true, false);
	      if (new_agename.size() == name.strlen()
		  && !strcmp(new_agename.c_str(), name.c_str())) {
		// match
		if (current_node && current_node != node) {
		  if (modified) {
		    printf("There are unsaved changes, change anyway? ");
		    std::getline(std::cin, input);
		    if (!std::cin.good()) {
		      break;
		    }
		    if (input[0] == 'y' || input[0] == 'Y') {
		      if (new_node) {
			delete current_node;
		      }
		    }
		    else {
		      break;
		    }
		  }
		}
		agename = new_agename;
		if (current_state) {
		  delete current_state;
		  current_state = NULL;
		}
		modified = new_node = false;
		current_node = node;
		break;
	      }
	    }
	  }
	  if (iter == sdlnodes.end()) {
	    // didn't find the node
	    bool go_on = !modified;
	    if (current_node) {
	      if (modified) {
		printf("There are unsaved changes, change anyway? ");
		std::getline(std::cin, input);
		if (!std::cin.good()) {
		  break;
		}
		if (input[0] == 'y' || input[0] == 'Y') {
		  go_on = true;
		  if (new_node) {
		    delete current_node;
		  }
		}
	      }
	    }
	    if (go_on) {
	      agename = new_agename;
	      if (current_state) {
		delete current_state;
		current_state = NULL;
	      }
	      modified = new_node = false;
	      current_node = NULL;
	      printf("No node found for age %s (use 'c')\n", agename.c_str());
	    }
	  }
	}
      }
      else if (cmd[0] == 'd') {
	if (agename.size() == 0) {
	  printf("No age selected (use 'a')\n");
	}
	else if (!current_node) {
	  printf("No node found for age %s\n", agename.c_str());
	}
	else {
	  if (!current_state) {
	    current_state = read_state(current_node, sdls);
	  }
	  if (current_state) {
	    print_state(current_state);
	  }
	}
      }
      else if (cmd[0] == 'c') {
	if (agename.size() == 0) {
	  printf("No age selected (use 'a')\n");
	}
	else if (current_node) {
	  printf("There is already a node for age %s\n", agename.c_str());
	}
	else {
	  SDLDesc *desc = SDLDesc::find_by_name(agename.c_str(), sdls, 0);
	  if (!desc) {
	    printf("Could not find SDL named '%s'\n", agename.c_str());
	  }
	  else {
	    current_node = new VaultNode();
	    current_node->num_ref(NodeType) = htole32(VaultNode::SDLNode);
	    UruString aname(agename);
	    u_int alen = aname.send_len(false, true, true);
	    u_char *name = current_node->data_ptr(String64_1, alen);
	    memcpy(name, aname.get_str(false, true, true), alen);
	    current_state = new SDLState(desc);
	    current_state->expand();
	    new_node = modified = true;
	    printf("Created new default '%s' SDL\n", agename.c_str());
	  }
	}
      }
      else if (cmd[0] == 'm') {
	if (agename.size() == 0) {
	  printf("No age selected (use 'a')\n");
	}
	else if (!current_node) {
	  printf("There is no node (use 'c')\n");
	}
	else {
	  if (!current_state) {
	    current_state = read_state(current_node, sdls);
	  }
	  if (current_state) {
	    std::string var;
	    std::getline(in, var, ' ');
	    if (in.fail()) {
	      printf("'m' requires a name argument\n");
	    }
	    else {
	      const std::vector<SDLDesc::Struct*> &structs
		= current_state->get_desc()->structs();
	      std::vector<SDLDesc::Struct*>::const_iterator s_iter;
	      for (s_iter = structs.begin();
		   s_iter != structs.end();
		   s_iter++) {
		SDLDesc::Struct *st = *s_iter;
		if (strlen(st->m_name) == var.size()
		    && !strcmp(st->m_name, var.c_str())) {
		  printf("You are doing something wrong if you're "
			 "editing a struct\n");
		  break;
		}
	      }
	      if (s_iter == structs.end()) {
		u_int idx = 0;
		const std::vector<SDLDesc::Variable*> &vars
		  = current_state->get_desc()->vars();
		std::vector<SDLDesc::Variable*>::const_iterator v_iter;
		for (v_iter = vars.begin();
		     v_iter != vars.end();
		     v_iter++, idx++) {
		  SDLDesc::Variable *vr = *v_iter;
		  if (strlen(vr->m_name) == var.size()
		      && !strcmp(vr->m_name, var.c_str())) {
		    // this is the one
		    break;
		  }
		}
		if (v_iter == vars.end()) {
		  printf("Variable %s not found\n", var.c_str());
		}
		else {
		  // finally we have the right one
		  if (update_sdl(current_state, idx, in)) {
		    modified = true;
		  }
		}
	      }
	    }
	  }
	}
      }
      else if (cmd[0] == 'w') {
	// write to DB
	if (modified) {
	  int len = current_state->body_len();
	  u_char *data = current_node->data_ptr(Blob_1, len+2);
	  write16(data, 0, no_plType);
	  int wlen = current_state->write_out(data+2, len);
	  if (wlen != len) {
	    // don't write mangled data to vault
	    printf("I am refusing to write that node because the SDL has\n"
		   "formatted to the wrong length\n");
	  }
	  else {
	    status_code_t save_result = NO_ERROR;
	    try {
	      if (new_node) {
		uint32_t newid;
		// at present there is no "account" or KI number
		u_char acctid[UUID_RAW_LEN];
		memset(acctid, 0, UUID_RAW_LEN);
		db->C->perform(VaultCreateNode_Request(current_node,
						       acctid, 0, newid,
						       /*Logger*/NULL));
		db->C->perform(VaultAddRef_Request(folder, newid, 0,
						   save_result));
		sdlnodes.push_back(current_node);
		new_node = modified = false;
	      }
	      else {
		db->C->perform(VaultSaveNode_Request(
					current_node->num_ref(NodeID),
					current_node, save_result,
					/*Logger*/NULL));
		if (save_result == NO_ERROR) {
		  modified = false;
		}
	      }
	    }
	    catch(const pqxx::in_doubt_error &e) {
	      fprintf(stderr, "in_doubt error from DB?!\n");
	      save_result = ERROR_INTERNAL;
	    }
	    catch(const pqxx::broken_connection &e) {
	      fprintf(stderr, "Connection to DB failed!\n");
	      save_result = ERROR_DB_TIMEOUT;
	    }
	    catch(const pqxx::sql_error &e) {
	      fprintf(stderr, "SQL error: %s\n", e.what());
	      save_result = ERROR_INTERNAL;
	    }
	    if (save_result != NO_ERROR) {
	      printf("Writing the node failed for reason %d\n", save_result);
	    }
	  }
	}
      }
      else {
	printf("Unknown command '%c'\n", cmd[0]);
      }
    }
  }
  delete db;
  return 0;
}

void print_state(SDLState *st, int indent) {
  const SDLDesc *desc = st->get_desc();

  u_char w[indent+3];
  memset(w, ' ', indent+2);
  w[indent] = '\0';

  printf("%sSDL state name %s version %d\n", w, desc->name(), desc->version());
  w[indent] = ' ';
  indent += 2;
  w[indent] = '\0';

  const std::vector<SDLState::Variable*> &vars = st->vars();
  const std::vector<SDLState::Struct*> &structs = st->structs();

  std::vector<SDLState::Variable*>::const_iterator vi;
  for (vi = vars.begin(); vi != vars.end(); vi++) {
    if (*vi) {
      SDLState::Variable *v = *vi;
      SDLDesc::Variable *d = desc->vars()[v->m_index];
      if ((!(d->m_options & SDL_OPT_VAULT)
	   || (d->m_options & SDL_DISP_HIDDEN))
	  && v->m_flags == SDLState::Default) {
	// if the value is set, show it regardless of options
	continue;
      }
      printf("%sVariable %s: ", w, d->m_name);
      if (v->m_flags & SDLState::Default) {
	printf("DEFAULT: ");
	print_data_by_type(&d->m_default, 1, d->m_type);
      }
      else {
	if (v->m_count > 1) { printf("[ "); }
	print_data_by_type(v->m_value, v->m_count, d->m_type);
	if (v->m_count > 1) { printf("]"); }
      }
      if (v->m_flags & SDLState::Timestamp) {
	printf("\t%ld.%08ld", v->m_ts.tv_sec, v->m_ts.tv_usec);
      }
      printf("\n");
    }
  }

  std::vector<SDLState::Struct*>::const_iterator si;
  for (si = structs.begin(); si != structs.end(); si++) {
    if (*si) {
      SDLState::Struct *s = *si;
      SDLDesc::Struct *d = desc->structs()[s->m_index];
      if ((!(d->m_options & SDL_OPT_VAULT)
	   || (d->m_options & SDL_DISP_HIDDEN))
	  && s->m_flags == SDLState::Default) {
	// if the value is set, show it regardless of options
	continue;
      }
      printf("%sStruct %s: ", w, d->m_name);
      if (s->m_flags & SDLState::Default) {
	printf("DEFAULT: ");
	// XXX
	printf("\n");
      }
      else {
	printf("\n");
	for (u_int j = 0; j < s->m_count; j++) {
	  if (s->m_count > 1) { printf("%s [\n", w); }
	  print_state(&s->m_child[j], indent+2);
	  if (s->m_count > 1) { printf("%s ]\n", w); }
	}
      }
    }
  }
}

void print_data_by_type(SDLDesc::Variable::data_t *data, u_int count,
			SDLDesc::sdl_type_t type) {
  switch (type) {
  case SDLDesc::INT:
    for (u_int j = 0; j < count; j++) {
      printf("%d ", data[j].v_int);
    }
    break;
  case SDLDesc::FLOAT:
    for (u_int j = 0; j < count; j++) {
      printf("%f ", data[j].v_float);
    }
    break;
  case SDLDesc::BOOL:
    for (u_int j = 0; j < count; j++) {
      printf("%d ", (data[j].v_bool ? 1 : 0));
    }
    break;
  case SDLDesc::STRING32:
    for (u_int j = 0; j < count; j++) {
      // I don't know if there is any requirement/expectation that this
      // string is null-terminated, so assume it is not, for safety.
      char str[33];
      strncpy(str, data[j].v_string, 32);
      str[32] = '\0';
      printf("%s ", str);
    }
    break;
  case SDLDesc::PLKEY:
    for (u_int j = 0; j < count; j++) {
      char *str = data[j].v_plkey.format();
      if (str) {
	printf("%s ", str);
	free(str);
      }
    }
    break;
  case SDLDesc::CREATABLE:
    // XXX
    printf("--");
    break;
  case SDLDesc::TIME:
    for (u_int j = 0; j < count; j++) {
      printf("%ld.%06ld ", data[j].v_time.tv_sec,
	     data[j].v_time.tv_usec);
    }
    break;
  case SDLDesc::BYTE:
    for (u_int j = 0; j < count; j++) {
      printf("%d ", data[j].v_byte);
    }
    break;
  case SDLDesc::SHORT:
    for (u_int j = 0; j < count; j++) {
      printf("%d ", data[j].v_short);
    }
    break;
  case SDLDesc::AGETIMEOFDAY:
    for (u_int j = 0; j < count; j++) {
      printf("%ld.%06ld ", data[j].v_agetime.tv_sec,
	     data[j].v_agetime.tv_usec);
    }
    break;
  case SDLDesc::VECTOR3:
  case SDLDesc::POINT3:
    for (u_int j = 0; j < count; j++) {
      float *where = (type == SDLDesc::VECTOR3
		      ? data[j].v_vector3
		      : data[j].v_point3);
      printf("( ");
      for (u_int k = 0; k < 3; k++) {
	printf("%f ", where[k]);
      }
      printf(") ");
    }
    break;
  case SDLDesc::QUATERNION:
    for (u_int j = 0; j < count; j++) {
      printf("( ");
      for (u_int k = 0; k < 4; k++) {
	printf("%f ", data[j].v_quaternion[k]);
      }
      printf(") ");
    }
    break;
  case SDLDesc::RGB8:
    for (u_int j = 0; j < count; j++) {
      printf("( ");
      for (u_int k = 0; k < 3; k++) {
	printf("%d ", data[j].v_rgb8[k]);
      }
      printf(") ");
    }
    break;
  default:
    // can't happen
    break;
  }
}

int get_all_sdls(const char *dirname, std::list<SDLDesc*> &sdls,
		 bool die_on_error) {
  struct stat s;  
  int ret = stat(dirname, &s);

  if (s.st_mode & S_IFDIR) {
    // walk the directory tree
    DIR *dir = opendir(dirname);
    if (!dir) {
      fprintf(stderr, "Cannot open directory %s for listing: %s\n",
	      dirname, strerror(errno));
      if (die_on_error) {
	return 1;
      }
    }
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
      ret = strlen(entry->d_name);
      int dlen = ret + strlen(dirname) + 2;
      char fname[dlen];
      snprintf(fname, dlen, "%s%s%s", dirname, PATH_SEPARATOR, entry->d_name);
      if (ret > 4 && !strcasecmp(entry->d_name+(ret-4), ".sdl")) {
	std::ifstream file(fname, std::ios_base::binary | std::ios_base::in);
	if (file.fail()) {
	  fprintf(stderr, "Cannot open file %s\n", entry->d_name);
	  continue;
	}
	try {
	  SDLDesc::parse_file(sdls, file);
	}
	catch (const parse_error &e) {
	  fprintf(stderr, "Parse error in file %s line %d: %s\n",
		  entry->d_name, e.lineno(), e.what());
	  continue;
	}
      }
      else {
	ret = stat(fname, &s);
	if (s.st_mode & S_IFDIR
	    && !((strlen(entry->d_name) == 2
		  && !strcmp(entry->d_name, ".."))
		 || (strlen(entry->d_name) == 1
		     && !strcmp(entry->d_name, ".")))) {
	  ret = get_all_sdls(fname, sdls, false);
	}
      }
    }
    closedir(dir);
  }
  else {
    // not really as intended, but whatever
    std::ifstream file(dirname, std::ios_base::binary | std::ios_base::in);
    if (file.fail()) {
      fprintf(stderr, "Cannot open file %s\n", dirname);
      if (die_on_error) {
	return 1;
      }
    }
    else {
      try {
	SDLDesc::parse_file(sdls, file);
      }
      catch (const parse_error &e) {
	fprintf(stderr, "Parse error in file %s line %d: %s\n",
		dirname, e.lineno(), e.what());
      }
    }
  }
  return 0;
}

SDLState * read_state(VaultNode *node, std::list<SDLDesc*> &sdls) {
  SDLState *ret = NULL;
  const u_char *data = node->const_data_ptr(Blob_1);
  if (!data) {
    // XXX something is wrong with this node
  }
  else {
    u_int len = read32(data, 0);
    if (len < 2) {
      // XXX node is too short
    }
    ret = new SDLState();
    try {
      ret->read_in(data+6, len-2, sdls);
      ret->expand();
    }
    catch (const truncated_message &e) {
      // XXX node is too short
      delete ret;
      ret = NULL;
    }
  }
  return ret;
}

bool update_sdl(SDLState *sdl, u_int idx, std::stringstream &in) {
  SDLState::Variable *sdlvar = sdl->vars()[idx];
  SDLDesc::Variable *descvar = sdl->get_desc()->vars()[idx];
  if (descvar->m_count == 0) {
    printf("We can't change variable-size arrays\n");
    return false;
  }

  switch (descvar->m_type) {
  case SDLDesc::INT:
  case SDLDesc::BOOL:
  case SDLDesc::BYTE:
  case SDLDesc::SHORT:
    {
      std::string var;
      std::getline(in, var, ' ');
      if (in.fail()) {
	printf("A value argument is required\n");
      }
      int val = 0;
      std::stringstream in2(var);
      in2 >> val;
      if (in2.fail()) {
	printf("Could not parse '%s' as an integer\n", var.c_str());
	return false;
      }
      bool is_default = false;
      switch (descvar->m_type) {
      case SDLDesc::INT:
	if (val == descvar->m_default.v_int) {
	  is_default = true;
	}
	break;
      case SDLDesc::BOOL:
	if ((val && descvar->m_default.v_bool)
	    || (!val && !descvar->m_default.v_bool)) {
	  is_default = true;
	}
	break;
      case SDLDesc::BYTE:
	if ((int8_t)val == descvar->m_default.v_byte) {
	  is_default = true;
	}
	break;
      case SDLDesc::SHORT:
	if ((int16_t)val == descvar->m_default.v_short) {
	  is_default = true;
	}
      default:
	// shut up the compiler
	;
      }
      if (is_default) {
	sdlvar->m_flags |= SDLState::Default;
      }
      else {
	sdlvar->m_flags &= ~SDLState::Default;
	if (!sdlvar->m_value) {
	  sdlvar->m_value = new SDLDesc::Variable::data_t[descvar->m_count];
	  sdlvar->m_count = descvar->m_count;
	}
	switch (descvar->m_type) {
	case SDLDesc::INT:
	  for (u_int j = 0; j < sdlvar->m_count; j++) {
	    sdlvar->m_value[j].v_int = val;
	  }
	  break;
	case SDLDesc::BOOL:
	  for (u_int j = 0; j < sdlvar->m_count; j++) {
	    sdlvar->m_value[j].v_bool = (val ? true : false);
	  }
	  break;
	case SDLDesc::BYTE:
	  for (u_int j = 0; j < sdlvar->m_count; j++) {
	    sdlvar->m_value[j].v_byte = (int8_t)val;
	  }
	  break;
	case SDLDesc::SHORT:
	  for (u_int j = 0; j < sdlvar->m_count; j++) {
	    sdlvar->m_value[j].v_short = (int16_t)val;
	  }
	  break;
	default:
	  // shut up the compiler
	  ;
	}
      }
    }
    break;
  case SDLDesc::FLOAT:
    {
      std::string var;
      std::getline(in, var, ' ');
      if (in.fail()) {
	printf("A value argument is required\n");
      }
      float val = 0;
      std::stringstream in2(var);
      in2 >> val;
      if (in2.fail()) {
	printf("Could not parse '%s' as an float\n", var.c_str());
	return false;
      }
      if (val == descvar->m_default.v_float) {
	sdlvar->m_flags |= SDLState::Default;
      }
      else {
	sdlvar->m_flags &= ~SDLState::Default;
	if (!sdlvar->m_value) {
	  sdlvar->m_value = new SDLDesc::Variable::data_t[descvar->m_count];
	  sdlvar->m_count = descvar->m_count;
	}
	for (u_int j = 0; j < sdlvar->m_count; j++) {
	  sdlvar->m_value[j].v_float = val;
	}
      }
    }
    break;
  case SDLDesc::STRING32:
    {
      std::string arg;
      if (in.peek() == '"') {
	std::streampos pos = in.tellg();
	std::getline(in, arg, '"');
	std::getline(in, arg, '"');
	if (in.fail()) {
	  in.seekg(pos);
	  std::getline(in, arg);
	  printf("Invalid input: %s\n", arg.c_str());
	  return false;
	}
      }
      else {
	std::getline(in, arg);
      }
      if (arg.size() > 32) {
	arg.resize(32);
	printf("Value is too long and will be truncated to %s\n",
	       arg.c_str());
      }
      // I don't know if there is any requirement/expectation that this
      // string is null-terminated, so assume it is not, for safety.
      char str[33];
      strncpy(str, descvar->m_default.v_string, 32);
      str[32] = '\0';
      if (arg.size() == strlen(str)  && !strncmp(arg.c_str(), str, 32)) {
	sdlvar->m_flags |= SDLState::Default;
      }
      else {
	sdlvar->m_flags &= ~SDLState::Default;
	if (!sdlvar->m_value) {
	  sdlvar->m_value = new SDLDesc::Variable::data_t[descvar->m_count];
	  sdlvar->m_count = descvar->m_count;
	}
	for (u_int j = 0; j < sdlvar->m_count; j++) {
	  memset(sdlvar->m_value[j].v_string, 0, 32);
	  memcpy(sdlvar->m_value[j].v_string, arg.c_str(), arg.size());
	}
      }
    }
    break;
  default:
    printf("Changing that type is not supported\n");
    return false;
  }
  sdlvar->m_flags |= (SDLState::Timestamp|SDLState::Dirty);
  gettimeofday(&sdlvar->m_ts, NULL);
  return true;
}
