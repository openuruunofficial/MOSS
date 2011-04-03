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
#include <stdarg.h>
#include <iconv.h>
#include <sys/stat.h>
#include <getopt.h>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <stdexcept>
#include <list>
#include <vector>

#include "config.h"
#include "machine_arch.h"
#include "protocol.h"
#include "exceptions.h"
#include "UruString.h"
#include "PlKey.h"
#include "Logger.h"
#include "SDL.h"

void print_info(std::list<SDLDesc*> &sdls, std::list<SDLState*> &state,
		bool print_index=false);
void print_state(SDLState *st, int indent=0);
void print_data_by_type(SDLDesc::Variable::data_t *data, u_int count,
			SDLDesc::sdl_type_t type);

int main(int argc, char *argv[]) {
  static struct option options[] = {
    { "interactive", no_argument, 0, 'i' },
    { "load", required_argument, 0, 'l' },
    { 0, 0, 0, 0 }
  };
  static const char *usage = "Usage: %s [-i] [-l <saved state file>] <SDL file or directory>[...]\n";
  char c;
  opterr = 0;
  char *saved_state = NULL;
  bool interactive = false;
  while ((c = getopt_long(argc, argv, "il:", options, NULL)) != -1) {
    switch (c) {
    case 'i':
      interactive = true;
      break;
    case 'l':
      saved_state = strdup(optarg);
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
  for ( ; i < argc; i++) {
    int ret = stat(argv[i], &s);
    if (ret < 0) {
      fprintf(stderr, "%s does not exist\n", argv[i]);
      return -1;
    }
    else if (s.st_mode & S_IFDIR) {
      std::string foo(argv[i]);
      if (SDLDesc::parse_directory(NULL, sdls, foo, true, true)) {
	fprintf(stderr, "Error parsing directory %s\n", argv[i]);
	return -1;
      }
    }
    else {
      std::ifstream file(argv[i], std::ios_base::in);
      if (file.fail()) {
	fprintf(stderr, "Error opening file %s\n", argv[i]);
	return -1;
      }
      try {
	SDLDesc::parse_file(sdls, file);
      }
      catch (const parse_error &e) {
	fprintf(stderr, "Parse error, line %d: %s\n",
		e.lineno(), e.what());
      }
    }
  }

  // if we are to read a saved-state file, do so
  std::list<SDLState*> state;
  if (saved_state) {
    std::ifstream file(saved_state, std::ios_base::in);
    if (file.fail()) {
      fprintf(stderr, "Error opening file %s\n", saved_state);
      return -1;
    }
#ifdef ALCUGS_FORMAT
    file.seekg(4); // skip object count
#endif
    if (!SDLState::load_file(file, state, sdls, NULL)) {
      printf("Error loading SDL from file %s\n", saved_state);
    }
  }

  // check on them
  if (!interactive) {
    print_info(sdls, state);
  }

  if (interactive) {
    std::string input;
    std::string cmd;
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
		 "\tp\t\t\tprint info\n"
		 "\td <index>\t\tprint state at index\n"
		 "\te <index>\t\t\"expand\" state at index\n"
		 "\tn <name> [version]\tcreate new default SDL\n"
		 "\tl <file>\t\tload saved file\n"
		 "\tw <file>\t\twrite saved file\n"
		 "\tq\t\t\tquit\n");
	}
	else if (cmd[0] == 'q') {
	  break;
	}
	else if (cmd[0] == 'p') {
	  print_info(sdls, state, true);
	}
	else if (cmd[0] == 'd') {
	  u_int index = 0;
	  in >> index;
	  if (in.fail()) {
	    printf("Index required\n");
	  }
	  else if (index >= state.size()) {
	    printf("Invalid index");
	  }
	  else {
	    std::list<SDLState*>::iterator siter;
	    u_int i = 0;
	    for (siter = state.begin(); siter != state.end(); siter++) {
	      if (i == index) {
		print_state(*siter);
	      }
	      i++;
	    }
	  }
	}
	else if (cmd[0] == 'e') {
	  u_int index = 0;
	  in >> index;
	  if (in.fail()) {
	    printf("Index required\n");
	  }
	  else if (index >= state.size()) {
	    printf("Invalid index");
	  }
	  else {
	    std::list<SDLState*>::iterator siter;
	    u_int i = 0;
	    for (siter = state.begin(); siter != state.end(); siter++) {
	      if (i == index) {
		(*siter)->expand();
		print_state(*siter);
	      }
	      i++;
	    }
	  }
	}
	else if (cmd[0] == 'n') {
	  std::string name;
	  std::getline(in, name, ' ');
	  if (in.fail()) {
	    printf("'n' requires a name argument\n");
	  }
	  else {
	    u_int version = 0;
	    in >> version;
	    SDLDesc *desc = SDLDesc::find_by_name(name.c_str(),
						  sdls, version);
	    if (!desc) {
	      printf("Could not find SDL named '%s'", name.c_str());
	      if (version != 0) {
		printf(" version '%d'\n", version);
	      }
	      else {
		printf("\n");
	      }
	    }
	    else {
	      SDLState *s = new SDLState(desc);
	      s->expand();
	      printf("Created new default '%s' SDL\n", name.c_str());

	      bool replaced = false;
	      std::list<SDLState*>::iterator siter;
	      for (siter = state.begin(); siter != state.end(); siter++) {
		SDLState *other = *siter;
		if (other->get_desc() == desc) {
		  printf("Replacing read-in state with new state\n");
		  replaced = true;
		  state.erase(siter);
		  s->key() = other->key();
		  delete other;
		  break;
		}
	      }
	      if (!replaced) {
		printf("Warning: using invalid PageID -1 and assuming name "
		       "AgeSDLHook!\n");
		s->invent_age_key((uint32_t)-1);
	      }
	      state.push_front(s);
	    }
	  }
	}
	else if (cmd[0] == 'l') {
	  std::string name;
	  std::getline(in, name, ' ');
	  if (in.fail()) {
	    printf("'l' requires a filename argument\n");
	  }
	  else {
	    std::ifstream file(name.c_str(), std::ios_base::in);
	    if (file.fail()) {
	      printf("Error opening file %s\n", name.c_str());
	    }
	    else {
#ifdef ALCUGS_FORMAT
	      file.seekg(4); // skip object count
#endif
	      if (!SDLState::load_file(file, state, sdls, NULL)) {
		printf("Error loading SDL from file %s\n", name.c_str());
	      }
	    }
	  }
	}
	else if (cmd[0] == 'w') {
	  std::string name;
	  std::getline(in, name, ' ');
	  if (in.fail()) {
	    printf("'w' requires a filename argument\n");
	  }
	  else {
	    std::ofstream file(name.c_str(), std::ios_base::out);
	    if (file.fail()) {
	      printf("Error opening file %s\n", name.c_str());
	    }
	    else {
#ifdef ALCUGS_FORMAT_OUTPUT
	      int zero = 0;
	      file.write((char*)&zero, 4); // skip object count
#endif
	      if (!SDLState::save_file(file, state)) {
		printf("Error saving SDL to file %s\n", name.c_str());
	      }
	    }
	  }
	}
	else {
	  printf("Unknown command '%c'\n", cmd[0]);
	}
      }
    }
  }

  return 0;
}

void print_info(std::list<SDLDesc*> &sdls, std::list<SDLState*> &state,
		bool print_index) {
  std::list<SDLDesc*>::iterator iter;
  for (iter = sdls.begin(); iter != sdls.end(); iter++) {
    SDLDesc *desc = *iter;
    printf("SDL name %s version %d\n", desc->name(), desc->version());
    // XXX print some stuff
    printf("\tVariables: %u Structs %u\n", (u_int)desc->vars().size(),
	   (u_int)desc->structs().size());
  }

  std::list<SDLState*>::iterator siter;
  u_int index = 0;
  for (siter = state.begin(); siter != state.end(); siter++) {
    SDLState *s = *siter;
    if (print_index) {
      printf("%4d: ", index);
    }
    printf("Saved SDL object %s SDL name %s version %d\n",
	   s->key().m_name ? s->key().m_name->c_str() : "",
	   s->get_desc()->name(),
	   s->get_desc()->version());
    index++;
  }
}

void print_state(SDLState *st, int indent) {
  const SDLDesc *desc = st->get_desc();

  u_char w[indent+3];
  memset(w, ' ', indent+2);
  w[indent] = '\0';

  printf("%sSDL state name %s version %d\n", w, desc->name(), desc->version());
  char *str = st->key().format();
  if (str) {
    printf("%s %s\n", w, str);
    free(str);
  }
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
      printf("\n");
    }
  }

  std::vector<SDLState::Struct*>::const_iterator si;
  for (si = structs.begin(); si != structs.end(); si++) {
    if (*si) {
      SDLState::Struct *s = *si;
      SDLDesc::Struct *d = desc->structs()[s->m_index];

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
      printf("%s ", data[j].v_string);
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
