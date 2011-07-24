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
#include <stdio.h>  /* for sscanf() */
#include <string.h> /* for strdup() */
#include <stdarg.h>

#include <exception>
#include <stdexcept>
#include <list>
#include <string>

#include <iostream>
#include <fstream>

#include "machine_arch.h"
#include "exceptions.h"

#include "ConfigParser.h"

ConfigParser::~ConfigParser() {
  std::list<Entry*>::iterator iter;
  for (iter = m_options.begin(); iter != m_options.end(); iter++) {
    delete *iter;
  }
}

int ConfigParser::register_config(const char *name,
				  int *value, int the_default) {
  std::list<Entry*>::iterator iter;
  for (iter = m_options.begin(); iter != m_options.end(); iter++) {
    if (strlen((*iter)->m_name) == strlen(name)
	&& !strcmp((*iter)->m_name, name)) {
      // we already have that one!
      return 1;
    }
  }

  Entry *new_entry = new Entry(TYPE_INT, name, (void *)value);
  m_options.push_back(new_entry);
  *value = the_default;
  return 0;
}

int ConfigParser::register_config(const char *name,
				  char **value, const char *the_default) {
  std::list<Entry*>::iterator iter;
  for (iter = m_options.begin(); iter != m_options.end(); iter++) {
    if (strlen((*iter)->m_name) == strlen(name)
	&& !strcmp((*iter)->m_name, name)) {
      // we already have that one!
      return 1;
    }
  }

  Entry *new_entry = new Entry(TYPE_CHARSTAR, name, (void *)value);
  m_options.push_back(new_entry);
  if (*value) {
    free(*value);
  }
  if (!the_default) {
    the_default = "";
  }
  *value = strdup(the_default);
  return 0;
}

int ConfigParser::register_config(const char *name,
				  bool *value, bool the_default) {
  std::list<Entry*>::iterator iter;
  for (iter = m_options.begin(); iter != m_options.end(); iter++) {
    if (strlen((*iter)->m_name) == strlen(name)
	&& !strcmp((*iter)->m_name, name)) {
      // we already have that one!
      return 1;
    }
  }

  Entry *new_entry = new Entry(TYPE_BOOL, name, (void *)value);
  m_options.push_back(new_entry);
  *value = the_default;
  return 0;
}

int ConfigParser::unregister_config(const char *name) {
  std::list<Entry*>::iterator iter;
  for (iter = m_options.begin(); iter != m_options.end(); iter++) {
    if (strlen((*iter)->m_name) == strlen(name)
	&& !strcmp((*iter)->m_name, name)) {
      Entry *e = *iter;
      m_options.erase(iter);
      delete e;
      return 0;
    }
  }
  return 1;
}

int ConfigParser::read_config(const char *filename, bool complain) {
  std::ifstream file(filename, std::ios_base::binary | std::ios_base::in);
  if (file.fail()) {
    return -1;
  }

  u_int bufsize = 256, bufat = 0, lineno = 1;
  int checked;
  char *linebuf = NULL;

  try {
    linebuf = new char[bufsize];
    while (!file.eof()) {
      file.getline(linebuf+bufat, bufsize-bufat);
      if (file.fail() && !file.eof()) {
	bufat = strlen(linebuf)-1;
	bufsize *= 2;
	char *newbuf = new char[bufsize];
	memcpy(newbuf, linebuf, bufat);
	delete[] linebuf;
	linebuf = newbuf;
      }
      else if (strlen(linebuf) > 0 && linebuf[strlen(linebuf)-1] == '\\') {
	// continuation on next line
	bufat = strlen(linebuf)-1;
      }
      else {
	// here we have the whole line
	checked = check_line(linebuf, complain);
	if (checked) {
	  file_error(lineno, checked);
	}
	bufat = 0;
	lineno++;
      }
    }
    checked = check_line(linebuf, complain);
    if (checked) {
      file_error(lineno, checked);
    }
  }
  catch (const std::bad_alloc& e) {
  }

  if (linebuf) {
    delete[] linebuf;
  }
  return 0;
}

#define ERROR_NONE 0
#define ERROR_NOT_PAIR 0x1
#define ERROR_BAD_FORMAT 0x2
#define ERROR_UNRECOGNIZED 0x4
#define ERROR_UNKNOWN_TYPE 0x10 /* internal error */

static bool is_whitespace(char c) {
  return (c == ' ' || c == '\r' || c == '\n' || c == '\t');
}

int ConfigParser::check_line(char *linebuf, bool complain) {
  char *name = linebuf;
  while (is_whitespace(*name)) {
    name++;
  }
  if (*name == '\0' || *name == '#') {
    // empty line or comment
    return ERROR_NONE;
  }
  char *value = name;
  while (*value != '=' && *value != '\0') {
    value++;
  }
  char *rtrim = value-1;
  while (rtrim > name && is_whitespace(*rtrim)) {
    *rtrim-- = '\0';
  }
  bool end = (*value == '\0');
  if (!end) {
    *value++ = '\0'; // set string terminator for name
    while (is_whitespace(*value)) {
      value++;
    }
    rtrim = value+strlen(value)-1;
    while (rtrim > value && is_whitespace(*rtrim)) {
      *rtrim-- = '\0';
    }
  }

  std::list<Entry*>::iterator iter;
  for (iter = m_options.begin(); iter != m_options.end(); iter++) {
    Entry *e = *iter;
    if (strlen(e->m_name) == strlen(name) && !strcmp(e->m_name, name)) {
      if (end) {
	// no '=' found
	return ERROR_NOT_PAIR;
      }
      else if (e->m_type == TYPE_INT) {
	int num = sscanf(value, "%i", (int *)e->m_addr);
	if (num != 1) {
	  return ERROR_BAD_FORMAT;
	}
	return ERROR_NONE;
      }
      else if (e->m_type == TYPE_BOOL) {
	if (value[0] == 't' || value[0] == 'T') {
	  *(bool *)e->m_addr = true;
	}
	else if (value[0] == 'f' || value[0] == 'F') {
	  *(bool *)e->m_addr = false;
	}
	else {
	  int val;
	  if (sscanf(value, "%i", &val) != 1) {
	    return ERROR_BAD_FORMAT;
	  }
	  *(bool *)e->m_addr = (val != 0);
	}
	return ERROR_NONE;
      }
      else if (e->m_type == TYPE_CHARSTAR) {
	char **loc = (char **)e->m_addr;
	if (*loc) {
	  free(*loc);
	}
	if (end) {
	  // empty string
	  *loc = strdup("");
	}
	else {
	  *loc = strdup(value);
	  // handle escaped characters
	  value = *loc;
	  while (*value) {
	    if (value[0] == '\\') {
	      if (value[1] == 'r') {
		value[0] = '\r';
		strcpy(value+1, value+2);
	      }
	      else if (value[1] == 'n') {
		value[0] = '\n';
		strcpy(value+1, value+2);
	      }
	    }
	    value++;
	  }
	}
	return ERROR_NONE;
      }
      else {
	// bad type
	return ERROR_UNKNOWN_TYPE;
      }
    }
  }
  if (complain && iter == m_options.end()) {
    // unrecognized name
    return ERROR_UNRECOGNIZED | (end ? ERROR_NOT_PAIR : ERROR_NONE);
  }
  return ERROR_NONE;
}

void ConfigParser::file_error(u_int lineno, int error) {
  const char *text;

  switch(error) {
  case ERROR_NOT_PAIR:
    text = "parse error (no = found)";
    break;
  case ERROR_BAD_FORMAT:
    text = "parse error";
    break;
  case ERROR_UNRECOGNIZED:
    text = "unknown option name";
    break;
  case ERROR_UNRECOGNIZED | ERROR_NOT_PAIR:
    text = "unknown option name (and no = found)";
    break;
  case ERROR_UNKNOWN_TYPE:
    text = "unknown configuration type (internal error!)";
    break;
  default:
    text = "unknown error";
  }
  throw parse_error(lineno, text);
}

char** ConfigParser::split_string(const char *str, u_int *count) {
  const char *at = str;
  u_int num = 1;
  *count = 0;
  while (*at != '\0') {
    if (*at == '\\' && *(at+1) == ',') {
      // ignore that one
      *at++;
    }
    else if (*at == ',') {
      num++;
    }
    *at++;
  }

  char **result = (char **)malloc(num*sizeof(char *));
  if (!result) {
    return NULL;
  }
  at = str;
  *count = num;
  num = 0;
  while (num < *count) {
    if (*at == '\\' && *(at+1) == ',') {
      // ignore that one
      *at++;
    }
    else if (*at == ',' || *at == '\0') {
      result[num] = (char *)malloc((at-str)+1);
      if (!result[num]) {
	while (--num) {
	  free(result[num]);
	}
	free(result);
	return NULL;
      }
      strncpy(result[num], str, (at-str));
      result[num][at-str] = '\0';
      num++;
      str = at+1;
    }
    if (*at == '\0') {
      break;
    }
    *at++;
  }
  return result;
}
