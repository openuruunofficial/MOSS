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
 * ConfigParser is a simple parser for simple name=value configuration files;
 * names are registered, and when the file is read, the values are filled in.
 *
 * XXX it would be nice to make it more powerful, e.g. allow to provide the
 * set of valid values, maybe have a file type that checks the file's
 * existence, etc.
 */

#ifndef _CONFIG_PARSER_H_
#define _CONFIG_PARSER_H_

//#include <list>
//
//#include "exceptions.h"

class ConfigParser {
public:
  /*
   * For each configuration option available, register (once) the name
   * and the location to place the value if it appears in the file. The
   * location will be populated with the default option during
   * register_config() and with the configuration value, if present,
   * during read_config(). An attempt to register an existing name results
   * in a non-zero return value indicating failure.
   */
  int register_config(const char *name, int *value, int the_default);
  int register_config(const char *name, char **value, const char *the_default);
  int register_config(const char *name, bool *value, bool the_default);

  /*
   * For things that cannot be changed at a reload, unregister.
   */
  int unregister_config(const char *name);

  /*
   * Read the contents of a config file and change any registered values
   * accordingly. Unrecognized values are ignored unless the complain flag
   * is set to true. A return value < 0 means the file open failed.
   * Throws the parse_error exception.
   */
  int read_config(const char *filename, bool complain=false);

  /*
   * Constructor/destructor.
   */
  ~ConfigParser();

  /*
   * Split up a comma-separated string. A comma preceded by \ is considered
   * quoted and does not split the string (and the \ is removed). The return
   * value and its contents must be free()d. NULL will be returned if there
   * is a malloc failure.
   */
  static char** split_string(const char *str, u_int *count);

protected:
  typedef enum {
    TYPE_INT,
    TYPE_BOOL,
    TYPE_CHARSTAR
  } entry_type_t;

  class Entry {
  public:
    Entry(entry_type_t the_type, const char *the_name, void *the_addr)
      : m_type(the_type), m_addr(the_addr) {
      m_name = strdup(the_name);
    }
    ~Entry() {
      if (m_name) free(m_name);
    }

    entry_type_t m_type;
    char *m_name;
    void *m_addr;
  };

  std::list<Entry*> m_options;

  // helpers for read_config
  int check_line(char *linebuf, bool complain);
  void file_error(u_int lineno, int error);
};

#endif /* _CONFIG_PARSER_H_ */
