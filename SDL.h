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
 * SDL-handling classes. There are two kinds of SDL objects: the descriptions,
 * from the .sdl text files, and the actual data transmitted in a binary form.
 */

//#include <sys/time.h>
//
//#include <list>
//#include <vector>
//
//#include <iostream>
//#include <fstream>
//
//#include "exceptions.h"
//#include "protocol.h"
//#include "PlKey.h"
//
//#include "Logger.h"

class SDLDesc {
public:
  /*
   * Data types.
   */
  typedef enum {
    INVALID_SDL = -1,
    INT = 0,
    FLOAT = 1,
    BOOL = 2,
    STRING32 = 3,
    PLKEY = 4,
    CREATABLE = 6,
    TIME = 8,
    BYTE = 9,
    SHORT = 10,
    AGETIMEOFDAY = 11,
    VECTOR3 = 50,
    POINT3 = 51,
    QUATERNION = 54,
    RGB8 = 55
  } sdl_type_t;

  class DescObj {
  public:
    DescObj() : m_name(NULL), m_count(0), m_options(0) { }
    virtual ~DescObj() { if (m_name) free(m_name); }
    char *m_name;
    u_int m_count;
#define SDL_OPT_VAULT   1
#define SDL_DISP_RED    2
#define SDL_DISP_HIDDEN 4
    int m_options;
  };

  class Variable : public DescObj {
  public:
    Variable(sdl_type_t type) : DescObj(), m_type(type) {
      memset(&m_default, 0, sizeof(m_default));
    }
    virtual ~Variable() { }
    typedef union {
      int v_int;
      float v_float;
      bool v_bool;
      char v_string[32];
      PlKey v_plkey;
      u_char *v_creatable; // first four bytes is following length
      struct timeval v_time;
      int8_t v_byte;
      int16_t v_short;
      struct timeval v_agetime;
      float v_vector3[3];
      float v_point3[3];
      float v_quaternion[4];
      uint8_t v_rgb8[3];
    } data_t;

    sdl_type_t m_type;
    data_t m_default;
  private:
    Variable();
    Variable(Variable &);
    Variable & operator=(const Variable &);
  };
  class Struct : public DescObj {
  public:
    Struct(SDLDesc *type) : DescObj(), m_data(type) { }
    virtual ~Struct() { }
    SDLDesc *m_data;
  private:
    Struct();
    Struct(Struct &);
    Struct & operator=(const Struct &);
  };

  /*
   * SDLDesc itself; note objects are constructed with parse_file and
   * parse_directory.
   */

  ~SDLDesc();

  // accessors
  const char * name() const { return m_name; }
  u_int version() const { return m_version; }
  static SDLDesc * find_by_name(const char *name, const std::list<SDLDesc*> &l,
				u_int version=0);
  const std::vector<Variable*> & vars() const { return m_vars; }
  const std::vector<Struct*> & structs() const { return m_structs; }

  // throws parse_error
  static void parse_file(std::list<SDLDesc*> &sdls, std::ifstream &file);
  // returns non-zero for an error: < 0 for an error, > 0 for dirname
  // not present (or not a directory)
  static int parse_directory(Logger *log, std::list<SDLDesc*> &sdls,
			     std::string &dirname, bool is_common,
			     bool not_present_is_error);

protected:
  char *m_name;
  u_int m_version;

  std::vector<Variable*> m_vars;
  std::vector<Struct*> m_structs;

  static SDLDesc * read_desc(std::ifstream &file, u_int &lineno,
			     std::list<SDLDesc*> &descs);
  void set_version(u_int v) { m_version = v; }
  void add_var(Variable *v) { m_vars.push_back(v); }
  void add_struct(Struct *s) { m_structs.push_back(s); }

  SDLDesc(const std::string &name);

private:
  static sdl_type_t string_to_type(std::string &s);
  static u_int name_and_count(std::string &namestr, u_int lineno);
};

// utility functions
u_int do_message_compression(u_char *buf);

class SDLState {
public:
  typedef enum {
    Unknown01 = 0x01,
    Unknown02 = 0x02,
    Timestamp = 0x04,
    Default = 0x08,
    Dirty = 0x10,
    Unknown20 = 0x20
  } sdl_flag_t;

  class StateObj {
  public:
    StateObj(u_int index)
      : m_index(index), m_flags(Default), m_count(0) { }
    u_int m_index;
    u_int m_flags;
    struct timeval m_ts;
    u_int m_count;
  };
  class Variable : public StateObj {
  public:
    Variable(u_int index, const SDLDesc::sdl_type_t type)
      : StateObj(index), m_type(type), m_value(NULL) { }
    ~Variable();
    // == excludes the timestamp! (both the flag and the actual ts value)
    bool operator==(const Variable &other);
    Variable & operator=(const Variable &other);
    SDLDesc::sdl_type_t m_type;
    SDLDesc::Variable::data_t *m_value;
  private:
    Variable();
    Variable(Variable &);
  };
  class Struct : public StateObj {
  public:
    Struct(u_int index, const SDLDesc *parent)
      : StateObj(index), m_desc(parent), m_child(NULL) { }
    ~Struct() { if (m_child) delete[] m_child; }
    Struct & operator=(const Struct &other);
    const SDLDesc *m_desc;
    SDLState *m_child;
  private:
    Struct();
    Struct(Struct &);
  };

  // the constructor is used with no arguments when reading state from network
  // messages (set_desc() and read_in() fill in the data); when creating new,
  // default state at startup, the SDLDesc is passed in
  SDLState(const SDLDesc *desc=NULL);
  ~SDLState();

  // Read in a full SDL message. Returns the number of bytes used, or
  // -(bytes used) if the SDL is not recognized.
  // throws parse_error, truncated_message
  int read_msg(const u_char *buf, size_t bufsize,
	       const std::list<SDLDesc*> &descs);
  // Returns how many (uncompressed) bytes the entire message requires.
  // When written the message may be smaller due to compression.
  u_int send_len() const;
  // Write out a full SDL message. Returns -1 if the buffer is too small.
  int write_msg(u_char *buf, size_t bufsize, bool no_compress=false);

  // set the SDLDesc that goes with the SDLState being created
  void set_desc(const SDLDesc *desc);
  // Returns < 0 if the SDL is not recognized. Otherwise returns how many
  // bytes were read.
  // throws truncated_message
  int read_in(const u_char *buf, size_t bufsize,
	      const std::list<SDLDesc*> &descs);
  // Returns how many (uncompressed) bytes the body of the message requires
  // (not including the plKey or the lengths/compression flag).
  u_int body_len() const;
  // Returns < 0 if the buffer is not big enough, otherwise how many bytes
  // were written.
  int write_out(u_char *buf, size_t bufsize) const;

  /*
   * These methods manage the persistent SDL for everything in an age.
   */
  // cons up a plKey for an AgeSDLHook
  void invent_age_key(uint32_t pageid);
  // we aren't tracking one of these yet, this will become the master copy
  void expand();
  // update this, the master copy
  void update_from(SDLState *newer, bool vault=false, bool global=true,
		   bool age_load=false);

  // write encoded form to a file
  static bool save_file(std::ofstream &file, std::list<SDLState*> &save);
  // read encoded form from a file
  static bool load_file(std::ifstream &file, std::list<SDLState*> &load,
			std::list<SDLDesc*> &descs, Logger *log);

  /*
   * Utility functions
   */
  // check name
  bool name_equals(const char *name);
  // use to determine whether an SDL is avatar-specific
  bool is_avatar_sdl() const;

  /*
   * Accessors
   */
  const SDLDesc * get_desc() const { return m_desc; }
  PlKey & key() { return m_key; }
  const std::vector<Variable*> & vars() const { return m_vars; }
  const std::vector<Struct*> & structs() const { return m_structs; }

protected:
  PlKey m_key;
  uint16_t m_flag;
  const SDLDesc *m_desc;
  bool m_saving_to_file;

  std::vector<Variable*> m_vars;
  std::vector<Struct*> m_structs;

private:
  int recursive_parse(const u_char *buf, size_t bufsize);
  int recursive_write(u_char *buf, size_t bufsize) const;
  u_int recursive_len() const;
};

/*
 * I am sticking the .age file parser here with the SDL parser because the
 * files are parsed at the same time and so on.
 */
class AgeDesc {
public:
  class Page {
  public:
    Page(const char *name);
    ~Page() { if (m_name) free(m_name); }
    char *m_name;
    bool m_owned; // XXX ownership is not per-page in MOUL
    kinum_t m_owner; // so these two are probably unneeded
    u_int m_pagenum;
    u_int m_conditional_load;
  };

  ~AgeDesc();

  // throws parse_error
  static AgeDesc * parse_file(std::ifstream &file);

  // accessors
  u_int linger_time() const { return m_linger; }
  int seq_prefix() const { return m_seq_prefix; }

protected:
  std::vector<Page*> m_pages;
  u_int m_start_date_time;
  float m_daylen;
  u_int m_capacity; // used for what??
  u_int m_linger;
  int m_seq_prefix;
  int m_release;

  AgeDesc() : m_linger(180/*default*/) { };
};
