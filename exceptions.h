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
 * Exceptions used internally by MOSS.
 */

//#include <stdexcept>

// parse_error is used by ConfigParser, SDLDesc, and AgeDesc
// SDLState also uses it
class parse_error : public std::runtime_error {
public:
  parse_error(unsigned int lineno, const std::string &error="")
    : std::runtime_error(error), m_line(lineno) { }
  unsigned int lineno() const { return m_line; }
protected:
  unsigned int m_line;
private:
  parse_error();
};

// overlong_message is used by *Message
class overlong_message : public std::runtime_error {
public:
  overlong_message(unsigned int claimed_len, const std::string &error="")
    : std::runtime_error(error), m_claimed(claimed_len) { }
  unsigned int claimed_len() const { return m_claimed; }
protected:
  unsigned int m_claimed;
private:
  overlong_message();
};

// truncated_message is used by SDLState and GameMgr
class truncated_message : public std::runtime_error {
public:
  truncated_message(const std::string &error="")
    : std::runtime_error(error) { }
};
