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
 * Logger does what it sounds like. It provides an object with methods to
 * access the file object through a mutex, so that multiple threads can
 * safely share the same log file. The globally-defined log_* functions
 * below handle the lock acquisition automatically and should be sufficient
 * for most uses. These functions also allow for the Logger object to be
 * NULL; that case, logging is simply not done except for ERR level,
 * which is then written to stderr.
 *
 * It may be important to bear in mind that, by design, the Logger
 * constructor does not fail if the file to log to cannot be opened.
 */

//#include <stdio.h>
//
//#include <stdarg.h> /* or varargs.h if no stdarg.h */
//#include <pthread.h>

#ifndef _LOGGER_H_
#define _LOGGER_H_

class Logger {
public:
  /*
   * The init() class method should be called once at startup before creating
   * any Logger objects.
   */
  static void init(); // can throw bad_alloc
  static void shutdown();

  /*
   * The logging heirarchy.
   */
  typedef enum {
    NONE = 0,
    LOG_MSGS,
    LOG_DEBUG,
    LOG_NET,	// unrecognized, incorrectly parsed, etc. network messages
    LOG_WARN,
    LOG_INFO,
    LOG_ERR
  } level_t;
  level_t set_level(level_t new_level) {
    level_t old_level = m_log_level;
    m_log_level = new_level;
    return old_level;
  }
  level_t get_level() const {
    return m_log_level;
  }
  bool would_log_at(level_t level) const {
    return (level >= m_log_level);
  }
  static level_t str_to_level(const char *name);
  static const char * level_to_str(level_t level);

  /*
   * If the filename specified in the constructor cannot be opened for
   * writing, the open will simply fail and no logging will happen. If it
   * is necessary to test for this state, test the return value from calling
   * get_lock(Logger::LOG_ERR) (the highest log level); if it's NULL, then
   * the open failed. Don't forget to release the lock if it's non-NULL...
   */
  Logger(const char *system, const char *filename, level_t level=LOG_NET);
  Logger(const char *system, Logger *to_share, level_t level=LOG_NET);
  virtual ~Logger();

  /*
   * A mutex protects against concurrent logging. To get the file stream to
   * write to, the lock must be acquired with get_lock. If NULL is returned,
   * the log level is too low, so log nothing. After logging, the lock must
   * be released with release_lock(). The get_prefix() method returns a
   * pointer to a "static" buffer (one per instance, not one per function
   * call), so should be called only while the lock is held.
   */
  FILE * get_lock(level_t level);
  const char * get_prefix(level_t level);
  void release_lock();

  /*
   * Utility function: dump buffer contents.
   */
  void dump_contents(level_t level, const u_char *buf, size_t len);

protected:
  FILE *m_logf;
  char *m_log_prefix;
  level_t m_log_level;
  pthread_mutex_t *m_mutex;
  u_int *m_refct;

  void setup_logger(const char *system, const char *filename);

private:
  // don't copy
  Logger();
  Logger(Logger &);
  Logger & operator=(const Logger &);
};

/*
 * Note that these functions use a mutex to protect against concurrent
 * logging. The fmt argument should end in a newline unless you are planning
 * to use log_raw to append one later.
 */
inline void log_err(Logger *logger, const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  if (logger) {
    FILE *f = logger->get_lock(Logger::LOG_ERR);
    if (f) {
      fprintf(f, "%s", logger->get_prefix(Logger::LOG_ERR));
      vfprintf(f, fmt, ap);
      fflush(f);
      logger->release_lock();
    }
    else {
      vfprintf(stderr, fmt, ap);
      fflush(stderr);
    }
  }
  else {
    vfprintf(stderr, fmt, ap);
    fflush(stderr);
  }
  va_end(ap);
}

#ifdef __GNUC__
inline std::string methodName(const char *prettyFuncNameChars)
{
	std::string prettyFuncName(prettyFuncNameChars);

	size_t end = prettyFuncName.length() - 1;

	if (prettyFuncName.substr(end, 1).compare(")") == 0) {
		uint_t lvl = 1;
		while (lvl > 0 && end >= 0) {
			end -= 1;
			if (prettyFuncName.substr(end, 1).compare(")") == 0)
				lvl += 1;
			else if (prettyFuncName.substr(end, 1).compare("(") == 0)
				lvl -= 1;
		}
	}
	size_t begin = prettyFuncName.substr(0, end).rfind(" ") + 1;

	return prettyFuncName.substr(begin, end-begin) + "()";
}
inline std::string methodName(std::string prettyFuncName)
{
	size_t end = prettyFuncName.length() - 1;

	if (prettyFuncName.substr(end, 1).compare(")") == 0) {
		uint_t lvl = 1;
		while (lvl > 0 && end >= 0) {
			end -= 1;
			if (prettyFuncName.substr(end, 1).compare(")") == 0)
				lvl += 1;
			else if (prettyFuncName.substr(end, 1).compare("(") == 0)
				lvl -= 1;
		}
	}
	size_t begin = prettyFuncName.substr(0, end).rfind(" ") + 1;

	return prettyFuncName.substr(begin, end-begin) + "()";
}
#define __METHOD_NAME__ methodName(__PRETTY_FUNCTION__)
#define LOGGER_WHERE __METHOD_NAME__, __LINE__

#define log_info(logger, ...) log_at(Logger::LOG_INFO, logger, __VA_ARGS__)
#define log_warn(logger, ...) log_at_where(Logger::LOG_WARN, logger, LOGGER_WHERE, __VA_ARGS__)
#define log_net(logger, ...) log_at_where(Logger::LOG_NET, logger, LOGGER_WHERE, __VA_ARGS__)
#define log_debug(logger, ...) log_at_where(Logger::LOG_DEBUG, logger, LOGGER_WHERE, __VA_ARGS__)
#define log_msgs(logger, ...) log_at_where(Logger::LOG_MSGS, logger, LOGGER_WHERE, __VA_ARGS__)

#else /* Non GCC */

#define log_info(logger, ...) log_at(Logger::LOG_INFO, logger, __VA_ARGS__)
#define log_warn(logger, ...) log_at(Logger::LOG_WARN, logger, __VA_ARGS__)
#define log_net(logger, ...) log_at(Logger::LOG_NET, logger, __VA_ARGS__)
#define log_debug(logger, ...) log_at(Logger::LOG_DEBUG, logger, __VA_ARGS__)
#define log_msgs(logger, ...) log_at(Logger::LOG_MSGS, logger, __VA_ARGS__)

#endif


inline void log_at(Logger::level_t level, Logger *logger,
		   const char *fmt, ...) {
  va_list ap;

  if (logger) {
    va_start(ap, fmt);
    FILE *f = logger->get_lock(level);
    if (f) {
      fprintf(f, "%s", logger->get_prefix(level));
      vfprintf(f, fmt, ap);
      fflush(f);
      logger->release_lock();
    }
    va_end(ap);
  }
}

inline void log_at_where(Logger::level_t level, Logger *logger,
		   std::string methodName, int lineno, const char *fmt, ...) {
  va_list ap;

  if (logger) {
    va_start(ap, fmt);
    FILE *f = logger->get_lock(level);
    if (f) {
      fprintf(f, "%s%s#%d ", logger->get_prefix(level), methodName.c_str(), lineno);
      vfprintf(f, fmt, ap);
      fflush(f);
      logger->release_lock();
    }
    va_end(ap);
  }
}

inline void log_raw(Logger::level_t level, Logger *logger,
		    const char *fmt, ...) {
  va_list ap;

  if (logger) {
    va_start(ap, fmt);
    FILE *f = logger->get_lock(level);
    if (f) {
      vfprintf(f, fmt, ap);
      fflush(f);
      logger->release_lock();
    }
    va_end(ap);
  }
}

#endif /* _LOGGER_H_ */
