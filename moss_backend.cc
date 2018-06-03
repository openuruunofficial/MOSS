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
#include <errno.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdarg.h>
#include <pthread.h>
#include <signal.h>
#include <iconv.h>

#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/select.h>

#include <netinet/in.h>

#include <exception>
#include <stdexcept>
#include <list>
#include <deque>

#ifdef USE_POSTGRES
#ifdef USE_PQXX
#include <pqxx/pqxx>
#else
#include <libpq-fe.h>
#endif
#endif

#include <getopt.h>
#ifdef HAVE_OPENSSL_RC4
#include <openssl/rc4.h>
#else
#include "rc4.h"
#endif

#include "machine_arch.h"
#include "exceptions.h"
#include "constants.h"
#include "protocol.h"
#include "backend_typecodes.h"
#include "util.h"
#include "UruString.h"
#include "Buffer.h"

#include "Logger.h"
#include "ConfigParser.h"
#include "NetworkMessage.h"
#include "BackendMessage.h"
#include "MessageQueue.h"

#include "moss_serv.h"
#include "moss_backend.h"

#define RELOAD 0
#define SHUTDOWN 1
#define SIGNAL_RESPONSES 2
static int todo[SIGNAL_RESPONSES] = { 0, 0 };

static void sig_handler(int sig) {
  if (sig == SIGHUP) {
    todo[RELOAD] = 1;
  }
  else if (sig == SIGTERM || sig == SIGINT) {
    todo[SHUTDOWN] = 1;
  }
  else if (sig == SIGALRM) {
    _exit(1);
  }
}

class BackendProcessor : public Server::SignalProcessor {
public:
  Server::reason_t signalled(int *todo, Server *s) {
    if (todo[SHUTDOWN]) {
      return Server::SERVER_SHUTDOWN;
    }
    if (todo[RELOAD]) {
      this->read_config(false);
      Logger::level_t new_level = Logger::str_to_level(log_level);
      if (!s->log()) {
	// try to create a new logger in the current log_dir
	char *temp_str = NULL;
	try {
	  if (log_dir) {
	    size_t len = strlen(log_dir) + sizeof("moss_backend.log") + 2;
	    temp_str = new char[len];
	    snprintf(temp_str, len, "%s%smoss_backend.log",
		     log_dir, PATH_SEPARATOR);
	  }
	  m_log = new Logger("backend",
			     log_dir ? temp_str : "moss_backend.log",
			     Logger::str_to_level(log_level));
	  s->set_logger(m_log);
	}
	catch (const std::bad_alloc&) {
	}
	if (temp_str) {
	  delete[] temp_str;
	  temp_str = NULL;
	}
      }
      if (new_level == Logger::NONE) {
	log_err(m_log, "Invalid log_level: %s\n", log_level ? log_level : "");
	if (log_level) {
	  free(log_level);
	}
	if (m_log) {
	  log_level = strdup(Logger::level_to_str(m_log->get_level()));
	}
	else {
	  log_level = strdup("NET");
	}
      }
      else {
	if (s->log()) {
	  s->log()->set_level(new_level);
	}
      }
      todo[RELOAD] = 0;
    }
    return Server::NO_SHUTDOWN;
  }

  BackendProcessor(Logger *logger, const char *config_file)
    : bind_addr_name(NULL), log_dir(NULL),
      log_level(NULL), pid_file(NULL), db_addr(NULL), db_user(NULL),
      db_passwd(NULL), db_name(NULL), db_params(NULL),
      bind_port(0), db_port(0), egg_mask(0),
      m_log(logger), m_cfg_file(config_file), m_egg_disable(NULL) { }
  void set_logger(Logger *logger) { m_log = logger; }
  void register_options() {
    m_back_config.register_config("bind_address", &bind_addr_name,
				  "127.0.0.1");
    m_back_config.register_config("bind_port", &bind_port, 14618);
    m_back_config.register_config("log_dir", &log_dir, "log");
    m_back_config.register_config("log_level", &log_level, "NET");
    m_back_config.register_config("pid_file", &pid_file,
				  "/var/run/moss_backend.pid");
    m_back_config.register_config("db_address", &db_addr, "");
    m_back_config.register_config("db_port", &db_port, 0);
    m_back_config.register_config("db_user", &db_user, "");
    m_back_config.register_config("db_password", &db_passwd, "");
    m_back_config.register_config("db_name", &db_name, "moss");
    m_back_config.register_config("db_params", &db_params,"");
    m_back_config.register_config("egg_disable", &m_egg_disable, "");
  }
  bool read_config(bool complain) {
    try {
      if (m_back_config.read_config(m_cfg_file, complain)) {
	log_err(m_log, "Could not open config file %s\n", m_cfg_file);
	return false;
      }
    }
    catch (const parse_error &e) {
      log_err(m_log, "Error reading config file %s line %u: %s\n",
	      m_cfg_file, e.lineno(), e.what());
      return false;
    }
    if (m_egg_disable && strlen(m_egg_disable) > 0) {
      u_int count = 0;
      char **split = ConfigParser::split_string(m_egg_disable, &count);
      if (split) {
	egg_mask = 0;
	for (u_int i = 0; i < count; i++) {
	  int val;
	  if (sscanf(split[i], "%i", &val) != 1) {
	    // non-integer value, disable all eggs
	    egg_mask = (u_int)-1;
	    break;
	  }
	  else if (val < 0) {
	    val = -val;
	  }
	  egg_mask |= 1 << val;
	}
	free(split);
      }
    }
    else {
      egg_mask = 0;
    }
    return true;
  }
  void unregister_options() {
    m_back_config.unregister_config("bind_address");
    m_back_config.unregister_config("bind_port");
    m_back_config.unregister_config("pid_file");
    m_back_config.unregister_config("db_address");
    m_back_config.unregister_config("db_port");
    m_back_config.unregister_config("db_user");
    m_back_config.unregister_config("db_password");
    m_back_config.unregister_config("db_name");
    m_back_config.unregister_config("db_params");
  }
  virtual ~BackendProcessor() {
    if (bind_addr_name) {
      free(bind_addr_name);
    }
    if (log_dir) {
      free(log_dir);
    }
    if (log_level) {
      free(log_level);
    }
    if (pid_file) {
      free(pid_file);
    }
    if (db_addr) {
      free(db_addr);
    }
    if (db_user) {
      free(db_user);
    }
    if (db_passwd) {
      free(db_passwd);
    }
    if (db_name) {
      free(db_name);
    }
    if (db_params) {
      free(db_params);
    }
    if (m_egg_disable) {
      free(m_egg_disable);
    }
  }
  
  char *bind_addr_name, *log_dir, *log_level, *pid_file,
    *db_addr, *db_user, *db_passwd, *db_name, *db_params;
  int bind_port, db_port;
  u_int egg_mask;
protected:
  Logger *m_log;
  const char *m_cfg_file;
  char *m_egg_disable;
  ConfigParser m_back_config;
};

int main(int argc, char *argv[]) {
  int ret, fd = -1;
  long return_value = 0;
  struct sockaddr_in bind_addr;
  Logger *log = NULL;
  char *temp_str = NULL;
  BackendServer *server = NULL;

  // process stuff
  struct sigaction sig;

  // command-line arguments
  char *cfg_file = NULL;
  bool do_fork = true;

  static struct option options[] = {
    { "config", required_argument, 0, 'c' },
    { "daemon", no_argument, 0, 'd' },
    { "foreground", no_argument, 0, 'f' },
    { 0, 0, 0, 0 }
  };
  static const char *usage = "Usage: %s [-f] [-c <config file>]\n";
  char c;
  opterr = 0;
  while ((c = getopt_long(argc, argv, "c:df", options, NULL)) != -1) {
    switch (c) {
    case 'c':
      cfg_file = strdup(optarg);
      if (!cfg_file) {
	log_err(log, "Cannot allocate memory?!\n");
	return 1;
      }
      break;
    case 'd':
      // noop: for backward compatibility
      break;
    case 'f':
      do_fork = false;
      break;
    default:
      log_err(log, usage, argv[0]);
      return 0;
    }
  }
  if (!cfg_file) {
    cfg_file = strdup("./etc/moss_backend.cfg");
    if (!cfg_file) {
      log_err(log, "Cannot allocate memory?!\n");
      return 1;
    }
  }

  BackendProcessor *bp = NULL;

  /* configuration controls */

  try {
    bp = new BackendProcessor(log, cfg_file);
    bp->register_options();
    if (!bp->read_config(true)) {
      return_value = 1;
      goto early_shutdown;
    }
    bp->unregister_options();
  }
  catch (const std::bad_alloc&) {
    log_err(log, "Cannot allocate memory while reading config file\n");
    return_value = 1;
    goto early_shutdown;
  }

  /* check validity of config */

  if (Logger::str_to_level(bp->log_level) == Logger::NONE) {
    log_err(log, "Invalid log_level: %s\n",
	    bp->log_level ? bp->log_level : "");
    return_value = 1;
  }
  if (bp->bind_port > 65535 || bp->bind_port < 1) {
    log_err(log, "Invalid bind_port: %d\n", bp->bind_port);
    return_value = 1;
  }
  if (!bp->db_name || bp->db_name[0] == '\0') {
    log_err(log, "A valid database name must be provided\n");
    return_value = 1;
  }
  if (return_value == 1) {
    goto early_shutdown;
  }

  /* check remaining values for sanity */

  memset(&bind_addr, 0, sizeof(struct sockaddr_in));
  bind_addr.sin_port = (uint16_t)ntohs(bp->bind_port);
  bind_addr.sin_family = PF_INET;

  if (bp->bind_addr_name && bp->bind_addr_name[0] != '\0') {
    const char *result = resolve_hostname(bp->bind_addr_name,
					  &bind_addr.sin_addr.s_addr);
    if (result) {
      log_err(log, "Could not resolve \"%s\": %s\n", bp->bind_addr_name,
	      result);
      return_value = 1;
    }
  }
  else {
    bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  }

  {
    const char *dir = ".";
    if (bp->log_dir) {
      dir = bp->log_dir;
    }
    struct stat s;
    ret = stat(dir, &s);
    if (ret < 0) {
      ret = mkdir(dir, S_IRWXU|S_IRWXG);
      if (ret) {
	log_err(log, "Directory %s does not exist and "
		"cannot be created (%s)\n", dir, strerror(errno));
	return_value = 1;
      }
    }
    else if (!(S_ISDIR(s.st_mode))) {
      log_err(log, "%s is not a directory\n", dir);
      return_value = 1;
    }
  }
  if (return_value == 1) {
    goto early_shutdown;
  }

  /* now spin up everything */

  do_random_seed();

  Logger::init();
  try {
    if (bp->log_dir) {
      size_t len = strlen(bp->log_dir) + sizeof("moss_backend.log") + 1;
      temp_str = new char[len];
      snprintf(temp_str, len, "%s%smoss_backend.log",
	       bp->log_dir, PATH_SEPARATOR);
    }
    log = new Logger("backend",
		     bp->log_dir ? temp_str : "moss_backend.log",
		     Logger::str_to_level(bp->log_level));
    bp->set_logger(log);
  }
  catch (const std::bad_alloc&) {
  }
  if (temp_str) {
    delete[] temp_str;
    temp_str = NULL;
  }

  if (do_fork) {
    pid_t pid = fork();
    if (pid < 0) {
      log_err(log, "Fork error: %s\n", strerror(errno));
      return_value = 1;
      goto logger_shutdown;
    }
    else if (pid > 0) {
      // parent
      goto logger_shutdown;
    }
  }
  fd = open(bp->pid_file ? bp->pid_file : "/var/run/moss_backend.pid",
	    O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
  if (fd >= 0) {
    char pid_str[100];
    pid_t pid = getpid();
    snprintf(pid_str, 100, "%u\n", pid);
    // the "if" is to shut up gcc; I don't care if the write fails
    if (write(fd, pid_str, strlen(pid_str))) ;
    close(fd);
    fd = -1;
  }

  fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (fd < 0) {
    log_err(log, "Error creating listen socket: %s\n", strerror(errno));
    return_value = 1;
    goto logger_shutdown;
  }
  ret = fcntl(fd, F_GETFL, NULL);
  if (fcntl(fd, F_SETFL, ret|O_NONBLOCK)) {
    log_err(log, "Error setting socket nonblocking: %s\n", strerror(errno));
    return_value = 1;
    goto logger_shutdown;
  }
  if (bind(fd, (struct sockaddr *)&bind_addr, sizeof(struct sockaddr_in))) {
    log_err(log, "Error in bind: %s\n", strerror(errno));
    return_value = 1;
    goto logger_shutdown;
  }
  if (listen(fd, 100)) {
    log_err(log, "Error in listen: %s\n", strerror(errno));
    return_value = 1;
    goto logger_shutdown;
  }

  try {
    server = new BackendServer(fd, bind_addr.sin_addr.s_addr, bp->db_addr,
			       bp->db_port, bp->db_user, bp->db_passwd,
			       bp->db_name, bp->db_params, bp->egg_mask);
    server->set_logger(log);
    server->set_signal_data(todo, SIGNAL_RESPONSES, bp);
  }
  catch (const std::bad_alloc&) {
    log_err(log, "Cannot allocate memory for backend connection object\n");
    return_value = 1;
    goto logger_shutdown;
  }

  sigemptyset(&sig.sa_mask);
  sig.sa_handler = SIG_IGN;
  sig.sa_flags = 0;
  if (sigaction(SIGPIPE, &sig, NULL)) {
    log_err(log, "Error setting SIGPIPE to SIG_IGN! (%s)\n", strerror(errno));
  }
  sig.sa_handler = sig_handler;
  if (sigaction(SIGHUP, &sig, NULL)) {
    log_err(log, "Error setting SIGHUP handler! (%s)\n", strerror(errno));
  }
  if (sigaction(SIGTERM, &sig, NULL)) {
    log_err(log, "Error setting SIGTERM handler! (%s)\n", strerror(errno));
  }
  if (sigaction(SIGINT, &sig, NULL)) {
    log_err(log, "Error setting SIGINT handler! (%s)\n", strerror(errno));
  }
  if (sigaction(SIGALRM, &sig, NULL)) {
    log_err(log, "Error setting SIGALRM handler! (%s)\n", strerror(errno));
  }

  return_value = (long)serv_main((void *)server);
  // closing the listening fd before deleting the server will prevent the
  // listen socket from going into TIME_WAIT in Linux
  close(fd);
  fd = -1;

  delete server;
  log = NULL; // the Logger is deleted by the server

 logger_shutdown:
  if (fd >= 0) {
    close(fd);
  }

  if (log) {
    delete log;
  }
  Logger::shutdown();
  unlink(bp->pid_file ? bp->pid_file : "/var/run/moss_backend.pid");

 early_shutdown:
  if (bp) {
    delete bp;
  }
  if (cfg_file) {
    free(cfg_file);
  }
  return return_value;
}
