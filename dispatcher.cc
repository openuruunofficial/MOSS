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
 * The dispatcher is actually main(). It's the top-level select loop that
 * spawns all other threads and processes.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h> /* for fork(), getpid() */
#endif

#include <stdarg.h>
#include <pthread.h>
#include <signal.h>
#include <iconv.h>
#ifdef FORK_ENABLE
#include <sys/wait.h>
#endif

#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/time.h>

#include <arpa/inet.h> /* for inet_ntop() */
#include <netinet/in.h>

#include <exception>
#include <stdexcept>
#include <deque>
#include <map>
#include <list>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>

#include <getopt.h>
#ifdef HAVE_OPENSSL
#ifdef USING_RSA
#include <openssl/rsa.h>
#endif
#ifdef USING_DH
#include <openssl/dh.h>
#endif
#else
#if defined(USING_RSA) || defined(USING_DH)
#error OpenSSL is required to use RSA or D-H!
#endif
#endif

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
#include "PlKey.h"
#include "Buffer.h"

#include "Logger.h"
#include "SDL.h"
#include "ConfigParser.h"
#include "FileTransaction.h"
#include "NetworkMessage.h"
#include "MessageQueue.h"
#include "BackendMessage.h"

#include "moss_serv.h"
#include "ThreadManager.h"
#include "AuthServer.h"
#include "FileMessage.h"
#include "FileServer.h"
#include "GameState.h"
#include "GameServer.h"
#ifndef OLD_PROTOCOL
#include "GatekeeperServer.h"
#endif


#define RELOAD 0
#define SHUTDOWN 1
#define THREAD_JOIN 2
#define CHILD_EXIT 3
#define SIGNAL_RESPONSES 4
static int todo[SIGNAL_RESPONSES] = { 0, 0, 0, 0 };

static void sig_handler(int sig) {
  if (sig == SIGHUP) {
    todo[RELOAD] = 1;
  }
  else if (sig == SIGTERM) {
    todo[SHUTDOWN] = 1;
  }
  else if (sig == SIGINT) {
    todo[SHUTDOWN] = 1;
  }
  else if (sig == SIGQUIT) {
    todo[THREAD_JOIN] = 1;
  }
#ifdef FORK_ENABLE
  else if (sig == SIGCHLD) {
    todo[CHILD_EXIT] = 1;
  }
#endif
  else if (sig == SIGALRM) {
    _exit(1);
  }
}

static void usr2_handler(int sig) {
  // nothing need be done
}

#define DEFAULT_CFG_FILE "./etc/moss.cfg"
#define DEFAULT_AUTH_KEY "./etc/auth_key.der"
#define DEFAULT_GAME_KEY "./etc/game_key.der"
#define DEFAULT_GATE_KEY "./etc/gatekeeper_key.der"

class DispatcherProcessor : public Server::SignalProcessor {
public:
  Server::reason_t signalled(int *todo, Server *s);

  DispatcherProcessor(Logger *logger, const char *config_file)
    : bind_addr_name(NULL), track_addr_name(NULL), log_dir(NULL),
      log_level(NULL), pid_file(NULL), server_types(NULL),
      ext_addr_name(NULL), child_name(NULL),
      auth_dir(NULL), file_dir(NULL), game_dir(NULL), auth_log_level(NULL),
      file_log_level(NULL), game_log_level(NULL), gate_log_level(NULL),
      game_addr_name(NULL), auth_key_file(NULL), game_key_file(NULL),
      gate_key_file(NULL), status_str(NULL), always_resolve(false),
      bind_port(0), track_port(0), status_len(0), m_thread_manager(NULL),
      m_do_auth(0), m_do_file(0), m_do_game(0), m_do_gate(0), m_do_status(0),
      m_cfg_file(config_file), m_log(logger) { }
  void set_logger(Logger *logger) { m_log = logger; }
  void register_options() {
    m_disp_config.register_config("bind_address", &bind_addr_name, "");
    m_disp_config.register_config("bind_port", &bind_port, 14617);
    // note, if there is ever a separate vault and tracking server, add and
    // use track_* here
    m_disp_config.register_config("vault_address", &track_addr_name, "");
    m_disp_config.register_config("vault_port", &track_port, 14618);
    m_disp_config.register_config("log_dir", &log_dir, "log");
    m_disp_config.register_config("log_level", &log_level, "NET");
    m_disp_config.register_config("pid_file", &pid_file, "/var/run/moss.pid");
    m_disp_config.register_config("server_types", &server_types,
				  "auth,file,game,gatekeeper");
    m_disp_config.register_config("external_address", &ext_addr_name, "");
    m_disp_config.register_config("always_resolve", &always_resolve, false);
    m_disp_config.register_config("child_name", &child_name,
				  "./bin/moss_serv");
    m_disp_config.register_config("auth_download_dir", &auth_dir, "auth");
    m_disp_config.register_config("file_download_dir", &file_dir, "file");
    m_disp_config.register_config("game_data_dir", &game_dir, "game");
    m_disp_config.register_config("auth_log_level", &auth_log_level, "NET");
    m_disp_config.register_config("file_log_level", &file_log_level, "WARN");
    m_disp_config.register_config("game_log_level", &game_log_level, "NET");
    m_disp_config.register_config("gatekeeper_log_level", &gate_log_level,
				  "NET");
    m_disp_config.register_config("game_address", &game_addr_name, "");
    m_disp_config.register_config("auth_key_file", &auth_key_file,
				  DEFAULT_AUTH_KEY);
    m_disp_config.register_config("game_key_file", &game_key_file,
				  DEFAULT_GAME_KEY);
    m_disp_config.register_config("gatekeeper_key_file", &gate_key_file,
				  DEFAULT_GATE_KEY);
    m_disp_config.register_config("status_message", &status_str,
				  "Welcome to MOSS");
  }
  bool read_config(bool complain) {
    try {
      if (m_disp_config.read_config(m_cfg_file, complain)) {
	log_err(m_log, "Could not open config file %s\n", m_cfg_file);
	return false;
      }
    }
    catch (const parse_error &e) {
      log_err(m_log, "Error reading config file %s line %u: %s\n",
	      m_cfg_file, e.lineno(), e.what());
      return false;
    }
    return true;
  }
  void unregister_options() {
    m_disp_config.unregister_config("bind_address");
    m_disp_config.unregister_config("bind_port");
    m_disp_config.unregister_config("vault_address");
    m_disp_config.unregister_config("vault_port");
    m_disp_config.unregister_config("pid_file");
  }
  virtual ~DispatcherProcessor();

  bool parse_server_types();
  bool check_log_level() {
    if (!log_level || log_level[0] == '\0') {
      // empty (must be a reload)
      return false;
    }
    if (Logger::str_to_level(log_level) == Logger::NONE) {
      log_err(m_log, "Invalid log_level: %s\n", log_level ? log_level : "");
      return false;
    }
    return true;
  }
  bool check_auth_log_level() {
    if (!auth_log_level || auth_log_level[0] == '\0') {
      // empty (must be a reload)
      return false;
    }
    if (Logger::str_to_level(auth_log_level) == Logger::NONE) {
      log_err(m_log, "Invalid auth_log_level: %s\n",
	      auth_log_level ? auth_log_level : "");
      return false;
    }
    return true;
  }
  bool check_file_log_level() {
    if (!file_log_level || file_log_level[0] == '\0') {
      // empty (must be a reload)
      return false;
    }
    if (Logger::str_to_level(file_log_level) == Logger::NONE) {
      log_err(m_log, "Invalid file_log_level: %s\n",
	      file_log_level ? file_log_level : "");
      return false;
    }
    return true;
  }
  bool check_game_log_level() {
    if (!game_log_level || game_log_level[0] == '\0') {
      // empty (must be a reload)
      return false;
    }
    if (Logger::str_to_level(game_log_level) == Logger::NONE) {
      log_err(m_log, "Invalid game_log_level: %s\n",
	      game_log_level ? game_log_level : "");
      return false;
    }
    return true;
  }
  bool check_gate_log_level() {
    if (!gate_log_level || gate_log_level[0] == '\0') {
      // empty (must be a reload)
      return false;
    }
    if (Logger::str_to_level(gate_log_level) == Logger::NONE) {
      log_err(m_log, "Invalid gatekeeper_log_level: %s\n",
	      gate_log_level ? gate_log_level : "");
      return false;
    }
    return true;
  }
  bool check_ports() {
    if (bind_port > 65535 || bind_port < 1
	|| track_port > 65535 || track_port < 1) {
      if (bind_port > 65535 || bind_port < 1) {
	log_err(m_log, "Invalid bind_port: %d\n", bind_port);
      }
      if (track_port > 65535 || bind_port < 1) {
	log_err(m_log, "Invalid vault_port: %d\n", track_port);
      }
      return false;
    }
    return true;
  }
  bool resolve_ext_addr(bool config_load, struct sockaddr_in *bind_addr,
			Logger *log) {
    if (ext_addr_name && ext_addr_name[0] != '\0') {
      const char *result = resolve_hostname(ext_addr_name, &m_ext_addr);
      if (result) {
	log_err(log, "Could not resolve \"%s\": %s\n", ext_addr_name,
		result);
	return false;
      }
    }
    else if (config_load && game_addr_name && game_addr_name[0] != '\0') {
      // for backwards compatability of pre-gatekeeper conf files
      const char *result = resolve_hostname(game_addr_name, &m_ext_addr);
      if (result) {
	log_err(log, "Could not resolve \"%s\": %s\n", game_addr_name,
		result);
	return false;
      }
    }
    else if (bind_addr) {
      // We only fall back to the bind address at initial startup time. If
      // there is a reconfiguration that removes the external_address
      // entirely, we'll keep using the previous one.
      if (bind_addr->sin_addr.s_addr == INADDR_ANY) {
	log_warn(log, "Using 127.0.0.1 as external address\n");
	m_ext_addr = htonl(INADDR_LOOPBACK);
      }
      else {
	m_ext_addr = bind_addr->sin_addr.s_addr;
      }
    }
    else {
      // non-startup case with NO external_address configured
      return false;
    }
    return true;
  }
#ifdef FORK_ENABLE
  bool check_child_name() {
    struct stat s;
    int ret = stat(child_name, &s);
    if (ret < 0) {
      log_err(m_log, "Child server executable file %s does not exist\n",
	      child_name);
      return false;
    }
    else if (!(s.st_mode & (S_IRUSR|S_IRGRP|S_IROTH))
	     || !(s.st_mode & (S_IXUSR|S_IXGRP|S_IXOTH))) {
      log_err(m_log, "Child server executable file %s is not executable\n",
	      child_name);
      return false;
    }
    return true;
  }
#endif
  bool test_maybe_create_dir(const char *dir, bool create) {
    if (!dir) {
      return false;
    }
    struct stat s;
    int ret = stat(dir, &s);
    if (ret < 0) {
      if (create) {
	ret = recursive_mkdir(dir, S_IRWXU|S_IRWXG);
	if (ret) {
	  log_err(m_log, "Directory %s does not exist and "
		  "cannot be created (%s)\n", dir, strerror(errno));
	  return false;
	}
      }
      else {
	log_err(m_log, "Required directory %s does not exist\n", dir);
	return false;
      }
    }
    else if (!(S_ISDIR(s.st_mode))) {
      log_err(m_log, "%s is not a directory\n", dir);
      return false;
    }
    return true;
  }
  void setup_status_str() {
    if (status_str && strlen(status_str) > 1000) {
      status_str[1000] = '\0';
      status_len = 1001;
    }
    else if (status_str) {
      status_len = strlen(status_str) + 1;
    }
  }

  char *bind_addr_name, *track_addr_name, *log_dir, *log_level, *pid_file,
    *server_types, *ext_addr_name, *child_name, *auth_dir, *file_dir,
    *game_dir, *auth_log_level, *file_log_level, *game_log_level,
    *gate_log_level, *game_addr_name, *auth_key_file, *game_key_file,
    *gate_key_file, *status_str;
  bool always_resolve;
  int bind_port, track_port, status_len;

  ThreadManager *m_thread_manager;
  u_char m_do_auth, m_do_file, m_do_game, m_do_gate, m_do_status;
  uint32_t m_ext_addr; // network order

  const char *m_cfg_file;

  TrackServiceTypes_BackendMessage * construct_tracking_update(uint32_t id1,
							       uint32_t id2);
protected:
  Logger *m_log;
  ConfigParser m_disp_config;
};

class Dispatcher : public Server {
public:
  Dispatcher(int listen_fd, uint32_t ipaddr, struct sockaddr_in &track_address)
    : Server(listen_fd, ipaddr), m_track_addr(track_address),
#ifndef FORK_ENABLE
      m_auth_log(NULL), m_file_log(NULL),
#endif
      m_gate_log(NULL),
      m_auth_keydata(NULL), m_game_keydata(NULL), m_gate_keydata(NULL),
      m_track(NULL), m_retry(false)
  {
    int err = pthread_attr_init(&m_thread_attr);
    if (err) {
      log_err(m_log, "pthread_attr_init() failed: %s\n", strerror(err));
      throw std::bad_alloc();
    }
    pthread_attr_setdetachstate(&m_thread_attr, PTHREAD_CREATE_JOINABLE);
  }
  virtual ~Dispatcher();

  int type() const { return 0; }
  const char * type_name() const { return "main"; }

  int init();
  bool shutdown(reason_t reason) {
    log_info(m_log, "MOSS shutdown in progress...\n");
    if (m_track && m_track->fd() >= 0) {
      m_track->msg_queue()->clear_queue();
      DispatcherProcessor *dp = (DispatcherProcessor*)m_signal_processor;
      if (dp->m_do_game || dp->m_do_auth || dp->m_do_file) {
	TrackServiceTypes_BackendMessage *bye =
	  new TrackServiceTypes_BackendMessage(m_ipaddr, m_id, false, false,
					       false, 0U);
	send_tracking_update(bye);
      }
      return false;
    }
    return true;
  };

  reason_t message_read(Connection *conn, NetworkMessage *msg);

  void add_client_conn(int fd, u_char first);
  void conn_completed(Connection *conn);
  reason_t conn_timeout(Connection *conn, reason_t why);
  reason_t conn_shutdown(Connection *conn, reason_t why);

  /*
   * functions for DispatcherProcessor
   */
  uint32_t const id1() { return m_ipaddr; }
  uint32_t const id2() { return m_id; }
  void send_tracking_update(TrackServiceTypes_BackendMessage *msg) {
    m_track->enqueue(msg);
  }
  void * update_keydata(const char *fname, int auth_game_gate);

protected:
  struct sockaddr_in m_track_addr;
#ifndef FORK_ENABLE
  Logger *m_auth_log, *m_file_log;
#endif
  Logger *m_gate_log; // no forkable gatekeeper
  void *m_auth_keydata, *m_game_keydata, *m_gate_keydata;

  pthread_attr_t m_thread_attr;
  std::list<SDLDesc*> m_common_sdl;

  // state for talking to tracking server
  BackendConnection *m_track;
  bool m_retry;
  int do_connect();

  // state for managing connections to game servers
  std::map<uint32_t, GameServer*> m_games;
};

static const char *http_reply =
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n";
static const char *http_404 =
    "HTTP/1.0 404 Not Found\r\nContent-Type: text/html\r\n\r\n"
    "The requested URL does not exist.";

int main(int argc, char *argv[]) {
  int ret;
  long return_value = 0;

  /* config stuff */
  struct sockaddr_in bind_addr, track_addr;
  int fd = -1;

  /* server stuff */
  Logger *log = NULL;
  char *temp_str = NULL;
  Dispatcher *server = NULL;
    
  /* process stuff */
  struct sigaction sig;

  /* command-line arguments */

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
    cfg_file = strdup(DEFAULT_CFG_FILE);
    if (!cfg_file) {
      log_err(log, "Cannot allocate memory?!\n");
      return 1;
    }
  }

  DispatcherProcessor *dp = NULL;

  /* configuration controls */

  try {
    dp = new DispatcherProcessor(log, cfg_file);
    dp->register_options();
    if (!dp->read_config(true)) {
      return_value = 1;
      goto early_shutdown;
    }
    dp->unregister_options();
  }
  catch (const std::bad_alloc&) {
    log_err(log, "Cannot allocate memory while reading config file\n");
    return_value = 1;
    goto early_shutdown;
  }

  /* check validity of config */

  if (!dp->check_log_level() || !dp->check_ports()
      || !dp->parse_server_types() || !dp->check_auth_log_level()
      || !dp->check_file_log_level() || !dp->check_game_log_level()
      || !dp->check_gate_log_level()) {
    return_value = 1;
    goto early_shutdown;
  }

  /* check remaining values for sanity */

  memset(&bind_addr, 0, sizeof(struct sockaddr_in));
  memset(&track_addr, 0, sizeof(struct sockaddr_in));
  bind_addr.sin_port = (uint16_t)htons(dp->bind_port);
  track_addr.sin_port = (uint16_t)htons(dp->track_port);
  bind_addr.sin_family = PF_INET;
  track_addr.sin_family = PF_INET;

  if (dp->bind_addr_name && dp->bind_addr_name[0] != '\0') {
    const char *result = resolve_hostname(dp->bind_addr_name,
					  &bind_addr.sin_addr.s_addr);
    if (result) {
      log_err(log, "Could not resolve \"%s\": %s\n", dp->bind_addr_name,
	      result);
      return_value = 1;
    }
  }
  else {
    bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  }
  if (dp->track_addr_name && dp->track_addr_name[0] != '\0') {
    const char *result = resolve_hostname(dp->track_addr_name,
					  &track_addr.sin_addr.s_addr);
    if (result) {
      log_err(log, "Could not resolve \"%s\": %s\n", dp->track_addr_name,
	      result);
      return_value = 1;
    }
  }
  else {
    track_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  }
  if (!dp->resolve_ext_addr(true, &bind_addr, log)) {
    return_value = 1;
  }

#ifdef FORK_ENABLE
  if (!dp->child_name) {
    dp->child_name = strdup("./moss_serv");
  }
  if (!dp->child_name) {
    log_err(log, "Cannot allocate memory?!\n");
    return_value = 1;
  }
  if (!dp->check_child_name()) {
    return_value = 1;
  }
#endif
  if (dp->m_do_auth) {
    if (!dp->auth_dir) {
      dp->auth_dir = strdup(".");
    }
    else if (!dp->test_maybe_create_dir(dp->auth_dir, false)) {
      return_value = 1;
    }
  }
  if (dp->m_do_file) {
    if (!dp->file_dir) {
      dp->file_dir = strdup(".");
    }
    else if (!dp->test_maybe_create_dir(dp->file_dir, false)) {
      return_value = 1;
    }
  }
  if (dp->m_do_game) {
    if (!dp->game_dir) {
      dp->game_dir = strdup(".");
    }
    else if (!dp->test_maybe_create_dir(dp->game_dir, false)) {
      return_value = 1;
    }
    try {
      ret = strlen(dp->game_dir)+sizeof("/state");
      temp_str = new char[ret];
      snprintf(temp_str, ret, "%s%sstate", dp->game_dir, PATH_SEPARATOR);
      if (!dp->test_maybe_create_dir(temp_str, true)) {
	return_value = 1;
      }
    }
    catch (const std::bad_alloc&) {
      log_err(log, "Cannot allocate memory at startup!\n");
    }
    if (temp_str) {
      delete[] temp_str;
      temp_str = NULL;
    }
  }
  if (dp->log_dir && !dp->test_maybe_create_dir(dp->log_dir, true)) {
    free(dp->log_dir);
    dp->log_dir = NULL;
  }
  dp->setup_status_str();
  if (return_value == 1) {
    goto early_shutdown;
  }

  /* now spin up everything */

  do_random_seed();

  Logger::init();
  try {
    dp->m_thread_manager = new ThreadManager();
  }
  catch (const std::bad_alloc&) {
    log_err(log, "Cannot allocate memory at startup\n");
    return_value = 1;
    goto shutdown;
  }

  try {
    if (dp->log_dir) {
      size_t len = strlen(dp->log_dir) + sizeof("moss.log") + 2;
      temp_str = new char[len];
      snprintf(temp_str, len, "%s%smoss.log", dp->log_dir, PATH_SEPARATOR);
    }
    log = new Logger("dispatcher",
		     dp->log_dir ? temp_str : "moss.log",
		     Logger::str_to_level(dp->log_level));
    dp->set_logger(log);
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
      goto shutdown;
    }
    else if (pid > 0) {
      // parent
      goto shutdown;
    }
  }
  fd = open(dp->pid_file ? dp->pid_file : "/var/run/moss.pid",
	    O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
  if (fd >= 0) {
    char pid_str[100];
    pid_t pid = getpid();
    snprintf(pid_str, 100, "%u\n", pid);
    // the "if" is to shut up gcc; I don't care if the write fails
    if (write(fd, pid_str, strlen(pid_str))) ;
    close(fd);
  }

  log_info(log, "\n\n        MOSS startup -- the stone stopped rolling\n\n");

  fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (fd < 0) {
    log_err(log, "Error creating listen socket: %s\n", strerror(errno));
    return_value = 1;
    goto shutdown;
  }
  ret = fcntl(fd, F_GETFL, NULL);
  if (fcntl(fd, F_SETFL, ret|O_NONBLOCK)) {
    log_err(log, "Error setting socket nonblocking: %s\n", strerror(errno));
    return_value = 1;
    goto shutdown;
  }
  if (bind(fd, (struct sockaddr *)&bind_addr, sizeof(struct sockaddr_in))) {
    log_err(log, "Error in bind: %s\n", strerror(errno));
    return_value = 1;
    goto shutdown;
  }
  if (listen(fd, 100)) {
    log_err(log, "Error in listen: %s\n", strerror(errno));
    return_value = 1;
    goto shutdown;
  }

  try {
    // Multiple dispatchers could all be listening on 0.0.0.0 which means that
    // their tid/pid is the only distinguishing data in the backend. Use some
    // random data instead if the bind address is INADDR_ANY. This field is
    // just used as an identifier in backend traffic, so using random data is
    // safe.
    uint32_t use_addr = (uint32_t)bind_addr.sin_addr.s_addr;
    if (use_addr == INADDR_ANY) {
      // turn address into 0.x.x.x
      u_char *addrp = (u_char*)&use_addr;
      get_random_data(addrp+1, 3);
    }
    server = new Dispatcher(fd, use_addr, track_addr);
    server->set_logger(log);
    server->set_signal_data(todo, SIGNAL_RESPONSES, dp);
  }
  catch (const std::bad_alloc&) {
    log_err(log, "Cannot allocate memory for backend connection object\n");
    return_value = 1;
    goto shutdown;
  }
#if defined(USING_RSA) || defined(USING_DH)
  if (dp->m_do_auth) {
    if (server->update_keydata(dp->auth_key_file, -1) == NULL) {
      log_warn(log, "Disabling auth service because there is no key\n");
      dp->m_do_auth = 0;
    }
  }
  if (dp->m_do_game) {
    if (server->update_keydata(dp->game_key_file, 0) == NULL) {
      log_warn(log, "Disabling game service because there is no key\n");
      dp->m_do_game = 0;
    }
  }
  if (dp->m_do_gate) {
    if (server->update_keydata(dp->gate_key_file, 1) == NULL) {
      log_warn(log, "Disabling gatekeeper service because there is no key\n");
      dp->m_do_gate = 0;
    }
  }
#endif

  sigemptyset(&sig.sa_mask);
#ifdef FORK_ENABLE
#if 0
  sig.sa_handler = SIG_IGN;
  sig.sa_flags = SA_NOCLDSTOP | SA_NOCLDWAIT; // doesn't work
  if (sigaction(SIGCHLD, &sig, NULL)) {
    log_err(log, "Error setting SIGCHLD to SIG_IGN! (%s)\n", strerror(errno));
  }
#else
  sig.sa_handler = sig_handler;
  sig.sa_flags = SA_NOCLDSTOP;
  if (sigaction(SIGCHLD, &sig, NULL)) {
    log_err(log, "Error setting SIGCHLD handler! (%s)\n", strerror(errno));
  }
#endif
#endif
  sig.sa_handler = SIG_IGN;
  sig.sa_flags = 0;
  if (sigaction(SIGPIPE, &sig, NULL)) {
    log_err(log, "Error setting SIGPIPE to SIG_IGN! (%s)\n", strerror(errno));
  }
  if (sigaction(SIGUSR2, &sig, NULL)) {
    log_err(log, "Error setting SIGUSR2 to SIG_IGN! (%s)\n", strerror(errno));
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
  if (sigaction(SIGQUIT, &sig, NULL)) {
    log_err(log, "Error setting SIGQUIT handler! (%s)\n", strerror(errno));
  }
  // SIGUSR2 is used to bump game servers out of select()
  sig.sa_handler = usr2_handler;
  if (sigaction(SIGUSR2, &sig, NULL)) {
    log_err(log, "Error setting SIGUSR2 handler! (%s)\n", strerror(errno));
  }

  return_value = (long)serv_main((void *)server);
  // we must wait for all child threads to finish before deleting server,
  // because doing so deletes m_common_sdl, which is shared with game servers
  // and then they will try to access freed memory
  dp->m_thread_manager->finish_shutdown();

  delete server;
  log = NULL; // the Logger is deleted by the server

  /* clean shutdown */

 shutdown:
  if (dp->m_thread_manager) {
    delete dp->m_thread_manager;
  }
  if (fd >= 0) {
    close(fd);
  }

  if (log) {
    delete log;
  }
  Logger::shutdown();
  unlink(dp->pid_file ? dp->pid_file : "/var/run/moss.pid");

 early_shutdown:
  if (dp) {
    delete dp;
  }
  if (cfg_file) {
    free(cfg_file);
  }
  return return_value;
}

Server::reason_t DispatcherProcessor::signalled(int *todo, Server *s) {
  Dispatcher *server = (Dispatcher *)s;

    if (todo[SHUTDOWN]) {
      m_thread_manager->start_shutdown();
      todo[SHUTDOWN] = 0;
      return Server::SERVER_SHUTDOWN;
    }
    if (todo[THREAD_JOIN]) {
      todo[THREAD_JOIN] = 0;
      m_thread_manager->thread_join();
    }
#ifdef FORK_ENABLE
    if (todo[CHILD_EXIT]) {
      todo[CHILD_EXIT] = 0;
      m_thread_manager->child_exit();
    }
#endif
    if (todo[RELOAD]) {
#ifdef FORK_ENABLE
      char *old_child = child_name;
      child_name = NULL;
#endif
      char *old_log_level = log_level;
      char *old_auth_level = auth_log_level;
      char *old_file_level = file_log_level;
      char *old_game_level = game_log_level;
      char *old_gate_level = gate_log_level;
      log_level = auth_log_level = file_log_level = game_log_level = NULL;
      gate_log_level = NULL;
      char *old_auth_dir = auth_dir;
      char *old_file_dir = file_dir;
      char *old_game_dir = game_dir;
      auth_dir = file_dir = game_dir = NULL;
      bool old_always_resolve = always_resolve;
      char *old_ext_addr_name = ext_addr_name;
      ext_addr_name = NULL;
      // now re-read file
      m_disp_config.read_config(m_cfg_file, false);

      if (!check_log_level()) {
	if (log_level) {
	  free(log_level);
	}
	log_level = old_log_level;
      }
      else if (old_log_level) {
	free(old_log_level);
      }
      if (!s->log()) {
	// try to create a new logger in the current log_dir
	char *temp_str = NULL;
	try {
	  if (log_dir) {
	    size_t len = strlen(log_dir) + sizeof("moss.log") + 2;
	    temp_str = new char[len];
	    snprintf(temp_str, len, "%s%smoss.log", log_dir, PATH_SEPARATOR);
	  }
	  m_log = new Logger("dispatcher",
			     log_dir ? temp_str : "moss.log",
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
      else {
	s->log()->set_level(Logger::str_to_level(log_level));
      }
      if (!always_resolve && !resolve_ext_addr(true, NULL, m_log)) {
	// Well, they had an address but then reconfigured it to unset. The
	// best thing we can do is keep using the previous address.
      }
      u_char did_game = m_do_game, did_file = m_do_file, did_auth = m_do_auth;
      parse_server_types();
#if defined(USING_RSA) || defined(USING_DH)
      if (m_do_auth) {
	if (server->update_keydata(auth_key_file, -1) == NULL) {
	  // we can't provide useful auth service with no key, so don't try
	  if (did_auth) {
	    log_warn(m_log, "Telling backend we are not running auth service "
		     "any longer because we have no key\n");
	  }
	  m_do_auth = 0;
	}
      }
      if (m_do_game) {
	if (server->update_keydata(game_key_file, 0) == NULL) {
	  // we can't provide useful game service with no key either
	  if (did_game) {
	    log_warn(m_log, "Telling backend we are not running game service "
		     "any longer because we have no key\n");
	  }
	  m_do_game = 0;
	}
      }
      if (m_do_gate) {
	if (server->update_keydata(gate_key_file, 1) == NULL) {
	  // we can't provide useful gatekeeper service with no key either
	  m_do_gate = 0;
	}
      }
#endif
      if ((did_game != m_do_game) || (did_auth != m_do_auth)
	  || (did_file != m_do_file) || (old_always_resolve != always_resolve)
	  || (old_ext_addr_name != ext_addr_name
	      && strcasecmp(old_ext_addr_name ? old_ext_addr_name : "",
			    ext_addr_name ? ext_addr_name : ""))) {
	log_info(m_log, "Sending new service type available msg ( %s%s%s)\n",
		 m_do_game ? "game " : "", m_do_auth ? "auth " : "",
		 m_do_file ? "file " : "");
	server->send_tracking_update(construct_tracking_update(server->id1(),
							       server->id2()));
      }
      if (old_ext_addr_name) {
	free(old_ext_addr_name);
      }
#ifdef FORK_ENABLE
      if (child_name) {
	if (!check_child_name()) {
	  log_warn(m_log, "Falling back to old file %s\n", old_child);
	  free(child_name);
	  child_name = old_child;
	}
	else {
	  // name ok
	  free(old_child);
	}
      }
      else {
	child_name = old_child;
      }
#endif
      if (!check_auth_log_level()) {
	if (auth_log_level) {
	  free(auth_log_level);
	}
	auth_log_level = old_auth_level;
      }
      else if (old_auth_level) {
	free(old_auth_level);
      }
      if (!check_file_log_level()) {
	if (file_log_level) {
	  free(file_log_level);
	}
	file_log_level = old_file_level;
      }
      else if (old_file_level) {
	free(old_file_level);
      }
      if (!check_game_log_level()) {
	if (game_log_level) {
	  free(game_log_level);
	}
	game_log_level = old_game_level;
      }
      else if (old_game_level) {
	free(old_game_level);
      }
      if (!check_gate_log_level()) {
	if (gate_log_level) {
	  free(gate_log_level);
	}
	gate_log_level = old_gate_level;
      }
      else if (old_gate_level) {
	free(old_gate_level);
      }
      // check on presence of auth_dir, file_dir, game_dir
      if (m_do_auth && !test_maybe_create_dir(auth_dir, false)) {
	// if old_auth_dir doesn't exist either then we have no
	// auth directory at all, so might as well just fall back
	if (auth_dir) {
	  free(auth_dir);
	}
	auth_dir = old_auth_dir;
      }
      else if (!auth_dir) {
	auth_dir = old_auth_dir;
      }
      else if (old_auth_dir) {
	free(old_auth_dir);
      }
      if (m_do_file && !test_maybe_create_dir(file_dir, false)) {
	if (file_dir) {
	  free(file_dir);
	}
	file_dir = old_file_dir;
      }
      else if (!file_dir) {
	file_dir = old_file_dir;
      }
      else if (old_file_dir) {
	free(old_file_dir);
      }
      if (m_do_game && !test_maybe_create_dir(game_dir, false)) {
	if (game_dir) {
	  free(game_dir);
	}
	game_dir = old_game_dir;
      }
      else if (!game_dir) {
	game_dir = old_game_dir;
      }
      else if (old_game_dir) {
	free(old_game_dir);
      }
      setup_status_str();
      todo[RELOAD] = 0;
    }
    return Server::NO_SHUTDOWN;
}

TrackServiceTypes_BackendMessage *
DispatcherProcessor::construct_tracking_update(uint32_t id1, uint32_t id2) {
  bool doing_something = (m_do_auth || m_do_file || m_do_game);
  if (always_resolve && doing_something
      && ext_addr_name && strlen(ext_addr_name)) {
    return new TrackServiceTypes_BackendMessage(id1, id2,
						m_do_auth, m_do_file,
						m_do_game, ext_addr_name);
  }
  else {
    return new TrackServiceTypes_BackendMessage(id1, id2,
						m_do_auth, m_do_file,
						m_do_game, m_ext_addr);
  }
}

void Dispatcher::add_client_conn(int fd, u_char type) {
  int ret;
  DispatcherProcessor *dp = (DispatcherProcessor*)m_signal_processor;

	    // dispatch!

	      // Note to self: see signal(7) in NetBSD for list of what can
	      // be done after fork(2) in a threaded program
	      if (type == dp->m_do_auth) {
		log_msgs(m_log, "Connection %d: Auth\n", fd);
#ifdef FORK_ENABLE
		char fdnum[100];
		pid_t pid;
		snprintf(fdnum, 100, "%d", fd);
		pid = fork();
		if (pid == 0) {
		  // child
		  close(m_fd);
		  cleanup_accepted_fds(fd);
		  delete m_log;
		  if (execlp(dp->child_name, "moss_auth",
			     fdnum, dp->m_cfg_file, NULL) < 0) {
		    fprintf(stderr, "exec for auth failed! (%s)\n",
			    strerror(errno));
		    exit(1);
		  }
		}
		else {
		  if (pid == -1) {
		    log_err(m_log, "fork for auth failed! (%s)\n",
			    strerror(errno));
		  }
		  else {
		    dp->m_thread_manager->new_child(pid);
		  }
		  // fd was passed to child process, or fork failed
		  close(fd);
		}
#else
		if (!m_auth_log) {
		  char *temp_str = NULL;
		  try {
		    if (dp->log_dir) {
		      size_t len
			= strlen(dp->log_dir) + sizeof("moss_auth.log") + 2;
		      temp_str = new char[len];
		      snprintf(temp_str, len, "%s/moss_auth.log", dp->log_dir);
		    }
		    m_auth_log = new Logger("auth",
				dp->log_dir ? temp_str : "moss_auth.log",
				Logger::str_to_level(dp->auth_log_level));
		  }
		  catch (const std::bad_alloc&) {
		  }
		  if (temp_str) {
		    delete[] temp_str;
		    temp_str = NULL;
		  }
		}
		// any other common auth infrastructure goes here
		AuthServer *server = NULL;
		try {
		  server = new AuthServer(fd, dp->auth_dir, true,
					  m_track_addr);
		}
		catch (const std::bad_alloc&) {
		  log_err(m_log, "Cannot allocate memory for Auth server\n");
		  log_err(m_log, "Closing connection!\n");
		  close(fd);
		}
		if (server) {
		  pthread_t tid;
		  uint32_t new_id;

		  do {
		    get_random_data((u_char *)&new_id, 4);
		  } while (!dp->m_thread_manager->is_id_available(new_id));
		  server->set_id(new_id);
		  server->setup_logger(fd, dp->auth_log_level, m_auth_log);
#ifdef USING_RSA
		  RSA *rsa = (RSA *)m_auth_keydata;
		  if (rsa) {
		    RSA_up_ref(rsa);
		    server->setkey(m_auth_keydata);
		  }
#endif
#ifdef USING_DH
		  DH *dh = (DH *)m_auth_keydata;
		  if (dh) {
		    DH_up_ref(dh);
		    server->setkey(m_auth_keydata);
		  }
#endif
		  ret = pthread_create(&tid, &m_thread_attr, serv_main,
				       server);
		  if (ret) {
		    log_err(m_log, "Auth pthread_create failed: %s\n",
			    strerror(ret));
		    log_err(m_log, "Closing connection!\n");
		    delete server;
		  }
		  else {
		    dp->m_thread_manager->new_thread(tid, server);
		  }
		}
#endif
	      }
	      else if (type == dp->m_do_file) {
		log_msgs(m_log, "Connection %d: File\n", fd);
#ifdef FORK_ENABLE
		char fdnum[100];
		pid_t pid;
		snprintf(fdnum, 100, "%d", fd);
		pid = fork();
		if (pid == 0) {
		  // child
		  close(m_fd);
		  cleanup_accepted_fds(fd);
		  delete m_log;
		  if (execlp(dp->child_name, "moss_file",
			     fdnum, dp->m_cfg_file, NULL) < 0) {
		    fprintf(stderr, "exec for file failed! (%s)\n",
			    strerror(errno));
		    exit(1);
		  }
		}
		else {
		  if (pid == -1) {
		    log_err(m_log, "fork for file failed! (%s)\n",
			    strerror(errno));
		  }
		  else {
		    dp->m_thread_manager->new_child(pid);
		  }
		  // fd was passed to child process, or fork failed
		  close(fd);
		}
#else
		if (!m_file_log) {
		  char *temp_str = NULL;
		  try {
		    if (dp->log_dir) {
		      size_t len
			= strlen(dp->log_dir) + sizeof("moss_file.log") + 2;
		      temp_str = new char[len];
		      snprintf(temp_str, len, "%s/moss_file.log", dp->log_dir);
		    }
		    m_file_log = new Logger("file",
				dp->log_dir ? temp_str : "moss_file.log",
				Logger::str_to_level(dp->file_log_level));
		  }
		  catch (const std::bad_alloc&) {
		  }
		  if (temp_str) {
		    delete[] temp_str;
		    temp_str = NULL;
		  }
		}
		FileServer *server = NULL;
		try {
		  server = new FileServer(fd, dp->file_dir, true);
		}
		catch (const std::bad_alloc&) {
		  log_err(m_log, "Cannot allocate memory for File server\n");
		  log_err(m_log, "Closing connection!\n");
		  close(fd);
		}
		if (server) {
		  pthread_t tid;
		  uint32_t new_id;

		  do {
		    get_random_data((u_char *)&new_id, 4);
		  } while (!dp->m_thread_manager->is_id_available(new_id));
		  server->set_id(new_id);
		  server->setup_logger(fd, dp->file_log_level, m_file_log);
		  ret = pthread_create(&tid, &m_thread_attr, serv_main,
				       server);
		  if (ret) {
		    log_err(m_log, "File pthread_create failed: %s\n",
			    strerror(ret));
		    log_err(m_log, "Closing connection!\n");
		    delete server;
		  }
		  else {
		    dp->m_thread_manager->new_thread(tid, server);
		  }
		}
#endif
	      }
	      else if (type == dp->m_do_game) {
		// game
		log_msgs(m_log, "Connection %d: Game\n", fd);

		// Since we have to get through negotiation and wait for the
		// JoinAge before we know which game server to pass the
		// connection to, we must keep the connection in the
		// dispatcher. Create a GameConnection object, add it to the
		// dispatcher's list, and set a timeout. We'll just use the
		// same timeout value that we did for receiving this data
		// after the TCP handshake.
		GameServer::GameConnection *conn
		  = new GameServer::GameConnection(fd, m_log);
		m_conns.push_back(conn);
		conn->m_interval = ACCEPTING_TIMEOUT;
		gettimeofday(&conn->m_timeout, NULL);
		conn->m_timeout.tv_sec += conn->m_interval;
	      }
#ifndef OLD_PROTOCOL
	      else if (type == dp->m_do_gate) {
		if (!m_gate_log) {
		  char *temp_str = NULL;
		  try {
		    if (dp->log_dir) {
		      size_t len = strlen(dp->log_dir)
				   + sizeof("moss_gatekeeper.log") + 2;
		      temp_str = new char[len];
		      snprintf(temp_str, len, "%s/moss_gatekeeper.log",
			       dp->log_dir);
		    }
		    m_gate_log = new Logger("gatekeeper",
				dp->log_dir ? temp_str : "moss_gatekeeper.log",
				Logger::str_to_level(dp->gate_log_level));
		  }
		  catch (const std::bad_alloc&) {
		  }
		  if (temp_str) {
		    delete[] temp_str;
		    temp_str = NULL;
		  }
		}
		GatekeeperServer *server = NULL;
		try {
		  server = new GatekeeperServer(fd, NULL, true, m_track_addr);
		}
		catch (const std::bad_alloc&) {
		  log_err(m_log,
			  "Cannot allocate memory for Gatekeeper server\n");
		  log_err(m_log, "Closing connection!\n");
		  close(fd);
		}
		if (server) {
		  pthread_t tid;
		  uint32_t new_id;

		  do {
		    get_random_data((u_char *)&new_id, 4);
		  } while (!dp->m_thread_manager->is_id_available(new_id));
		  server->set_id(new_id);
		  server->setup_logger(fd, dp->gate_log_level, m_gate_log);
#ifdef USING_RSA
		  RSA *rsa = (RSA *)m_gate_keydata;
		  if (rsa) {
		    RSA_up_ref(rsa);
		    server->setkey(m_gate_keydata);
		  }
#endif
#ifdef USING_DH
		  DH *dh = (DH *)m_gate_keydata;
		  if (dh) {
		    DH_up_ref(dh);
		    server->setkey(m_gate_keydata);
		  }
#endif
		  ret = pthread_create(&tid, &m_thread_attr, serv_main,
				       server);
		  if (ret) {
		    log_err(m_log, "Gatekeeper pthread_create failed: %s\n",
			    strerror(ret));
		    log_err(m_log, "Closing connection!\n");
		    delete server;
		  }
		  else {
		    dp->m_thread_manager->new_thread(tid, server);
		  }
		}
	      }
#endif /* !OLD_PROTOCOL */
	      else if (type == dp->m_do_status) {
		// treat as an HTTP GET request, spit out status message
		log_msgs(m_log, "Connection %d: status\n", fd);
		u_int rsz = sizeof("ET /serverstatus/")-1;
		char request[200];
		ret = read(fd, request, 200);
		if (!strncmp(request, "ET /serverstatus/", rsz)
		    && (!strncmp(request+rsz, "urulivelive.php HTTP",
				 sizeof("urulivelive.php HTTP")-1)
			|| !strncmp(request+rsz, "moullive.php HTTP",
				    sizeof("moullive.php HTTP")-1))) {
		  ret = write(fd, http_reply, strlen(http_reply));
		  if (dp->status_str) {
		    ret = write(fd, dp->status_str, dp->status_len);
		  }
		  else {
		    ret = write(fd, "Welcome to MOSS",
				sizeof("Welcome to MOSS"));
		  }
		}
		else {
		  log_warn(m_log, "Connection on %d got a possible GET "
			   "request for a bad URL\n", fd);
		  ret = write(fd, http_404, strlen(http_404)+1);
		}
		// XXX consider shutdown()
		close(fd);
	      }
	      else {
		if (type == TYPE_AUTH) {
		  log_warn(m_log, "Connection on %d requested auth\n", fd);
		}
		else if (type == TYPE_FILE) {
		  log_warn(m_log, "Connection on %d requested file\n", fd);
		}
		else if (type == TYPE_GAME) {
		  log_warn(m_log, "Connection on %d requested game\n", fd);
		}
		else if (type == TYPE_GATEKEEPER) {
		  log_warn(m_log, "Connection on %d requested gatekeeper\n",
			   fd);
		}
		else {
		  log_warn(m_log, "Connection on %d requested unknown "
			   "type %u\n", fd, (unsigned int)type);
		}
		close(fd);
	      }
}

int Dispatcher::init() {
  // set up vault/tracking server connection
  m_track = new BackendConnection();
  m_track->m_interval = 0;
  if (do_connect()) {
    delete m_track;
    m_track = NULL;
    return -1;
  }
  m_conns.push_back(m_track);
  return 0;
}

int Dispatcher::do_connect() {
  m_track->set_in_connect(false);
  m_track->set_fd(socket(PF_INET, SOCK_STREAM, IPPROTO_TCP));
  if (m_track->fd() < 0) {
    log_err(m_log, "Error in socket(): %s\n", strerror(errno));
    return -1;
  }
  int flags = fcntl(m_track->fd(), F_GETFL, NULL);
  if (fcntl(m_track->fd(), F_SETFL, flags|O_NONBLOCK)) {
    log_err(m_log, "Error setting socket nonblocking: %s\n", strerror(errno));
    return -1;
  }
  if (connect(m_track->fd(),
	      (struct sockaddr *)&m_track_addr, sizeof(struct sockaddr_in))) {
    if (errno == EINPROGRESS) {
      m_track->set_in_connect(true);
    }
    else {
      log_err(m_log, "Error in connect(): %s\n", strerror(errno));
      return -1;
    }
  }
  else {
    // make sure to send hello
    conn_completed(m_track);
  }

  return 0;
}

void * Dispatcher::update_keydata(const char *fname, int auth_game_gate) {
  const char *use_file;
  void **keydata;
  if (auth_game_gate < 0) {
    use_file = DEFAULT_AUTH_KEY;
    keydata = &m_auth_keydata;
  }
  else if (auth_game_gate == 0) {
    use_file = DEFAULT_GAME_KEY;
    keydata = &m_game_keydata;
  }
  else {
    use_file = DEFAULT_GATE_KEY;
    keydata = &m_gate_keydata;
  }
  if (fname && fname[0] != '\0') {
    use_file = fname;
  }

  void *newkey = read_keyfile(use_file, m_log);
  if (newkey) {
    if ((*keydata) != NULL) {
#ifdef USING_RSA
      RSA *rsa = (RSA *)(*keydata);
      RSA_free(rsa);
#endif
#ifdef USING_DH
      DH *dh = (DH *)(*keydata);
      DH_free(dh);
#endif
    }
    *keydata = newkey;
  }
  // if !newkey, keep what we currently have (which could well be NULL too)
  return *keydata;
}

void Dispatcher::conn_completed(Connection *conn) {
  conn->set_in_connect(false);
  if (conn == m_track) {
    m_retry = false;
    conn->m_interval = BACKEND_KEEPALIVE_INTERVAL;
    gettimeofday(&conn->m_timeout, NULL);
    conn->m_timeout.tv_sec += conn->m_interval;

    log_msgs(m_log, "Sending Hello to backend\n");
    Hello_BackendMessage *msg = new Hello_BackendMessage(m_ipaddr, m_id,
							 type());
    conn->enqueue(msg, MessageQueue::FRONT);

    DispatcherProcessor *dp = (DispatcherProcessor*)m_signal_processor;
    if (dp->m_do_game || dp->m_do_auth || dp->m_do_file) {
      send_tracking_update(dp->construct_tracking_update(m_ipaddr, m_id));
    }
  }
  else {
    log_err(m_log, "Unknown outgoing connection (fd %d) completed!",
	    conn->fd());
  }
}

Server::reason_t Dispatcher::message_read(Connection *conn,
					  NetworkMessage *msg) {
  int msg_type = msg->type();
  Server::reason_t result = NO_SHUTDOWN;

  if (conn == m_track) {
    if (msg_type == -1) {
      // unrecognized message
      log_err(m_log, "Unrecognized backend message!\n");
      if (m_log) {
	m_log->dump_contents(Logger::LOG_ERR, msg->buffer(),
			     msg->message_len());
      }
    }
    else {
      switch (msg_type) {
      case (ADMIN_HELLO|FROM_SERVER):
	{
	  Hello_BackendMessage *hello = (Hello_BackendMessage *)msg;
	  log_msgs(m_log, "Backend connection protocol version %u\n",
		   hello->peer_info());
	  // no more required at this time (all speak version 0)
	}
	break;
      case (TRACK_START_GAME|FROM_SERVER):
	{
	  TrackStartAge_FromBackendMessage *request
	    = (TrackStartAge_FromBackendMessage *)msg;

	  // see if we are allowed to do that
	  DispatcherProcessor *dp
	    = (DispatcherProcessor*)m_signal_processor;
	  if (!dp->m_do_game) {
	    log_warn(m_log, "Received a request to start a game server but "
		     "we should not be registered to do so\n");
	    TrackStartAge_ToBackendMessage *reject =
	      new TrackStartAge_ToBackendMessage(m_ipaddr, m_id,
				request->age_uuid(),
				TrackStartAge_ToBackendMessage::NOT_ALLOWED);
	    conn->enqueue(reject);
	    break;
	  }

	  if (m_log && m_log->would_log_at(Logger::LOG_MSGS)) {
	    char uuid[UUID_STR_LEN];
	    format_uuid(request->age_uuid(), uuid);
	    log_msgs(m_log, "TRACK_START_GAME %s (%s)\n",
		     request->filename()->c_str(), uuid);
	  }
#ifndef FORK_GAME_TOO
	  // read in the common SDL if necessary
	  if (m_common_sdl.size() == 0) {
	    std::string directory(dp->game_dir);
	    directory = directory + PATH_SEPARATOR + "SDL"
			+ PATH_SEPARATOR + "common";
	    if (SDLDesc::parse_directory(m_log, m_common_sdl,
					 directory, true, true)) {
#ifndef STANDALONE
	      m_common_sdl.clear();
	      // can't actually start up a game server
	      log_err(m_log, "Cannot read common SDL\n");
	      log_info(m_log,
		       "Telling backend we cannot create new game servers "
		       "(reload config after fixing problem to start "
		       "accepting new server requests again)\n");
	      dp->m_do_game = 0;
	      send_tracking_update(dp->construct_tracking_update(m_ipaddr,
								 m_id));
	      char uuid[UUID_STR_LEN];
	      format_uuid(request->age_uuid(), uuid);
	      log_warn(m_log,
		       "Rejecting request for new game server UUID %s\n",
		       uuid);
	      TrackStartAge_ToBackendMessage *reject =
		new TrackStartAge_ToBackendMessage(m_ipaddr, m_id,
				request->age_uuid(),
				TrackStartAge_ToBackendMessage::NO_SDL);
	      conn->enqueue(reject);
	      break;
#else
	      // forge on (but if we can't read the age's SDL either some
	      // game mechanics will break)
#endif /* !STANDALONE */
	    }
	  }

	  // read in the .age file
	  AgeDesc *newage = NULL;
	  {
	    std::string fname(dp->game_dir);
	    fname = fname + PATH_SEPARATOR + "age" + PATH_SEPARATOR
		    + request->filename()->c_str() + ".age";
	    std::ifstream file(fname.c_str(), std::ios_base::in);
	    if (file.fail()) {
	      log_warn(m_log, "Request for unavailable age %s\n",
		       request->filename()->c_str());
	    }
	    else {
	      try {
		newage = AgeDesc::parse_file(file);
	      }
	      catch (const parse_error &e) {
		log_err(m_log, "Parse error in %s.age, line %u: %s\n",
			request->filename()->c_str(), e.lineno(), e.what());
		
	      }
	    }
	  }
	  if (!newage) {
	    TrackStartAge_ToBackendMessage *reject =
	      new TrackStartAge_ToBackendMessage(m_ipaddr, m_id,
				request->age_uuid(),
				TrackStartAge_ToBackendMessage::NO_AGE);
	    conn->enqueue(reject);
	    break;
	  }
#else
	  // just make sure we aren't going to try to start an age with
	  // an empty string for a name -- the forked server will load
	  // the .age file and SDL files and let us know if there's a problem
	  if (request->filename()->send_len(false, false, false) == 0) {
	    TrackStartAge_ToBackendMessage *reject =
	      new TrackStartAge_ToBackendMessage(m_ipaddr, m_id,
				request->age_uuid(),
				TrackStartAge_ToBackendMessage::NO_AGE);
	    conn->enqueue(reject);
	    break;
	  }
#endif /* !FORK_GAME_TOO */

	  // resolve the address if necessary
	  if (dp->always_resolve) {
	    if (!dp->resolve_ext_addr(false, NULL, m_log) 
		&& m_log->would_log_at(Logger::LOG_WARN)) {
	      char addr[INET_ADDRSTRLEN];
	      if (inet_ntop(AF_INET, &dp->m_ext_addr, addr, INET_ADDRSTRLEN)) {
		log_warn(m_log, "Using old external address %s\n", addr);
	      }
	      else {
		log_warn(m_log, "Using old external address 0x%08x\n",
			 dp->m_ext_addr);
	      }
	    }
	  }

	  uint32_t new_id;
	  do {
	    get_random_data((u_char *)&new_id, 4);
	  } while (!dp->m_thread_manager->is_id_available(new_id));
#ifdef FORK_GAME_TOO
	  // set up sockets for new game server
	  int sockets[2];
	  if (socketpair(PF_LOCAL, SOCK_DGRAM, PF_UNSPEC, sockets) < 0) {
	    log_err(m_log, "Cannot create socket pair for game server\n");
	    TrackStartAge_ToBackendMessage *reject =
	      new TrackStartAge_ToBackendMessage(m_ipaddr, m_id,
				request->age_uuid(),
				TrackStartAge_ToBackendMessage::NO_RESOURCE);
	    conn->enqueue(reject);
	    break;
	  }
	  // set up connection to new game server
	  int sflags = fcntl(sockets[0], F_GETFL, NULL);
	  if (fcntl(sockets[0], F_SETFL, sflags|O_NONBLOCK)) {
	    log_err(m_log, "Error setting socket nonblocking: %s\n",
		    strerror(errno));
	  }
	  GameServer::DispatcherConnection *game_conn
	    = new GameServer::DispatcherConnection(sockets[0], m_log,
						   sockets[1]);
#else
	  // set up new game server thread
	  GameServer *server = NULL;
	  try {
	    server = new GameServer(dp->game_dir, true, m_track_addr,
				    request->age_uuid(),
				    request->filename()->c_str(),
				    dp->m_ext_addr,
				    newage, m_common_sdl);
	  }
	  catch (const std::bad_alloc&) {
	    log_err(m_log, "Cannot allocate memory for Game server\n");
	    TrackStartAge_ToBackendMessage *reject =
	      new TrackStartAge_ToBackendMessage(m_ipaddr, m_id,
				request->age_uuid(),
				TrackStartAge_ToBackendMessage::NO_RESOURCE);
	    conn->enqueue(reject);
	    delete newage;
	    break;
	  }
	  server->set_id(new_id);
#endif

	  size_t len = sizeof("game///.log") + UUID_STR_LEN;
	  len += dp->log_dir ? strlen(dp->log_dir) + 1 : 2;
	  len += request->filename()->send_len(false, false, false);
	  char temp_str[len];
	  snprintf(temp_str, len, "%s%sgame%s%s",
		   dp->log_dir ? dp->log_dir : ".", PATH_SEPARATOR,
		   PATH_SEPARATOR, request->filename()->c_str());
	  if (recursive_mkdir(temp_str, S_IRWXU|S_IRWXG)) {
	    log_warn(m_log, "Cannot create game server log directory %s: %s\n",
		     temp_str, strerror(errno));
	  }
	  else {
	    len = strlen(temp_str);
	    temp_str[len++] = PATH_SEPARATOR[0];
	    format_uuid(request->age_uuid(), temp_str+len);
	    strcat(temp_str, ".log");
#ifndef FORK_GAME_TOO
	    try {
	      Logger *game_log
		= new Logger("game", temp_str,
			     Logger::str_to_level(dp->game_log_level));
	      server->set_logger(game_log);
	    }
	    catch (const std::bad_alloc&) {
	    }
#endif
	  }

#ifdef FORK_GAME_TOO
	  char fdnum[100], idstr[100];
	  pid_t pid;
	  snprintf(fdnum, 100, "%u", sockets[1]);
	  snprintf(idstr, 100, "%u", new_id);
	  pid = fork();
	  if (pid == 0) {
	    // child
	    close(m_fd);
	    cleanup_accepted_fds(fd);
	    delete m_log;
	    if (execlp(dp->child_name, request->filename()->c_str(),
		       fdnum, idstr, dp->m_cfg_file, NULL) < 0) {
	      fprintf(stderr, "exec for game failed! (%s)\n", strerror(errno));
	      exit(1);
	    }
	  }
	  else {
	    if (pid == -1) {
	      log_err(m_log, "fork for game failed! (%s)\n", strerror(errno));
	      delete game_conn;
	      TrackStartAge_ToBackendMessage *reject =
		new TrackStartAge_ToBackendMessage(m_ipaddr, m_id,
				request->age_uuid(),
				TrackStartAge_ToBackendMessage::NO_RESOURCE);
	      conn->enqueue(reject);
	      break;
	    }
	    else {
	      // now wait to hear from the child
	      dp->m_thread_manager->new_child(pid, game_conn);
	      // XXX need timeout
	      m_conns.push_back(game_conn);
	    }
	  }
#else
	  // now actually make and start the thread
	  pthread_t tid;

	  int ret = pthread_create(&tid, &m_thread_attr, serv_main, server);
	  if (ret) {
	    log_err(m_log, "Game pthread_create failed: %s\n",
		    strerror(ret));
	    delete server;
	    TrackStartAge_ToBackendMessage *reject =
	      new TrackStartAge_ToBackendMessage(m_ipaddr, m_id,
				request->age_uuid(),
				TrackStartAge_ToBackendMessage::NO_RESOURCE);
	    conn->enqueue(reject);
	    break;
	  }
	  else {
	    dp->m_thread_manager->new_thread(tid, server, new_id);
	  }
#endif
	}
	break;
      default:
	log_err(m_log, "Unknown message type 0x%08x\n", msg_type);
      }
    }
  }
  else {
    // it's a nascent game server connection
    GameServer::GameConnection *gconn = (GameServer::GameConnection *)conn;
    uint32_t sid;
    result = GameServer::handle_negotiation(gconn, m_game_keydata,
					    msg, m_log, sid);
    if (gconn->state() == GameServer::JOIN_REQ) {
      DispatcherProcessor *dp = (DispatcherProcessor*)m_signal_processor;
#ifdef FORK_GAME_TOO
      GameServer::DispatcherConnection *who
	= (GameServer::DispatcherConnection *)
	  dp->m_thread_manager->get_server_from_id(sid);
#else
      GameServer *who
	= (GameServer *)
	  dp->m_thread_manager->get_server_from_id(sid);
#endif
      if (!who) {
	GameServer::send_no_join(conn, msg);
      }
      else {
#ifdef FORK_GAME_TOO
	// NOTE: if the client sends anything after the JoinAge and it
	// arrives in the same read as the JoinAge, we have to also forward
	// the remaining data that is in the read buffer.
	who->forward_conn(gconn);
	// take the connection out of the dispatcher's list; the
	// DispatcherConnection will delete it when handoff is complete
	m_conns.remove(conn);
#else
#ifdef DEBUG_ENABLE
	if (!msg->persistable()) {
	  // this message refers to memory that may be freed or overwritten!
	  throw std::logic_error("Message not marked as persistable "
				 "has been saved");
	}
#endif
	who->queue_client_connection(gconn, msg);
	// now that the connection is passed on, take it out of the
	// dispatcher's list
	m_conns.remove(conn);
	// and wake up the game server
	dp->m_thread_manager->signal_thread(who, SIGUSR2);
	// since we don't want to delete the message yet, and we need to
	// tell the select loop that a different thread owns conn, return now
	return Server::FORGET_THIS_CONNECTION;
#endif
      }
    }
  }
  delete msg;
  return result;
}

Server::reason_t Dispatcher::conn_timeout(Connection *conn, reason_t why) {
  if (conn == m_track) {
    TrackPing_BackendMessage *msg
      = new TrackPing_BackendMessage(m_ipaddr, m_id);
    conn->enqueue(msg);
    conn->m_timeout.tv_sec += conn->m_interval;
    return NO_SHUTDOWN;
  }
  else {
    return conn_shutdown(conn, why);
  }
}

Server::reason_t Dispatcher::conn_shutdown(Connection *conn, reason_t why) {
  if (conn == m_track) {
    if (m_retry) {
      // the connection failed and then we failed to connect(), so give up
      close(conn->fd());
      conn->set_fd(-1);
      return BACKEND_ERROR;
    }
    else {
      m_retry = true;
      m_track->m_write_fill = 0;
      m_track->msg_queue()->reset_head();
      close(conn->fd());
      if (do_connect()) {
	close(conn->fd());
	conn->set_fd(-1);
	return BACKEND_ERROR;
      }
    }
  }
  else {
    // incomplete game server connection
    if (why == CLIENT_TIMEOUT) {
      log_debug(m_log, "Incomplete game server connection (fd %d) timed out\n",
		conn->fd());
    }
    else {
      log_warn(m_log, "Shutting down incomplete game server connection (fd %d)"
	       " for reason %s\n", conn->fd(), Server::reason_to_string(why));
    }
    // remove connection from list and mercilessly delete it
    for (std::list<Connection*>::iterator
	   c_iter = m_conns.begin(); c_iter != m_conns.end(); c_iter++) {
      Connection *c = *c_iter;
      if (conn == c) {
#ifdef FORK_GAME_TOO
	// deleted in ThreadManager::child_exit() XXX confirm
#else
	delete c;
#endif
	m_conns.erase(c_iter);
	break;
      }
    }
  }
  return NO_SHUTDOWN;
}

Dispatcher::~Dispatcher() {
#ifndef FORK_ENABLE
  if (m_file_log) {
    delete m_file_log;
  }
  if (m_auth_log) {
    delete m_auth_log;
  }
#endif
  if (m_gate_log) {
    delete m_gate_log;
  }
  if (m_auth_keydata) {
#ifdef USING_RSA
    RSA *rsa = (RSA *)(m_auth_keydata);
    RSA_free(rsa);
#endif
#ifdef USING_DH
    DH *dh = (DH *)(m_auth_keydata);
    DH_free(dh);
#endif
  }
  if (m_game_keydata) {
#ifdef USING_RSA
    RSA *rsa = (RSA *)(m_game_keydata);
    RSA_free(rsa);
#endif
#ifdef USING_DH
    DH *dh = (DH *)(m_game_keydata);
    DH_free(dh);
#endif
  }
  if (m_gate_keydata) {
#ifdef USING_RSA
    RSA *rsa = (RSA *)(m_gate_keydata);
    RSA_free(rsa);
#endif
#ifdef USING_DH
    DH *dh = (DH *)(m_gate_keydata);
    DH_free(dh);
#endif
  }

  for (std::list<SDLDesc*>::iterator
	 iter = m_common_sdl.begin(); iter != m_common_sdl.end(); iter++) {
    SDLDesc *sdl = *iter;
    delete sdl;
  }
  pthread_attr_destroy(&m_thread_attr);
}

DispatcherProcessor::~DispatcherProcessor() {
  if (bind_addr_name) {
    free(bind_addr_name);
  }
  if (track_addr_name) {
    free(track_addr_name);
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
  if (server_types) {
    free(server_types);
  }
  if (ext_addr_name) {
    free(ext_addr_name);
  }
  if (child_name) {
    free(child_name);
  }
  if (auth_dir) {
    free(auth_dir);
  }
  if (file_dir) {
    free(file_dir);
  }
  if (game_dir) {
    free(game_dir);
  }
  if (auth_log_level) {
    free(auth_log_level);
  }
  if (file_log_level) {
    free(file_log_level);
  }
  if (game_log_level) {
    free(game_log_level);
  }
  if (gate_log_level) {
    free(gate_log_level);
  }
  if (game_addr_name) {
    free(game_addr_name);
  }
  if (auth_key_file) {
    free(auth_key_file);
  }
  if (game_key_file) {
    free(game_key_file);
  }
  if (gate_key_file) {
    free(gate_key_file);
  }
  if (status_str) {
    free(status_str);
  }
}

bool DispatcherProcessor::parse_server_types() {
  u_int count;
  bool return_value = true;

  if (!server_types) {
    log_err(m_log, "At least one server_type must be specified\n");
    return false;
  }    
  char **s_types = ConfigParser::split_string(server_types, &count);
  if (!s_types) {
    log_err(m_log, "Can't allocate memory!\n");
    return false;
  }

  u_char auth = 0, file = 0, game = 0, gate = 0, status = 0;
  for (u_int i = 0; i < count; i++) {
    if (!strcasecmp(s_types[i], "auth")) {
      auth = TYPE_AUTH;
    }
    else if (!strcasecmp(s_types[i], "file")) {
      file = TYPE_FILE;
    }
    else if (!strcasecmp(s_types[i], "game")) {
      game = TYPE_GAME;
    }
    else if (!strcasecmp(s_types[i], "gatekeeper")) {
      gate = TYPE_GATEKEEPER;
    }
    else if (!strcasecmp(s_types[i], "status")) {
      status = 'G';
    }
    else {
      log_err(m_log, "Invalid server_type: %s\n", s_types[i]);
      return_value = false;
    }
    free(s_types[i]);
  }
  free(s_types);
  if (!(auth + file + game + gate + status)) {
    log_err(m_log, "At least one server_type must be specified\n");
    return_value = false;
  }
  if (return_value) {
    m_do_auth = auth;
    m_do_file = file;
    m_do_game = game;
#ifndef OLD_PROTOCOL
    m_do_gate = gate;
#else
    // automatically disable the gatekeeper if using an older protocol version
    m_do_gate = 0;
#endif
    m_do_status = status;
  }
  return return_value;
}
