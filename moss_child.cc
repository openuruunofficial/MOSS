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
 * This file contains a wrapper main() function for standalone forked
 * versions of the auth, game, and file servers. It decides which you wanted
 * based on argv[0], which is set by the dispatcher (main server component)
 * when starting up the new process.
 *
 * All that is done in this file is to set up what is set up differently
 * when these servers are new processes instead of new threads before
 * calling the same entry point as the threaded versions.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <stdarg.h>
#include <pthread.h>
#include <signal.h>
#include <iconv.h>

#include <sys/stat.h>
#include <sys/time.h>

#include <arpa/inet.h> /* for ntohl() and friends */
#include <netinet/in.h>

#include <exception>
#include <stdexcept>
#include <deque>
#include <list>
#include <vector>

#ifdef HAVE_OPENSSL
#include <openssl/rc4.h>
#else
#include "rc4.h"
#endif

#include "machine_arch.h"
#include "exceptions.h"
#include "constants.h"
#include "protocol.h"
#include "util.h"
#include "UruString.h"
#include "Buffer.h"

#include "Logger.h"
#include "ConfigParser.h"
#include "FileTransaction.h"
#include "NetworkMessage.h"
#include "MessageQueue.h"
#include "BackendMessage.h"

#include "moss_serv.h"
#include "AuthServer.h"
#include "FileMessage.h"
#include "FileServer.h"
#ifdef FORK_GAME_TOO
#include "SDL.h"
#include "GameMessage.h"
#include "GameState.h"
#endif

#ifdef FORK_GAME_TOO
static const char *usage = "moss_auth|moss_file|agename "
			   "<file no> <config file>\n";
#else
static const char *usage = "moss_auth|moss_file <file no> <config file>\n";
#endif

#define SHUTDOWN 0
#define SIGNAL_RESPONSES 1
static int todo[SIGNAL_RESPONSES] = { 0 };
static void sig_handler(int sig) {
  if (sig == SIGTERM || sig == SIGINT) {
    todo[SHUTDOWN] = 1;
  }
}

class ShutdownProcessor : public Server::SignalProcessor {
public:
  Server::reason_t signalled(int *todo, Server *s) {
    return Server::SERVER_SHUTDOWN;
  }  
};

int main(int argc, char *argv[]) {
  int fd;
  long ret;
  struct sockaddr_in vault_addr;

  if (argc != 3) {
    fprintf(stderr, "%s", usage);
    return 1;
  }
  if (sscanf(argv[1], "%d", &fd) != 1) {
    fprintf(stderr, "%s", usage);
    return 1;
  }
#ifndef FORK_GAME_TOO
  if (strcmp(argv[0], "moss_auth") && strcmp(argv[0], "moss_file")) {
    fprintf(stderr, "%s", usage);
    return 1;
  }
#endif

  //kill(getpid(), SIGSTOP);

  bool is_auth = strcmp(argv[0], "moss_auth") ? false : true;
  bool is_game = is_auth || !strcmp(argv[0], "moss_file") ? false : true;

  /* configuration controls */

  char *vault_addr_name, *log_dir, *log_level, *auth_dir, *file_dir, *game_dir,
    *auth_key_file, *game_key_file;
  int vault_port;
  vault_addr_name = log_dir = log_level = auth_dir = file_dir = game_dir
    = auth_key_file = NULL;
  ConfigParser *disp_config = new ConfigParser();

  if (is_auth || is_game) {
    disp_config->register_config("vault_address", &vault_addr_name, "");
    disp_config->register_config("vault_port", &vault_port, 14618);
  }
  disp_config->register_config("log_dir", &log_dir, "log");
  if (is_auth) {
    disp_config->register_config("auth_log_level", &log_level, "NET");
    disp_config->register_config("auth_download_dir", &auth_dir, "auth");
    disp_config->register_config("auth_key_file", &auth_key_file,
				 "./auth_key.der");
  }
  else if (is_game) {
    disp_config->register_config("game_log_level", &log_level, "NET");
    disp_config->register_config("game_data_dir", &game_dir, "auth");
    disp_config->register_config("game_key_file", &game_key_file,
				 "./game_key.der");
  }
  else {
    disp_config->register_config("file_log_level", &log_level, "NET");
    disp_config->register_config("file_download_dir", &file_dir, "file");
  }

  try {
    disp_config->read_config(argv[2], false);
  }
  catch (const parse_error &e) {
    fprintf(stderr, "Error reading config file %s line %u: %s\n",
	    argv[2], e.lineno(), e.what());
  }

  delete disp_config;

  /* check validity of config */

  memset(&vault_addr, 0, sizeof(struct sockaddr_in));
  vault_addr.sin_family = PF_INET;

  if (is_auth || is_game) {
    if (vault_port > 65535 || vault_port < 1) {
      fprintf(stderr, "Invalid vault_port: %d\n", vault_port);
      return 1;
    }
    vault_addr.sin_port = (uint16_t)htons(vault_port);
    if (vault_addr_name && vault_addr_name[0] != '\0') {
      const char *result = resolve_hostname(vault_addr_name,
					    &vault_addr.sin_addr.s_addr);
      if (result) {
	fprintf(stderr, "Could not resolve \"%s\": %s", vault_addr_name,
		result);
	return 1;
      }
    }
    else {
      vault_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    }
  }

  if (Logger::str_to_level(log_level) == Logger::NONE) {
    fprintf(stderr, "Invalid log_level: %s\n", log_level);
    free(log_level);
    log_level = strdup("debug");
  }

  if ((is_auth && auth_dir) || (!is_auth && !is_game && file_dir)
      || (is_game && game_dir)) {
    struct stat s;
    const char *dir = (is_auth ? auth_dir : (is_game ? game_dir : file_dir));
    ret = stat(dir, &s);
    if (ret < 0) {
      fprintf(stderr, "Required directory %s does not exist\n", dir);
      return 1;
    }
    else if (!(S_ISDIR(s.st_mode))) {
      fprintf(stderr, "%s is not a directory\n", dir);
      return 1;
    }
  }
  else if (is_auth) {
    auth_dir = strdup(".");
  }
  else if (is_game) {
    game_dir = strdup(".");
  }
  else {
    file_dir = strdup(".");
  }

  /* start up */

  do_random_seed();

  Server *server = NULL;
  ShutdownProcessor *processor = NULL;
  Logger::init();

  try {
    if (is_auth) {
      server = new AuthServer(fd, auth_dir, false, vault_addr);
#if defined(USING_RSA) || defined(USING_DH)
      const char *use_file = "./auth_key.der";
      if (auth_key_file && auth_key_file[0] != '\0') {
	use_file = auth_key_file;
      }

      void *newkey = Server::read_keyfile(use_file, NULL);
      if (newkey) {
	((AuthServer*)server)->setkey(newkey);
      }
#endif
    }
#ifdef FORK_GAME_TOO
    else if (is_game) {
      server = new GameServer(fd, game_dir, false, vault_addr);
    }
#endif
    else {
      server = new FileServer(fd, file_dir, false);
    }
    processor = new ShutdownProcessor();
  }
  catch (const std::bad_alloc &) {
    fprintf(stderr, "Could not allocate memory initializing server!\n");
    return 1;
  }
  server->setup_logger(fd, log_level, log_dir ? log_dir : "log");
  server->set_signal_data(todo, SIGNAL_RESPONSES, processor);

  struct sigaction sig;
  sig.sa_flags = 0;
  sigemptyset(&sig.sa_mask);
  sig.sa_handler = SIG_IGN;
  if (sigaction(SIGPIPE, &sig, NULL)) {
    log_err(server->log(),
	    "Error setting SIGPIPE to SIG_IGN! (%s)\n", strerror(errno));
  }
  if (sigaction(SIGHUP, &sig, NULL)) {
    // we don't have config reload, so just ignore the signal
    log_err(server->log(),
	    "Error setting SIGHUP to SIG_IGN! (%s)\n", strerror(errno));
  }
  sig.sa_handler = sig_handler;
  if (sigaction(SIGTERM, &sig, NULL)) {
    log_err(server->log(),
	    "Error setting SIGTERM handler! (%s)\n", strerror(errno));
  }
  if (sigaction(SIGINT, &sig, NULL)) {
    log_err(server->log(),
	    "Error setting SIGINT handler! (%s)\n", strerror(errno));
  }

  ret = (long)serv_main(server);

  delete server;
  delete processor;
  if (vault_addr_name) {
    free(vault_addr_name);
  }
  if (log_dir) {
    free(log_dir);
  }
  if (log_level) {
    free(log_level);
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
  if (auth_key_file) {
    free(auth_key_file);
  }
  if (game_key_file) {
    free(game_key_file);
  }
  return ret;
}
