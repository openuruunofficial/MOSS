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
 * This is the main loop for each connection, be it a thread or a separate
 * child process. It handles select, read, and write for the file
 * descriptors required, and then uses callbacks into the Server to handle
 * data having been read. All the useful state of the connection is stored
 * as part of the Server.
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
#ifdef HAVE_ASSERT_H
#include <assert.h>
#endif

#include <stdarg.h>
#include <pthread.h>
#include <signal.h>
#include <iconv.h>

#include <sys/socket.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/uio.h> /* for struct iovec */

#include <arpa/inet.h> /* for ntohl() and friends */
#include <netinet/in.h>

#include <exception>
#include <stdexcept>
#include <deque>
#include <list>
#include <vector>
#include <algorithm> /* for heap */

#ifdef HAVE_OPENSSL
#include <openssl/rc4.h>
#include <openssl/rand.h>
#ifdef USING_RSA
#include <openssl/rsa.h>
#include <openssl/x509.h>
#endif
#ifdef USING_DH
#include <openssl/dh.h>
#include <openssl/asn1t.h>
#endif
#else
#include "rc4.h"
#if defined(USING_RSA) || defined(USING_DH)
#error OpenSSL is required to use RSA or D-H!
#endif
#endif

#include "machine_arch.h"
#include "exceptions.h"
#include "constants.h"
#include "protocol.h"
#include "util.h"
#include "UruString.h"
#include "Buffer.h"

#include "Logger.h"
#include "NetworkMessage.h"
#include "BackendMessage.h"
#include "MessageQueue.h"

#include "moss_serv.h"

void Server::internal_setup_logger(int conn_fd, const char *log_level,
				   Logger *to_share, const char *log_dir) {
  struct sockaddr_in him, me;
  socklen_t himlen, melen;
  uint32_t himaddr, meaddr;
  int himport, meport, peername_err, sockname_err;

  if (!m_is_child) {
    throw std::logic_error("Server::setup_logger called for non-child server");
  }
  Logger::level_t level = Logger::str_to_level(log_level);

  himlen = melen = sizeof(struct sockaddr_in);
  peername_err = sockname_err = 0;
  if (getpeername(conn_fd, (struct sockaddr *)&him, &himlen)) {
    peername_err = errno;
    // shut up compiler
    himport = 0;
    himaddr = 0;
  }
  else {
    himport = ntohs(him.sin_port);
    himaddr = ntohl(him.sin_addr.s_addr);
  }
  if (getsockname(conn_fd, (struct sockaddr *)&me, &melen)) {
    sockname_err = errno;
    m_ipaddr = 0;
    // shut up compiler
    meport = 0;
    meaddr = 0;
  }
  else {
    meport = ntohs(me.sin_port);
    meaddr = ntohl(me.sin_addr.s_addr);
    m_ipaddr = me.sin_addr.s_addr;
  }

  char sys_str[100];
  snprintf(sys_str, 100, "%s.%x:%s%u", type_name(),
	   peername_err ? 0 : himaddr, peername_err ? "error " : "",
	   peername_err ? peername_err : himport);

  if (to_share) {
    m_log = new Logger(sys_str, to_share, level);
  }
  else {
    size_t len = strlen(log_dir) + 100;
    char *temp_str = new char[len];
    snprintf(temp_str, len, "%s/%s.%x:%s%u.log", log_dir, type_name(),
	     peername_err ? 0 : himaddr, peername_err ? "error" : "",
	     peername_err ? peername_err : himport);
    m_log = new Logger(type_name(), temp_str, level);
    delete[] temp_str;
  }

  // log about the connection

  if (peername_err && peername_err != ENOTCONN) {
    log_warn(m_log, "Error in getpeername: %s\n",
	     strerror(peername_err));
  }
  if (sockname_err) {
    log_warn(m_log, "Error in getsockname: %s\n",
	     strerror(sockname_err));
  }
  if (!peername_err && !sockname_err) {
    log_debug(m_log, "Connection: (client) %u.%u.%u.%u:%u <->"
	      " %u.%u.%u.%u:%u (server)\n", 
	      himaddr >> 24, (himaddr >> 16) & 0xFF, (himaddr >> 8) & 0xFF,
	      himaddr & 0xFF, ntohs(him.sin_port),
	      meaddr >> 24, (meaddr >> 16) & 0xFF, (meaddr >> 8) & 0xFF,
	      meaddr & 0xFF, ntohs(me.sin_port));
  }
  else if (peername_err && !sockname_err) {
    log_debug(m_log, "%sConnection: (client) unknown <->"
	      " %u.%u.%u.%u:%u (server)\n", 
	      peername_err == ENOTCONN ? "DEAD " : "",
	      meaddr >> 24, (meaddr >> 16) & 0xFF, (meaddr >> 8) & 0xFF,
	      meaddr & 0xFF, ntohs(me.sin_port));
  }
  else if (sockname_err && !peername_err) {
    log_debug(m_log, "Connection: (client) %u.%u.%u.%u:%u <->"
	      " unknown (server)\n", 
	      himaddr >> 24, (himaddr >> 16) & 0xFF, (himaddr >> 8) & 0xFF,
	      himaddr & 0xFF, ntohs(him.sin_port));
  }
  else {
    log_debug(m_log, "Connection: (client) unknown <->"
	      " unknown (server) [something is very broken]\n");
  }
}

Server::BackendConnection *
Server::connect_to_backend(const struct sockaddr_in *vault_addr) {
  BackendConnection *vault = new BackendConnection();
  vault->set_in_connect(false);
  vault->set_fd(socket(PF_INET, SOCK_STREAM, IPPROTO_TCP));
  if (vault->fd() < 0) {
    log_err(m_log, "Error in socket(): %s\n", strerror(errno));
    delete vault;
    return NULL;
  }
  int flags = fcntl(vault->fd(), F_GETFL, NULL);
  if (fcntl(vault->fd(), F_SETFL, flags|O_NONBLOCK)) {
    log_err(m_log, "Error setting socket nonblocking: %s\n", strerror(errno));
    delete vault;
    return NULL;
  }
  if (connect(vault->fd(),
	      (const sockaddr *)vault_addr, sizeof(struct sockaddr_in))) {
    if (errno == EINPROGRESS) {
      vault->set_in_connect(true);
    }
    else {
      log_err(m_log, "Error in connect(): %s\n", strerror(errno));
      delete vault;
      return NULL;
    }
  }
  return vault;
}

#ifdef USING_DH
/*
 * The following OpenSSL ASN1 goo is because OpenSSL does not already have
 * functions to write out the D-H parameters as needed by the modified D-H
 * we have.
 */
#if OPENSSL_VERSION_NUMBER >= 0x00909000L
static int dh_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
		 void *exarg)
#else
static int dh_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it)
#endif
{
  if (operation == ASN1_OP_NEW_PRE) {
    *pval = (ASN1_VALUE *)DH_new();
    if (*pval) return 2;
    return 0;
  } else if(operation == ASN1_OP_FREE_PRE) {
    DH_free((DH *)*pval);
    *pval = NULL;
    return 2;
  }
  return 1;
}
ASN1_SEQUENCE_cb(CyanDHParams, dh_cb) = {
  ASN1_SIMPLE(DH, p, BIGNUM),
  ASN1_SIMPLE(DH, g, BIGNUM),
  ASN1_SIMPLE(DH, priv_key, BIGNUM)
} ASN1_SEQUENCE_END_cb(DH, CyanDHParams)
IMPLEMENT_ASN1_FUNCTIONS_name(DH, CyanDHParams)
#define i2d_CyanDHParams_fp(fp,dh) ASN1_i2d_fp_of(DH,i2d_CyanDHParams,fp,dh)
#define d2i_CyanDHParams_fp(fp,dh) ASN1_d2i_fp_of(DH,DH_new,d2i_CyanDHParams,fp,dh)
#endif /* USING_DH */

void * Server::read_keyfile(const char *fname, Logger *log) {
#ifdef USING_RSA
  FILE *file = fopen(fname, "r");
  if (!file) {
    log_err(log, "Error opening key file %s\n", fname);
    return NULL;
  }
  RSA *rsa = NULL;
  if (!(rsa = d2i_RSAPrivateKey_fp(file, NULL))) {
    log_err(log, "Error reading key file %s\n", fname);
  }
  fclose(file);
  return (void *)rsa;
#else
#ifdef USING_DH
  FILE *file = fopen(fname, "r");
  if (!file) {
    log_err(log, "Error opening key file %s\n", fname);
    return NULL;
  }
  DH *dh = NULL;
  if (!(dh = d2i_CyanDHParams_fp(file, NULL))) {
    log_err(log, "Error reading key file %s\n", fname);
  }
  fclose(file);
  return (void *)dh;
#else
  return NULL;
#endif /* ! USING_DH */
#endif /* ! USING_RSA */
}

void Server::Connection::set_rc4_key(const u_char *session_key) {
#ifdef HAVE_OPENSSL
  m_c2s_rc4 = new RC4_KEY;
  m_s2c_rc4 = new RC4_KEY;
  RC4_set_key(m_c2s_rc4, 7, session_key);
  memcpy(m_s2c_rc4, m_c2s_rc4, sizeof(RC4_KEY));
#else
  m_c2s_rc4 = new rc4_state_t;
  m_s2c_rc4 = new rc4_state_t;
  rc4_init_key(m_c2s_rc4, session_key, 7);
  memcpy(m_s2c_rc4, m_c2s_rc4, sizeof(rc4_state_t));
#endif
}

Server::reason_t Server::Connection::setup_rc4_key(const u_char *inbuf,
						   size_t inbuflen,
						   const void *keydata,
						   int fd, Logger *log) {
#ifdef DEBUG_ENABLE
  assert(inbuflen <= 64);
#endif

#ifdef USING_RSA
  if (!keydata) {
    log_err(log, "No server key data provided!\n");
    return INTERNAL_ERROR;
  }
  RSA *rsa = (RSA *)keydata;

  u_char dkey[64];
  u_char swapped[64];
  for (u_int blargh = 0; blargh < inbuflen; blargh++) {
    swapped[blargh] = inbuf[inbuflen-1-blargh];
  }
  int dec_res = RSA_private_decrypt(inbuflen, swapped, dkey, rsa, RSA_NO_PADDING);
  if (dec_res != 64) {
    log_warn(log, "Decryption produced only %d bytes?!\n", dec_res);
  }
  for (int blargh = 0; blargh < 32; blargh++) {
    u_char keep = dkey[63-blargh];
    dkey[63-blargh] = dkey[blargh];
    dkey[blargh] = keep;
  }
  const u_char *finalkey = dkey;
#else
#ifdef USING_DH
  if (!keydata) {
    log_err(log, "No server key data provided!\n");
    return INTERNAL_ERROR;
  }
  DH *dh = (DH *)keydata;
  if (DH_size(dh) != 64) {
    log_err(log, "Server D-H key malformed\n");
    return INTERNAL_ERROR;
  }

  u_char dkey[64];
  u_char swapped[64];
  for (u_int blargh = 0; blargh < inbuflen; blargh++) {
    swapped[blargh] = inbuf[inbuflen-1-blargh];
  }
  BIGNUM *clientkey = BN_new();
  BN_bin2bn(swapped, inbuflen, clientkey);
  int keysize = DH_compute_key(dkey, clientkey, dh);
  // usually keysize == 64, but when its most significant bytes are zero
  // DH_compute_key apparently omits them
  if (keysize < 0) {
    log_warn(log, "Failed to compute key\n");
    return INTERNAL_ERROR;
  }
  for (int blargh = 0; blargh < keysize/2; blargh++) {
    u_char keep = dkey[keysize-1-blargh];
    dkey[keysize-1-blargh] = dkey[blargh];
    dkey[blargh] = keep;
  }
  for (int i = keysize; i < 7; i++) { // unlikely to ever happen
    dkey[i] = 0;
  }
  const u_char *finalkey = dkey;
#else
  const u_char *finalkey = (const u_char *)keydata;
#endif /* ! USING_DH */
#endif /* ! USING_RSA */

  u_char session_key[7];
  get_random_data(session_key, 7);

#ifdef I_DONT_NEED_NO_STINKIN_SECURITY
  // FOR DEBUGGING
  memset(session_key, 0, 7);
#endif
  log_msgs(log, "Sending nonce response\n");
  NonceResponse *response = new NonceResponse(session_key, 7);
  enqueue(response, MessageQueue::NORMAL);
  // we can't set is_encrypted yet or the event loop will encrypt this
  // message
  for (int i = 0; i < 7; i++) {
    session_key[i] ^= finalkey[i];
  }
  try {
    set_rc4_key(session_key);
  }
  catch (const std::bad_alloc &) {
    log_err(log, "Cannot allocate memory for RC4 state\n");
    return INTERNAL_ERROR;
  }
#if defined(USING_RSA) || defined(USING_DH)
  log_debug(log, "Session key for fd %d: %02X%02X%02X%02X%02X%02X%02X\n", fd,
	    session_key[0], session_key[1], session_key[2], session_key[3],
	    session_key[4], session_key[5], session_key[6]);
#endif
  return NO_SHUTDOWN;
}

NetworkMessage * 
Server::BackendConnection::make_if_enough(const u_char *buf, size_t len,
					  int *want_len, bool become_owner) {
  return BackendMessage::make_if_enough(buf, len, want_len, become_owner);
}

const char * Server::reason_to_string(Server::reason_t why) {
  switch(why) {
  case Server::NO_SHUTDOWN:
    return "No shutdown requested";
  case Server::CLIENT_CLOSE:
    return "Client connection closed";
  case Server::CLIENT_TIMEOUT:
    return "Client connection timed out";
  case Server::SERVER_SHUTDOWN:
    return "Server shutdown";
  case Server::PEER_SHUTDOWN:
    return "Peer shutdown";
  case Server::SELECT_ERROR:
    return "Select error";
  case Server::READ_ERROR:
    return "Read error";
  case Server::WRITE_ERROR:
    return "Write error";
  case Server::INTERNAL_ERROR:
    return "Server-internal error";
  case Server::PROTOCOL_ERROR:
    return "Protocol error";
  case Server::UNEXPECTED_STATE:
    return "Client/protocol state not as expected";
  case Server::BACKEND_ERROR:
    return "Error in backend connection";
  case Server::BACKEND_TIMEOUT:
    return "Backend connection timed out";
  case Server::QUEUE_DRAINED:
    return "Connection's outbound queue emptied";
  default:
    return "Unknown";
  }
}

#ifdef FORK_ENABLE
void Server::cleanup_accepted_fds(int fd_to_keep) {
  if (!m_fds_size) {
    return;
  }
  int size = *m_fds_size;
  int *a_fds = *m_accepted_fds;
  for (int i = 0; i < size; i++) {
    if (a_fds[i] >= 0 && a_fds[i] != fd_to_keep) {
      close(a_fds[i]);
    }
  }
}
void Server::set_accepted_fds(int **accepted_fds, int *fds_size) {
  m_accepted_fds = accepted_fds;
  m_fds_size = fds_size;
}
#endif

// ok, this is a hack but it gets me what I need!
Server::TimerQueue::TimerQueue() : Connection(-255, (MessageQueue*)1) {
  m_msg_queue = NULL;
  if (m_readbuf) {
    delete m_readbuf;
    m_readbuf = NULL;
  }
}

Server::TimerQueue::~TimerQueue() {
  std::deque<Timer*>::iterator iter;
  for (iter = m_queue.begin(); iter != m_queue.end(); iter++) {
    Timer *t = *iter;
    delete t;
  }
}

void Server::TimerQueue::insert(Server::TimerQueue::Timer *el) {
  m_queue.push_back(el);
  push_heap(m_queue.begin(), m_queue.end(), timer_compare);
  set_timeout();
}

void Server::TimerQueue::handle_timeout(struct timeval &time) {
  while (m_queue.size() > 0
	 && (timeval_lessthan(m_queue[0]->m_when, time)
	     || m_queue[0]->m_cancelled)) {
    Timer *t = m_queue[0];
    if (!t->m_cancelled) {
      t->callback();
    }
    pop_heap(m_queue.begin(), m_queue.end(), timer_compare);
    m_queue.pop_back();
    delete t;
  }
  set_timeout();
}

void Server::TimerQueue::set_timeout() {
  if (m_queue.size() == 0) {
    // disable timeout
    m_interval = 0;
  }
  else {
    m_interval = 1;
    m_timeout = m_queue[0]->m_when;
  }
}



void * serv_main(void *serv) {
  Server *server = (Server *)serv;

  Logger *log = server->log();
  Server::reason_t shutdown_reason = Server::NO_SHUTDOWN;

  int ret;

  // accepted connections
  int *accepted_fds = NULL;
  struct timeval *fd_timeouts = NULL;
  int fds_size = 10;
  int fds_used = 0;
  int max_accepted_fds = ACCEPTING_FDS;
  int accepted_timeout = ACCEPTING_TIMEOUT;
  // client & backend connections
  std::list<Server::Connection*> &conns = server->get_conn_list();
  std::list<Server::Connection*>::iterator iter;
  Server::Connection *conn;

  // local state
  int exit_value = 1;
  int i, j;
  struct iovec *iov = NULL;
  u_int wrote;

  // select loop state
  int *signal_bits = server->get_signal_flags();
  size_t signal_len = server->get_signal_flagct();
  fd_set zerofds, savefds, readfds, writefds;
  int nfds, save_nfds = 0, fd_ct;
  struct timeval timeout, next, now;
#define IN_SHUTDOWN() (shutdown_reason != Server::NO_SHUTDOWN)
  // this macro makes sure that if we are already in shutdown, we don't
  // re-shutdown or worse, clear shutdown_reason
#define CHECK_SHUTDOWN(e, control) { \
	  Server::reason_t resp = (e); \
	  if (resp != Server::NO_SHUTDOWN) { \
	    if (!IN_SHUTDOWN()) { \
	      shutdown_reason = resp; \
	      server->shutdown(resp); \
            } \
	    control; \
	  } \
	}

  if (server->is_thread()) {
    // clear out signal mask, but only when a thread
    sigset_t sigs;
    sigemptyset(&sigs);
    sigaddset(&sigs, SIGCHLD);
    sigaddset(&sigs, SIGHUP);
    sigaddset(&sigs, SIGTERM);
    sigaddset(&sigs, SIGINT);
    sigaddset(&sigs, SIGALRM);
    // blocking QUIT should not be necessary since it is only sent to the
    // "main" thread, but let us see if it makes a difference
    sigaddset(&sigs, SIGQUIT);
    pthread_sigmask(SIG_BLOCK, &sigs, NULL);
  }
  else {
    // pid_t is 4 bytes even on 64-bit machines, so this is safe
    server->set_id((uint32_t)getpid());
  }

  log_info(log, "%s startup\n", server->type_name());
  try {
    ret = server->init();
    UruString::setup_thread_iconv();
  }
  catch (const std::bad_alloc &) {
    log_err(log, "Cannot allocate memory in init(), shutting down\n");
    goto quitting;
  }
  if (ret) {
    // we can't expect to forge on
    if (server->is_child()) {
      log_debug(log,
		"Closing client connection because of an error in init()\n");
    }
    else {
      log_debug(log, "Quitting because of an error in init()\n");
    }
    goto quitting;
  }

  /* set up select loop stuff */

  try {
    iov = new struct iovec[MAX_IOVEC_COUNT];
    // The select loop allows for fds_size to start < max_accepted_fds and
    // then growing accepted_fds up to max_accepted_fds as necessary.
    // Unfortunately that code is untested (even 10 concurrent accepting
    // connections is impossible when your user base is 3), so to be safe,
    // fds_size is set == max_accepted_fds. This will disable the growing
    // code and only "waste" 120 bytes.
    fds_size = max_accepted_fds;
    accepted_fds = new int[fds_size];
    fd_timeouts = new struct timeval[fds_size];
  }
  catch (const std::bad_alloc &) {
    log_err(log, "Cannot allocate memory, shutting down\n");
    goto quitting;
  }

  for (i = 0; i < fds_size; i++) {
    accepted_fds[i] = -1;
  }
#ifdef FORK_ENABLE
  server->set_accepted_fds(&accepted_fds, &fds_size);
#endif

  /* now enter the select loop, woo! */

  FD_ZERO(&zerofds);
  savefds = zerofds;
  if (server->listen_fd() >= 0) {
    FD_SET(server->listen_fd(), &savefds);
    save_nfds = server->listen_fd() + 1;
  }
  gettimeofday(&next, NULL);
  next.tv_sec += (3600*24); /* once a day */

  while (1) {
    // process any signals
    if (signal_bits) {
      for (u_int s = 0; s < signal_len; s++) {
	if (signal_bits[s]) {
	  CHECK_SHUTDOWN(server->process_signals(),);
	  break;
	}
      }
    }
    // check for explicit shutdown request
    CHECK_SHUTDOWN((server->shutdown_requested()
		    ? Server::SERVER_SHUTDOWN : Server::NO_SHUTDOWN),);
    // set up and check the listen socket
    writefds = zerofds;
    if (IN_SHUTDOWN()) {
      readfds = zerofds;
      nfds = 0;
    }
    else {
      readfds = savefds;
      nfds = save_nfds;
    }
    ret = gettimeofday(&now, NULL);
    if (timeval_lessthan(next, now)) {
      log_info(log, "I am alive!\n");
      // log only once if the server was asleep (suspended) for > 1 day
      do {
	next.tv_sec += (3600*24);
      } while (timeval_lessthan(next, now));
    }
    timeout = next;
    // get accepted sockets not yet completed
    i = j = 0;
    while (j < fds_used && i < fds_size) {
      if (accepted_fds[i] >= 0) {
	FD_SET(accepted_fds[i], &readfds);
	if (timeval_lessthan(fd_timeouts[i], timeout)) {
	  timeout = fd_timeouts[i];
	}
	if (accepted_fds[i] >= nfds) {
	  nfds = accepted_fds[i]+1;
	}
	j++;
      }
      i++;
    }
    // now pick up the active connections
    for (iter = conns.begin(); iter != conns.end(); ) {
      // conn_shutdown() may invalidate the iterator, so take care with it
      conn = *iter;
      iter++;
      if (conn->m_interval && timeval_lessthan(conn->m_timeout, timeout)) {
	timeout = conn->m_timeout;
      }
      if (conn->fd() < 0) {
	continue;
      }
      if (conn->in_shutdown()
	  && conn->queue_size() == 0 && conn->m_write_fill == 0) {
	server->conn_shutdown(conn, Server::QUEUE_DRAINED);
	continue;
      }
      int include = -1;
      if (!IN_SHUTDOWN() && !conn->in_connect() && !conn->in_shutdown()) {
	Buffer *cbuf = conn->m_bigbuf ? conn->m_bigbuf : conn->m_readbuf;
	if (conn->m_read_fill < cbuf->len()) {
	  FD_SET(conn->fd(), &readfds);
	  include = conn->fd();
	}
      }
      if ((!IN_SHUTDOWN() && conn->in_connect())
	  || conn->queue_size() > 0 || conn->m_write_fill != 0) {
	FD_SET(conn->fd(), &writefds);
	include = conn->fd();
      }
      if (include >= nfds) {
	nfds = include+1;
      }
    }

    if (IN_SHUTDOWN() && nfds == 0) {
      // all done
      log_info(log, "Server shutdown for reason: %s\n",
	       Server::reason_to_string(shutdown_reason));

      if (shutdown_reason == Server::SERVER_SHUTDOWN
	  ||shutdown_reason == Server::CLIENT_CLOSE
	  || shutdown_reason == Server::CLIENT_TIMEOUT) {
	exit_value = 0;
      }
      goto quitting;
    }

    timeval_difference(timeout, now, timeout);
    if (timeout.tv_sec < 0) {
      timeout.tv_sec = 0;
      timeout.tv_usec = 1;
    }
#ifdef DEBUG_ENABLE
    if (0) {
      char rfd_list[1024];
      char wfd_list[1024];
      rfd_list[0] = '\0';
      wfd_list[0] = '\0';
      for (i = 0; i < FD_SETSIZE; i++) {
	if (FD_ISSET(i, &readfds)) {
	  u_int list_off = strlen(rfd_list);
	  if (list_off < 1023) {
	    snprintf(rfd_list+list_off, 1024-list_off, " %d", i);
	  }
	}
	if (FD_ISSET(i, &writefds)) {
	  u_int list_off = strlen(wfd_list);
	  if (list_off < 1023) {
	    snprintf(wfd_list+list_off, 1024-list_off, " %d", i);
	  }
	}
      }
      log_debug(log, "Write fds BEFORE:%s\n", wfd_list);
      log_debug(log, "Read fds BEFORE:%s\n", rfd_list);
    }
#endif
    fd_ct = select(nfds, &readfds, &writefds, NULL, &timeout);
    gettimeofday(&now, NULL);
    if (fd_ct < 0) {
      // error
      if (errno == EINTR) {
      }
      else if (errno == EINVAL) {
	// bad timeout parameter
	log_err(log, "Bad timeout parameter %d.%06d!\n",
		timeout.tv_sec, timeout.tv_usec);
      }
      else {
	log_err(log, "Error in select: %s\n", strerror(errno));
	CHECK_SHUTDOWN(Server::SELECT_ERROR,);
	continue;
      }
    }
    else if (fd_ct == 0) {
      // timeout
      j = fds_used;
      i = 0;
      while (j > 0 && i < fds_size) {
	if (accepted_fds[i] >= 0) {
	  j--;
	  if (timeval_lessthan(fd_timeouts[i], now)) {
	    // no data came in the timeout interval
	    log_debug(log, "Timeout for connection on %d\n", accepted_fds[i]);
	    close(accepted_fds[i]);
	    accepted_fds[i] = -1;
	    fds_used--;
	  }
	}
      }
      for (iter = conns.begin(); iter != conns.end(); ) {
	// conn_timeout() may invalidate the iterator, so take care with it
	conn = *iter;
	iter++;
	if (conn->m_interval && timeval_lessthan(conn->m_timeout, now)) {
	  CHECK_SHUTDOWN(server->conn_timeout(conn, Server::CLIENT_TIMEOUT),
			 break);
	}
      }
    }
    else {
#ifdef DEBUG_ENABLE
      if (0) {
	char rfd_list[1024];
	char wfd_list[1024];
	rfd_list[0] = '\0';
	wfd_list[0] = '\0';
	for (i = 0; i < FD_SETSIZE; i++) {
	  if (FD_ISSET(i, &readfds)) {
	    u_int list_off = strlen(rfd_list);
	    if (list_off < 1023) {
	      snprintf(rfd_list+list_off, 1024-list_off, " %d", i);
	    }
	  }
	  if (FD_ISSET(i, &writefds)) {
	    u_int list_off = strlen(wfd_list);
	    if (list_off < 1023) {
	      snprintf(wfd_list+list_off, 1024-list_off, " %d", i);
	    }
	  }
	}
	log_debug(log, "Read fds AFTER:%s\n", rfd_list);
	log_debug(log, "Write fds AFTER:%s\n", wfd_list);
      }
#endif
      // do we need to accept() ?
      if (server->listen_fd() >= 0
	  && FD_ISSET(server->listen_fd(), &readfds)) {
	struct sockaddr_in addr;
	u_int socklen = sizeof(struct sockaddr_in);
	int newfd = accept(server->listen_fd(),
			   (struct sockaddr *)&addr, &socklen);
	if (newfd < 0) {
	  if (errno == EAGAIN) {
	    log_warn(log, "Listen socket selected for read "
		     "but nothing to accept()\n");
	  }
	  else if (errno == ECONNABORTED) {
	    log_warn(log, "Connection aborted\n");
	  }
	  else if (errno == EMFILE || errno == ENFILE) {
	    // XXX out of fd's
	    log_err(log, "Out of file descriptors in accept!\n");
	  }
	  else {
	    log_err(log, "Error in accept: %s\n", strerror(errno));
	  }
	}
	else {
	  unsigned int ipaddr = ntohl(addr.sin_addr.s_addr);
	  log_debug(log, "Accepted %d from %u.%u.%u.%u:%u\n", newfd,
		    ipaddr >> 24, (ipaddr >> 16) & 0xFF,
		    (ipaddr >> 8) & 0xFF, ipaddr & 0xFF,
		    ntohs(addr.sin_port));

	  ret = fcntl(newfd, F_GETFL, NULL);
	  if (fcntl(newfd, F_SETFL, ret|O_NONBLOCK)) {
	    log_err(log, "Error setting %d nonblocking: %s\n",
		    newfd, strerror(errno));
	    close(newfd);
	  }
	  else {
	    for (i = 0; i < fds_size; i++) {
	      if (accepted_fds[i] < 0) {
		accepted_fds[i] = newfd;
		fd_timeouts[i].tv_sec = now.tv_sec+accepted_timeout;
		fd_timeouts[i].tv_usec = now.tv_usec;
		fds_used++;
		break;
	      }
	    }
	    if (i == fds_size) {
	      int next_size = fds_size * 2;
	      if (next_size > max_accepted_fds && fds_size < max_accepted_fds) {
		next_size = max_accepted_fds;
	      }
	      if (next_size > max_accepted_fds) {
		// eject older fds
		int count = 0, j;
		i = -1;
		for (j = 0; j < fds_size; j++) {
		  if (fd_timeouts[j].tv_sec < now.tv_sec+(accepted_timeout/2)) {
		    count++;
		    close(accepted_fds[j]);
		    fds_used--;
		    accepted_fds[j] = -1;
		    i = j;
		  }
		}
		if (i < 0) {
		  // we closed nothing
		  log_warn(log, "Max connections in less than "
			   "timeout/2 seconds: possible DoS\n");
		  // this is not perfectly fair but it's simple
		  for (j = 0; j < fds_size; j++) {
		    if (j > 0
			&& fd_timeouts[j].tv_sec < fd_timeouts[j-1].tv_sec) {
		      close(accepted_fds[j]);
		      fds_used--;
		      accepted_fds[j] = -1;
		      i = j;
		      break;
		    }
		  }
		  if (j == fds_size) {
		    close(accepted_fds[0]);
		    fds_used--;
		    accepted_fds[0] = -1;
		    i = 0;
		  }
		}
		accepted_fds[i] = newfd;
		fd_timeouts[i].tv_sec = now.tv_sec+accepted_timeout;
		fd_timeouts[i].tv_usec = now.tv_usec;
		fds_used++;
	      }
	      else {
		int *new_a_fds = NULL;
		struct timeval *new_fd_ts = NULL;
		try {
		  new_a_fds = new int[next_size];
		  new_fd_ts = new struct timeval[next_size];

		  memcpy(new_a_fds, accepted_fds, fds_size);
		  memcpy(new_fd_ts, fd_timeouts, fds_size);
		  delete[] accepted_fds;
		  delete[] fd_timeouts;
		  fds_size = next_size;
		  accepted_fds = new_a_fds;
		  fd_timeouts = new_fd_ts;

		  accepted_fds[i] = newfd;
		  fd_timeouts[i].tv_sec = now.tv_sec+accepted_timeout;
		  fd_timeouts[i].tv_usec = now.tv_usec;
		  fds_used++;
		  for (i++; i < fds_size; i++) {
		    accepted_fds[i] = -1;
		  }
		}
		catch (const std::bad_alloc&) {
		  // man do we have a serious problem
		  if (new_a_fds) {
		    delete[] new_a_fds;
		  }
		  if (new_fd_ts) {
		    delete[] new_fd_ts;
		  }
		  log_err(log,
			  "Cannot allocate memory for accepted fds list!\n");
		  // drop connection, nothing else we can do
		  close(newfd);
		}
	      }
	    }
	  }
	}
	// decrement count of file descriptors selected
	fd_ct--;
      }

      // now, check on previously accepted fds
      if (server->listen_fd() >= 0 && fd_ct > 0) {
	i = j = 0;
	while (j < fds_used && i < fds_size) {
	  if (accepted_fds[i] >= 0 && FD_ISSET(accepted_fds[i], &readfds)) {
	    u_char type;
	    ret = read(accepted_fds[i], &type, 1);
	    if (ret <= 0) {
	      if (ret < 0) {
		if (errno == EAGAIN) {
		  /*log_warn(log, "Socket selected for read but "
			   "nothing to read()\n");*/
		  // this is ok if the client is slow to send the data after
		  // connecting, so just try again (next time data should
		  // be present)
		}
		else {
		  log_err(log, "Error reading type on %d: %s\n",
			  accepted_fds[i], strerror(errno));
		  close(accepted_fds[i]);
		  accepted_fds[i] = -1;
		  fds_used--;
		}
	      }
	      else {
		// EOF
		log_debug(log, "Unexpected early EOF on %d\n",
			  accepted_fds[i]);
		close(accepted_fds[i]);
		accepted_fds[i] = -1;
		fds_used--;
	      }
	    }
	    else {
	      server->add_client_conn(accepted_fds[i], type);
	      accepted_fds[i] = -1;
	      fds_used--;
	    }
	    // decrement count of file descriptors selected
	    fd_ct--;
	  }
	  if (accepted_fds[i] >= 0) {
	    j++;
	  }
	  i++;
	}
      }

      // check connections
      bool fd_used = false;
      for (iter = conns.begin(); iter != conns.end(); ) {
	// conn_shutdown() may invalidate the iterator, so take care with it
	conn = *iter;
	iter++;
	if (fd_used) {
	  fd_ct--;
	}
	if (fd_ct <= 0) {
	  break;
	}
	fd_used = false;
	if (conn->fd() < 0) {
	  continue;
	}
	if (FD_ISSET(conn->fd(), &readfds)) {
	  fd_used = true;
	  Buffer *cbuf = conn->m_bigbuf ? conn->m_bigbuf : conn->m_readbuf;
	  int to_read = cbuf->len() - conn->m_read_fill;
	  if (to_read <= 0) {
	    // XXX we have a protocol problem; the Server should clear
	    // out the buffer if an oversize message is in progress
	    log_err(log, "Read buffer on %d overfull, a protocol error "
		    "happened somewhere\n", conn->fd());
	    if (log) {
	      log->dump_contents(Logger::LOG_ERR,
					 cbuf->buffer(),
					 conn->m_read_fill);
	    }
	    CHECK_SHUTDOWN(server->conn_shutdown(conn, Server::PROTOCOL_ERROR),
			   break);
	    continue;
	  }
	  ret = read(conn->fd(), cbuf->buffer() + conn->m_read_fill, to_read);
	  if (ret < 0) {
	    if (errno == EAGAIN) {
	      log_warn(log,
		       "Socket %d selected for read but nothing to read()\n",
		       conn->fd());
	    }
	    else if (errno == EINTR) {
	    }
	    else if (errno == ECONNRESET) {
	      log_debug(log, "Peer on %d reset connection\n", conn->fd());
	      CHECK_SHUTDOWN(server->conn_shutdown(conn, Server::CLIENT_CLOSE),
			     break);
	      continue;
	    }
	    else {
	      log_err(log, "Error in read on %d: %s\n",
		      conn->fd(), strerror(errno));
	      CHECK_SHUTDOWN(server->conn_shutdown(conn, Server::READ_ERROR),
			     break);
	      continue;
	    }
	  }
	  else if (ret == 0) {
	    log_debug(log, "Peer on %d closed connection\n", conn->fd());
	    CHECK_SHUTDOWN(server->conn_shutdown(conn, Server::CLIENT_CLOSE),
			   break);
	    continue;
	  }
	  else {
	    conn->m_lastread = now;
	    if (conn->is_encrypted()) {
	      conn->decrypt(cbuf->buffer() + conn->m_read_fill, ret);
	    }
	    conn->m_read_fill += ret;
	    u_int read_off = 0;

	    NetworkMessage *msg = NULL;
	    Server::reason_t conn_reason = Server::NO_SHUTDOWN;
	    do {
	      try {
		msg = conn->make_if_enough(cbuf->buffer()+read_off,
					   conn->m_read_fill-read_off,
					   &to_read, conn->m_bigbuf != NULL);
	      }
	      catch (const overlong_message &e) {
		log_net(log, "Message on %d too long: claimed %d bytes\n",
			conn->fd(), e.claimed_len());
		if (log) {
		  log->dump_contents(Logger::LOG_DEBUG,
				     cbuf->buffer()+read_off,
				     conn->m_read_fill-read_off);
		}
		// we cannot continue, but it may not be cause to shut down
		conn_reason = Server::PROTOCOL_ERROR;
		CHECK_SHUTDOWN(server->conn_shutdown(conn, conn_reason),);
		break; // pop out of do..while loop
	      }
	      if (!msg) {
		if (to_read > 0) {
		  if (conn->m_bigbuf) {
		    if (to_read != (int)cbuf->len()) {
		      log_err(log, "Connection on %d message length changed "
			      "from %u to %u!\n", conn->fd(), cbuf->len(),
			      to_read);
		      // serious problem
		      conn_reason = Server::INTERNAL_ERROR;
		      CHECK_SHUTDOWN(server->conn_shutdown(conn, conn_reason),);
		    }
		  }
		  else if (to_read > BUFSIZE) {
		    log_debug(log, "This is a large %s message (%u)\n",
			      server->type_name(), to_read);
		    // the checks that throw overlong_message are intended to
		    // ensure that to_read is a reasonable size (and not
		    // something to DoS me)
		    conn->m_bigbuf = new Buffer(to_read,
						cbuf->buffer()+read_off, true,
						conn->m_read_fill-read_off);
		    conn->m_read_fill -= read_off;
		    read_off = 0;
		  }
		}
		break; // pop out of do..while loop
	      }
	      if (conn->m_bigbuf) {
		// we asked the new message to become owner of the data buffer
		conn->m_bigbuf->make_unowned();
	      }
#ifdef DEBUG_ENABLE
	      size_t used_len = msg->message_len();
#endif
	      read_off += msg->message_len();

	      conn_reason = server->message_read(conn, msg);
#ifdef DEBUG_ENABLE
	      if (!conn->m_bigbuf) {
		// this should cause all kinds of nice problems if a message
		// is being used after this moment, but it still refers to
		// the contents of the read buffer
		memset(cbuf->buffer()+read_off-used_len, 0xf0, used_len);
	      }
#endif
	      if (conn_reason != Server::NO_SHUTDOWN) {
		CHECK_SHUTDOWN(server->conn_shutdown(conn, conn_reason),);
		break; // pop out of do..while loop
	      }
	      else if (conn->m_bigbuf) {
		delete conn->m_bigbuf;
		conn->m_bigbuf = NULL;
		conn->m_read_fill = 0;
		break; // we are done with all that's been read, by definition
	      }
	    } while (msg && (conn->m_read_fill > read_off));

	    if (IN_SHUTDOWN()) {
	      break;
	    }
	    else if (conn_reason != Server::NO_SHUTDOWN) {
	      continue; // go on to next connection
	    }

	    if (read_off < conn->m_read_fill) {
	      if (read_off > 0) {
		conn->m_read_fill -= read_off;
		memmove(conn->m_readbuf->buffer(),
			conn->m_readbuf->buffer()+read_off, conn->m_read_fill);
	      }
	    }
	    else {
	      conn->m_read_fill = 0;
	    }
	  }
	}
	if (FD_ISSET(conn->fd(), &writefds)) {
	  fd_used = true;
	  if (!IN_SHUTDOWN() && conn->in_connect()) {
	    // see if it succeeded
	    socklen_t socketlen = sizeof(int);
	    if ((getsockopt(conn->fd(), SOL_SOCKET, SO_ERROR,
			   &ret, &socketlen) < 0) || ret) {
	      // it did not
	      log_warn(log,
		       "Backend connection on %d connect failed: %s\n",
		       conn->fd(), strerror(ret));
	      CHECK_SHUTDOWN(server->conn_shutdown(conn, Server::WRITE_ERROR),
			     break);
	    }
	    else {
	      server->conn_completed(conn);
	    }
	    continue;
	  }
	  ret = 0;
	  if (conn->is_encrypted()) {
	    // when the connection is encrypted, we have to write to a buffer
	    // so it can be encrypted
	    wrote
	      = conn->msg_queue()->fill_buffer(
					conn->m_writebuf+conn->m_write_fill,
					BUFSIZE-conn->m_write_fill);
	    if (wrote > 0) {
	      conn->encrypt(conn->m_writebuf+conn->m_write_fill, wrote);
	      conn->m_write_fill += wrote;
	    }
	    if (conn->m_write_fill > 0) {
	      ret = write(conn->fd(), conn->m_writebuf, conn->m_write_fill);
	    }
	  }
	  else {
	    // when the connection is unencrypted, we can use writev() and
	    // avoid copying
	    wrote = conn->msg_queue()->fill_iovecs(iov, MAX_IOVEC_COUNT);
	    if (wrote > 0) {
	      ret = writev(conn->fd(), iov, wrote);
	    }
	  }
	  if (ret < 0) {
	    if (errno == EPIPE) {
	      // EOF
	      log_debug(log, "Peer on %d closed connection\n", conn->fd());
	      CHECK_SHUTDOWN(server->conn_shutdown(conn, Server::CLIENT_CLOSE),
			     break);
	      continue;
	    }
	    else if (errno == EAGAIN) {
	      log_warn(log, "Socket %d selected for write but "
		       "could not write()\n", conn->fd());
	    }
	    else if (errno == EINTR) {
	    }
	    else {
	      log_err(log, "Error in write on %d: %s\n",
		      conn->fd(), strerror(errno));
	      CHECK_SHUTDOWN(server->conn_shutdown(conn, Server::WRITE_ERROR),
			     break);
	      continue;
	    }
	  }
	  else if (ret > 0) {
	    wrote = (u_int)ret;
	    if (!conn->is_encrypted()) {
	      conn->msg_queue()->iovecs_written_bytes(wrote);
	    }
	    else {
	      if (conn->m_write_fill > wrote) {
		conn->m_write_fill -= wrote;
		memmove(conn->m_writebuf, conn->m_writebuf+ret,
			conn->m_write_fill);
	      }
	      else {
		conn->m_write_fill = 0;
	      }
	    }
	  }
	}
      } // for
    }
  } // while (1)

  // we should not get here

 quitting:
  UruString::clear_thread_iconv();
  if (iov) {
    delete[] iov;
  }
  if (accepted_fds) {
    i = 0;
    while (fds_used > 0 && i < fds_size) {
      if (accepted_fds[i] >= 0) {
	close(accepted_fds[i]);
	fds_used--;
      }
      i++;
    }
    delete[] accepted_fds;
  }
  if (fd_timeouts) {
    delete[] fd_timeouts;
  }
  server->signal_parent();
  return (void *)exit_value;
}
