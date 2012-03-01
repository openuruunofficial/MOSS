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
 * Each server type is a subclass of Server. This is an abstract class.
 * The serv_main() function, declared at the end, is the main loop.
 */

//#include <pthread.h>
//#include <signal.h>
//
//#include <sys/time.h>
//
//#include <netinet/in.h>
//
//#ifdef HAVE_OPENSSL
//#include <openssl/rc4.h>
//#else
//#include "rc4.h"
//#endif
//
//#include <stdexcept>
//#include <deque>
//#include <list>
//
//#include "constants.h"
//#include "Buffer.h"
//
//#include "Logger.h"
//#include "NetworkMessage.h"
//#include "MessageQueue.h"

#ifndef _MOSS_SERV_H_
#define _MOSS_SERV_H_

class Server {
public:
  // forward reference
  class Connection;
  class BackendConnection;

  /*
   * The following functions are called by serv_main() and represent the
   * real work of each respective server type.
   */

  // Initialize state. Returns 0 for success and < 0 for other errors during
  // initialization.
  // throws std::bad_alloc
  virtual int init() { return 0; }

  /*
   * As far as the generic select loop is concerned, there is no difference
   * between "client" and "backend" connections, except that client
   * connections are accept()ed and backend connections were connect()ed
   * by the Server and the select loop has to complete the connection.
   */

  // The following functions that *return* a shutdown reason_t should all
  // return NO_SHUTDOWN if the server/select loop should continue on. If
  // the situation is fatal, return a different, appropriate reason.
  typedef enum {
    NO_SHUTDOWN = 0,
    FORGET_THIS_CONNECTION, // NOT fatal, used when connections change threads
    CLIENT_CLOSE,
    CLIENT_TIMEOUT,
    SERVER_SHUTDOWN,
    PEER_SHUTDOWN,
    SELECT_ERROR,
    READ_ERROR,
    WRITE_ERROR,
    INTERNAL_ERROR,
    PROTOCOL_ERROR,
    UNEXPECTED_STATE,
    BACKEND_ERROR,
    BACKEND_TIMEOUT,
    QUEUE_DRAINED
  } reason_t;
  static const char * reason_to_string(Server::reason_t why);

  // Notify the Server that a complete message was read; this function
  // should return a shutdown reason_t other than NO_SHUTDOWN if the
  // server/select loop should shut down *this connection*. This will in
  // turn call conn_closed(), which should return a reason other than
  // NO_SHUTDOWN if the server/select loop itself should shut down.
  virtual reason_t message_read(Connection *conn, NetworkMessage *msg) {
    delete msg;
    return NO_SHUTDOWN;
  }

  // Notify the Server that a connection has been accept()ed and pass in first
  // byte; from this moment on the Server is responsible for closing the fd
  // (even if it does so immediately).
  virtual void add_client_conn(int fd, u_char first) { close(fd); }

  // Notify the Server that a connection that was connect()ing has completed.
  virtual void conn_completed(Connection *conn) { conn->set_in_connect(false);}

  // Notify the Server that a connection's timeout was hit. This function
  // should return a shutdown reason_t other than NO_SHUTDOWN if the
  // server/select loop should be shut down (shutdown() will still be called).
  // This function is allowed to invalidate the iterator for this connection
  // only.
  virtual reason_t conn_timeout(Connection *conn,
				reason_t why) { return why; }

  // Notify the Server that a connection needs to be shutdown: it could be due
  // to some kind of protocol error, or an error with select/read/etc. The
  // return value and iterator invalidation rules are the same as
  // conn_timeout().
  virtual reason_t conn_shutdown(Connection *conn,
				 reason_t why) { return why; }

  // Function to call when shutting down. Returns true if immediate shutdown
  // is ok, false if any connection must be flushed because a message needs to
  // be sent (generally to another server).
  // The Server is responsible for emptying out buffers that do not need to
  // be written and shutting down connections that don't need to be flushed
  // (and removing them from the list).
  // This function is allowed to invalidate any connection iterators.
  virtual bool shutdown(reason_t reason) { return true; }

  // Any server that wishes to have the select loop handle deferred
  // processing from a signal handler has to call this to set up the location
  // of the flags and the SignalProcessor object. The SignalProcessor's
  // signalled() method is only called if the contents of the flags is
  // non-zero. Note the SignalProcessor is *not* deleted by ~Server().
  class SignalProcessor {
  public:
    virtual reason_t signalled(int *todo, Server *s) { return NO_SHUTDOWN; }
    virtual ~SignalProcessor() { };
  };
  void set_signal_data(int *flags, size_t flagct, SignalProcessor *processor) {
    m_signal_flags = flags; m_signal_ct = flagct;
    m_signal_processor = processor;
  }


  /*
   * Constructors and stuff.
   */

  // constructor for child servers
  Server(const char *server_dir, bool is_thread)
    : m_serv_dir(server_dir), m_is_thread(is_thread),
      m_signal_flags(NULL), m_signal_ct(0), m_signal_processor(NULL),
      m_log(NULL), m_is_child(true), m_fd(-1), m_ipaddr(0), m_id(0),
      m_shutdown_done(false), m_in_shutdown(false)
  { 
    m_main_thread = pthread_self();
  }
  // constructor for non-child servers
  Server(int listen_fd, uint32_t ipaddr)
    : m_serv_dir(NULL), m_is_thread(false),
      m_signal_flags(NULL), m_signal_ct(0), m_signal_processor(NULL),
      m_log(NULL), m_is_child(false), m_fd(listen_fd),
      m_ipaddr(ipaddr), m_id(0), m_shutdown_done(false), m_in_shutdown(false)
  { }
  virtual ~Server() {
    if (m_log) {
      delete m_log;
    }
    // clean up any Connections still in the list
    std::list<Connection*>::iterator iter;
    for (iter = m_conns.begin(); iter != m_conns.end(); iter++) {
      delete *iter;
    }
  }

  virtual int type() const = 0;
  virtual const char * type_name() const = 0;


  /*
   * The following methods are basically just for the select loop
   * infrastructure and shouldn't need to be overridden. (If they
   * do, they need to be changed to virtual here!)
   */

  // Set up the server's Logger, either by using a shared logger object,
  // or a new one. This should be used for "child" servers only, with a
  // valid conn_fd representing the client connection.
  // Side effect: this->m_ipaddr is set to the connection's local IP address.
  void setup_logger(int conn_fd, const char *log_level, Logger *to_share) {
    internal_setup_logger(conn_fd, log_level, to_share, NULL);
  }
  void setup_logger(int conn_fd, const char *log_level, const char *log_dir) {
    internal_setup_logger(conn_fd, log_level, NULL, log_dir);
  }
  // Set the server's Logger. This should be used for non-"child" servers.
  void set_logger(Logger *log) { m_log = log; }
  // Set the server's local ID -- note, for non-"child" servers, the IP
  // address must also be explicitly set
  void set_id(uint32_t id) { m_id = id; }

  // Get the server's Logger
  Logger * log() { return m_log; }

  // Get the listen socket
  int listen_fd() const { return m_fd; }
  // Get a reference to the list of connections (it is called only once)
  std::list<Connection*> & get_conn_list() { return m_conns; }
  // Get the pointer to the signal handler's array (called once)
  int * get_signal_flags() const { return m_signal_flags; }
  size_t get_signal_flagct() const { return m_signal_ct; }
  // Actually process signalled tasks
  reason_t process_signals() {
    return m_signal_processor->signalled(m_signal_flags, this);
  }

  // Is it a thread or a forked process?
  bool is_thread() const { return m_is_thread; }
  // Is it a child server or a listening one?
  bool is_child() const { return m_is_child; }

  // Shutdown control
  void request_shutdown() { m_in_shutdown = true; }
  void signal_parent() {
    // called when all processing is complete
    m_shutdown_done = true;
    if (m_is_thread) {
      pthread_kill(m_main_thread, SIGQUIT);
    }
    // do not modify this object any more after the pthread_kill!
  }
  bool shutdown_requested() const { return m_in_shutdown; }
  bool shutdown_done() const { return m_shutdown_done; }

#ifdef FORK_ENABLE
  // This nice abstraction-breaker is necessary for the proper
  // closing of file descriptors in child processes. To not break
  // the abstraction, the array of accept()ed fds would have to be
  // stored and managed in the server object itself, and since it
  // is only necessary if FORK_ENABLE is defined, I am choosing to
  // do it this way instead.
private:
  int **m_accepted_fds;
  int *m_fds_size;
protected:
  void cleanup_accepted_fds(int fd_to_keep);
public:
  void set_accepted_fds(int **accepted_fds, int *fds_size);
#endif

protected:
  /*
   * "arguments" passed to serv_main() (child server: File, Auth, Game)
   */
  const char *m_serv_dir;
  bool m_is_thread;

  /*
   * local state
   */
  int *m_signal_flags;
  size_t m_signal_ct;
  SignalProcessor *m_signal_processor;
  Logger *m_log;
  bool m_is_child;
  int m_fd;
  // note, this *has* to be a list so that iterators work across removals
  std::list<Connection*> m_conns;

  /*
   * server info (for use by backend connections)
   */
  uint32_t m_ipaddr; // network order
  uint32_t m_id;

  /*
   * shutdown status
   */
  // thread ID of parent if (m_is_thread)
  pthread_t m_main_thread;
  // completed all shutdown work: thread/proc may be cleaned up
  bool m_shutdown_done;
  // shutdown has been asynchronously *requested*
  bool m_in_shutdown;

  virtual void internal_setup_logger(int conn_fd, const char *log_level,
				     Logger *to_share, const char *log_dir);
  // utility function
  BackendConnection * connect_to_backend(const struct sockaddr_in *vault_addr);
#ifdef FORK_ENABLE
public:
#endif
  // for reading in key files; return value should be cast appropriately,
  // and it will be NULL for errors
  static void * read_keyfile(const char *fname, Logger *log);

private:
  // prevent use of default constructor
  Server();

public:
  /*
   * Class encapsulating connection info. This object is used for the
   * client connections, as well as any backend connections.
   *
   *
   */
  class Connection {
  public:
    int fd() const { return m_fd; }
    void set_fd(int fd) { m_fd = fd; }
    bool in_connect() const { return m_in_connect; }
    void set_in_connect(bool c) { m_in_connect = c; }
    bool in_shutdown() const { return m_in_shutdown; }
    void set_in_shutdown(bool s) { m_in_shutdown = s; }
    void enqueue(NetworkMessage *msg,
		 MessageQueue::priority_t p = MessageQueue::NORMAL) {
      m_msg_queue->enqueue(msg, p);
    }
    size_t queue_size() const { return m_msg_queue->size(); }
    MessageQueue * msg_queue() const { return m_msg_queue; }

    struct timeval m_timeout; // timeout if this time is hit
    u_int m_interval; // in seconds; 0 for no timeout
    struct timeval m_lastread;

    Buffer *m_readbuf;
    u_int m_read_fill;
    u_int m_read_off;
    Buffer *m_bigbuf;
    u_char *m_writebuf;
    u_int m_write_fill;

    Connection(int fd=-1, MessageQueue *writeq=NULL)
      : m_interval(0),
	m_read_fill(0), m_read_off(0), m_bigbuf(NULL),
	m_writebuf(NULL), m_write_fill(0),
	m_fd(fd), m_in_connect(false), m_in_shutdown(false),
	m_is_encrypted(false), m_c2s_rc4(NULL), m_s2c_rc4(NULL) {

      memset(&m_lastread, 0, sizeof(struct timeval));
      m_readbuf = new Buffer(BUFSIZE);
      if (writeq) {
	m_msg_queue = writeq;
      }
      else {
	// XXX do I need to get message queue types in here?
	// (if it's shared it's passed in so maybe not)
	m_msg_queue = new MessageQueue();
      }
    }
    virtual ~Connection() {
      if (m_fd >= 0) {
	close(m_fd);
      }
      if (m_msg_queue) {
	delete m_msg_queue;
      }
      if (m_bigbuf) {
	delete m_bigbuf;
      }
      if (m_readbuf) {
	delete m_readbuf;
      }
      if (m_writebuf) {
	delete[] m_writebuf;
      }
      if (m_c2s_rc4) {
	delete m_c2s_rc4;
      }
      if (m_s2c_rc4) {
	delete m_s2c_rc4;
      }
    }

    // this function should call the appropriate connection type's
    // message class's make_if_enough
    virtual NetworkMessage * make_if_enough(const u_char *buf, size_t len,
					    int *want_len,
					    bool become_owner=false) = 0;

    /*
     * Encrypted connection management
     */
    // backend connections are unencrypted -- if they go over the network
    // and need to be encrypted, use IPsec or an ssh tunnel or something
    // XXX later add encryption feature?
    bool is_encrypted() const { return m_is_encrypted; }
    // set up the keys
    // can throw std::bad_alloc
    void set_rc4_key(const u_char *session_key);
    reason_t setup_rc4_key(const u_char *nego_buf, size_t nego_buf_len,
			   const void *keydata, int fd, Logger *log);
    // when converting a connection to encrypted, call this
    // XXX can throw std::bad_alloc
    void set_encrypted() {
      m_is_encrypted = true;
      if (!m_writebuf) {
	// do not change this from BUFSIZE; XXX the select loop assumes this
	// length!
	m_writebuf = new u_char[BUFSIZE];
      }
    }
    // do not call these without having called set_encrypted and set_rc4_key!
    void encrypt(u_char *buf, size_t len) {
#ifdef HAVE_OPENSSL
      RC4(m_s2c_rc4, len, buf, buf);
#else
      rc4_encrypt(m_s2c_rc4, buf, len);
#endif
    }
    void decrypt(u_char *buf, size_t len) {
#ifdef HAVE_OPENSSL
      RC4(m_c2s_rc4, len, buf, buf);
#else
      rc4_encrypt(m_c2s_rc4, buf, len);
#endif
    }

  protected:
    int m_fd;
    bool m_in_connect;
    bool m_in_shutdown;
    MessageQueue *m_msg_queue;

    bool m_is_encrypted;
#ifdef HAVE_OPENSSL
    RC4_KEY *m_c2s_rc4;
    RC4_KEY *m_s2c_rc4;
#else
    rc4_state_t *m_c2s_rc4;
    rc4_state_t *m_s2c_rc4;
#endif
    
  };
  class BackendConnection : public Connection {
  public:
    // for things with a connection *to* a backend server, or when the
    // "connection" is purely by message queue
    BackendConnection(MessageQueue *writeq=NULL)
      : Connection(-1, writeq) { }
    // for things listening for backend connections
    BackendConnection(int fd)
      : Connection(fd) { }

    virtual NetworkMessage * make_if_enough(const u_char *buf, size_t len,
					    int *want_len,
					    bool become_owner=false);
  };

  /*
   * Generic timer queue. It is built on top of a Connection so that the
   * timeouts are automatically managed by the select loop, so users of
   * the TimerQueue must add the object to their connections list and
   * handle the conn_timeout() callback for them.
   *
   * Note that Timers can only be added or cancelled. If you need to
   * change the timeout of one, cancel it and add a new one.
   */
  class TimerQueue : public Connection {
  public:
    TimerQueue();
    NetworkMessage * make_if_enough(const u_char *buf, size_t len,
				    int *want_len, bool become_owner) {
      throw std::logic_error("A TimerQueue 'Connection' can't receive data");
    }
    ~TimerQueue();

    // Subclass Timer and implement the callback method, which is called
    // at expiration time unless the timer has been cancelled. Note that
    // Timer* is the container's element, and that it is automatically
    // deleted when the timer fires, so beware dangling pointers.
    class Timer {
      friend class TimerQueue;
    public:
      Timer(struct timeval &when) : m_cancelled(false) { m_when = when; }
      virtual ~Timer() { };

      void cancel() { m_cancelled = true; }
      bool cancelled() const { return m_cancelled; }

      virtual void callback() = 0;

    protected:
      struct timeval m_when;
      bool m_cancelled;
    };

    // for queue management
    void insert(Timer *el);
    void handle_timeout(struct timeval &time);

    // for iterating through queue
    std::deque<Timer*>::const_iterator begin() { return m_queue.begin(); }
    std::deque<Timer*>::const_iterator end() { return m_queue.end(); }
  protected:
    std::deque<Timer*> m_queue;
    void set_timeout();
    static int timer_compare(const Timer *a, const Timer *b) {
      return timeval_lessthan(b->m_when, a->m_when);
    }
  };
};


/*
 * This is the startup function for each server thread. It handles common
 * startup operations and is the select loop, managing reading and writing
 * buffers.
 */
//int serv_main(Server *server); // but, it must be the following type
void * serv_main(void *serv);


#endif /* _MOSS_SERV_H_ */
