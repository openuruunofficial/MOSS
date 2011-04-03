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
 * NetworkMessage is essentially an abstract class (even though it could be
 * instantiated). All network messages that could be put on MessageQueues
 * must inherit from NetworkMessage. A small set of common methods are
 * required for the queue to be able to treat all message types the same.
 * As a very basic example (and as messages that belong to all four front-end
 * server types), the "negotiation" and "nonce" messages are implemented here.
 */

//#include <stdlib.h>
//#include <string.h>
//#include <sys/uio.h> /* for struct iovec */

//#include "constants.h"
//#include "machine_arch.h"

#ifndef _NETWORK_MESSAGE_H_
#define _NETWORK_MESSAGE_H_

class NetworkMessage {
public:
  /*
   * This class should be subclassed by message category. It represents the
   * basic API.
   */

  /*
   * Messages read from the network implement this to create them. Resulting
   * instances do not typically "own" the buffer so they don't free it.
   */
  // throws overlong_message
  static NetworkMessage * make_if_enough(const u_char *buf, size_t len) {
    return NULL;
  }

  /*
   * Messages read from the network should be checked for useability (e.g.
   * if the message is too short, we don't want to read off the end).
   * XXX correctness check as well later?
   */
  virtual bool check_useable() const { return false; }

  /*
   * Messages read from the network should also implement whatever accessors
   * are required.
   */
  virtual int type() const { return m_type; }
  virtual size_t message_len() const { return m_buflen; }
  virtual const u_char * buffer() const { return m_buf; }

  /*
   * Messages written to the network implement normal constructors. Resulting
   * instances typically "own" the buffer and should free it in the
   * destructor, unless the message type implements reference counting (e.g.,
   * game server messages and backend messages).
   */

  /*
   * Some messages are refcounted. By default a message is not refcounted; the
   * functions below make the default behavior as if there is no refcounting
   * at all. If a mesage *is* refcounted, this add_ref() and del_ref() need
   * to be overridden. When a message is sent from a MessageQueue, the queue
   * calls del_ref() and deletes the message if the value returned is < 1.
   */
  // these functions return the refcount
  virtual int add_ref() { return 1; }
  virtual int del_ref() { return 0; }

  /*
   * Don't forget to make all destructors virtual so things work the way
   * they do in all the other OO languages.
   */
  virtual ~NetworkMessage() { };

  /*
   * Messages written to the network get queued on a MessageQueue, and can
   * be partially written at a time. To allow good combining of messages in
   * write syscalls, writev can be used. That won't help much for encrypted
   * connections; for those a buffer is filled instead.
   */
  // fill_iovecs returns the number of iovecs filled
  virtual u_int fill_iovecs(struct iovec *iov, u_int iov_ct, u_int start_at) {
    return 0;
  }
  // returns the number of excess bytes in byte_ct
  virtual u_int iovecs_written_bytes(u_int byte_ct, u_int start_at,
				     bool *msg_done) {
    *msg_done = true;
    return byte_ct;
  }
  // fill_buffer returns the number of bytes filled
  virtual u_int fill_buffer(u_char *buffer, size_t len, u_int start_at,
			    bool *msg_done) {
    *msg_done = true;
    return 0;
  }

protected:
  NetworkMessage(const u_char *msg_buf, size_t msg_len, int msg_type)
    : m_type(msg_type), m_buflen(msg_len), m_buf(NULL) {
    // XXX yuck, look for a better answer
    // plan: make m_buf const, and introduce a m_obuf for "owned" data;
    // refer to m_buf wherever possible, but if we take "ownership" of a buf,
    // set m_obuf to the buf as well; when creating a new buf to write to,
    // assign it to m_obuf and m_buf as well
    // finally, have ~NetworkMessage delete m_obuf if not null, never delete
    // m_buf in child classes
    m_buf = const_cast<u_char*>(msg_buf);
  }
  NetworkMessage(int msg_type)
    : m_type(msg_type), m_buflen(0), m_buf(NULL) { }

  int m_type;

  size_t m_buflen;
  u_char *m_buf;

  static const int zero;

private:
  // do not allow copying of these objects
  NetworkMessage(NetworkMessage &);
  NetworkMessage & operator=(const NetworkMessage &);

#ifdef DEBUG_ENABLE
  // let's add in some extra checks for backing storage -- it's okay for
  // messages that will be handled immediately then deleted to reuse buffer
  // data, but if the message is reused or enqueued, it must have a safe
  // copy of data
  // assume messages avoid copying, and thus cannot be reused/queued
public:
  virtual bool persistable() const { return false; }
#endif
};

class UnknownMessage : public NetworkMessage {
public:
  UnknownMessage(const u_char *msg_buf, size_t msg_len)
    : NetworkMessage(msg_buf, msg_len, -1) { }
};

class NegotiationMessage : public NetworkMessage {
public:
  static NetworkMessage * make_if_enough(const u_char *buf, size_t len,
					 int type);

  bool check_useable() const;
  virtual size_t message_len() const;

  /*
   * Additional accessors
   */
  int client_version() const {
    if (m_type == TYPE_FILE) {
      return read32(m_buf, 34);
    }
    else {
      return read32(m_buf, 2);
    }
  }
  int release_number() const { return read32(m_buf, 10); }
  const u_char * uuid() const { return m_buf+14; }

protected:
  NegotiationMessage(const u_char *msg_buf, size_t msg_len, int msg_type)
    : NetworkMessage(msg_buf, msg_len, msg_type) { }
};

class NonceResponse : public NetworkMessage {
public:
  /*
   * This class copies the buffer passed in.
   */
  NonceResponse(const u_char *msg_buf, size_t len);

  virtual ~NonceResponse() { if (m_buf) delete[] m_buf; }

  u_int fill_iovecs(struct iovec *iov, u_int iov_ct, u_int start_at);
  u_int iovecs_written_bytes(u_int byte_ct, u_int start_at,
			     bool *msg_done);
  u_int fill_buffer(u_char *buffer, size_t len, u_int start_at,
		    bool *msg_done);

#ifdef DEBUG_ENABLE
  virtual bool persistable() const { return true; } // copies buffer
#endif
};

#endif /* _NETWORK_MESSAGE_H_ */
