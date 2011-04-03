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
 * The MessageQueue is a per-client connection FIFO. The select loop simply
 * directly accesses the queue when the socket can be written, and the Server
 * puts messages to send on the end of the queue.
 * The MessageQueue also is meant to allow for per-queue management of what
 * messages can be queued (vs. dropped due to bandwidth/client slowness). The
 * knowledge about the connection would be in the queue, not the Server, so
 * that any message addition is subject to the same management.
 */

//#include <sys/uio.h> /* for struct iovec */
//
//#include <deque>
//
//#include "constants.h"
//
//#include "NetworkMessage.h"

#ifndef _MESSAGE_QUEUE_H_
#define _MESSAGE_QUEUE_H_

class MessageQueue {
public:
  typedef enum {
    NORMAL = 0,
    AVATAR,
    VOICE,
    FRONT // special priority that means: force to front of queue
  } priority_t;

  MessageQueue() { }

  virtual ~MessageQueue() {
    std::deque<Entry>::iterator iter = m_queue.begin();
    for ( ; iter != m_queue.end(); iter++) {
      if (iter->msg->del_ref() < 1) {
	delete iter->msg;
      }
    }
  }

  /*
   * Basic message queue manipulation. Note clear_queue() will *not*
   * remove the first message if has been partially written.
   */
  virtual void enqueue(NetworkMessage *msg, priority_t p = NORMAL);
  virtual size_t size() const { return m_queue.size(); }
  virtual void clear_queue();
  virtual void reset_head();

  /*
   * Writing support. Either fill_iovecs() and iovecs_written_bytes(), or
   * fill_buffer() can be used. With fill_buffer() the number of bytes written
   * is known immediately so messages are dequeued. With fill_iovecs() it is
   * not known until after the write, so nothing is dequeued until
   * iovecs_written_bytes() provides the number of bytes written.
   */
  virtual u_int fill_iovecs(struct iovec *iov, u_int iov_ct);
  virtual void iovecs_written_bytes(u_int byte_ct);
  virtual u_int fill_buffer(u_char *buf, u_int buflen);

protected:

  class Entry {
  public:
    Entry(NetworkMessage *net_msg, priority_t p = NORMAL)
      : msg(net_msg), 
#ifdef DO_PRIORITIES
	priority(p),
#endif
	so_far(0) { }

    MessageQueue::priority_t get_priority() const {
#ifdef DO_PRIORITIES
      return priority;
#else
      return NORMAL;
#endif
    }

    NetworkMessage *msg;
    u_int so_far;

#ifdef DO_PRIORITIES
    MessageQueue::priority_t priority;
#endif
  };

  std::deque<Entry> m_queue;
};

/*
 * This class assumes it is constructed and managed by its "owner" thread,
 * that being the thread that reads from the queue to write to a socket.
 * As such, the only function other threads should call is enqueue().
 *
 * Priorities and bandwidth measurement is advanced stuff, to manage proactive
 * dropping of non-mandatory traffic when a connection gets backed up.
 * XXX At the moment, it's not implemented, so the MultiWriterMessageQueue
 * is pretty much just wrapping a mutex lock around the base MessageQueue
 * methods; if priorities are implemented, few parent methods will be useable.
 */
class MultiWriterMessageQueue : public MessageQueue {
public:
  MultiWriterMessageQueue()
    : MessageQueue(),
#ifdef DO_PRIORITIES
      m_data_queued(0), m_max_priority_queued(NORMAL),
      m_avatar_ct(0), m_voice_ct(0),
#endif
      m_draining(false)
  {
    m_owner_tid = pthread_self();
    if (pthread_mutex_init(&m_mutex, NULL)) {
      throw std::bad_alloc();
    }
  }

  virtual ~MultiWriterMessageQueue() {
    pthread_mutex_destroy(&m_mutex);
  }

  virtual void enqueue(NetworkMessage *msg, priority_t p = NORMAL);
  // be careful using size(); it does take the lock
  virtual size_t size();
  virtual void clear_queue();
  virtual void reset_head();
  virtual u_int fill_iovecs(struct iovec *iov, u_int iov_ct);
  virtual void iovecs_written_bytes(u_int byte_ct);
  virtual u_int fill_buffer(u_char *buf, u_int buflen);

protected:
  pthread_t m_owner_tid;
  pthread_mutex_t m_mutex;
  bool m_draining;

#ifdef DO_PRIORITIES
  // current state of queue
  int m_data_queued;
  int m_avatar_ct;
  int m_voice_ct;

  int m_bandwidth_1min;
  int m_bandwidth_5min;

  // settings
  int m_avatar_high_water_mark;
  int m_avatar_low_water_mark;
  int m_voice_high_water_mark;
  int m_voice_low_water_mark;
#endif
};

#endif /* _MESSAGE_QUEUE_H_ */
