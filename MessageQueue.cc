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
#include <string.h>
#ifdef HAVE_ASSERT_H
#include <assert.h>
#endif

#include <stdarg.h>
#include <pthread.h>

#include <sys/uio.h> /* for struct iovec */

#include <stdexcept>
#include <deque>

#include "machine_arch.h"
#include "constants.h"

#include "NetworkMessage.h"
#include "MessageQueue.h"

void MessageQueue::enqueue(NetworkMessage *msg, priority_t p) {
#ifdef DEBUG_ENABLE
  if (!msg->persistable()) {
    // this message refers to memory that may be freed or overwritten!
    throw std::logic_error("Message not marked as persistable "
			   "has been enqueued");
  }
#endif
  Entry e(msg, p);
  if (p == FRONT) {
    m_queue.push_front(e);
  }
  else {
    m_queue.push_back(e);
  }
}

void MessageQueue::clear_queue() {
  if (m_queue.size() == 0) {
    return;
  }

  std::deque<Entry>::iterator iter = m_queue.begin();

  for (iter++; iter != m_queue.end(); iter++) {
    if (iter->msg->del_ref() < 1) {
      delete iter->msg;
    }
  }
  iter = m_queue.begin();
  if (iter->so_far != 0) {
    iter++;
  }
  else {
    if (iter->msg->del_ref() < 1) {
      delete iter->msg;
    }
  }
  m_queue.erase(iter, m_queue.end());
}

void MessageQueue::reset_head() {
  if (m_queue.size() > 0) {
    m_queue[0].so_far = 0;
  }
}

u_int MessageQueue::fill_iovecs(struct iovec *iov, u_int iov_ct) {
  u_int how_many = 0;
  std::deque<Entry>::iterator iter = m_queue.begin();

  while (how_many < iov_ct && iter != m_queue.end()) {
#ifdef DEBUG_ENABLE
    u_int previous_how_many = how_many;
#endif
    how_many += iter->msg->fill_iovecs(iov + how_many, iov_ct - how_many,
				       iter->so_far);
#ifdef DEBUG_ENABLE
    // we test iter->so_far != 0 so that a message could turn itself into
    // a zero-length message without tripping this test (none do so right
    // now but I can imagine it happening someday)
    if (previous_how_many == how_many && iter->so_far) {
      throw std::logic_error("We called fill_iovecs on a message which "
			     "was already fully written!");
    }
#endif
    iter++;
  }
  return how_many;
}

void MessageQueue::iovecs_written_bytes(u_int byte_ct) {
  std::deque<Entry>::iterator iter = m_queue.begin();

  while (byte_ct > 0 && iter != m_queue.end()) {
    bool msg_done;
    u_int bytes = iter->msg->iovecs_written_bytes(byte_ct, iter->so_far,
						  &msg_done);
    if (msg_done) {
      byte_ct = bytes;
      if (iter->msg->del_ref() < 1) {
	delete iter->msg;
      }
      iter++;
    }
    else {
      iter->so_far += byte_ct;
      break;
    }
  }

#ifdef DEBUG_ENABLE
  if (iter == m_queue.end() && byte_ct > 0) {
    // this is probably due to an incorrect iovecs_written_bytes
    throw std::logic_error("We wrote more bytes than were in the queue!");
  }
#endif
  if (iter != m_queue.begin()) {
    m_queue.erase(m_queue.begin(), iter);
  }
}

u_int MessageQueue::fill_buffer(u_char *buf, u_int buflen) {
  u_int how_many = 0;
  std::deque<Entry>::iterator iter = m_queue.begin();

  while (how_many < buflen && iter != m_queue.end()) {
    bool msg_done;
    u_int filled = iter->msg->fill_buffer(buf + how_many, buflen - how_many,
					  iter->so_far, &msg_done);
    how_many += filled;
#ifdef DEBUG_ENABLE
    // we test iter->so_far != 0 so that a message could turn itself into
    // a zero-length message without tripping this test (none do so right
    // now but I can imagine it happening someday)
    if (filled == 0 && iter->so_far) {
      throw std::logic_error("We called fill_buffer on a message which "
			     "was already fully written!");
    }
#endif
    if (msg_done) {
      if (iter->msg->del_ref() < 1) {
	delete iter->msg;
      }
      iter++;
    }
    else {
      iter->so_far += filled;
      break;
    }
  }

  if (iter != m_queue.begin()) {
    m_queue.erase(m_queue.begin(), iter);
  }

  return how_many;
}

void MultiWriterMessageQueue::enqueue(NetworkMessage *msg, priority_t p) {
#ifdef DEBUG_ENABLE
  if (!msg->persistable()) {
    // this message refers to memory that may be freed or overwritten!
    throw std::logic_error("Message not marked as persistable "
			   "has been enqueued");
  }
#endif
  bool is_owner = (pthread_self() == m_owner_tid);
  Entry e(msg, p);
  pthread_mutex_lock(&m_mutex);
  // we allow the owner to enqueue always (since it should know its own
  // state and may need to be able to enqueue shutting-down messages)
  if (!m_draining || is_owner) {
    if (p == FRONT) {
      m_queue.push_front(e);
    }
    else {
      m_queue.push_back(e);
    }
#ifdef DO_PRIORITIES
    m_data_queued += e.msg_len();
#endif
  }
  pthread_mutex_unlock(&m_mutex);
#ifdef DO_PRIORITIES
  if (p == AVATAR) {
    m_avatar_ct++;
  }
  else if (p == VOICE) {
    m_voice_ct++;
  }
#endif
}

size_t MultiWriterMessageQueue::size() {
  size_t sz;
#ifdef QUEUE_PARANOIA
  assert(pthread_self() == m_owner_tid);
#endif
  pthread_mutex_lock(&m_mutex);
  sz = m_queue.size();
  pthread_mutex_unlock(&m_mutex);
  return sz;
}

void MultiWriterMessageQueue::clear_queue() {
#ifdef QUEUE_PARANOIA
  assert(pthread_self() == m_owner_tid);
#endif
  pthread_mutex_lock(&m_mutex);
  m_draining = true;
  MessageQueue::clear_queue();
  pthread_mutex_unlock(&m_mutex);
#ifdef DO_PRIORITIES
  m_avatar_ct = m_voice_ct = 0;
  if (m_queue.size() > 0) {
    if (m_queue[0].get_priority() == AVATAR) {
      m_avatar_ct = 1;
    }
    else if (m_queue[0].get_priority() == VOICE) {
      m_voice_ct = 1;
    }
  }
#endif
}

void MultiWriterMessageQueue::reset_head() {
#ifdef QUEUE_PARANOIA
  assert(pthread_self() == m_owner_tid);
#endif
  // if I used a container guaranteed not to move elements when one is
  // added, this lock would be unnecessary
  pthread_mutex_lock(&m_mutex);
  MessageQueue::reset_head();
  pthread_mutex_unlock(&m_mutex);
}

// XXX we want the queue *readers* to minimize their locks, but this will
// be sure to work correctly for now
u_int MultiWriterMessageQueue::fill_iovecs(struct iovec *iov, u_int iov_ct) {
#ifdef QUEUE_PARANOIA
  assert(pthread_self() == m_owner_tid);
#endif
  pthread_mutex_lock(&m_mutex);
  u_int ret = MessageQueue::fill_iovecs(iov, iov_ct);
  pthread_mutex_unlock(&m_mutex);
  return ret;
}

void MultiWriterMessageQueue::iovecs_written_bytes(u_int byte_ct) {
#ifdef QUEUE_PARANOIA
  assert(pthread_self() == m_owner_tid);
#endif
  pthread_mutex_lock(&m_mutex);
  MessageQueue::iovecs_written_bytes(byte_ct);
  pthread_mutex_unlock(&m_mutex);
}

u_int MultiWriterMessageQueue::fill_buffer(u_char *buf, u_int buflen) {
#ifdef QUEUE_PARANOIA
  assert(pthread_self() == m_owner_tid);
#endif
  pthread_mutex_lock(&m_mutex);
  u_int ret = MessageQueue::fill_buffer(buf, buflen);
  pthread_mutex_unlock(&m_mutex);
  return ret;
}
