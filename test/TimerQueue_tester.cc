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

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <sys/time.h>

//#include <netinet/in.h>

#ifdef HAVE_OPENSSL
#include <openssl/rc4.h>
#else
#include "rc4.h"
#endif

#include <deque>
#include <list>
#include <stdexcept>

#include "constants.h"
#include "machine_arch.h"
#include "util.h"
#include "Buffer.h"

#include "Logger.h"
#include "NetworkMessage.h"
#include "MessageQueue.h"
#include "moss_serv.h"

static int which = 1;
static struct timeval t1, t2, t3, t4, t5, t6, t7, none;

class SimpleTimer : public Server::TimerQueue::Timer {
public:
  SimpleTimer(struct timeval &when) : Timer(when) { };
  virtual void callback() {
    printf("  Callback for time %ld.%ld\n", m_when.tv_sec, m_when.tv_usec);
    if (m_cancelled) {
      printf("===> FAILED: this timer was cancelled\n");
    }
    struct timeval *tv;
    switch (which) {
    case 1:
      tv = &t1;
      break;
    case 2:
      tv = &t2;
      break;
    case 3:
      tv = &t3;
      break;
    case 4:
      tv = &t4;
      break;
    case 5:
      tv = &t5;
      break;
    case 6:
      tv = &t6;
      break;
    case 7:
      tv = &t7;
      break;
    default:
      tv = &none;
    }
    if (timeval_lessthan(m_when, (*tv)) || timeval_lessthan((*tv), m_when)) {
      printf("===> FAILED: order is wrong\n");
    }
    which++;
  }
  // have to expose data for printing queue contents
  const struct timeval & timeval() const { return m_when; }
};

int main(int argc, char *argv[]) {
  Server::TimerQueue *timers = new Server::TimerQueue();

  t1.tv_sec = 1;
  t1.tv_usec = 0;
  t2.tv_sec = 2;
  t2.tv_usec = 0;
  t3.tv_sec = 2;
  t3.tv_usec = 500;
  t4.tv_sec = 3;
  t4.tv_usec = 0;
  t5.tv_sec = 3;
  t5.tv_usec = 0;
  t6.tv_sec = 4;
  t6.tv_usec = 0;
  t7.tv_sec = 5;
  t7.tv_usec = 0;
  none.tv_sec = -1;
  none.tv_usec = 0;

  timers->insert(new SimpleTimer(t1));
  timers->insert(new SimpleTimer(t4));
  timers->insert(new SimpleTimer(t6));
  timers->insert(new SimpleTimer(t7));
  timers->insert(new SimpleTimer(t3));
  timers->insert(new SimpleTimer(t5));
  timers->insert(new SimpleTimer(t2));
  SimpleTimer *cancelled = new SimpleTimer(t3);
  cancelled->cancel();
  timers->insert(cancelled);
  struct timeval t6less;
  t6less.tv_sec = 3;
  t6less.tv_usec = 999;
  cancelled = new SimpleTimer(t6less);
  cancelled->cancel();
  timers->insert(cancelled);

  printf("Timer heap: ");
  std::deque<Server::TimerQueue::Timer*>::const_iterator iter;
  for (iter = timers->begin(); iter != timers->end(); iter++) {
    const SimpleTimer *t = (const SimpleTimer*)*iter;
    printf("%ld.%ld%s ", t->timeval().tv_sec, t->timeval().tv_usec,
	   t->cancelled() ? "(c)" : "");
  }
  printf("\n");

  struct timeval now;
  now.tv_sec = 0;
  now.tv_usec = 500;

  if (timers->m_interval == 0 || timeval_lessthan(timers->m_timeout, t1)
      || timeval_lessthan(t1, timers->m_timeout)) {
    // this means the timeout was computed wrong
    printf("===> FAILED: timeout set wrong\n");
  }

  printf("Firing timer, none ready\n");
  timers->handle_timeout(now);
  if (which != 1) {
    printf("===> FAILED: timers expired early\n");
  }

  if (timers->m_interval == 0 || timeval_lessthan(timers->m_timeout, t1)
      || timeval_lessthan(t1, timers->m_timeout)) {
    // this means the timeout was computed wrong
    printf("===> FAILED: timeout set wrong\n");
  }

  now.tv_sec = 1;
  printf("Firing timer, one ready\n");
  timers->handle_timeout(now);
  if (which > 2) {
    printf("===> FAILED: timers expired early\n");
  }
  else if (which < 2) {
    printf("===> FAILED: timer did not expire\n");
  }

  if (timers->m_interval == 0 || timeval_lessthan(timers->m_timeout, t2)
      || timeval_lessthan(t2, timers->m_timeout)) {
    // this means the timeout was computed wrong
    printf("===> FAILED: timeout set wrong\n");
  }

  printf("Firing timer at same time, none should expire\n");
  timers->handle_timeout(now);
  if (which != 2) {
    printf("===> FAILED: timers expired on duplicate call\n");
  }

  if (timers->m_interval == 0 || timeval_lessthan(timers->m_timeout, t2)
      || timeval_lessthan(t2, timers->m_timeout)) {
    // this means the timeout was computed wrong
    printf("===> FAILED: timeout set wrong\n");
  }

  printf("Timer heap: ");
  for (iter = timers->begin(); iter != timers->end(); iter++) {
    const SimpleTimer *t = (const SimpleTimer*)*iter;
    printf("%ld.%ld%s ", t->timeval().tv_sec, t->timeval().tv_usec,
	   t->cancelled() ? "(c)" : "");
  }
  printf("\n");

  now.tv_sec = 3;
  printf("Firing timer, four ready\n");
  timers->handle_timeout(now);
  if (which > 6) {
    printf("===> FAILED: timers expired early\n");
  }
  else if (which < 6) {
    printf("===> FAILED: timers did not expire\n");
  }

  if (timers->m_interval == 0 || timeval_lessthan(timers->m_timeout, t6)
      || timeval_lessthan(t6, timers->m_timeout)) {
    // this means the timeout was computed wrong
    printf("===> FAILED: timeout set wrong\n");
  }

  int size = 0;
  printf("Timer heap: ");
  for (iter = timers->begin(); iter != timers->end(); iter++) {
    const SimpleTimer *t = (const SimpleTimer*)*iter;
    printf("%ld.%ld%s ", t->timeval().tv_sec, t->timeval().tv_usec,
	   t->cancelled() ? "(c)" : "");
    size++;
  }
  printf("\n");
  if (size != 2) {
    printf("===> FAILED: cancelled timer at head of queue still present?\n");
  }

  now.tv_sec = 5;
  printf("Firing timer, two ready\n");
  timers->handle_timeout(now);
  if (which > 8) {
    printf("===> FAILED: timers expired early\n");
  }
  else if (which < 8) {
    printf("===> FAILED: timers did not expire\n");
  }

  if (timers->m_interval != 0) {
    printf("===> FAILED: timeout set but should not be\n");
  }

  if (timers->begin() != timers->end()) {
    printf("===> FAILED: timer queue not empty\nTimer heap: ");
    for (iter = timers->begin(); iter != timers->end(); iter++) {
      const SimpleTimer *t = (const SimpleTimer*)*iter;
      printf("%ld.%ld%s ", t->timeval().tv_sec, t->timeval().tv_usec,
	     t->cancelled() ? "(c)" : "");
    }
    printf("\n");
  }
  return 0;
}
