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
 * This class is meant to encapsulate all the thread management for threads
 * exiting and requiring cleanup. Primarily this is to reduce code clutter
 * in the dispatcher.
 */

//#include <unistd.h> /* for alarm() */
//
//#include <pthread.h>
//#include <signal.h>
//
//#include <map>
//#ifdef ENABLE_FORK
//#include <list>
//#endif
//
//#include "machine_arch.h"
//
//#include "moss_serv.h"

#ifndef _THREAD_MANAGER_H_
#define _THREAD_MANAGER_H_

class ThreadManager {
public:
  bool is_id_available(uint32_t id) {
    if (id == 0) {
      return false;
    }
    std::map<uint32_t,void*>::iterator iter = m_id_to_ptr.find(id);
    return (iter == m_id_to_ptr.end());
  }
  void * get_server_from_id(uint32_t id) {
    std::map<uint32_t,void*>::iterator iter = m_id_to_ptr.find(id);
    if (iter != m_id_to_ptr.end()) {
      return iter->second;
    }
    return NULL;
  }

  void new_thread(pthread_t thread, Server *server, uint32_t id=0) {
    m_threads[server] = thread;
    if (id != 0) {
      m_id_to_ptr[id] = (void *)server;
    }
  }
  void thread_join() {
    // do cleanup -- I don't know how better to do this, since there is no
    // wait(-1, status, WNOHANG) equivalent for pthreads
    std::map<Server*,pthread_t>::iterator this_one, iter = m_threads.begin();
    std::map<uint32_t,void*>::iterator id;
    while (iter != m_threads.end()) {
      Server *s = iter->first;
      if (s->shutdown_done()) {
	this_one = iter;
	iter++;
	if (pthread_join(this_one->second, NULL)) {
	  log_warn(s->log(), "pthread_join failed: %s\n", strerror(errno));
	}
	m_threads.erase(this_one);
	for (id = m_id_to_ptr.begin(); id != m_id_to_ptr.end(); id++) {
	  if (id->second == (void *)s) {
	    m_id_to_ptr.erase(id);
	    break;
	  }
	}
	delete s;
      }
      else {
	iter++;
      }
    }
  }
  void signal_thread(Server *server, int signal) {
    std::map<Server*,pthread_t>::iterator iter = m_threads.find(server);
    if (iter != m_threads.end()) {
      pthread_kill(iter->second, signal);
    }
  }
#ifdef FORK_ENABLE
  // might as well provide the same services for child processes
  void new_child(pid_t pid, Server::Connection *conn=NULL, uint32_t id=0) {
    m_children[pid] = conn;
    if (conn) {
      m_id_to_ptr[id] = (void *)conn;
    }
  }
  void child_exit() {
    pid_t pid;
    int status;

    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
      std::map<pid_t,Server::Connection*>::iterator iter = m_children.find(pid);
      std::map<uint32_t,void*>::iterator id;
      if (iter != m_children.end() && iter->second) {
	void *srv = (void *)iter->second;
	for (id = m_id_to_ptr.begin(); id != m_id_to_ptr.end(); id++) {
	  if (id->second == srv) {
	    m_id_to_ptr.erase(id);
	    break;
	  }
	}
	delete iter->second;
      }
      m_children.erase(iter);
    }
  }
#endif

  void start_shutdown() {
#ifdef FORK_ENABLE
    std::map<pid_t,Server::Connection*>::iterator l_iter;
    for (l_iter = m_children.begin(); l_iter != m_children.end(); l_iter++) {
      kill(l_iter->first, SIGTERM);
    }
#endif
    std::map<Server*,pthread_t>::iterator t_iter;
    for (t_iter = m_threads.begin(); t_iter != m_threads.end(); t_iter++) {
      Server *s = t_iter->first;
      s->request_shutdown();
      // and wake up the thread
      pthread_kill(t_iter->second, SIGUSR2);
    }
    // if we haven't finished up in 2 seconds, we will just stop anyway
    alarm(2);
  }
  void finish_shutdown() {
    std::map<Server*,pthread_t>::iterator iter;
    for (iter = m_threads.begin(); iter != m_threads.end(); iter++) {
      Server *s = iter->first;
      pthread_join(iter->second, NULL);
      delete s;
    }
#ifdef FORK_ENABLE
    std::map<pid_t,Server::Connection*>::iterator l_iter;
    for (l_iter = m_children.begin(); l_iter != m_children.end(); l_iter++) {
      int status;
      waitpid(l_iter->first, &status, 0);
#ifdef FORK_GAME_TOO
      // probably have to delete l_iter->second here
#endif
    }
#endif
  }

private:
  std::map<Server*,pthread_t> m_threads;
#ifdef FORK_ENABLE
  std::map<pid_t,Server::Connection*> m_children;
#endif
  // this map goes from the opaque random 32-bit "id2" to a pointer,
  // either Server* or Server::Connection*
  std::map<uint32_t,void*> m_id_to_ptr;
};

#endif /* _THREAD_MANAGER_H_ */
