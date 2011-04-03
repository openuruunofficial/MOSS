/*
  MOSS - A server for the Myst Online: Uru Live client/protocol
  Copyright (C) 2008-2009  a'moaca'

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

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/select.h>

static int gotit = 0;
static void sig_handler(int sig) {
  if (sig == SIGQUIT) {
    gotit = 2;
  }
  else {
    gotit = 1;
  }
}

static void usr2_handler(int sig) {
}

void * serv_main(void *arg) {
  pthread_t ptid = (pthread_t)arg;
  sigset_t sigs;
  sigemptyset(&sigs);
  sigaddset(&sigs, SIGINT);
  pthread_sigmask(SIG_BLOCK, &sigs, NULL);

  fprintf(stderr, "Thread 1 entering select\n");
  fflush(stderr);
  
  while (1) {
    select(0, NULL, NULL, NULL, NULL);
    fprintf(stderr, "%d: Thread 1 bumped\n", time(NULL));
    pthread_kill(ptid, SIGQUIT);
    fflush(stderr);
  }

  return (void *)0;
}

void * serv_main2(void *arg) {
  sigset_t sigs;
  sigemptyset(&sigs);
  sigaddset(&sigs, SIGINT);
  pthread_sigmask(SIG_BLOCK, &sigs, NULL);

  fprintf(stderr, "Thread 2 entering select\n");
  fflush(stderr);
  
  while (1) {
    select(0, NULL, NULL, NULL, NULL);
    fprintf(stderr, "%d: Thread 2 bumped\n", time(NULL));
    fflush(stderr);
  }

  return (void *)0;
}

int main(int argc, char *argv[]) {

  struct sigaction sig;
  sigemptyset(&sig.sa_mask);
  sig.sa_flags = 0;
#if 0
  sig.sa_handler = SIG_IGN;
  if (sigaction(SIGUSR2, &sig, NULL)) {
    fprintf(stderr, "Error setting SIGUSR2 to SIG_IGN! (%s)\n", strerror(errno));
  }
#else
  sig.sa_handler = usr2_handler;
  if (sigaction(SIGUSR2, &sig, NULL)) {
    fprintf(stderr, "Error setting SIGUSR2 handler! (%s)\n", strerror(errno));
  }
#endif
  sig.sa_handler = sig_handler;
  if (sigaction(SIGINT, &sig, NULL)) {
    fprintf(stderr, "Error setting SIGINT handler! (%s)\n", strerror(errno));
  }
  if (sigaction(SIGQUIT, &sig, NULL)) {
    fprintf(stderr, "Error setting SIGQUIT handler! (%s)\n", strerror(errno));
  }
  pthread_t mytid = pthread_self();


  pthread_attr_t thread_attr;
  pthread_attr_init(&thread_attr);
  pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_JOINABLE);

  pthread_t tid;
  int ret = pthread_create(&tid, &thread_attr, serv_main, (void*)mytid);
  pthread_t tid2;
  ret = pthread_create(&tid2, &thread_attr, serv_main2, NULL);

  int count = 0;
  while (count < 15) {
    select(0, NULL, NULL, NULL, NULL);
    fprintf(stderr, "%d: Parent bumped %d\n", time(NULL), gotit);
    fflush(stderr);
    gotit = 0;
    if (count & 1) {
      pthread_kill(tid2, SIGUSR2);
    }
    else {
      pthread_kill(tid, SIGUSR2);
    }
    count++;
  }

  exit(0);
}
