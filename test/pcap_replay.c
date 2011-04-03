/*
  MOSS - A server for the Myst Online: Uru Live client/protocol
  Copyright (C) 2008  a'moaca'

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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/in_systm.h> /* hmm? */
#include <netinet/ip.h>
#include <net/if.h>
#ifdef linux
#include <net/ethernet.h>
/* we have to define __FAVOR_BSD before including <netinet/tcp.h>
   to get the struct tcphdr definitions we want */
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#else
#include <net/if_ether.h>
#endif
#include <netinet/tcp.h>
#include <pcap.h>

#define BUFSIZE 65536

static int stop = 0;
static void sig_handler(int sig) {
  stop = 1;
}

int do_read_and_dump(int fd, int loopback, pcap_dumper_t *outp,
		     struct sockaddr_in *addr, struct sockaddr_in *peer,
		     int *seqnum) {
  int ret, off;
  unsigned char packetbuf[BUFSIZE];
  struct pcap_pkthdr hdr;
  struct ether_header *ethh;
  struct ip *iph;
  struct tcphdr *tcph;

  ret = read(fd, packetbuf+(loopback ? 44 : 54), BUFSIZE-54);
  if (ret <= 0) {
    return -1;
  }
  if (outp) {
    off = 0;
    if (loopback) {
      *(int *)(packetbuf+off) = 2; /* not network order */
      off += 4;
    }
    else {
      ethh = (struct ether_header *)(packetbuf+off);
      memset(ethh, 0, sizeof(struct ether_header));
      ethh->ether_dhost[ETHER_ADDR_LEN-1] = 2;
      ethh->ether_shost[ETHER_ADDR_LEN-1] = 1;
      ethh->ether_type = ETHERTYPE_IP;
      off += 14;
    }
    iph = (struct ip *)(packetbuf+off);
    memset(iph, 0, sizeof(struct ip));
    iph->ip_v = 4;
    iph->ip_hl = 5;
    iph->ip_len = htons(40+ret);
    iph->ip_ttl = 255;
    iph->ip_p = IPPROTO_TCP;
    iph->ip_src.s_addr = addr->sin_addr.s_addr;
    iph->ip_dst.s_addr = peer->sin_addr.s_addr;
    off += 20;
    tcph = (struct tcphdr *)(packetbuf+off);
    memset(tcph, 0, sizeof (struct tcphdr));
    tcph->th_sport = addr->sin_port;
    tcph->th_dport = peer->sin_port;
    tcph->th_seq = htonl(*seqnum);
    tcph->th_off = 5;
    tcph->th_win = htons(32768);
    *seqnum += ret;
    tcph->th_flags = TH_PUSH;
    hdr.len = hdr.caplen = ret+54;
    gettimeofday(&hdr.ts, NULL);
    pcap_dump((unsigned char *)outp, &hdr, packetbuf);
  }
  return 0;
}

int main(int argc, char *argv[]) {
  unsigned int len;
  int ret, off;

  char errbuf[PCAP_ERRBUF_SIZE];
  const unsigned char *data;
  pcap_t *inp;
  struct pcap_pkthdr hdr;
  struct ip *iph;
  struct tcphdr *tcph;
  int rd_loop;

  struct sockaddr_in addr, peer;
  int fd;
  struct timeval start, last, now, delta_trace, delta_real, select_time;
  fd_set readfds;
  pcap_dumper_t *outp;
  int seqnum, wr_loop;

  if (argc != 4 && argc != 5) {
    fprintf(stderr, "Usage: %s <pcap file> <IP address> <port> [output file]\n"
	    "\t(pcap file must be filtered for one side of the\n"
	    "\t conversation; the file name may be '-' for stdin)\n",
	    argv[0]);
    exit(1);
  }
  memset(&addr, 0, sizeof(struct sockaddr_in));
  addr.sin_family = AF_INET;
  if (!inet_aton(argv[2], &addr.sin_addr)) {
    fprintf(stderr, "%s: Could not interpret %s as an IP address\n", argv[0],
	    argv[2]);
    exit(1);
  }
  if (sscanf(argv[3], "%d", &ret) != 1) {
    fprintf(stderr, "%s: Could not interpret %s as a port number\n", argv[0],
	    argv[3]);
    exit(1);
  }
  if (ret > 65535) {
    fprintf(stderr, "%s: Invalid port number %d\n", argv[0], ret);
    exit(1);
  }
  addr.sin_port = htons(ret);

  inp = pcap_open_offline(argv[1], errbuf);
  if (!inp) {
    fprintf(stderr, "%s: Cannot open file: %s\n", argv[0], errbuf);
    exit(1);
  }
  if (argc == 5) {
    int dlt = pcap_datalink(inp);
    if ((ntohl(addr.sin_addr.s_addr) & 0xffffff00)
	== (INADDR_LOOPBACK & 0xffffff00)) {
      pcap_set_datalink(inp, DLT_NULL);
      wr_loop = 1;
    }
    else {
      pcap_set_datalink(inp, DLT_EN10MB);
      wr_loop = 0;
    }
    outp = pcap_dump_open(inp, argv[4]);
    if (!outp) {
      fprintf(stderr, "%s: Cannot open file: %s\n", argv[0],
	      pcap_geterr(inp));
    }
    pcap_set_datalink(inp, dlt);
  }
  else {
    outp = NULL;
  }
  fd = socket(PF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    fprintf(stderr, "Error in socket(): %s\n", strerror(errno));
    pcap_close(inp);
    if (outp) pcap_dump_close(outp);
    exit(1);
  }
  if (connect(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in))) {
    fprintf(stderr, "Error in connect(): %s\n", strerror(errno));
    close(fd);
    pcap_close(inp);
    if (outp) pcap_dump_close(outp);
    exit(1);
  }
  if (fcntl(fd, F_SETFL, O_NONBLOCK)) {
    fprintf(stderr, "%s: Error in fcntl(): %s\n", argv[0], strerror(errno));
    close(fd);
    pcap_close(inp);
    if (outp) pcap_dump_close(outp);
    exit(1);
  }
  len = sizeof(struct sockaddr_in);
  getsockname(fd, (struct sockaddr *)&peer, &len);
  FD_ZERO(&readfds);
  if (pcap_datalink(inp) == DLT_NULL) {
    rd_loop = 1;
  }
  else {
    rd_loop = 0;
  }

  signal(SIGPIPE, SIG_IGN);
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  data = pcap_next(inp, &hdr);
  gettimeofday(&last, NULL);
  start = hdr.ts;
  seqnum = 1;
  while (data && !stop) {
    len = hdr.caplen;
    if (rd_loop) {
      if (len < 24) {
	/* bail! */
	fprintf(stderr, "truncated packet\n");
	break;
      }
      off = 4;
    }
    else {
      if (len < 34) {
	/* bail! */
	fprintf(stderr, "truncated packet\n");
	break;
      }
      off = 14;
    }
    iph = (struct ip *)(data+off);
    if (len < ntohs(iph->ip_len)) {
      fprintf(stderr, "truncated packet\n");
      break;
    }
    len = ntohs(iph->ip_len);
    off += iph->ip_hl*4;
    len -= iph->ip_hl*4;
    if (len < 20) {
      /* bail */
      fprintf(stderr, "truncated packet\n");
      break;
    }
    tcph = (struct tcphdr *)(data+off);
    off += tcph->th_off*4;
    len -= tcph->th_off*4;
    if (len <= 0) {
      data = pcap_next(inp, &hdr);
      continue;
    }

    timersub(&hdr.ts, &start, &delta_trace);
    while (!stop) {
      gettimeofday(&now, NULL);
      timersub(&now, &last, &delta_real);
      timersub(&delta_trace, &delta_real, &select_time);
      if (select_time.tv_sec > 0
	  || (select_time.tv_sec == 0 && select_time.tv_usec > 0)) {
	FD_SET(fd, &readfds);
	ret = select(fd+1, &readfds, NULL, NULL, &select_time);
	if (ret < 0) {
	  if (errno != EINTR) {
	    fprintf(stderr, "%s: Error in select(): %s\n", argv[0],
		    strerror(errno));
	  }
	}
	else if (ret > 0) {
	  if (FD_ISSET(fd, &readfds)) {
	    if (do_read_and_dump(fd, wr_loop, outp, &addr, &peer, &seqnum)) {
	      goto the_end;
	    }
	  }
	  else {
	    /* shouldn't happen */
	  }
	}
      }
      else {
	break;
      }
    }
    if (stop) {
      goto the_end;
    }
    ret = write(fd, data+off, len);
    if (ret < 0) {
      goto the_end;
    }
    data = pcap_next(inp, &hdr);
  }

  while (!stop) {
    FD_SET(fd, &readfds);
    ret = select(fd+1, &readfds, NULL, NULL, NULL);
    if (ret < 0) {
      if (errno != EINTR) {
	fprintf(stderr, "%s: Error in select(): %s\n", argv[0],
		strerror(errno));
	goto the_end;
      }
    }
    else if (ret > 0) {
      if (FD_ISSET(fd, &readfds)) {
	if (do_read_and_dump(fd, wr_loop, outp, &addr, &peer, &seqnum)) {
	  goto the_end;
	}
      }
      else {
	/* shouldn't happen */
      }
    }
  }

 the_end:
  close(fd);
  pcap_close(inp);
  if (outp) pcap_dump_close(outp);
  exit(0);
}
