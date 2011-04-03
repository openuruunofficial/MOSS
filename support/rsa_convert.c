/*
  MOSS - A server for the Myst Online: Uru Live client/protocol
  Copyright (C) 2008,2011  a'moaca'

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
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>

int main(int argc, char *argv[]) {
  char c;
  opterr = 0;
  static char *usage = "Usage: %s [-h] -s <server file> -c <client file> <pem file>\n";
  static struct option options[] = {
    { "server", required_argument, 0, 's' },
    { "client", required_argument, 0, 'c' },
    { "help", no_argument, 0, 'h' },
    { 0, 0, 0, 0 }
  };

  char *server_fname = NULL, *client_fname = NULL;
  FILE *inf, *serverf, *clientf;
  RSA *rsa;

  while ((c = getopt_long(argc, argv, "s:c:h", options, NULL)) != -1) {
    switch (c) {
    case 's':
      server_fname = strdup(optarg);
      break;
    case 'c':
      client_fname = strdup(optarg);
      break;
    case 'h':
      fprintf(stdout, usage, argv[0]);
      return 0;
    default:
      fprintf(stderr, usage, argv[0]);
      return 1;
    }
  }
  if (optind+1 != argc) {
    fprintf(stderr, usage, argv[0]);
    return 1;
  }
  if (!server_fname || !client_fname) {
    fprintf(stderr, usage, argv[0]);
    return 1;
  }
  /* we have now processed the arguments */

  inf = fopen(argv[argc-1], "r");
  if (!inf) {
    fprintf(stderr, "Cannot open file %s: %s\n", argv[argc-1],
	    strerror(errno));
    return 1;
  }
  rsa = PEM_read_RSAPrivateKey(inf, NULL, 0, NULL);
  fclose(inf);
  if (!rsa) {
    fprintf(stderr, "Failed to read key from file %s\n", argv[argc-1]);
    return 1;
  }
  serverf = fopen(server_fname, "w");
  if (!serverf) {
    fprintf(stderr, "Failed to open %s for write: %s\n", server_fname,
	    strerror(errno));
  }
  else {
    if (!i2d_RSAPrivateKey_fp(serverf, rsa)) {
      fprintf(stderr, "Failed to write key to file %s\n", server_fname);
    }
    fclose(serverf);
  }
  clientf = fopen(client_fname, "w");
  if (!clientf) {
    fprintf(stderr, "Failed to open %s for write: %s\n", client_fname,
	    strerror(errno));
  }
  else {
    int i;
    unsigned char buf[128];
    memset(buf, 0, 128);
    if (BN_num_bytes(rsa->n) > 64) {
      fprintf(stderr, "Bad modulus (too big)\n");
    }
    if (BN_num_bytes(rsa->e) > 64) {
      fprintf(stderr, "Bad exponent (too big)\n");
    }
    else {
      /* write little-endian raw data */
      BN_bn2bin(rsa->n, buf);
      BN_bn2bin(rsa->e, buf+128-BN_num_bytes(rsa->e));
      for (i = 0; i < 32; i++) {
	buf[i] ^= buf[63-i];
	buf[63-i] ^= buf[i];
	buf[i] ^= buf[63-i];
      }
      for (i = 0; i < 32; i++) {
	buf[64+i] ^= buf[127-i];
	buf[127-i] ^= buf[64+i];
	buf[64+i] ^= buf[127-i];
      }
      if (fwrite(buf, 1, 128, clientf) != 128) {
	fprintf(stderr, "Error writing file %s: %s\n", client_fname,
		strerror(errno));
      }
    }
    fclose(clientf);
  }
  return 0;
}
