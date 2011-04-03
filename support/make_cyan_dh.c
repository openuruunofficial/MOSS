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
 * Well, we can't get what we need from the OpenSSL command-line utilities.
 * They will produce D-H constants, but naturally only the modulus and
 * generator. What we need is the modulus, an exponenent, and
 * generator^exponent. This program will produce a file with the right data
 * for the server, and one with the data for the client.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>

/* sigh, no standard format for what we need */
#if OPENSSL_VERSION_NUMBER >= 0x00909000L
static int cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
	      void *exarg)
#else
static int cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it)
#endif
{
  if (operation == ASN1_OP_NEW_PRE) {
    *pval = (ASN1_VALUE *)DH_new();
    if(*pval) return 2;
    return 0;
  } else if(operation == ASN1_OP_FREE_PRE) {
    DH_free((DH *)*pval);
    *pval = NULL;
    return 2;
  }
  return 1;
}
ASN1_SEQUENCE_cb(CyanDHParams, cb) = {
  ASN1_SIMPLE(DH, p, BIGNUM),
  ASN1_SIMPLE(DH, g, BIGNUM),
  ASN1_SIMPLE(DH, priv_key, BIGNUM)
} ASN1_SEQUENCE_END_cb(DH, CyanDHParams)
IMPLEMENT_ASN1_FUNCTIONS_name(DH, CyanDHParams)
#define i2d_CyanDHParams_fp(fp,dh) ASN1_i2d_fp_of(DH,i2d_CyanDHParams,fp,dh)
#define d2i_CyanDHParams_fp(fp,dh) ASN1_d2i_fp_of(DH,DH_new,d2i_CyanDHParams,fp,dh)

static void print_bignum(BIGNUM *bn);
static void print_private(DH *dh);

int main(int argc, char *argv[]) {
  char c;
  opterr = 0;
  int text = 0, read = 0;
  static char *usage = "Usage: %s [-h] [-t] [-g 2|4|5] [-s <server file>] [-c <client file>] [-r] [-w <wireshark file>]\n";
  static struct option options[] = {
    { "server", required_argument, 0, 's' },
    { "client", required_argument, 0, 'c' },
    { "generator", required_argument, 0, 'g' },
    { "wireshark", required_argument, 0, 'w' },
    { "text", no_argument, 0, 't' },
    { "readin", no_argument, 0, 'r' },
    { "help", no_argument, 0, 'h' },
    { 0, 0, 0, 0 }
  };

  char *server_fname = NULL, *client_fname = NULL, *wireshark_fname = NULL;
  int generator = 4, codes;
  DH *dh;
  FILE *serverf, *clientf, *wiresharkf;

  while ((c = getopt_long(argc, argv, "s:c:g:w:trh", options, NULL)) != -1) {
    switch (c) {
    case 's':
      server_fname = strdup(optarg);
      break;
    case 'c':
      client_fname = strdup(optarg);
      break;
    case 'g':
      if ((sscanf(optarg, "%u", &generator) != 1)) {
	fprintf(stderr, usage, argv[0]);
	return 1;
      }
    case 'w':
      wireshark_fname = strdup(optarg);
      break;
    case 't':
      text = 1;
      break;
    case 'r':
      read = 1;
      break;
    case 'h':
      fprintf(stdout, usage, argv[0]);
      fprintf(stdout,
	      "\tGenerate Cyanish D-H constants\n"
	      "\t-g specifies the generator; the default is 4. NOTE: OpenSSL\n"
	      "\t\tconsiders 4 an \"unusable\" generator.\n"
	      "\t\tFor MOULa client: auth=41 game=73 gatekeeper=4\n"
	      "\tIf -s or -c is not provided, or -t or -r is provided, the\n"
	      "\t\tdata is printed to stdout.\n"
	      "\tIf -r or -w is provided, -s is required, and the server\n"
	      "\t\tfile will be read instead of generating new data.\n");
      return 0;
    default:
      fprintf(stderr, usage, argv[0]);
      return 1;
    }
  }
  if (optind > argc) {
    fprintf(stderr, usage, argv[0]);
    return 1;
  }
  if (read && !server_fname) {
    fprintf(stderr, "%s: -r requires -s\n", argv[0]);
    return 1;
  }
  if (wireshark_fname) {
    read = 1;
    if (!server_fname) {
      fprintf(stderr, "%s: -w requires -s\n", argv[0]);
      return 1;
    }
  }
  /* we have now processed the arguments */

  if (!read) {
    /* generate data */
    dh = DH_new();
    if (!dh) {
      ERR_print_errors_fp(stderr);
      fprintf(stderr, "Could not create DH (out of memory)\n");
      return 1;
    }
    if (!DH_generate_parameters_ex(dh, 512, generator, NULL)) {
      ERR_print_errors_fp(stderr);
      DH_free(dh);
      return 1;
    }
    if (!DH_check(dh, &codes)) {
      /* no idea why this might happen */
      fprintf(stderr, "Unable to check D-H parameters, please try again\n");
      DH_free(dh);
      return 1;
    }
    if (codes & ~(DH_UNABLE_TO_CHECK_GENERATOR)) {
      fprintf(stderr, "Bad D-H parameters generated, please try again\n");
      DH_free(dh);
      return 1;
    }
    if (!DH_generate_key(dh)) {
      ERR_print_errors_fp(stderr);
      fprintf(stderr, "Unable to generate D-H key\n");
      DH_free(dh);
      return 1;
    }
    /* now, dh->p is the modulus, dh->priv_key is "b", and dh->pub_key is
       what the client has */
    if (server_fname) {
      serverf = fopen(server_fname, "w");
      if (!serverf) {
	fprintf(stderr, "Cannot open file %s: %s\n", server_fname,
		strerror(errno));
      }
      else {
	if (!i2d_CyanDHParams_fp(serverf, dh)) {
	  ERR_print_errors_fp(stderr);
	}
	fclose(serverf);
      }
    }
    if (!server_fname || text) {
      print_private(dh);
    }
    if (client_fname) {
      int i;
      unsigned char buf[128];
      if (BN_num_bytes(dh->p) > 64) {
	fprintf(stderr, "Bad modulus (too big)\n");
      }
      if (BN_num_bytes(dh->pub_key) > 64) {
	fprintf(stderr, "Bad public key (too big)\n");
      }
      else {
	clientf = fopen(client_fname, "w");
	if (!clientf) {
	  fprintf(stderr, "Cannot open file %s: %s\n", client_fname,
		  strerror(errno));
	}
	else {
	  /* write little-endian raw data */
	  BN_bn2bin(dh->p, buf);
	  BN_bn2bin(dh->pub_key, buf+64);
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
	  fclose(clientf);
	}
      }
    }
    if (!client_fname || text) {
      printf("Public key:\n");
      print_bignum(dh->pub_key);
    }
    DH_free(dh);
  }
  else { /* !read */
    serverf = fopen(server_fname, "r");
    if (!serverf) {
      fprintf(stderr, "Cannot open file %s: %s\n", server_fname,
	      strerror(errno));
      return 1;
    }
    dh = d2i_CyanDHParams_fp(serverf, NULL);
    if (!dh) {
      ERR_print_errors_fp(stderr);
    }
    else if (wireshark_fname) {
      wiresharkf = fopen(wireshark_fname, "w");
      if (!wiresharkf) {
	fprintf(stderr, "Cannot open file %s: %s\n", wireshark_fname,
		strerror(errno));
	fclose(serverf);
	return 1;
      }
      {
	int size = BN_num_bytes(dh->p) + BN_num_bytes(dh->priv_key);
	unsigned char buf[size];

	BN_bn2bin(dh->p, buf);
	BN_bn2bin(dh->priv_key, buf+BN_num_bytes(dh->p));
	if (fwrite(buf, 1, size, wiresharkf) != 128) {
	  fprintf(stderr, "Error writing file %s: %s\n", wireshark_fname,
		  strerror(errno));
	}
      }
      fclose(wiresharkf);
    }
    else {
      print_private(dh);
    }
    if (dh) {
      DH_free(dh);
    }
    fclose(serverf);
  }
  return 0;
}

static void print_bignum(BIGNUM *bn) {
  int i, size = BN_num_bytes(bn);
  unsigned char buf[size];
  BN_bn2bin(bn, buf);
  for (i = 0; i < size; i++) {
    printf("%02X ", buf[i]);
    if ((i + 1) % 16 == 0) {
      printf("\n");
    }
  }
  if ((i % 16) != 0) {
    printf("\n");
  }
}

static void print_private(DH *dh) {
  printf("Prime (modulus):\n");
  print_bignum(dh->p);
  printf("Generator:\n");
  print_bignum(dh->g);
  printf("Private key:\n");
  print_bignum(dh->priv_key);
}
