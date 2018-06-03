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
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/asn1t.h>
#include <openssl/bio.h>

#include "dh_keyfile.h"

static void print_bignum(const BIGNUM *bn);
static void print_as_C(FILE *file, unsigned char *buf);

int main(int argc, char *argv[]) {
  char c;
  opterr = 0;
  int text = 0, read = 1;
  static char *usage = "Usage: %s [-h] [-t] [-g <generator>] [-f] [-s <server file>] [-C <code file>] [-c <client file>] [-w <wireshark file>]\n";
  static struct option options[] = {
    { "server", required_argument, 0, 's' },
    { "client", required_argument, 0, 'c' },
    { "code", required_argument, 0, 'C' },
    { "generator", required_argument, 0, 'g' },
    { "wireshark", required_argument, 0, 'w' },
    { "text", no_argument, 0, 't' },
    { "readin", no_argument, 0, 'r' },
    { "force", no_argument, 0, 'o' },
    { "help", no_argument, 0, 'h' },
    { 0, 0, 0, 0 }
  };

  char *server_fname = NULL, *client_fname = NULL, *source_fname = NULL,
       *wireshark_fname = NULL;
  int exitval = 0, generator = 4, codes;
  dh_params *params = NULL;
  DH *dh = NULL;
  FILE *serverf = NULL, *clientf = NULL, *sourcef = NULL, *wiresharkf;
  const BIGNUM *p, *q, *g, *priv_key, *pub_key;

  while ((c = getopt_long(argc, argv,
			  "s:c:C:g:w:trfh", options, NULL)) != -1) {
    switch (c) {
    case 's':
      server_fname = strdup(optarg);
      break;
    case 'c':
      client_fname = strdup(optarg);
      break;
    case 'C':
      source_fname = strdup(optarg);
      break;
    case 'g':
      if ((sscanf(optarg, "%d", &generator) != 1)) {
	fprintf(stderr, usage, argv[0]);
	return 1;
      }
      break;
    case 'w':
      wireshark_fname = strdup(optarg);
      break;
    case 't':
      text = 1;
      break;
    case 'r':
      /* no-op */
      break;
    case 'f':
      read = 0;
      break;
    case 'h':
      fprintf(stdout, usage, argv[0]);
      fprintf(stdout,
	      "\tGenerate Cyanish D-H constants\n"
	      "\t-g specifies the generator in decimal; the default is 4.\n"
	      "\t\tNOTE: OpenSSL considers 4 an \"unusable\" generator.\n"
	      "\t\tFor MOULa client: auth=41 game=73 gatekeeper=4\n"
	      "\tIf -s is not provided, or -t is provided, the data\n"
	      "\t\tis printed to stdout.\n"
	      "\tIf the file provided by -s exists, the key is read from\n"
	      "\t\tthat file. To force creation of a new key, use -f.\n");
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
  if (!server_fname && (client_fname || source_fname)) {
    printf("There is no value in keeping the public key "
	   "and throwing away the private key.\n\n");
  }
  /* we have now processed the arguments */

  /* see if we can read the private key file */
  if (server_fname) {
    if (read) {
      serverf = fopen(server_fname, "r");
    }
    if (!serverf) {
      /* make a new one */
      read = 0;
      serverf = fopen(server_fname, "w");
    }
    if (!serverf) {
      fprintf(stderr, "Cannot open file %s: %s\n", server_fname,
	      strerror(errno));
      return 1;
    }
  }
  else {
    read = 0;
  }

  BIO *errio = BIO_new_fd(fileno(stderr), BIO_NOCLOSE);
  /* ERR_print_errors might do non-buffered writing to stderr so flush now */
  fflush(stderr);
  if (!read) {
    /* generate data */
    dh = DH_new();
    if (!dh) {
      ERR_print_errors(errio);
      fprintf(stderr, "Could not create DH (out of memory)\n");
      exitval = 1;
      goto done;
    }
    if (!DH_generate_parameters_ex(dh, 512, generator, NULL)) {
      ERR_print_errors(errio);
      exitval = 1;
      goto done;
    }
    if (!DH_check(dh, &codes)) {
      /* no idea why this might happen */
      fprintf(stderr, "Unable to check D-H parameters, please try again\n");
      exitval = 1;
      goto done;
    }
    if (codes & ~(DH_UNABLE_TO_CHECK_GENERATOR)) {
      fprintf(stderr, "Bad D-H parameters generated, please try again\n");
      exitval = 1;
      goto done;
    }
    if (!DH_generate_key(dh)) {
      ERR_print_errors(errio);
      fprintf(stderr, "Unable to generate D-H key\n");
      exitval = 1;
      goto done;
    }
    /* now, dh->p is the modulus, dh->priv_key is "b", and dh->pub_key is
       what the client has */
    if (serverf) {
      params = create_dh_params();
#if OPENSSL_VERSION_NUMBER < 0x10100000L
      params->p = dh->p;
      params->g = dh->g;
      params->priv_key = dh->priv_key;
#else
      DH_get0_pqg(dh, (const BIGNUM **)&params->p, &q,
		  (const BIGNUM **)&params->g);
      DH_get0_key(dh, &pub_key, (const BIGNUM **)&params->priv_key);
#endif
      BIO *serverio = BIO_new_fd(fileno(serverf), BIO_NOCLOSE);
      int writeok = i2d_CyanDHParams_bio(serverio, params);
      BIO_free(serverio);
      free(params);
      if (!writeok) {
	ERR_print_errors(errio);
	exitval = 1;
	goto done;
      }
    }
  }
  else { /* !read */
    BIO *serverio = BIO_new_fd(fileno(serverf), BIO_NOCLOSE);
    params = d2i_CyanDHParams_bio(serverio, NULL);
    BIO_free(serverio);
    if (!params) {
      ERR_print_errors_fp(stderr);
      fprintf(stderr, "Erorr reading key file %s\n", server_fname);
      exitval = 1;
      goto done;
    }
    dh = DH_new();
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    dh->p = params->p;
    dh->g = params->g;
    dh->priv_key = params->priv_key;
#else
    int ok = DH_set0_pqg(dh, params->p, NULL, params->g);
    if (!ok) {
      fprintf(stderr, "Error setting DH p and g\n");
    }
    else {
      /* 
       * some versions of OpenSSL unnecessarily required a non-NULL
       * public key
       */
      BIGNUM *empty = BN_new();
      ok = DH_set0_key(dh, empty, params->priv_key);
      if (!ok) {
	fprintf(stderr, "Error setting DH private key\n");
	/* p and g already adopted */
	params->p = NULL;
	params->g = NULL;
	BN_free(empty);
      }
    }
    if (!ok) {
      cleanup_dh_params(params);
      free(params);
      exitval = 1;
      goto done;
    }
#endif
    free(params);

    /* recompute public key if needed */
    if (client_fname || source_fname || text) {
      char *genstr;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
      genstr = BN_bn2dec(dh->g);
#else
      DH_get0_pqg(dh, &p, &q, &g);
      genstr = BN_bn2dec(g);
#endif
      if (sscanf(genstr, "%d", &generator) != 1) {
	fprintf(stderr, "Could not convert generator to decimal\n");
	OPENSSL_free(genstr);
	exitval = 1;
	goto done;
      }
      OPENSSL_free(genstr);
      if (!DH_generate_key(dh)) {
	ERR_print_errors_fp(stderr);
	fprintf(stderr, "Unable to recompute D-H public key\n");
	exitval = 1;
	goto done;
      }
    }
  }

  /* put all the DH parameters in local variables for convenience */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  p = dh->p;
  g = dh->g;
  pub_key = dh->pub_key;
  priv_key = dh->priv_key;
#else
  DH_get0_pqg(dh, &p, &q, &g);
  DH_get0_key(dh, &pub_key, &priv_key);
#endif

  if (!server_fname || text) {
    printf("Prime (modulus):\n");
    print_bignum(p);
    printf("Generator (in hex):\n");
    print_bignum(g);
    printf("Private key:\n");
    print_bignum(priv_key);
  }
  if (client_fname || source_fname) {
    int i;
    unsigned char buf[128];
    if (BN_num_bytes(p) > 64) {
      fprintf(stderr, "Bad modulus (too big)\n");
    }
    if (BN_num_bytes(pub_key) > 64) {
      fprintf(stderr, "Bad public key (too big)\n");
    }
    else {
      if (client_fname) {
	clientf = fopen(client_fname, "w");
	if (!clientf) {
	  fprintf(stderr, "Cannot open file %s: %s\n", client_fname,
		  strerror(errno));
	}
      }
      if (source_fname) {
	sourcef = fopen(source_fname, "w");
	if (!sourcef) {
	  fprintf(stderr, "Cannot open file %s: %s\n", source_fname,
		  strerror(errno));
	}
      }
      if (clientf || sourcef) {
	BN_bn2bin(p, buf);
	BN_bn2bin(pub_key, buf+64);
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
	if (clientf) {
	  /* write little-endian raw data */
	  if (fwrite(buf, 1, 128, clientf) != 128) {
	    fprintf(stderr, "Error writing file %s: %s\n", client_fname,
		    strerror(errno));
	  }
	  fclose(clientf);
	}
	if (sourcef) {
	  /* generate C++ source */
	  fprintf(sourcef,
		  "/* This file was auto-generated by make_cyan_dh */\n");
	  fprintf(sourcef, "\nstatic const unsigned kDhGValue = %d;\n",
		  generator);
	  fprintf(sourcef, "\nstatic const byte kDhNData[] = {");
	  print_as_C(sourcef, buf);
	  fprintf(sourcef, "\n};\nCOMPILER_ASSERT("
		  "sizeof(kDhNData) == kNetDiffieHellmanKeyBits / 8);\n");
	  fprintf(sourcef, "\nstatic const byte kDhXData[] = {");
	  print_as_C(sourcef, buf+64);
	  fprintf(sourcef, "\n};\nCOMPILER_ASSERT("
		  "sizeof(kDhXData) == kNetDiffieHellmanKeyBits / 8);\n");
	  fclose(sourcef);
	}
      }
    }
  }
  if (!server_fname || text) {
    printf("Public key:\n");
    print_bignum(pub_key);
  }
  if (wireshark_fname) {
    wiresharkf = fopen(wireshark_fname, "w");
    if (!wiresharkf) {
      fprintf(stderr, "Cannot open file %s: %s\n", wireshark_fname,
	      strerror(errno));
    }
    else {
      int size = BN_num_bytes(p) + BN_num_bytes(priv_key);
      unsigned char buf[size];

      BN_bn2bin(p, buf);
      BN_bn2bin(priv_key, buf+BN_num_bytes(p));
      if (fwrite(buf, 1, size, wiresharkf) != 128) {
	fprintf(stderr, "Error writing file %s: %s\n", wireshark_fname,
		strerror(errno));
      }
      fclose(wiresharkf);
    }
  }

 done:
  if (dh) {
    DH_free(dh);
  }
  BIO_free(errio);
  if (serverf) {
    fclose(serverf);
  }

  return exitval;
}

static void print_bignum(const BIGNUM *bn) {
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

static void print_as_C(FILE *file, unsigned char *buf) {
  int i;

  for (i = 0; i < 64; i++) {
    if (i % 8 == 0) {
      if (i == 0) {
	fprintf(file, "\n\t");
      }
      else {
	fprintf(file, ",\n\t");
      }
    }
    else {
      fprintf(file, ", ");
    }
    fprintf(file, "0x%02x", buf[i]);
  }
}
