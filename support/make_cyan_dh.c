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
  DH *dh = NULL;
  FILE *serverf = NULL, *clientf = NULL, *sourcef = NULL, *wiresharkf;

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

  if (!read) {
    /* generate data */
    dh = DH_new();
    if (!dh) {
      ERR_print_errors_fp(stderr);
      fprintf(stderr, "Could not create DH (out of memory)\n");
      exitval = 1;
      goto done;
    }
    if (!DH_generate_parameters_ex(dh, 512, generator, NULL)) {
      ERR_print_errors_fp(stderr);
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
      ERR_print_errors_fp(stderr);
      fprintf(stderr, "Unable to generate D-H key\n");
      exitval = 1;
      goto done;
    }
    /* now, dh->p is the modulus, dh->priv_key is "b", and dh->pub_key is
       what the client has */
    if (serverf) {
      if (!i2d_CyanDHParams_fp(serverf, dh)) {
	ERR_print_errors_fp(stderr);
	exitval = 1;
	goto done;
      }
    }
  }
  else { /* !read */
    dh = d2i_CyanDHParams_fp(serverf, NULL);
    if (!dh) {
      ERR_print_errors_fp(stderr);
      fprintf(stderr, "Erorr reading key file %s\n", server_fname);
      exitval = 1;
      goto done;
    }

    /* recompute public key if needed */
    if (client_fname || source_fname || text) {
      char *genstr;

      genstr = BN_bn2dec(dh->g);
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

  if (!server_fname || text) {
    print_private(dh);
  }
  if (client_fname || source_fname) {
    int i;
    unsigned char buf[128];
    if (BN_num_bytes(dh->p) > 64) {
      fprintf(stderr, "Bad modulus (too big)\n");
    }
    if (BN_num_bytes(dh->pub_key) > 64) {
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
    print_bignum(dh->pub_key);
  }
  if (wireshark_fname) {
    wiresharkf = fopen(wireshark_fname, "w");
    if (!wiresharkf) {
      fprintf(stderr, "Cannot open file %s: %s\n", wireshark_fname,
	      strerror(errno));
    }
    else {
      int size = BN_num_bytes(dh->p) + BN_num_bytes(dh->priv_key);
      unsigned char buf[size];

      BN_bn2bin(dh->p, buf);
      BN_bn2bin(dh->priv_key, buf+BN_num_bytes(dh->p));
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
  if (serverf) {
    fclose(serverf);
  }

  return exitval;
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
  printf("Generator (in hex):\n");
  print_bignum(dh->g);
  printf("Private key:\n");
  print_bignum(dh->priv_key);
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
