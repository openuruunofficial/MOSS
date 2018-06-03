/*
  MOSS - A server for the Myst Online: Uru Live client/protocol
  Copyright (C) 2010-2011  a'moaca'

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
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#ifdef HAVE_OPENSSL_SHA
#include <openssl/sha.h>
#else
#include <stdint.h>
#include "sha.h"
#endif

int main(int argc, char *argv[]) {
  unsigned int size, i;
  unsigned char hash[20];
  unsigned char *input, *cp;

  if (argc != 3) {
    fprintf(stderr, "Usage: %s <email address> <password>\n", argv[0]);
    exit(1);
  }

  size = strlen(argv[1]) + strlen(argv[2]);
  size *= 2;
  input = (unsigned char *)malloc(size);
  if (!input) {
    printf("Cannot allocate memory\n");
    exit(1);
  }

  cp = input;
  for (i = 0; i < strlen(argv[2])-1; i++) {
    *cp++ = argv[2][i];
    *cp++ = '\0';
  }
  /* yes, we are intentionally overwriting the last character of the
     password (and username) with 0 */
  *cp++ = '\0';
  *cp++ = '\0';
  for (i = 0; i < strlen(argv[1])-1; i++) {
    *cp++ = (char)tolower((unsigned char)argv[1][i]);
    *cp++ = '\0';
  }
  *cp++ = '\0';
  *cp++ = '\0';

#ifdef HAVE_OPENSSL_SHA
  SHA(input, size, hash);
#else
  sha0_hash(input, size, hash);
#endif
  free(input);

  for (i = 0; i < 20; i++) {
    printf("%02x", hash[i]);
  }
  printf("\n");
  return 0;
}
