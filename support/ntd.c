/*
  MOSS - A server for the Myst Online: Uru Live client/protocol
  Copyright (C) 2007,2011  a'moaca'

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
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>

u_int32_t btea( u_int32_t * v, int n , u_int32_t * k );

int main(int argc, char *argv[]) {
  int n, len, all, i;
  FILE *inf, *outf;
  char *mapped;
  struct stat ss;

  u_int32_t crossRef[4];

  if ((argc != 4 && argc != 5) || (argv[1][0] != 'e' && argv[1][0] != 'd')) {
    printf("Usage: %s <e|d> <keyfile> <infile> [outfile]\n", argv[0]);
    exit(1);
  }
  n = -2;
  if (argv[1][0] == 'e') {
    n = 2;
  }
  inf = fopen(argv[2], "rb");
  if (!inf) {
    fprintf(stderr, "Could not open file %s for reading: %s\n",
	    argv[2], strerror(errno));
    exit(1);
  }
  len = fread((char*)crossRef, 1, 16, inf);
  fclose(inf);
  if (len != 16) {
    fprintf(stderr, "Key file not long enough!\n");
    exit(1);
  }
  inf = fopen(argv[3], "rb");
  if (!inf) {
    fprintf(stderr, "Could not open file %s for reading: %s\n",
	    argv[3], strerror(errno));
    exit(1);
  }
  if (argc == 5) {
    outf = fopen(argv[4], "wb");
    if (!outf) {
      fprintf(stderr, "Could not open file %s for writing: %s\n",
	      argv[4], strerror(errno));
      fclose(inf);
      exit(1);
    }
  }
  else {
    outf = stdout;
  }

  if (stat(argv[3], &ss)) {
    fprintf(stderr, "Error getting filesize of %s: %s\n", argv[3],
	    strerror(errno));
    fclose(outf);
    fclose(inf);
    exit(1);
  }
  len = ss.st_size;
  if (len % 8) {
    len += 8 - (len % 8);
  }
  mapped = mmap(0, len, PROT_READ|PROT_WRITE, MAP_FILE, fileno(inf), 0);
  fclose(inf);
  if (mapped == MAP_FAILED) {
    fprintf(stderr, "error mmap'ing file %s: %s\n", argv[3], strerror(errno));
    fclose(outf);
    exit(1);
  }
  if (n < 0) {
    /* decrypt */
    if (ss.st_size < 16) {
      fprintf(stderr, "%s is not a notthedroids file\n", argv[3]);
      fclose(outf);
      exit(1);
    }
    if (strncmp(mapped, "notthedroids", 12)) {
      fprintf(stderr, "%s is not a notthedroids file\n", argv[3]);
      fclose(outf);
      exit(1);
    }
    all = *(int*)(mapped+12);
    i = 16;
  }
  else {
    /* encrypt */
    char buf[16];
    memcpy(buf, "notthedroids", 12);
    memcpy(buf+12, (char*)&ss.st_size, 4);
    fwrite(buf, 1, 16, outf);
    all = len;
    i = 0;
  }
  while (i < len) {
    btea((u_int32_t*)(mapped+i), n, crossRef);
    i += 8;
  }
  fwrite(mapped+(n < 0 ? 16 : 0), 1, all, outf);
  fclose(outf);
  exit(0);
}

/* The following code is from the original at
   http://www.movable-type.co.uk/scripts/xxtea.pdf
*/

#define MX (((z>>5)^(y<<2))+((y>>3)^(z<<4)))^((sum^y)+(k[(p&3)^e]^z))

u_int32_t btea( u_int32_t * v, int n , u_int32_t * k ) {
  u_int32_t z, y=v[0], sum=0, e, DELTA=0x9e3779b9;
  u_int32_t p, q ;

  if (n > 1) {
    /* Coding Part */
    q = 6+52/n ;
    z = v[n-1];
    while ( q-- > 0 ) {
      sum += DELTA ;
      e = sum >> 2&3 ;
      for ( p = 0 ; p < n-1 ; p++ )
	y = v[p+1],
	  z = v[p] += MX;
      y = v[0] ;
      z = v[n-1] += MX;
    }
    return 0 ;
  }
  /* Decoding Part */
  else if (n < -1) {
    n = -n ;
    q = 6+52/n ;
    z = v[n-1];
    sum = q*DELTA ;
    while (sum != 0)   {
      e = sum>>2 & 3 ;
      for (p = n-1 ; p > 0 ; p-- )
	z = v[p-1],
	  y = v[p] -= MX;
      z = v[n-1] ;
      y = v[0] -= MX;
      sum -= DELTA ;
    }
    return 0 ;
  }
  return 1 ;
} /* Signal n=0,1,-1 */
