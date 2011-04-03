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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <iconv.h>
#include <sys/stat.h>
#include <getopt.h>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <stdexcept>
#include <list>
#include <vector>

#include "machine_arch.h"
#include "protocol.h"
#include "exceptions.h"
#include "UruString.h"
#include "PlKey.h"
#include "Logger.h"
#include "SDL.h"

void print_age(AgeDesc *age);

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <.age file>\n", argv[0]);
    return 1;
  }

  std::ifstream file(argv[1], std::ios_base::in);
  if (file.fail()) {
    fprintf(stderr, "Error opening file %s\n", argv[1]);
    return 1;
  }

  AgeDesc *age = NULL;
  try {
    age = AgeDesc::parse_file(file);
  }
  catch (const parse_error &e) {
    printf("Parse error line %d: %s\n", e.lineno(), e.what());
    return -1;
  }

  print_age(age);
  return 0;
}

// evil wrapper
class AgeDescWrapper : public AgeDesc {
public:
  std::vector<Page*> & pages() { return m_pages; }
  u_int start_date_time() { return m_start_date_time; }
  float daylen() { return m_daylen; }
  u_int capacity() { return m_capacity; }
  int seq_prefix() { return m_seq_prefix; }
  int release() { return m_release; }
};
void print_age(AgeDesc *inage) {
  AgeDescWrapper *age = (AgeDescWrapper *)inage;

  printf("StartDateTime: %u DayLength: %f\n",
	 age->start_date_time(), age->daylen());
  printf("LingerTime: %u MaxCapacity: %u\n",
	 age->linger_time(), age->capacity());
  printf("SequencePrefix: %d (%08x) ReleaseVersion: %d\n",
	 age->seq_prefix(), age->seq_prefix(), age->release());
  printf("Pages:\n");
  std::vector<AgeDesc::Page*>::iterator iter;
  for (iter = age->pages().begin(); iter != age->pages().end(); iter++) {
    AgeDesc::Page *p = *iter;
    printf("  Name: %s\tNumber: %u Conditional load: %u\n",
	   p->m_name, p->m_pagenum, p->m_conditional_load);
  }
}

