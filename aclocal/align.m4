# MOSS - A server for the Myst Online: Uru Live client/protocol
# Copyright (C) 2006,2008,2011  a'moaca'
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


# Macro to test whether unaligned accesses fail. If they do,
#  NEED_STRICT_ALIGNMENT is defined.

AC_DEFUN([MOSS_ALIGN], [
  AC_CACHE_CHECK(
   [for alignment requirement],
   [moss_cv_need_align],
   [
      case "${host}" in
      *-*-cygwin* | *-*-mingw32*)
	# I am doing this because I have NO idea if the test code I am writing
	# will work in Windows. If you are running Windows on hardware that
	# requires strict alignment, ouch. (Does such a beast exist?)
	moss_cv_need_align=no
	;;
      *)
	AC_RUN_IFELSE(
	   dnl NOTE: we do a function call to get the unaligned data
	   dnl in order to force the compiler NOT to optimize out the whole
	   dnl body of the function.
	   [AC_LANG_SOURCE([[
		#include <stdlib.h>
		#include <signal.h>
		void bushandler(int s) { exit(1); }
		unsigned int gimme() {
			unsigned int data[2] = { 0x12345678, 0x90abcdef };
			unsigned int foo;
			signal(SIGBUS, bushandler);
			foo = *((unsigned int *)(((unsigned char *)data)+1));
			return foo;
		}
		int main() {
			if (gimme() == 0);
			exit(0);
		}
	   ]])],
	   [moss_cv_need_align=no],
	   [moss_cv_need_align=yes],
	   [moss_cv_need_align=yes])
	;;
      esac
   ])dnl end AC_CACHE_CHECK

  if test x$moss_cv_need_align = xyes; then
	AC_DEFINE(NEED_STRICT_ALIGNMENT,1,[Define to 1 if unaligned pointer dereferences fail.])
  fi
]) # MOSS_ALIGN
