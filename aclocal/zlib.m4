# MOSS - A server for the Myst Online: Uru Live client/protocol
# Copyright (C) 2008,2011  a'moaca'
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


dnl Find zlib library

dnl The variables $moss_zlib_CPPFLAGS and $moss_zlib_LDFLAGS
dnl are set.

AC_DEFUN([MOSS_ZLIB], [

  AC_ARG_WITH([zlib],
    [AS_HELP_STRING([--with-zlib=PREFIX],[location of zlib])],
    [if test x$withval = xno; then
        AC_MSG_ERROR([zlib is required])
     else
	if test x$withval = xyes -o x$withval = x; then
		moss_zlib_path=""
	else
		moss_zlib_path="$withval"
	fi
     fi],
    [])

    AC_LANG_SAVE
    AC_LANG_C
    moss_cached_CPPFLAGS="$CPPFLAGS"
    moss_cached_LDFLAGS="$LDFLAGS"
    moss_cached_LIBS="$LIBS"

    AC_MSG_CHECKING([for zlib installation])
    if test ! x$moss_zlib_path = x; then
	CPPFLAGS="$CPPFLAGS -I$moss_zlib_path/include"
	LDFLAGS="$LDFLAGS -L$moss_zlib_path/lib"
    fi
    LIBS="$LIBS -lz"
    AC_COMPILE_IFELSE([AC_LANG_SOURCE([[#include <zlib.h>]])],
      [AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <zlib.h>]],
		[[zlibVersion()]])],
	    [AC_MSG_RESULT([yes])
	     if test x$moss_zlib_path = x; then
		moss_zlib_CPPFLAGS=""
		moss_zlib_LDFLAGS=""
	     else
		moss_zlib_CPPFLAGS="-I$moss_zlib_path/include"
		moss_zlib_LDFLAGS="-L$moss_zlib_path/lib"
	     fi],
	    [AC_MSG_RESULT([no])
	        AC_MSG_ERROR([zlib is required])])],
	  [AC_MSG_RESULT([no])
		AC_MSG_ERROR([zlib is required])])

    CPPFLAGS="$moss_cached_CPPFLAGS"
    LDFLAGS="$moss_cached_LDFLAGS"
    LIBS="$moss_cached_LIBS"
    AC_LANG_RESTORE
]) # MOSS_ZLIB
