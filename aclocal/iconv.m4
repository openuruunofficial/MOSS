# MOSS - A server for the Myst Online: Uru Live client/protocol
# Copyright (C) 2011  a'moaca'
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


# This iconv thing is stupid. Some OSes require arg 2 to be const, and some
# not.

dnl Find iconv library (in case it's not in libc).
dnl The variables $moss_iconv_CPPFLAGS, $moss_iconv_LDFLAGS, and
dnl $moss_iconv_LIBS are set.

AC_DEFUN([MOSS_ICONV], [

  AC_ARG_WITH([iconv],
    [AS_HELP_STRING([--with-iconv=PREFIX],[location of iconv])],
    [if test x$withval = xno; then
        AC_MSG_ERROR([iconv is required])
     else
	if test x$withval = xyes -o x$withval = x; then
		moss_iconv_path=""
	else
		moss_iconv_path="$withval"
	fi
     fi],
    [])

  AC_LANG_PUSH([C])
  moss_cached_CPPFLAGS="$CPPFLAGS"
  moss_cached_LDFLAGS="$LDFLAGS"
  moss_cached_LIBS="$LIBS"

  AC_MSG_CHECKING([for iconv installation])
  if test ! x$moss_iconv_path = x; then
	CPPFLAGS="$CPPFLAGS -I$moss_iconv_path/include"
	LDFLAGS="$LDFLAGS -L$moss_iconv_path/lib"
  fi
  AC_COMPILE_IFELSE([AC_LANG_SOURCE([[#include <iconv.h>]])],
      [AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <iconv.h>]],
		[[iconv_open("UTF-8", "UTF-16LE")]])],
	    [AC_MSG_RESULT([yes])
	     if test x$moss_iconv_path = x; then
		moss_iconv_CPPFLAGS=""
		moss_iconv_LDFLAGS=""
		moss_iconv_LIBS=""
	     else
		moss_iconv_CPPFLAGS="-I$moss_iconv_path/include"
		moss_iconv_LDFLAGS="-L$moss_iconv_path/lib"
		moss_iconv_LIBS=""
	     fi],
	    [LIBS="$LIBS -liconv"
	     AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <iconv.h>]],
		      [[iconv_open("UTF-8", "UTF-16LE");]])],
		  [AC_MSG_RESULT([yes])
		   if test x$moss_iconv_path = x; then
		      moss_iconv_CPPFLAGS=""
		      moss_iconv_LDFLAGS=""
		      moss_iconv_LIBS="-liconv"
		   else
		      moss_iconv_CPPFLAGS="-I$moss_iconv_path/include"
		      moss_iconv_LDFLAGS="-L$moss_iconv_path/lib"
		      moss_iconv_LIBS="-liconv"
		   fi],
		  [AC_MSG_RESULT([no])
		   AC_MSG_ERROR([iconv is required])])])],
	  [AC_MSG_RESULT([no])
		AC_MSG_ERROR([iconv is required])])

  CPPFLAGS="$moss_cached_CPPFLAGS"
  LDFLAGS="$moss_cached_LDFLAGS"
  LIBS="$moss_cached_LIBS"
  AC_LANG_POP([C])
]) # MOSS_ICONV


dnl Check whether const is required in the iconv() call, and define
dnl ICONV_CONST.

AC_DEFUN([MOSS_ICONV_CONST], [
  AC_LANG_PUSH([C])

  AC_CACHE_CHECK([for iconv arg constness],
      [moss_cv_iconv_const],
      [AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM([[#include <stdlib.h>
			   #include <iconv.h>]],
	  [[size_t iconv(iconv_t cd, char **i, size_t *ib, char **o, size_t *ob)]])],
	[moss_cv_iconv_const=""],
	[moss_cv_iconv_const="const"])])

  AC_LANG_POP([C])

  AC_DEFINE_UNQUOTED(ICONV_CONST,$moss_cv_iconv_const,[Define to "const" if iconv() arg 2 requires const])
]) # MOSS_ICONV_CONST
