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


dnl Find OpenSSL library

dnl The variable $moss_using_openssl is set to "yes" or "no"; if "yes"
dnl the variables $moss_openssl_CPPFLAGS, $moss_openssl_LDFLAGS, and
dnl $moss_openssl_LIBS are set.

AC_DEFUN([MOSS_OPENSSL], [

  moss_using_openssl="yes"
  AC_ARG_WITH([openssl],
    [AS_HELP_STRING([--with-openssl=PREFIX],[location of OpenSSL])],
    [if test x$withval = xno; then
	moss_using_openssl="no"
     else
	if test x$withval = xyes -o x$withval = x; then
		moss_openssl_path=""
	else
		moss_openssl_path="$withval"
	fi
     fi],
    [])

  if test x$moss_using_openssl = xyes; then
	AC_LANG_SAVE
	AC_LANG_C
	moss_cached_CPPFLAGS="$CPPFLAGS"
	moss_cached_LDFLAGS="$LDFLAGS"
	moss_cached_LIBS="$LIBS"

	AC_MSG_CHECKING([for OpenSSL installation])
	if test ! x$moss_openssl_path = x; then
		CPPFLAGS="$CPPFLAGS -I$moss_openssl_path/include"
		LDFLAGS="$LDFLAGS -L$moss_openssl_path/lib"
	fi
	LIBS="$LIBS -lssl"
	AC_COMPILE_IFELSE([AC_LANG_SOURCE([[#include <openssl/ssl.h>]])],
	  [AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <openssl/ssl.h>]],
		[[SSL_new(NULL)]])],
	    [AC_MSG_RESULT([yes])
	     if test x$moss_openssl_path = x; then
		moss_openssl_CPPFLAGS=""
		moss_openssl_LDFLAGS=""
		moss_openssl_LIBS="-lssl"
	     else
		moss_openssl_CPPFLAGS="-I$moss_openssl_path/include"
		moss_openssl_LDFLAGS="-L$moss_openssl_path/lib"
		moss_openssl_LIBS="-lssl"
	     fi
	     dnl on Mac OS X some symbols are in libcrypto instead
	     AC_MSG_CHECKING([whether -lcrypto is required])
	     AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <openssl/dh.h>]],
			[[DH_free(NULL)]])],
	      [AC_MSG_RESULT([no])],
	      [LIBS="$LIBS -lcrypto"
	       AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <openssl/dh.h>]],
			[[DH_free(NULL)]])],
	         [AC_MSG_RESULT([yes])
		  moss_openssl_LIBS="$moss_openssl_LIBS -lcrypto"],
		 [AC_MSG_ERROR([[I don't know where to find DH routines]])])])],
	    [AC_MSG_RESULT([no])
		moss_using_openssl="no"])],
	  [AC_MSG_RESULT([no])
		moss_using_openssl="no"])

	CPPFLAGS="$moss_cached_CPPFLAGS"
	LDFLAGS="$moss_cached_LDFLAGS"
	LIBS="$moss_cached_LIBS"
	AC_LANG_RESTORE
  fi
]) # MOSS_OPENSSL
