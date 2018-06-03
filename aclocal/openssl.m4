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
dnl $moss_openssl_LIBS are set. In addition, $moss_openssl_has_rc4 and
dnl $moss_openssl_has_sha indicate if RC4 and SHA were found, respectively.

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
	dnl it seems libssl used to include our stuff but now it's libcrypto
	LIBS="$moss_cached_LIBS -lssl"
	moss_openssl_LIBS=""
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <openssl/rand.h>]],
		[[return RAND_status();]])],
	  [moss_openssl_LIBS="-lssl"],[])
	if test x$moss_use_ssl_lib = x; then
		LIBS="$moss_cached_LIBS -lcrypto"
		AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <openssl/rand.h>]],
			[[return RAND_status();]])],
		  [moss_openssl_LIBS="-lcrypto"],[])
	fi
	if test x$moss_openssl_LIBS = x; then
		AC_MSG_RESULT([no])
		moss_using_openssl="no"
	else
		AC_MSG_RESULT([yes])
		if test x$moss_openssl_path = x; then
			moss_openssl_CPPFLAGS=""
			moss_openssl_LDFLAGS=""
		else
			moss_openssl_CPPFLAGS="-I$moss_openssl_path/include"
			moss_openssl_LDFLAGS="-L$moss_openssl_path/lib"
		fi
	fi

	dnl OpenSSL has been removing things we need
	if test x$moss_using_openssl = xyes; then
	   AC_MSG_CHECKING([for OpenSSL SHA-0])
	   AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <openssl/sha.h>]],
		[[SHA_CTX c;
		  SHA_Init(&c);]])],
	     [AC_MSG_RESULT([yes])
		AC_DEFINE(HAVE_OPENSSL_SHA,1,[Define to 1 if OpenSSL provides SHA-0.])
		moss_openssl_has_sha="yes"],
	     [AC_MSG_RESULT([no])])
	   AC_MSG_CHECKING([for OpenSSL RC4])
	   AC_COMPILE_IFELSE([AC_LANG_SOURCE([[#include <openssl/rc4.h>
		RC4_KEY rc4;]])],
	     [AC_MSG_RESULT([yes])
		AC_DEFINE(HAVE_OPENSSL_RC4,1,[Define to 1 if OpenSSL provides RC4.])
		moss_openssl_has_rc4="yes"],
	     [AC_MSG_RESULT([no])])
	fi

	CPPFLAGS="$moss_cached_CPPFLAGS"
	LDFLAGS="$moss_cached_LDFLAGS"
	LIBS="$moss_cached_LIBS"
	AC_LANG_RESTORE
  fi
]) # MOSS_OPENSSL
