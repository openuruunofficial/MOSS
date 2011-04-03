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


dnl Find PostgreSQL and libpqxx

dnl The variable $moss_using_postgres is set to "yes" or "no"; if "yes"
dnl the variables $moss_postgres_CPPFLAGS and $moss_postgres_LDFLAGS
dnl are set.
dnl Then look for libpqxx if using PostgreSQL. The variables are analogous:
dnl $moss_using_libpqxx, $moss_libpqxx_CPPFLAGS, $moss_libpqxx_LDFLAGS

AC_DEFUN([MOSS_POSTGRES], [

  moss_using_postgres="yes"
  moss_using_libpqxx="yes"
  AC_ARG_WITH([postgres],
    [AS_HELP_STRING([--with-postgres=PREFIX],[location of PostgreSQL])],
    [if test x$withval = xno; then
	moss_using_postgres="no"
     else
	if test x$withval = xyes -o x$withval = x; then
		moss_postgres_prefix=""
	else
		moss_postgres_prefix="$withval"
	fi
     fi],
    [moss_postgres_prefix=""])
  AC_ARG_WITH([libpqxx],
    [AS_HELP_STRING([--with-libpqxx=PREFIX],[location of PostgreSQL C++ library])],
    [if test x$withval = xno; then
	moss_using_libpqxx="no"
     else
	if test x$withval = xyes -o x$withval = x; then
		moss_libpqxx_prefix=""
	else
		moss_libpqxx_prefix="$withval"
	fi
     fi],
    [moss_libpqxx_prefix=""])

  AC_LANG_SAVE
  AC_LANG_CPLUSPLUS
  moss_cached_CPPFLAGS="$CPPFLAGS"
  moss_cached_LDFLAGS="$LDFLAGS"
  moss_cached_LIBS="$LIBS"

  if test x$moss_using_postgres = xyes; then

	AC_MSG_CHECKING([for PostgreSQL installation])
	if test x$moss_postgres_prefix = x; then
		# look in standard locations
		moss_postgres_places="/ /usr /usr/local"
	else
		moss_postgres_places="$moss_postgres_prefix"
	fi
	for moss_postgres_dir in $moss_postgres_places; do
	  # try pg_config
	  if test x$moss_postgres_dir = x/; then
		moss_postgres_includedir=`pg_config --includedir` 2>/dev/null || moss_postgres_includedir=""
		moss_postgres_libdir=`pg_config --libdir` 2>/dev/null || moss_postgres_libdir=""
	  else
		moss_postgres_includedir=`$moss_postgres_dir/bin/pg_config --includedir` 2>/dev/null || moss_postgres_includedir="$moss_postgres_dir/include"
		moss_postgres_libdir=`$moss_postgres_dir/bin/pg_config --libdir` 2>/dev/null || moss_postgres_libdir="$moss_postgres_dir/lib"
	  fi

	  if test x$moss_postgres_includedir = x; then
		CPPFLAGS="$moss_cached_CPPFLAGS"
	  else
		CPPFLAGS="$moss_cached_CPPFLAGS -I$moss_postgres_includedir"
	  fi
	  if test x$moss_postgres_libdir = x; then
		LDFLAGS="$moss_cached_LDFLAGS"
	  else
		LDFLAGS="$moss_cached_LDFLAGS -L$moss_postgres_libdir"
	  fi
	  LIBS="$moss_cached_LIBS -lpq"
	  AC_COMPILE_IFELSE([AC_LANG_SOURCE([[#include <libpq-fe.h>]])],
	    [if test x$moss_postgres_includedir = x; then
		moss_postgres_CPPFLAGS=""
	     else
		moss_postgres_CPPFLAGS="-I$moss_postgres_includedir"
	     fi
	     AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <libpq-fe.h>]],
	       			[[PQconninfoOption *defaults;
				  defaults = PQconndefaults();]])],
	       [if test x$moss_postgres_libdir = x; then
			moss_postgres_LDFLAGS=" "
		else
			moss_postgres_LDFLAGS="-L$moss_postgres_libdir"
		fi],
	       [])],
	    [])
	  if ! test "x$moss_postgres_LDFLAGS" = "x"; then
		break;
	  fi
	done
	if test "x$moss_postgres_LDFLAGS" = "x"; then
		AC_MSG_RESULT([no])
		moss_using_postgres="no"
	elif test x$moss_postgres_dir = x/; then
		AC_MSG_RESULT([yes])
	else
		AC_MSG_RESULT([$moss_postgres_dir])
	fi
  fi

  # now look for libpqxx (sigh)
  if test x$moss_using_postgres = xyes; then
    AC_MSG_CHECKING([for libpqxx])
    if test x$moss_using_libpqxx = xyes; then
	# try where we found postgres unless it was overridden
	# XXX if the user puts in trailing slashes inconsistently this will
	# break
	if test x$moss_postgres_dir = x$moss_libpqxx_prefix -o x$moss_libpqxx_prefix = x; then
		moss_libpqxx_CPPFLAGS=""
		moss_libpqxx_LDFLAGS=""
	else
		moss_libpqxx_CPPFLAGS="-I$moss_libpqxx_prefix/include"
		moss_libpqxx_LDFLAGS="-L$moss_libpqxx_prefix/lib"
	fi

	CPPFLAGS="$CPPFLAGS $moss_libpqxx_CPPFLAGS"
	LDFLAGS="$LDFLAGS $moss_libpqxx_LDFLAGS"
	LIBS="$LIBS -lpqxx"

	AC_COMPILE_IFELSE([AC_LANG_SOURCE([[#include <pqxx/pqxx>]])],
	    [AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <pqxx/pqxx>]],
	       			[[try {} catch (pqxx::broken_connection&) {};]])],
	       [],
	       [moss_using_libpqxx="no"])],
	    [moss_using_libpqxx="no"])

	if test x$moss_using_libpqxx = xno; then
		AC_MSG_RESULT([no])
		moss_libpqxx_CPPFLAGS=""
		moss_libpqxx_LDFLAGS=""
	else
		if test x$moss_libpqxx_dir = x; then
			AC_MSG_RESULT([yes])
		else
			AC_MSG_RESULT([$moss_libpqxx_dir])
		fi
	fi
    else
	AC_MSG_RESULT([(disabled)])
    fi
  else
	# certainly we aren't using libpqxx then
	moss_using_libpqxx="no"
  fi

  CPPFLAGS="$moss_cached_CPPFLAGS"
  LDFLAGS="$moss_cached_LDFLAGS"
  LIBS="$moss_cached_LIBS"
  AC_LANG_RESTORE
]) # MOSS_POSTGRES
dnl whew!
