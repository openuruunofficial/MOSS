# MOSS - A server for the Myst Online: Uru Live client/protocol
# Copyright (C) 2008-2011  a'moaca'
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

AC_INIT([moss], [1.0])

AC_CONFIG_MACRO_DIR([aclocal])
AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_SRCDIR([dispatcher.cc])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC
AC_PROG_CXX
AC_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)

###### system configuration

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h assert.h ctype.h dirent.h errno.h fcntl.h getopt.h iconv.h inttypes.h netdb.h netinet/in.h signal.h stdarg.h stdint.h stdio.h stdlib.h string.h sys/mman.h sys/param.h sys/select.h sys/socket.h sys/stat.h sys/time.h sys/uio.h sys/wait.h unistd.h varargs.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_TYPE(u_int)
AC_CHECK_TYPE(u_char)
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_MODE_T
AC_TYPE_INT8_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
if test "x$ac_cv_type_u_int" = "xno"; then
	AC_DEFINE(u_int,unsigned int,
		  [Define to `unsigned int' if not defined.])
fi
if test "x$ac_cv_type_u_char" = "xno"; then
	AC_DEFINE(u_char,unsigned char,
		  [Define to `unsigned char' if not defined.])
fi

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([alarm gethostbyname getaddrinfo gethostbyname_r gettimeofday memmove memset mkdir munmap select socket strcasecmp strchr strdup strerror strstr])

# Make sure compiler/OS has support for posix threads
AX_PTHREAD([
		AC_SUBST(AM_CFLAGS, "$AM_CFLAGS $PTHREAD_CFLAGS")
		AC_SUBST(AM_CXXFLAGS, "$AM_CXXFLAGS $PTHREAD_CFLAGS")
		AC_SUBST(AM_LDFLAGS, "$AM_LDFLAGS $PTHREAD_LDFLAGS")],
	AC_MSG_ERROR([Environment must support POSIX threads]))

# system config checks

AC_C_BIGENDIAN
MOSS_ALIGN
dnl I think this is always true, actually, if "real" configure is in use, but
dnl maybe there should be some kind of test
PATH_SEPARATOR="\"/\""
AC_DEFINE_UNQUOTED(PATH_SEPARATOR,$PATH_SEPARATOR,[File path directory separator ])
moss_need_openssl=no
moss_using_rsa=no
moss_using_dh=no
AC_ARG_ENABLE([encryption],
	[AS_HELP_STRING([--enable-encryption=type],
		[How to negotiate the symmetric key: (cyan_dh, none, rsa) [default=cyan_dh]])],
	[ case $enableval in
	  [[nN]][[oO]][[nN]][[eE]])
		;;
	  no)
		;;
	  [[rR]][[sS]][[aA]])
		moss_using_rsa=yes;;
	  [[cC]][[yY]][[aA]][[nN]]_[[dD]][[hH]])
		moss_using_dh=yes;;
	  yes)
		moss_using_dh=yes;;
	  *)
		AC_MSG_ERROR([Invalid encryption type]);;
	  esac ],
	[ moss_using_dh=yes ])
if test "x$moss_using_rsa" = "xno" -a "x$moss_using_dh" = "xno"; then
	AC_DEFINE(NO_ENCRYPTION,1,[Define to 1 to make client connections unencrypted])
else
	moss_need_openssl=yes;
	if test "x$moss_using_dh" = "xyes"; then
		AC_DEFINE(USING_DH,1,[Define to 1 to use modified D-H])
	else
		AC_DEFINE(USING_RSA,1,[Define to 1 to use RSA])
	fi
fi

AM_CONDITIONAL(USING_RSA, test "x$moss_using_rsa" = "xyes")
AM_CONDITIONAL(USING_DH, test "x$moss_using_dh" = "xyes")

###### check for dependent libraries

# database for backend
MOSS_POSTGRES
# PostgreSQL, libpqxx required
if test "x$moss_using_postgres" = "xno"; then
	AC_MSG_ERROR([PostgreSQL is required])
else
	AC_DEFINE(USE_POSTGRES,1,
		  [Define to 1 to use the PostgreSQL database])
	CPPFLAGS="$CPPFLAGS $moss_postgres_CPPFLAGS"
	LDFLAGS="$LDFLAGS $moss_postgres_LDFLAGS"
	if test "x$moss_using_libpqxx" = "xyes"; then
		AC_DEFINE(USE_PQXX,1,
			  [Define to 1 to use the libpqxx C++ library])
		CPPFLAGS="$CPPFLAGS $moss_libpqxx_CPPFLAGS"
		LDFLAGS="$LDFLAGS $moss_libpqxx_LDFLAGS"
		AC_SUBST(db_libs,"-lpq -lpqxx")
		if test "x$moss_libpqxx_trans_esc" = "xyes"; then
			AC_DEFINE(PQXX_TRANS_ESC,1,
				  [Define to 1 if libpqxx has transaction-based escape functions])
		fi
	else
		AC_MSG_ERROR([libpqxx is required])
	fi
fi

MOSS_OPENSSL
AM_CONDITIONAL(HAVE_OPENSSL, test "x$moss_using_openssl" = "xyes")
AM_CONDITIONAL(HAVE_OPENSSL_RC4, test "x$moss_openssl_has_rc4" = "xyes")
AM_CONDITIONAL(HAVE_OPENSSL_SHA, test "x$moss_openssl_has_sha" = "xyes")
if test x$moss_using_openssl = xno; then
	if test x$moss_need_openssl = xyes; then
		AC_MSG_ERROR([OpenSSL is required for --enable-encryption=$enable_encryption])
	else
		AC_MSG_WARN([[No OpenSSL; things won't work quite as well]])
		AC_SUBST(ssl_libs,"")
	fi
else
	CPPFLAGS="$CPPFLAGS $moss_openssl_CPPFLAGS"
	LDFLAGS="$LDFLAGS $moss_openssl_LDFLAGS"
	AC_DEFINE(HAVE_OPENSSL,1,[Define to 1 to use OpenSSL functionality])
	AC_SUBST(ssl_libs,$moss_openssl_LIBS)
fi

MOSS_ZLIB
CPPFLAGS="$CPPFLAGS $moss_zlib_CPPFLAGS"
LDFLAGS="$LDFLAGS $moss_zlib_LDFLAGS"
MOSS_ICONV
CPPFLAGS="$CPPFLAGS $moss_iconv_CPPFLAGS"
LDFLAGS="$LDFLAGS $moss_iconv_LDFLAGS"
LIBS="$LIBS $moss_iconv_LIBS"
MOSS_ICONV_CONST

# configure option for allowing downloads to proceed without application layer
# acks 
AC_ARG_ENABLE([fast-download],
	[AS_HELP_STRING([--enable-fast-download],
		[enable downloads without ChunkAcks [default=no]])],
	[if test "x$enableval" = "xyes"; then
		AC_DEFINE(DOWNLOAD_NO_ACKS,1,
			  [Define to 1 to enable downloads without ChunkAcks])
	 fi],
	[])

# configure option for account vs. player login exclusion
AC_ARG_ENABLE([single-login],
	[AS_HELP_STRING([--disable-single-login],
		[allow multiple avatars on the same account to be logged in])],
	[if test "x$enableval" = "xno"; then
		AC_DEFINE(MULTI_LOGIN,1,
			  [Define to 1 to enable multiple logins on the same account])
	 fi],
	[])

# configure option to disallow clients to skip the "secure download"
AC_ARG_ENABLE([require-secure-download],
	[AS_HELP_STRING([--enable-require-secure-download],
		[disallow clients from skipping the "secure download" [default=no]])],
	[if test "x$enableval" = "xyes"; then
		AC_DEFINE(DISALLOW_NO_DOWNLOAD,1,
			[Define to 1 to disallow clients from skipping the download])
	 fi],
	[])

# configure option to fork child processes where possible
MOSS_MSG_RIGHTS
AC_ARG_ENABLE([fork],
	[AS_HELP_STRING([--enable-fork],
		[make auth and file servers child processes [default=no]])],
	[if test "x$enableval" = "xyes"; then
		moss_fork_enable=1
	 else
		moss_fork_enable=0
	 fi],
	[moss_fork_enable=0])
AM_CONDITIONAL(FORK_ENABLE, test "x$moss_fork_enable" = "x1")
if test "x$moss_fork_enable" = "x1"; then
	AC_DEFINE(FORK_ENABLE,1,
		  [Define to 1 to make auth and file servers child processes])
    if test $ENABLE_THIS_LATER; then
	if test "x$moss_cv_msg_rights" = "xyes"; then
		AC_DEFINE(FORK_GAME_TOO,1,
			  [Define to 1 to make game server child processes])
	else
		AC_MSG_WARN([[SCM_RIGHTS not found; game servers will NOT be forked]])
	fi
    fi
fi

# configure option for special cases when in "standalone" mode
AC_ARG_ENABLE([standalone],
	[AS_HELP_STRING([--enable-standalone],
		[enable changes for "standalone" mode  [default=no]])],
	[if test "x$enableval" = "xyes"; then
		moss_standalone=1
	 else
		moss_standalone=0
	 fi],
	[moss_standalone=0])
AM_CONDITIONAL(STANDALONE, test "x$moss_standalone" = "x1")
if test "x$moss_standalone" = "x1"; then
	AC_DEFINE(STANDALONE,1,
		  [Define to 1 to enable changes for "standalone" mode])
fi

# configure option for special debugging code
AC_ARG_ENABLE([debug],
	[AS_HELP_STRING([--enable-debug],
		[run extra bug-hunting code [default=no]])],
	[if test "x$enableval" = "xyes"; then
		AC_DEFINE(DEBUG_ENABLE,1,
			  [Define to 1 to enable extra bug-hunting code])
	 fi],
	[])

# configure option for older protocol (changed sometime in Live 5-8)
AC_ARG_ENABLE([old-protocol],
	[AS_HELP_STRING([--enable-old-protocol],
		[enable older protocol (Live 1-3: yes, Live 4: 4, Live 8-9: no) [default=no]])],
	[if test "x$enableval" = "xyes" -o "x$enableval" = "x4"; then
		moss_old_protocol=1
		AC_DEFINE(OLD_PROTOCOL,1,
			  [Define to 1 to enable older protocol])
		if test "x$enableval" = "x4"; then
			AC_DEFINE(OLD_PROTOCOL4,1,
				  [Define to 1 to enable Live 4 protocol])
		else
			if ! test "x$enable_fast_download" = "xyes"; then
				AC_MSG_WARN([--enable-old-protocol given without --enable-fast-download; automatically enabling fast download])
				AC_DEFINE(DOWNLOAD_NO_ACKS,1,
					  [Define to 1 to enable downloads without ChunkAcks])
			fi
		fi
	 else
		moss_old_protocol=0
		if ! test "x$enableval" = "xno"; then
			AC_MSG_ERROR([--enable-old-protocol must be one of yes,no,4])
		fi
	 fi],
	[moss_old_protocol=0])
AM_CONDITIONAL(OLD_PROTOCOL, test "x$moss_old_protocol" = "x1")

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
