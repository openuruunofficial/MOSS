# MOSS - A server for the Myst Online: Uru Live client/protocol
# Copyright (C) 2009,2011  a'moaca'
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


# Macro to test that MSG_RIGHTS is available for sendmsg/recvmsg.

AC_DEFUN([MOSS_MSG_RIGHTS],[
  AC_CACHE_CHECK(
    [for SCM_RIGHTS],
    [moss_cv_msg_rights],
    [
	AC_TRY_COMPILE(
	  [#include <sys/socket.h>],
	  [	struct cmsghdr msg;
		msg.cmsg_level = SOL_SOCKET;
		msg.cmsg_type = SCM_RIGHTS;],
	  [moss_cv_msg_rights=yes],
	  [moss_cv_msg_rights=no])
    ])dnl end AC_CACHE_CHECK
]) # MOSS_MSG_RIGHTS
