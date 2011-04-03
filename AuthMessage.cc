/*
  MOSS - A server for the Myst Online: Uru Live client/protocol
  Copyright (C) 2008-2011  a'moaca'

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
#include <string.h>
#ifdef HAVE_ASSERT_H
#include <assert.h>
#endif

#include <stdarg.h>
#include <pthread.h>
#include <iconv.h>

#include <sys/uio.h> /* for struct iovec */

#include <stdexcept>
#include <string>
#include <vector>

#include "machine_arch.h"
#include "exceptions.h"
#include "constants.h"
#include "protocol.h"
#include "msg_typecodes.h"
#include "util.h"
#include "UruString.h"

#include "Logger.h"
#include "VaultNode.h"
#include "NetworkMessage.h"
#include "BackendMessage.h"
#include "FileTransaction.h"
#include "AuthMessage.h"

NetworkMessage * AuthClientMessage::make_if_enough(const u_char *buf,
						   size_t len,
						   int *want_len,
						   bool become_owner) {
  NetworkMessage *in = NULL;
  bool became_owner = false;

  if (len < 2) {
    *want_len = -1;
    return NULL;
  }
  uint16_t type = read16(buf, 0);
  switch (type) {
  case kCli2Auth_PingRequest:
    if (len < 14) {
      *want_len = 14;
      return NULL;
    }
    in = new AuthPingMessage(buf, 14);
    break;
  case kCli2Auth_AcctLoginRequest:
    in = (NetworkMessage*)AuthClientLoginMessage::make_if_enough(buf,
								 len,
								 want_len);
    break;
  case kCli2Auth_AcctChangePasswordRequest:
    in =
      (NetworkMessage*)AuthClientChangePassMessage::make_if_enough(buf,
								   len,
								   want_len);
    break;
  case kCli2Auth_FileListRequest:
  case kCli2Auth_FileDownloadRequest:
  case kCli2Auth_FileDownloadChunkAck:
    in = (NetworkMessage*)AuthClientFileMessage::make_if_enough(buf,
								len,
								want_len);
    break;
  case kCli2Auth_VaultNodeCreate:
  case kCli2Auth_VaultNodeFetch:
  case kCli2Auth_VaultNodeSave:
  case kCli2Auth_VaultNodeAdd:
  case kCli2Auth_VaultNodeRemove:
  case kCli2Auth_VaultFetchNodeRefs:
  case kCli2Auth_VaultInitAgeRequest:
  case kCli2Auth_VaultNodeFind:
  //case kCli2Auth_VaultSetSeen:
  case kCli2Auth_VaultSendNode:
  case kCli2Auth_GetPublicAgeList:
  case kCli2Auth_SetAgePublic:
#ifndef OLD_PROTOCOL
  case kCli2Auth_ScoreCreate:
  //case kCli2Auth_ScoreDelete:
  case kCli2Auth_ScoreGetScores:
  case kCli2Auth_ScoreAddPoints:
  case kCli2Auth_ScoreTransferPoints:
  //case kCli2Auth_ScoreSetPoints:
  //case kCli2Auth_ScoreGetRanks:
#endif
    in = (NetworkMessage*)AuthClientVaultMessage::make_if_enough(buf,
								 len,
								 want_len,
								 become_owner);
    became_owner = true;
    break;
  case kCli2Auth_LogPythonTraceback:
  case kCli2Auth_LogStackDump:
  case kCli2Auth_LogClientDebuggerConnect:
    in = (NetworkMessage*)AuthClientLogMessage::make_if_enough(buf,
							       len,
							       want_len);
    break;
  case kCli2Auth_ClientRegisterRequest:
    if (len < 6) {
      *want_len = 6;
      return NULL;
    }
    else {
      in = (NetworkMessage*)(new AuthClientMessage(buf, 6, type));
    }
    break;
  case kCli2Auth_AcctSetPlayerRequest:
  case kCli2Auth_UpgradeVisitorRequest:
  case kCli2Auth_PlayerDeleteRequest:
    if (len < 10) {
      *want_len = 10;
      return NULL;
    }
    else {
      in = (NetworkMessage*)(new AuthClientMessage(buf, 10, type));
    }
    break;
  case kCli2Auth_PlayerCreateRequest:
    in = 
      (NetworkMessage*)AuthClientPlayerCreateMessage::make_if_enough(buf,
								     len,
								     want_len);
    break;
  case kCli2Auth_AgeRequest:
    in =
      (NetworkMessage*)AuthClientAgeRequestMessage::make_if_enough(buf,
								   len,
								   want_len);
    break;
#ifndef OLD_PROTOCOL
  case kCli2Auth_SendFriendInviteRequest:
    // because this message is not really supported, I am just using a basic
    // AuthClientMessage
    {
      if (len < 24) {
	*want_len = -1;
	return NULL;
      }
      u_int total = 24;
      total += (2*read16(buf, 22)); // urustring?
      if (total > 24+(256*2)/*256-char SMTP limit on email addresses*/) {
	throw overlong_message(total);
      }
      if (len < total+2) {
	*want_len = -1;
	return NULL;
      }
      total += 2+(2*read16(buf, total)); // urustring?
      if (total > 24+(256*2)+14/*"Friend"*/) {
	throw overlong_message(total);
      }
      if (len < total) {
	*want_len = total;
	return NULL;
      }
      else {
	in = (NetworkMessage*)(new AuthClientMessage(buf, total, type));
      }
    }
    break;
#endif
  case kCli2Auth_PropagateBuffer:
  default:
    in = new UnknownMessage(buf, len);
  }

  if (in && become_owner && !became_owner) {
    // this should never happen
#ifdef DEBUG_ENABLE
    throw std::logic_error("AuthClientMessage ownership of buffer not taken");
#endif
    delete[] buf;
  }
  return in;
}

bool AuthClientMessage::check_useable() const {
  switch(m_type) {
    // the vault messages are tested in AuthClientVaultMessage

    // since these are not created unless they have enough data, no need
    // to recheck
  case kCli2Auth_PingRequest:
  case kCli2Auth_AcctLoginRequest:
  case kCli2Auth_ClientRegisterRequest:
  case kCli2Auth_FileListRequest:
  case kCli2Auth_FileDownloadRequest:
  case kCli2Auth_FileDownloadChunkAck:
  case kCli2Auth_AcctSetPlayerRequest:
  case kCli2Auth_UpgradeVisitorRequest:
  case kCli2Auth_PlayerCreateRequest:
  case kCli2Auth_PlayerDeleteRequest:
  case kCli2Auth_AgeRequest:
#ifndef OLD_PROTOCOL
  case kCli2Auth_SendFriendInviteRequest:
#endif
  case kCli2Auth_AcctChangePasswordRequest:

  case kCli2Auth_LogPythonTraceback:
  case kCli2Auth_LogStackDump:
  case kCli2Auth_LogClientDebuggerConnect:
    return true;

  default:
    break;
  }
  return false;
}


AuthServerMessage::AuthServerMessage(const u_char *contents,
				     size_t content_len, int type)
  : NetworkMessage(type) {

  m_buf = new u_char[content_len];
  m_buflen = content_len;
  memcpy(m_buf, contents, m_buflen);
}

u_int AuthServerMessage::fill_iovecs(struct iovec *iov, u_int iov_ct,
				     u_int start_at) {
  u_int iov_off = 0;
  if (iov_off < iov_ct && start_at == 0) {
#ifdef WORDS_BIGENDIAN
    iov[iov_off].iov_base = ((char*)&m_type)+3;
#else
    iov[iov_off].iov_base = (char*)&m_type;
#endif
    iov[iov_off].iov_len = 1;
    iov_off++;
    start_at += 1;
  }
  if (iov_off < iov_ct && start_at < 2) {
    iov[iov_off].iov_base = (u_char*)&zero;
    iov[iov_off].iov_len = 1;
    iov_off++;
    start_at += 1;
  }
  if (iov_off < iov_ct) {
    iov[iov_off].iov_base = m_buf+(start_at-2);
    iov[iov_off].iov_len = m_buflen-(start_at-2);
    iov_off++;
  }
  return iov_off;
}

u_int AuthServerMessage::iovecs_written_bytes(u_int byte_ct, u_int start_at,
					      bool *msg_done) {
  if (byte_ct + start_at < message_len()) {
    *msg_done = false;
    return 0;
  }
  *msg_done = true;
  return (byte_ct + start_at) - message_len();
}

u_int AuthServerMessage::fill_buffer(u_char *buffer, size_t len,
				     u_int start_at, bool *msg_done) {
  u_int i = 0;
  *msg_done = false;
  if (start_at == 0 && len > i) {
    buffer[i] = (u_char)m_type;
    i++;
    start_at++;
  }
  if (start_at < 2 && len > i) {
    buffer[i] = 0;
    i++;
    start_at++;
  }
  if (len > i) {
    u_int to_copy = m_buflen - (start_at-2);
    if ((len-i) < to_copy) {
      to_copy = len-i;
    }
    else {
      *msg_done = true;
    }
    memcpy(buffer+i, m_buf+(start_at-2), to_copy);
    i += to_copy;
  }
  return i;
}

AuthServerLoginMessage::AuthServerLoginMessage(uint32_t reqid,
					       status_code_t status)
  : AuthServerMessage(kAuth2Cli_AcctLoginReply) {

  m_buflen = 48;
  m_buf = new u_char[m_buflen];
  memset(m_buf, 0, m_buflen);
  write32(m_buf, 0, reqid);
  write32(m_buf, 4, status);
}

AuthServerLoginMessage::AuthServerLoginMessage(uint32_t reqid,
					       status_code_t status,
					       const u_char *uuid,
					       customer_type_t customer_type,
					       const u_char *key)
  : AuthServerMessage(kAuth2Cli_AcctLoginReply) {

  m_buflen = 48;
  m_buf = new u_char[m_buflen];
  write32(m_buf, 0, reqid);
  write32(m_buf, 4, status);
  memcpy(m_buf+8, uuid, 16);
  write32(m_buf, 24, 8); // XXX unknown
  write32(m_buf, 28, customer_type);
  memcpy(m_buf+32, key, 16);
}

AuthServerChangePassMessage::
  AuthServerChangePassMessage(uint32_t reqid, status_code_t status)
    : AuthServerMessage(kAuth2Cli_AcctChangePasswordReply) {

  m_buflen = 8;
  m_buf = new u_char[m_buflen];
  write32(m_buf, 0, reqid);
  write32(m_buf, 4, status);
}

AuthServerFileMessage::AuthServerFileMessage(FileTransaction *trans,
					     int msg_type)
  : AuthServerMessage(msg_type), m_transaction(trans)
#ifdef DOWNLOAD_NO_ACKS
    , m_header_bytes(0)
#endif
{
  if (m_type == kAuth2Cli_FileListReply) {
    m_buflen = 14;
  }
  else {
    m_buflen = 22;
  }
  m_buf = new u_char[m_buflen];
  write16(m_buf, 0, m_type);
  write32(m_buf, 2, m_transaction->request_id());
  write32(m_buf, 6, 0);
  if (m_type == kAuth2Cli_FileDownloadChunk) {
    write32(m_buf, 10, m_transaction->file_len());
#if !defined(OLD_PROTOCOL) || defined(OLD_PROTOCOL4)
    write32(m_buf, 14, m_transaction->chunk_offset());
    write32(m_buf, 18, m_transaction->chunk_length());
#else
    write32(m_buf, 14, m_transaction->chunk_length());
    m_buflen = 18;
#endif
  }
  else {
    write32(m_buf, 10, m_transaction->chunk_length());
  }
}

AuthServerFileMessage::~AuthServerFileMessage() {
#ifndef DOWNLOAD_NO_ACKS
  if (m_type == kAuth2Cli_FileListReply) {
    delete m_transaction;
  }
#else
  // with DOWNLOAD_NO_ACKS, there is only one message per download,
  // so we can forget the transaction in the AuthServer and we always
  // delete it here regardless of message type
  delete m_transaction;
#endif
}

#ifdef DOWNLOAD_NO_ACKS
void AuthServerFileMessage::next_offset() {
#if !defined(OLD_PROTOCOL) || defined(OLD_PROTOCOL4)
  write32(m_buf, 14, m_transaction->chunk_offset());
  write32(m_buf, 18, m_transaction->chunk_length());
#else
  write32(m_buf, 14, m_transaction->chunk_length());
#endif
  // account for the header size of the just-completed message
  m_header_bytes += m_buflen;
}
#endif

size_t AuthServerFileMessage::message_len() const {
  u_int len = m_transaction->chunk_length();
  if (m_type == kAuth2Cli_FileListReply) {
    len = (len*2) + 2;
  }
  return m_buflen+len;
}

// these three methods are unfortunately nearly identical to
// FileServerMessage's :-(
u_int AuthServerFileMessage::fill_iovecs(struct iovec *iov, u_int iov_ct,
					 u_int start_at) {
  u_int i = 0;
  bool done = true;

#ifdef DOWNLOAD_NO_ACKS
  // start_at will encompass the entire message length, including the headers
  if (m_type == kAuth2Cli_FileDownloadChunk) {
    u_int so_far = m_header_bytes+m_transaction->chunk_offset();
    if (start_at < so_far) {
#ifdef DEBUG_ENABLE
      throw std::logic_error("Auth download fill_iovecs start_at too small");
#endif
      start_at = 0;
    }
    else {
      start_at -= so_far;
    }
  }
#endif

  if (start_at < m_buflen) {
    iov[i].iov_base = m_buf + start_at;
    iov[i].iov_len = m_buflen - start_at;
    i++;
    start_at = 0;
  }
  else {
    start_at -= m_buflen;
  }
  if (i < iov_ct) {
    i += m_transaction->fill_iovecs(iov+i, iov_ct-i, &start_at);
  }
  else {
    done = false;
  }
  if (done && m_type == kAuth2Cli_FileListReply) {
    if (i < iov_ct && start_at < 2) {
      iov[i].iov_base = (u_char*)&zero;
      iov[i].iov_len = 2-start_at;
      i++;
    }
    else {
      done = false;
    }
  }
#ifdef DOWNLOAD_NO_ACKS
  // ok, now, if the message is "done" (remember, not yet written) and this
  // is not the last chunk, make the MessageQueue think it must write now
  if (done && m_type == kAuth2Cli_FileDownloadChunk
      && !m_transaction->in_last_chunk()) {
    // this sets all remaining iovecs to zero length (a bit wasteful, but
    // a lot better than the previous "no acks" hack)
    memset(iov+i, 0, (iov_ct-i)*sizeof(struct iovec));
    i = iov_ct;
  }
#endif
  return i;
}

u_int AuthServerFileMessage::iovecs_written_bytes(u_int byte_ct,
						  u_int start_at,
						  bool *msg_done) {
#ifdef DOWNLOAD_NO_ACKS
  // start_at will encompass the entire message length, including the headers
  if (m_type == kAuth2Cli_FileDownloadChunk) {
    u_int so_far = m_header_bytes+m_transaction->chunk_offset();
    if (start_at < so_far) {
#ifdef DEBUG_ENABLE
      throw std::logic_error("Auth download iovecs_written_bytes start_at "
			     "too small");
#endif
      start_at = 0;
    }
    else {
      start_at -= so_far;
    }
  }
#endif

  if (start_at < m_buflen) {
    if (byte_ct + start_at < m_buflen) {
      *msg_done = false;
      return 0;
    }
    else {
      byte_ct -= m_buflen - start_at;
      start_at = m_buflen;
    }
  }
  byte_ct = m_transaction->iovecs_written_bytes(byte_ct, start_at - m_buflen,
						msg_done);
  if (m_type == kAuth2Cli_FileListReply && *msg_done) {
    if (byte_ct >= 2) {
      byte_ct -= 2;
    }
    else {
      *msg_done = false;
      return 0;
    }
  }
#ifdef DOWNLOAD_NO_ACKS
  // there is no ChunkAck (or it's ignored) so pretend it happened here
  if (*msg_done && m_type == kAuth2Cli_FileDownloadChunk) {
    if (!m_transaction->in_last_chunk()) {
      // go for another round!
      m_transaction->chunk_acked();
      next_offset();
      *msg_done = false;
      // byte_ct better be zero here
#ifdef DEBUG_ENABLE
      assert(byte_ct == 0);
#endif
      return 0;
    }
  }
#endif
  return byte_ct;
}

u_int AuthServerFileMessage::fill_buffer(u_char *buffer, size_t len,
					 u_int start_at, bool *msg_done) {
  u_int offset = 0;
  *msg_done = false;

#ifdef DOWNLOAD_NO_ACKS
  // start_at will encompass the entire message length, including the headers
  if (m_type == kAuth2Cli_FileDownloadChunk) {
    u_int so_far = m_header_bytes+m_transaction->chunk_offset();
    if (start_at < so_far) {
#ifdef DEBUG_ENABLE
      throw std::logic_error("Auth download fill_buffer start_at too small");
#endif
      start_at = 0;
    }
    else {
      start_at -= so_far;
    }
  }
#endif

  if (start_at < m_buflen) {
    offset = m_buflen - start_at;
    if (offset > len) {
      offset = len;
    }
    memcpy(buffer, m_buf + start_at, offset);
    start_at = 0;
  }
  else {
    start_at -= m_buflen;
  }
  if (len > offset) {
    offset += m_transaction->fill_buffer(buffer+offset, len-offset, &start_at,
					 msg_done);
  }
  if (m_type == kAuth2Cli_FileListReply && *msg_done) {
    if (start_at < 2) {
      if (len - offset >= 2-start_at) {
	if (start_at == 0) {
	  write16(buffer, offset, 0);
	  offset += 2;
	}
	else {
	  buffer[offset++] = 0;
	}
      }
      else {
	*msg_done = false;
      }
    }
  }
#ifdef DOWNLOAD_NO_ACKS
  // ok, now, if the message is "done" (remember, not yet written) and this
  // is not the last chunk, go on
  while (*msg_done && m_type == kAuth2Cli_FileDownloadChunk
	 && !m_transaction->in_last_chunk()) {
    // there is no ChunkAck (or it's ignored) so pretend it happened here
    m_transaction->chunk_acked();
    next_offset();
    *msg_done = false;
    // start_at better be zero here
#ifdef DEBUG_ENABLE
    assert(start_at == 0);
#endif
    // this is a repeat of the above code, but it can be simpler because it
    // assumes start_at is 0
    u_int wlen = m_buflen;
    if (wlen > len-offset) {
      wlen = len-offset;
    }
    memcpy(buffer+offset, m_buf, wlen);
    offset += wlen;
    wlen = 0;
    if (len > offset) {
      offset += m_transaction->fill_buffer(buffer+offset, len-offset, &wlen,
					   msg_done);
    }
    else {
      break;
    }
  }
#endif
  return offset;
}

AuthServerPlayerCreateMessage::
  AuthServerPlayerCreateMessage(uint32_t reqid, status_code_t status,
				kinum_t kinum, customer_type_t acct_type,
				UruString *name, UruString *gender)
  : AuthServerMessage(kAuth2Cli_PlayerCreateReply) {

  if (status != NO_ERROR) {
    m_buflen = 20;
  }
  else {
    m_buflen = 16+name->send_len(true, true, false)
		 +gender->send_len(true, true, false);
  }
  m_buf = new u_char[m_buflen];
  write32(m_buf, 0, reqid);
  write32(m_buf, 4, status);
  if (status == NO_ERROR) {
    write32(m_buf, 8, kinum);
    write32(m_buf, 12, acct_type);
    u_int write_at = 16;
    memcpy(m_buf+write_at, name->get_str(true, true, false),
	   name->send_len(true, true, false));
    write_at += name->send_len(true, true, false);
    memcpy(m_buf+write_at, gender->get_str(true, true, false),
	   gender->send_len(true, true, false));
    write_at += gender->send_len(true, true, false);
    if (write_at != m_buflen) {
      // shouldn't happen
      m_buflen = write_at;
    }
  }
  else {
    memset(m_buf+8, 0, 12);
  }
}

AuthServerVaultMessage::AuthServerVaultMessage(VaultPassthrough_BackendMessage
					       *backend)
  : AuthServerMessage(backend->uru_msgtype()), m_passthru(backend) {

#ifdef DEBUG_ENABLE
  if (!backend->persistable()) {
    throw std::logic_error("Message not marked as persistable "
			   "has been saved");
  }
#endif
  m_passthru->add_ref();
}

AuthServerVaultMessage::~AuthServerVaultMessage() {
  if (m_passthru && m_passthru->del_ref() < 1) {
    delete m_passthru;
  }
}

u_int AuthServerVaultMessage::fill_iovecs(struct iovec *iov, u_int iov_ct,
					  u_int start_at) {
  return m_passthru->fill_iovecs(iov, iov_ct, start_at+16);
}

u_int AuthServerVaultMessage::iovecs_written_bytes(u_int byte_ct,
						   u_int start_at,
						   bool *msg_done) {
  return m_passthru->iovecs_written_bytes(byte_ct, start_at+16, msg_done);
}

u_int AuthServerVaultMessage::fill_buffer(u_char *buffer, size_t len,
					  u_int start_at, bool *msg_done) {
  return m_passthru->fill_buffer(buffer, len, start_at+16, msg_done);
}

AuthServerAgeReplyMessage::AuthServerAgeReplyMessage(uint32_t reqid,
						     status_code_t result,
						     const u_char *contents,
						     size_t content_len)
  : AuthServerMessage(contents, content_len, kAuth2Cli_AgeReply) {

  write16(m_topbuf, 0, m_type);
  write32(m_topbuf, 2, reqid);
  write32(m_topbuf, 6, result);
}

u_int AuthServerAgeReplyMessage::fill_iovecs(struct iovec *iov, u_int iov_ct,
					     u_int start_at) {
  u_int iov_off = 0;
  if (iov_off < iov_ct) {
    if (start_at < 10) {
      iov[iov_off].iov_base = m_topbuf+start_at;
      iov[iov_off].iov_len = 10-start_at;
      iov_off++;
      start_at = 0;
    }
    else {
      start_at -= 10;
    }
  }
  if (iov_off < iov_ct) {
    iov[iov_off].iov_base = m_buf+start_at;
    iov[iov_off].iov_len = m_buflen-start_at;
    iov_off++;
  }
  return iov_off;
}

u_int AuthServerAgeReplyMessage::fill_buffer(u_char *buffer, size_t len,
					     u_int start_at, bool *msg_done) {
  u_int i = 0;
  *msg_done = false;
  if (start_at < 10) {
    i = 10-start_at;
    if (len < i) {
      i = len;
    }
    memcpy(buffer, m_topbuf+start_at, i);
    start_at += i;
  }
  if (len > i) {
    u_int to_copy = m_buflen - (start_at-10);
    if ((len-i) < to_copy) {
      to_copy = len-i;
    }
    else {
      *msg_done = true;
    }
    memcpy(buffer+i, m_buf+(start_at-10), to_copy);
    i += to_copy;
  }
  return i;
}

AuthServerKickMessage::AuthServerKickMessage(status_code_t reason)
  : AuthServerMessage(kAuth2Cli_KickedOff) {

  m_buflen = 4;
  m_buf = new u_char[m_buflen];
  write32(m_buf, 0, reason);
}

u_int AuthPingMessage::fill_iovecs(struct iovec *iov, u_int iov_ct,
				   u_int start_at) {
  if (iov_ct > 0) {
    iov[0].iov_base = m_buf+start_at;
    iov[0].iov_len = m_buflen-start_at;
    return 1;
  }
  else {
    return 0;
  }
}

u_int AuthPingMessage::iovecs_written_bytes(u_int byte_ct, u_int start_at,
					    bool *msg_done) {
  if (byte_ct + start_at >= m_buflen) {
    *msg_done = true;
    return (byte_ct + start_at) - m_buflen;
  }
  else {
    *msg_done = false;
    return 0;
  }
}

u_int AuthPingMessage::fill_buffer(u_char *buffer, size_t len,
				   u_int start_at, bool *msg_done) {
  if (m_buflen - start_at <= len) {
    memcpy(buffer, m_buf+start_at, m_buflen-start_at);
    *msg_done = true;
    return m_buflen-start_at;
  }
  else {
    memcpy(buffer, m_buf+start_at, len);
    *msg_done = false;
    return len;
  }
}

NetworkMessage * AuthClientLoginMessage::make_if_enough(const u_char *buf,
							size_t len,
							int *want_len) {
  if (len < 12) {
    *want_len = -1;
    return NULL;
  }
  u_int total = 12;
  total += (2*read16(buf, 10)); // urustring ?
  if (total > 12+2+(64*2)/*64 is max username length*/) {
    throw overlong_message(total);
  }
  u_int hash_loc = total;
  total += 20;
  if (len < total+2) {
    *want_len = -1;
    return NULL;
  }
  total += 2 + (2*read16(buf, total)); // urustring ?
  if (len < total+2) {
    *want_len = -1;
    return NULL;
  }
  u_int os_loc = total;
  total += 2 + (2*read16(buf, total)); // urustring ?
  if (total > 12+2+(64*2)+150/*guess*/+150/*148-byte os name?*/) {
    throw overlong_message(total);
  }
  if (len < total) {
    *want_len = total;
    return NULL;
  }
  return new AuthClientLoginMessage(buf, total, kCli2Auth_AcctLoginRequest,
				    hash_loc, os_loc);
}

NetworkMessage * AuthClientChangePassMessage::make_if_enough(const u_char *buf,
							     size_t len,
							     int *want_len) {
  if (len < 28) {
    *want_len = -1;
    return NULL;
  }
  u_int total = 8;
  total += (2*read16(buf, 6)); // urustring ?
  if (total > 26+2+(64*2)/*64 is max username length*/) {
    throw overlong_message(total);
  }
  u_int hash_loc = total;
  total += 20;
  if (len < total) {
    *want_len = total;
    return NULL;
  }
  return new AuthClientChangePassMessage(buf, total,
					 kCli2Auth_AcctChangePasswordRequest,
					 hash_loc);
}

NetworkMessage * AuthClientFileMessage::make_if_enough(const u_char *buf,
						       size_t len,
						       int *want_len) {
  uint16_t type = read16(buf, 0);
  int total = -1;
  switch (type) {
  case kCli2Auth_FileDownloadChunkAck:
    total = 6;
    break;
  case kCli2Auth_FileListRequest:
    if (len < 10) {
      break;
    }
    total = 8;
    total += 2*read16(buf, 6);
    if (len < (u_int)total+2) {
      total = -1;
      break;
    }
    total += 2 + (2*read16(buf, total));
    if (total > 28) {
      throw overlong_message(total);
    }
    break;
  case kCli2Auth_FileDownloadRequest:
    if (len >= 8) {
      total = 8 + (2*read16(buf, 6));
    }
    if (total > 8+2+(1024/*typical MAX_PATH*/*2)) {
      throw overlong_message(total);
    }
    break;
  default:
    // programmer error!
    throw std::logic_error("AuthClientFileMessage::make_if_enough called "
			   "for an unhandled type");
  }
  if (total == -1 || (int)len < total) {
    *want_len = total;
    return NULL;
  }
  return new AuthClientFileMessage(buf, total, type);
}

NetworkMessage * 
AuthClientPlayerCreateMessage::make_if_enough(const u_char *buf,
					      size_t len,
					      int *want_len) {
  if (len < 8) {
    *want_len = -1;
    return NULL;
  }
  u_int total = 8 + 2*(read16(buf, 6)); // urustring?
  if (total > 8+(62*2)/*62 is max avatar name length*/) {
    throw overlong_message(total);
  }
  if (len < total+2) {
    *want_len = -1;
    return NULL;
  }
  total += 2 + 2*(read16(buf, total)); // urustring?
  total += 2 + 2*(read16(buf, total)); // invite code // urustring?
  if (total > 8+(62*2)+2+(12*2)/*12 is length of YeeshaNoGlow*/+2+(62*2)) {
    // actually the longest gender should be "female" in PlayerCreateMessage
    throw overlong_message(total);
  }
  if (len < total) {
    *want_len = total;
    return NULL;
  }
  return new AuthClientPlayerCreateMessage(buf, total,
					   kCli2Auth_PlayerCreateRequest);
}

NetworkMessage * AuthClientVaultMessage::make_if_enough(const u_char *buf,
							size_t len,
							int *want_len,
							bool become_owner) {
  uint16_t type = read16(buf, 0);
  int total = -1;
  switch(type) {
  case kCli2Auth_VaultNodeCreate:
  case kCli2Auth_VaultNodeFind:
    if (len >= 10) {
      total = 10 + read32(buf, 6);
    }
    break;
  case kCli2Auth_VaultNodeFetch:
  case kCli2Auth_VaultFetchNodeRefs:
  case kCli2Auth_VaultSendNode:
    total = 10;
    break;
  case kCli2Auth_VaultNodeSave:
#if !defined(OLD_PROTOCOL) || defined(OLD_PROTOCOL4)
    if (len >= 30) {
      total = 30 + read32(buf, 26);
    }
#else
    if (len >= 26) {
      total = 26 + read32(buf, 22);
    }
#endif
    break;
  case kCli2Auth_VaultNodeAdd:
#ifndef OLD_PROTOCOL
  case kCli2Auth_ScoreTransferPoints:
#endif
#if !defined(OLD_PROTOCOL) || defined(OLD_PROTOCOL4)
    total = 18;
#else
    total = 14;
#endif
    break;
  case kCli2Auth_VaultNodeRemove:
#ifndef OLD_PROTOCOL
  case kCli2Auth_ScoreAddPoints:
#endif
#if !defined(OLD_PROTOCOL) || defined(OLD_PROTOCOL4)
    total = 14;
#else
    total = 10;
#endif
    break;
  case kCli2Auth_VaultInitAgeRequest:
    total = 38;
    for (int i = 0; i < 4; i++) {
      if ((int)len < total+2) {
	total = -9; // so that when 8 is added below it's still -1
	break;
      }
      total += 2 + (2*read16(buf, total)); // urustrings ?
    }
    total += 8;
    break;
  case kCli2Auth_GetPublicAgeList:
    if (len >= 8) {
      total = 8 + (2*read16(buf, 6)); // urustring ?
    }
    break;
#ifndef OLD_PROTOCOL
  case kCli2Auth_ScoreCreate:
    if (len >= 12) {
      total = 20 + (2*read16(buf, 10)); // urustring ?
    }
    break;
  case kCli2Auth_ScoreGetScores:
    if (len >= 12) {
      total = 12 + (2*read16(buf, 10)); // urustring ?
    }
    break;
#endif
  case kCli2Auth_SetAgePublic:
    total = 7;
    break;
  case kCli2Auth_VaultSetSeen:
#ifndef OLD_PROTOCOL
  case kCli2Auth_ScoreDelete:
  case kCli2Auth_ScoreSetPoints:
  case kCli2Auth_ScoreGetRanks:
#endif
    // XXX unknown
  default:
    // programmer error!
    throw std::logic_error("AuthClientVaultMessage::make_if_enough called "
			   "for an unhandled type");
  }
  // XXX this is a catch-all; we could be more precise
  if (total > 600*1024/*let images be nearly 600k, which is way too much*/) {
    throw overlong_message(total);
  }
  if (total == -1 || (int)len < total) {
    *want_len = total;
    return NULL;
  }
  return new AuthClientVaultMessage(buf, total, type, become_owner);
}

bool AuthClientVaultMessage::check_useable() const {
  u_int start = 0;

  switch(m_type) {
  case kCli2Auth_VaultNodeFetch:
  case kCli2Auth_VaultFetchNodeRefs:
  case kCli2Auth_VaultSendNode:
  case kCli2Auth_VaultNodeAdd:
  case kCli2Auth_VaultNodeRemove:
#ifndef OLD_PROTOCOL
  case kCli2Auth_ScoreTransferPoints:
  case kCli2Auth_ScoreAddPoints:
#endif
  case kCli2Auth_SetAgePublic:
    // fixed length
  case kCli2Auth_VaultInitAgeRequest:
  case kCli2Auth_GetPublicAgeList:
#ifndef OLD_PROTOCOL
  case kCli2Auth_ScoreCreate:
  case kCli2Auth_ScoreGetScores:
#endif
    // not created unless all the data is there
    return true;

  case kCli2Auth_VaultNodeSave:
#if !defined(OLD_PROTOCOL) || defined(OLD_PROTOCOL4)
    start = 20;
#else
    start = 16;
#endif
    // FALLTHROUGH
  case kCli2Auth_VaultNodeCreate:
  case kCli2Auth_VaultNodeFind:
    start += 6;
    if (m_buflen < start+4) {
      return false;
    }
    if (read32(m_buf, start)+start+4 < m_buflen) {
      // this should not ever happen!
      return false;
    }
    return VaultNode::check_len_by_bitfields(m_buf+start+4,
					     m_buflen-(start+4));

  case kCli2Auth_VaultSetSeen:
#ifndef OLD_PROTOCOL
  case kCli2Auth_ScoreDelete:
  case kCli2Auth_ScoreSetPoints:
  case kCli2Auth_ScoreGetRanks:
#endif
    // XXX unknown
  default:
    break;
  }
  return false;
}

NetworkMessage * AuthClientAgeRequestMessage::make_if_enough(const u_char *buf,
							     size_t len,
							     int *want_len) {
  if (len < 8) {
    *want_len = -1;
    return NULL;
  }
  *want_len = 8 + (2*read16(buf, 6)) + 16; // urustring ?
  if (*want_len > 8+(128/*string length in PublicAgeList*/*2)+16) {
    throw overlong_message(*want_len);
  }
  if ((int)len < *want_len) {
    return NULL;
  }
  return new AuthClientAgeRequestMessage(buf, *want_len, buf[0]);
}

NetworkMessage * AuthClientLogMessage::make_if_enough(const u_char *buf,
						      size_t len,
						      int *want_len) {
  if (len < 4) {
    *want_len = -1;
    return NULL;
  }
  *want_len = 4 + (2*read16(buf, 2)); // urustring ?
  if (*want_len > 6+(32*1024/*32k is a lot of log*/)) {
    throw overlong_message(*want_len);
  }
  if ((int)len < *want_len) {
    return NULL;
  }
  return new AuthClientLogMessage(buf, *want_len, buf[0]);
}
