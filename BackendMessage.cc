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
#include <errno.h>

#include <iconv.h>

#include <sys/uio.h> /* for struct iovec */

#ifdef DEBUG_ENABLE
#include <stdexcept>
#endif
#include <string>
#include <vector>

#include "machine_arch.h"
#include "constants.h"
#include "protocol.h"
#include "msg_typecodes.h"
#include "backend_typecodes.h"
#include "util.h"
#include "UruString.h"
#include "VaultNode.h"
#include "Buffer.h"

#include "NetworkMessage.h"
#include "BackendMessage.h"


// isn't this nice and grotty?
#define START_FILL_TYPE \
  u_int done = 0, to_do, to_write; \
  do { \
    if (iovs) { \
      to_do = iov_ct; \
    } \
    else { \
      to_do = buflen; \
    } \
    *msg_done = false; \
  } while (0);
#define WRITE_4_BYTES(var, lastvar) \
  do { \
    if (start_at < 4) { \
      to_write = 4-start_at; \
      if (iovs) { \
	iov[done].iov_base = ((char*)&var)+start_at; \
	iov[done].iov_len = to_write; \
	done++; \
      } \
      else { \
	to_write = MIN(to_do-done, to_write); \
	memcpy(buffer+done, ((char*)&var)+start_at, to_write); \
	done += to_write; \
	if (lastvar) { \
	  if (to_write < 4-start_at) { \
	    return done; \
	  } \
	} \
      } \
      start_at = 0; \
    } \
    else if (lastvar) { \
      /* we have a problem! */ \
    } \
    else { \
      start_at -= 4; \
    } \
    if (!lastvar) { \
      if (done >= to_do) { \
	return done; \
      } \
    } \
  } while (0);
#define WRITE_2_BYTES(var, lastvar) \
  do { \
    if (start_at < 2) { \
      to_write = 2-start_at; \
      if (iovs) { \
	iov[done].iov_base = ((char*)&var)+start_at; \
	iov[done].iov_len = to_write; \
	done++; \
      } \
      else { \
	to_write = MIN(to_do-done, to_write); \
	memcpy(buffer+done, ((char*)&var)+start_at, to_write); \
	done += to_write; \
	if (lastvar) { \
	  if (to_write < 2-start_at) { \
	    return done; \
	  } \
	} \
      } \
      start_at = 0; \
    } \
    else if (lastvar) { \
      /* we have a problem! */ \
    } \
    else { \
      start_at -= 2; \
    } \
    if (!lastvar) { \
      if (done >= to_do) { \
	return done; \
      } \
    } \
  } while (0);
#define WRITE_1_BYTE(var, lastvar) \
  do { \
    if (start_at < 1) { \
      if (iovs) { \
	iov[done].iov_base = (char*)&var; \
	iov[done].iov_len = 1; \
	done++; \
      } \
      else { \
        buffer[done++] = var; \
	if (lastvar) { \
	  return done; \
	} \
      } \
    } \
    else if (lastvar) { \
      /* we have a problem! */ \
    } \
    else { \
      start_at -= 1; \
    } \
    if (!lastvar) { \
      if (done >= to_do) { \
	return done; \
      } \
    } \
  } while (0);
#define WRITE_URU_STRING_PTR(var, include_len, is_wide, include_null, flip, lastvar) \
  do { \
    if (var) { \
      u_int str_len = var->send_len(include_len, is_wide, include_null); \
      const u_char *str_str \
	= var->get_str(include_len, is_wide, include_null, flip); \
      if (start_at < str_len) { \
	to_write = str_len-start_at; \
	if (iovs) { \
	  iov[done].iov_base = (void*)(str_str+start_at); \
	  iov[done].iov_len = to_write; \
	  done++; \
	} \
	else { \
	  to_write = MIN(to_do-done, to_write); \
	  memcpy(buffer+done, str_str+start_at, to_write); \
	  done += to_write; \
	  if (lastvar) { \
	    if (to_write < str_len-start_at) { \
	      return done; \
	    } \
	  } \
	} \
	start_at = 0; \
      } \
      else if (lastvar) { \
	/* we have a problem! */ \
      } \
      else { \
	start_at -= str_len; \
      } \
    } \
    else { \
      WRITE_2_BYTES(zero, lastvar); \
    } \
    if (!lastvar) { \
      if (done >= to_do) { \
	return done; \
      } \
    } \
  } while (0);
#define WRITE_BUFFER(var, varlen, lastvar) \
  do { \
    if (start_at < varlen) { \
      to_write = varlen-start_at; \
      if (iovs) { \
	iov[done].iov_base = var+start_at; \
	iov[done].iov_len = to_write; \
	done++; \
      } \
      else { \
	to_write = MIN(to_do-done, to_write); \
	memcpy(buffer+done, var+start_at, to_write); \
	done += to_write; \
	if (lastvar) { \
	  if (to_write < varlen-start_at) { \
	    return done; \
	  } \
	} \
      } \
      start_at = 0; \
    } \
    else if (lastvar) { \
      /* we have a problem! */ \
    } \
    else { \
      start_at -= varlen; \
    } \
    if (!lastvar) { \
      if (done >= to_do) { \
	return done; \
      } \
    } \
  } while (0);
#define END_FILL_TYPE \
  *msg_done = true; \
  return done;



NetworkMessage * BackendMessage::make_if_enough(const u_char *buf, size_t len,
						int *want_len,
						bool become_owner) {
  if (len < 4) {
    *want_len = -1;
    return NULL;
  }
  *want_len = read32(buf, 0);
  if (*want_len > (int)len) {
    return NULL;
  }
  uint32_t msg_type = read32(buf, 4);

  switch(msg_type) {
  case ADMIN_HELLO:
  case ADMIN_HELLO|FROM_SERVER:
    return new Hello_BackendMessage(buf, *want_len, become_owner);
  case ADMIN_KILL_CLIENT|FROM_SERVER:
    return new KillClient_BackendMessage(buf, *want_len, become_owner);
  case AUTH_ACCT_LOGIN:
    return new AuthAcctLogin_ToBackendMessage(buf, *want_len, become_owner);
  case AUTH_ACCT_LOGIN|FROM_SERVER:
    return new AuthAcctLogin_FromBackendMessage(buf, *want_len, become_owner);
  case AUTH_KI_VALIDATE:
    return new AuthKIValidate_ToBackendMessage(buf, *want_len, become_owner);
  case AUTH_KI_VALIDATE|FROM_SERVER:
    return new AuthKIValidate_FromBackendMessage(buf, *want_len, become_owner);
  case AUTH_PLAYER_LOGOUT:
    return new AuthPlayerLogout_BackendMessage(buf, *want_len, become_owner);
  case AUTH_CHANGE_PASSWORD:
    return new AuthChangePassword_ToBackendMessage(buf, *want_len,
						   become_owner);
  case AUTH_CHANGE_PASSWORD|FROM_SERVER:
    return new AuthChangePassword_FromBackendMessage(buf, *want_len,
						     become_owner);
  case VAULT_PLAYER_CREATE:
    return new VaultPlayerCreate_ToBackendMessage(buf, *want_len,
						  become_owner);
  case VAULT_PLAYER_CREATE|FROM_SERVER:
    return new VaultPlayerCreate_FromBackendMessage(buf, *want_len,
						    become_owner);
  case VAULT_PLAYER_DELETE:
    return new VaultPlayerDelete_ToBackendMessage(buf, *want_len,
						  become_owner);
  case VAULT_PLAYER_DELETE|FROM_SERVER:
    return new VaultPlayerDelete_FromBackendMessage(buf, *want_len,
						    become_owner);
  case VAULT_PASSTHRU|FROM_SERVER:
    return new VaultPassthrough_BackendMessage(buf, *want_len, false,
					       become_owner);
  case TRACK_PING:
    return new TrackPing_BackendMessage(buf, *want_len, become_owner);
  case TRACK_DISPATCHER_HELLO:
    return new TrackDispatcherHello_BackendMessage(buf, *want_len,
						   become_owner);
  case TRACK_DISPATCHER_BYE:
    return new TrackDispatcherBye_BackendMessage(buf, *want_len,
						 become_owner);
  case TRACK_SERVICE_TYPES:
    return new TrackServiceTypes_BackendMessage(buf, *want_len, become_owner);
  case TRACK_FIND_SERVICE:
    return new TrackFindService_ToBackendMessage(buf, *want_len, become_owner);
  case TRACK_FIND_SERVICE|FROM_SERVER:
    return new TrackFindService_FromBackendMessage(buf, *want_len,
						   become_owner);
  case TRACK_GAME_HELLO:
    return new TrackGameHello_BackendMessage(buf, *want_len, become_owner);
  case TRACK_GAME_BYE:
    return new TrackGameBye_ToBackendMessage(buf, *want_len, become_owner);
  case TRACK_GAME_BYE|FROM_SERVER:
    return new TrackGameBye_FromBackendMessage(buf, *want_len, become_owner);
  case TRACK_GAME_PLAYERINFO:
    return new TrackGamePlayerInfo_BackendMessage(buf, *want_len,
						  become_owner);
  case TRACK_FIND_GAME:
    return new TrackAgeRequest_ToBackendMessage(buf, *want_len, become_owner);
  case TRACK_FIND_GAME|FROM_SERVER:
    return new TrackAgeRequest_FromBackendMessage(buf, *want_len,
						  become_owner);
  case TRACK_INTERAGE_FWD:
  case TRACK_INTERAGE_FWD|FROM_SERVER:
    return new TrackMsgForward_BackendMessage(buf, *want_len, msg_type,
					      become_owner);
  case TRACK_SDL_UPDATE|FROM_SERVER:
    return new TrackSDLUpdate_BackendMessage(buf, *want_len, become_owner);
  case TRACK_NEXT_GAMEID:
  case TRACK_NEXT_GAMEID|FROM_SERVER:
    return new TrackNextGameID_BackendMessage(buf, *want_len, msg_type,
					      become_owner);
  case TRACK_START_GAME|FROM_SERVER:
    return new TrackStartAge_FromBackendMessage(buf, *want_len, become_owner);
  case TRACK_START_GAME:
    return new TrackStartAge_ToBackendMessage(buf, *want_len, become_owner);
  case TRACK_ADD_PLAYER|FROM_SERVER:
    return new TrackAddPlayer_FromBackendMessage(buf, *want_len, become_owner);
  case TRACK_ADD_PLAYER:
    return new TrackAddPlayer_ToBackendMessage(buf, *want_len, become_owner);
  case MARKER_NEWGAME:
  case MARKER_NEWGAME|FROM_SERVER:
    return new MarkerGetGame_BackendMessage(buf, *want_len, msg_type,
					    become_owner);
  case MARKER_ADD:
  case MARKER_ADD|FROM_SERVER:
    return new MarkerAdd_BackendMessage(buf, *want_len, msg_type,
					become_owner);
  case MARKER_DUMP|FROM_SERVER:
    return new MarkersAll_BackendMessage(buf, *want_len, become_owner);
  case MARKER_STATE|FROM_SERVER:
    return new MarkersCaptured_BackendMessage(buf, *want_len, become_owner);
  case MARKER_GAME_RENAME:
  case MARKER_GAME_RENAME|FROM_SERVER:
    return new MarkerGameRename_BackendMessage(buf, *want_len, msg_type,
					       become_owner);
  case MARKER_GAME_DELETE:
  case MARKER_GAME_DELETE|FROM_SERVER:
    return new MarkerGameDelete_BackendMessage(buf, *want_len, msg_type,
					       become_owner);
  case MARKER_RENAME:
  case MARKER_RENAME|FROM_SERVER:
    return new MarkerGameRenameMarker_BackendMessage(buf, *want_len, msg_type,
						     become_owner);
  case MARKER_DELETE:
  case MARKER_DELETE|FROM_SERVER:
    return new MarkerGameDeleteMarker_BackendMessage(buf, *want_len, msg_type,
						     become_owner);
  case MARKER_CAPTURE:
  case MARKER_CAPTURE|FROM_SERVER:
    return new MarkerGameCaptureMarker_BackendMessage(buf, *want_len,
						      msg_type, become_owner);
  case MARKER_GAME_STOP:
  case MARKER_GAME_STOP|FROM_SERVER:
    return new MarkerGameStop_BackendMessage(buf, *want_len, msg_type,
					     become_owner);


  case VAULT_PASSTHRU:
    {
      NetworkMessage *in
	= VaultPassthrough_BackendMessage::make_if_enough(buf, len, want_len,
							  become_owner);
      if (in || *want_len != 0) {
	return in;
      }
      // FALLTHROUGH
    }
  default:
    return new UnknownMessage(buf, len);
  }
}

NetworkMessage *
VaultPassthrough_BackendMessage::make_if_enough(const u_char *buf, size_t len,
						int *want_len,
						bool become_owner) {
  if (len < 18) {
    // this should not happen
    *want_len = 0;
    return NULL;
  }
  int msgtype = read16(buf, 16);
  switch(msgtype) {
  case kCli2Auth_VaultFetchNodeRefs:
    return new VaultFetchRefs_ToBackendMessage(buf, *want_len, become_owner);
  case kCli2Auth_VaultNodeFind:
  case kCli2Auth_VaultNodeSave:
  case kCli2Auth_VaultNodeCreate:
    return new VaultNode_ToBackendMessage(buf, *want_len, become_owner);
  case kCli2Auth_VaultNodeFetch:
    return new VaultNodeFetch_ToBackendMessage(buf, *want_len, become_owner);
  case kCli2Auth_VaultNodeAdd:
  case kCli2Auth_VaultNodeRemove:
    return new VaultRefChange_ToBackendMessage(buf, *want_len, become_owner);
  case kCli2Auth_VaultInitAgeRequest:
    return new VaultInitAge_ToBackendMessage(buf, *want_len, become_owner);
  case kCli2Auth_GetPublicAgeList:
    return new VaultAgeList_ToBackendMessage(buf, *want_len, become_owner);
  case kCli2Auth_VaultSendNode:
    return new VaultNodeSend_BackendMessage(buf, *want_len, become_owner);
  case kCli2Auth_SetAgePublic:
    return new VaultSetAgePublic_BackendMessage(buf, *want_len, become_owner);
#ifndef OLD_PROTOCOL
  case kCli2Auth_ScoreGetScores:
    return new VaultScoreGet_ToBackendMessage(buf, *want_len, become_owner);
  case kCli2Auth_ScoreCreate:
    return new VaultScoreCreate_BackendMessage(buf, *want_len, become_owner);
  case kCli2Auth_ScoreAddPoints:
    return new VaultScoreAddPoints_BackendMessage(buf, *want_len,
						  become_owner);
  case kCli2Auth_ScoreTransferPoints:
    return new VaultScoreXferPoints_BackendMessage(buf, *want_len,
						   become_owner);
#endif


  default:
    break;
  }
  // unknown message type
  *want_len = 0;
  return NULL;
}

u_int BackendMessage::fill_iovecs(struct iovec *iov, u_int iov_ct,
				  u_int start_at) {
  u_int done = 0;

  if (start_at < 16) {
    iov[done].iov_base = m_header+start_at;
    iov[done].iov_len = 16-start_at;
    done++;
    start_at = 0;
  }
  else {
    start_at -= 16;
  }
  if (done >= iov_ct) {
    return done;
  }
  bool msg_done = false;
  done += fill_type(true, start_at, &msg_done, iov+done, iov_ct-done,
		    NULL, 0); 
  return done;
}

u_int BackendMessage::iovecs_written_bytes(u_int byte_ct, u_int start_at,
					   bool *msg_done) {
  if (byte_ct + start_at >= message_len()) {
    *msg_done = true;
    return byte_ct - (message_len()-start_at);
  }
  else {
    *msg_done = false;
    return 0;
  }
}

u_int BackendMessage::fill_buffer(u_char *buffer, size_t len, u_int start_at,
				  bool *msg_done) {
  u_int done = 0;

  if (start_at < 16) {
    done = MIN(len, 16-start_at);
    memcpy(buffer, m_header+start_at, done);
  }
  if (message_len() - start_at <= done) {
    *msg_done = true;
    return done;
  }
  else if (start_at + done == len) {
    *msg_done = false;
    return done;
  }
  else if (start_at > 16) {
    start_at -= 16;
  }
  else {
    start_at = 0;
  }
  done += fill_type(false, start_at, msg_done, NULL, 0, buffer+done, len-done);
  return done;
}

Hello_BackendMessage::
  Hello_BackendMessage(uint32_t id1, uint32_t id2, uint32_t peer_info,
		       bool to_server)
    : BackendMessage(ADMIN_HELLO|(to_server ? 0 : FROM_SERVER)),
      m_peer_info(htole32(peer_info))
{
  setup_header(id1, id2, 4);
}

Hello_BackendMessage::
  Hello_BackendMessage(const u_char *inbuf, size_t in_len,
		       bool become_owner)
    : BackendMessage(read32(inbuf, 4), inbuf, in_len),
      m_peer_info(read32le(inbuf, 16))
{
  if (become_owner) {
    delete[] inbuf;
  }
#ifdef DEBUG_ENABLE
  // message should not be queued m_unsafe = false;
#endif
}

u_int Hello_BackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  START_FILL_TYPE;
  WRITE_4_BYTES(m_peer_info, true);
  END_FILL_TYPE;
}

KillClient_BackendMessage::
  KillClient_BackendMessage(uint32_t id1, uint32_t id2, kill_reason_t why,
			    kinum_t player_id)
  : BackendMessage(ADMIN_KILL_CLIENT|FROM_SERVER), m_reason(htole32(why)),
    m_ki(htole32(player_id))
{
  if (why == AUTH_DISCONNECT) {
    setup_header(id1, id2, 8);
  }
  else {
    setup_header(id1, id2, 4);
  }
}

KillClient_BackendMessage::
  KillClient_BackendMessage(const u_char *inbuf, size_t in_len,
			    bool become_owner)
  : BackendMessage(ADMIN_KILL_CLIENT|FROM_SERVER, inbuf, in_len),
    m_reason(htole32(KillClient_BackendMessage::UNKNOWN)),
    m_ki(0)
{
  m_reason = read32le(inbuf, 16);
  if (why() == AUTH_DISCONNECT) {
    m_ki = read32le(inbuf, 20);
  }
  if (become_owner) {
    delete[] inbuf;
  }
#ifdef DEBUG_ENABLE
  // message should not be queued m_unsafe = false;
#endif
}

u_int KillClient_BackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  bool togame = (why() == AUTH_DISCONNECT ? true : false);
  START_FILL_TYPE;
  WRITE_4_BYTES(m_reason, !togame);
  if (togame) {
    WRITE_4_BYTES(m_ki, true);
  }
  END_FILL_TYPE;
}

AuthAcctLogin_ToBackendMessage::
  AuthAcctLogin_ToBackendMessage(uint32_t id1, uint32_t id2,
				 uint32_t reqid, const UruString &name,
				 const u_char *hash, authtype_t authtype,
				 uint32_t server_nonce, uint32_t client_nonce)
    : BackendMessage(AUTH_ACCT_LOGIN), m_reqid(htole32(reqid)), m_name(NULL),
      m_authtype(htole32(authtype))
{
  m_name = new UruString(name, true);
  memcpy(m_pwhash, hash, 20);
  u_int len = 28+m_name->send_len(true, true, true);
  if (this->authtype() != PLAIN_HASH) {
    // these are provided little-endian, no swapping necessary
    m_server = server_nonce;
    m_client = client_nonce;
    len += 8;
  }
  setup_header(id1, id2, len);
}

AuthAcctLogin_ToBackendMessage::
  AuthAcctLogin_ToBackendMessage(const u_char *inbuf, size_t in_len,
				 bool become_owner)
    : BackendMessage(AUTH_ACCT_LOGIN, inbuf, in_len), m_reqid(0), m_name(NULL),
      m_authtype(htole32(PLAIN_HASH))
{
  u_int read_at = 16;
  m_reqid = read32le(inbuf, read_at);
  read_at += 4;
  m_authtype = read32le(inbuf, read_at);
  read_at += 4;
  m_name = new UruString(inbuf+read_at, in_len-read_at,
			 true, true, !become_owner);
  read_at += m_name->arrival_len();
  if (in_len-read_at < 20) {
    // XXX serious problem
  }
  memcpy(m_pwhash, inbuf+read_at, 20);
  if (become_owner) {
    // pointed at by m_name!
    m_buf = const_cast<u_char*>(inbuf);
#ifdef DEBUG_ENABLE
    // message should not be queued m_unsafe = false;
#endif
  }
  read_at += 20;
  if (authtype() != PLAIN_HASH) {
    if (in_len-read_at < 8) {
      // XXX another serious problem -- login will fail
    }
    else {
      m_server = read32le(inbuf, read_at);
      read_at += 4;
      m_client = read32le(inbuf, read_at);
    }
  }
}

u_int AuthAcctLogin_ToBackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  bool nonces = (authtype() == PLAIN_HASH ? false : true);
  START_FILL_TYPE;
  WRITE_4_BYTES(m_reqid, false);
  WRITE_4_BYTES(m_authtype, false);
  WRITE_URU_STRING_PTR(m_name, true, true, true, false, false);
  WRITE_BUFFER(m_pwhash, 20, !nonces);
  if (nonces) {
    WRITE_4_BYTES(m_server, false);
    WRITE_4_BYTES(m_client, true);
  }
  END_FILL_TYPE;
}

AuthAcctLogin_FromBackendMessage::
  AuthAcctLogin_FromBackendMessage(uint32_t id1, uint32_t id2,
				   uint32_t reqid, status_code_t result,
				   const u_char *acct_uuid,
				   customer_type_t acct_type,
				   UruString *dirname,
				   u_char *p_info, u_int p_info_len,
				   bool become_owner)
    : BackendMessage(AUTH_ACCT_LOGIN|FROM_SERVER), m_reqid(htole32(reqid)),
      m_result(htole32(result)), m_acct_type(htole32(acct_type)),
      m_dirname(dirname)
{
  if (result == NO_ERROR) {
    memcpy(m_uuid, acct_uuid, UUID_RAW_LEN);
    if (p_info_len > 0) {
      m_buflen = p_info_len;
      if (become_owner) {
	m_buf = p_info;
      }
      else {
	m_buf = new u_char[p_info_len];
	memcpy(m_buf, p_info, p_info_len);
      }
    }
    else if (become_owner && p_info) {
      delete[] p_info;
    }
    setup_header(id1, id2, 28+dirname->send_len(true, false, true)+p_info_len);
  }
  else {
    memset(m_uuid, 0, UUID_RAW_LEN);
    setup_header(id1, id2, 8);
    if (become_owner && p_info) {
      delete[] p_info;
    }
  }
}

AuthAcctLogin_FromBackendMessage::
  AuthAcctLogin_FromBackendMessage(const u_char *inbuf, size_t in_len,
				   bool become_owner)
    : BackendMessage(AUTH_ACCT_LOGIN|FROM_SERVER, inbuf, in_len),
      m_reqid(0), m_result(htole32(ERROR_INTERNAL)),
      m_acct_type(htole32(GUEST_CUSTOMER)), m_dirname(NULL)
{
  m_reqid = read32le(inbuf, 16);
  m_result = read32le(inbuf, 20);
  if (result() == NO_ERROR) {
    u_int read_at = 24;
    memcpy(m_uuid, inbuf+read_at, UUID_RAW_LEN);
    read_at += UUID_RAW_LEN;
    m_acct_type = read32le(inbuf, read_at);
    read_at += 4;
    m_dirname = new UruString(inbuf+read_at, in_len-read_at,
			      true, false, true);
    m_buflen = message_len()-(read_at+m_dirname->arrival_len());
    if (m_buflen < 0) {
      // XXX serious problem
    }
    else if (m_buflen > 0) {
      m_buf = new u_char[m_buflen];
      memcpy(m_buf, inbuf+read_at+m_dirname->arrival_len(), m_buflen);
    }
  }
  else {
    memset(m_uuid, 0, UUID_RAW_LEN);
  }
  if (become_owner) {
    delete[] inbuf;
  }
#ifdef DEBUG_ENABLE
  // XXX we didn't really need to copy the data
  // message should not be queued m_unsafe = false; // data was copied
#endif
}

u_int AuthAcctLogin_FromBackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  bool bad = (result() != NO_ERROR);
  START_FILL_TYPE;
  WRITE_4_BYTES(m_reqid, false);
  WRITE_4_BYTES(m_result, bad);
  if (!bad) {
    WRITE_BUFFER(m_uuid, UUID_RAW_LEN, false);
    WRITE_4_BYTES(m_acct_type, false);
    WRITE_URU_STRING_PTR(m_dirname, true, false, true, false, false);
    WRITE_BUFFER(m_buf, m_buflen, true);
  }
  END_FILL_TYPE;
}

AuthKIValidate_ToBackendMessage::
  AuthKIValidate_ToBackendMessage(uint32_t id1, uint32_t id2,
				  const u_char *acct_uuid, kinum_t kinum)
    : BackendMessage(AUTH_KI_VALIDATE), m_kinum(htole32(kinum))
{
  memcpy(m_uuid, acct_uuid, UUID_RAW_LEN);
  setup_header(id1, id2, UUID_RAW_LEN+4);
}

AuthKIValidate_ToBackendMessage::
  AuthKIValidate_ToBackendMessage(const u_char *inbuf, size_t in_len,
				  bool become_owner)
    : BackendMessage(AUTH_KI_VALIDATE, inbuf, in_len), m_kinum(0)
{
  if (in_len < 40) {
    // XXX serious problem
  }
  memcpy(m_uuid, inbuf+16, UUID_RAW_LEN);
  m_kinum = read32le(inbuf, 32);
  if (become_owner) {
    delete[] inbuf;
  }
#ifdef DEBUG_ENABLE
  // message should not be queued m_unsafe = false;
#endif
}

u_int AuthKIValidate_ToBackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  START_FILL_TYPE;
  WRITE_BUFFER(m_uuid, UUID_RAW_LEN, false);
  WRITE_4_BYTES(m_kinum, true);
  END_FILL_TYPE;
}

AuthKIValidate_FromBackendMessage::
  AuthKIValidate_FromBackendMessage(uint32_t id1, uint32_t id2,
				    kinum_t kinum, status_code_t result)
    : BackendMessage(AUTH_KI_VALIDATE|FROM_SERVER),
      m_kinum(htole32(kinum)), m_result(htole32(result))
{
  setup_header(id1, id2, 8);
}

AuthKIValidate_FromBackendMessage::
  AuthKIValidate_FromBackendMessage(const u_char *inbuf, size_t in_len,
				    bool become_owner)
    : BackendMessage(AUTH_KI_VALIDATE|FROM_SERVER, inbuf, in_len),
      m_kinum(0), m_result(htole32(ERROR_INTERNAL))
{
  m_kinum = read32le(inbuf, 16);
  m_result = read32le(inbuf, 20);
  if (become_owner) {
    delete[] inbuf;
  }
#ifdef DEBUG_ENABLE
  // message should not be queued m_unsafe = false;
#endif
}

u_int AuthKIValidate_FromBackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  START_FILL_TYPE;
  WRITE_4_BYTES(m_kinum, false);
  WRITE_4_BYTES(m_result, true);
  END_FILL_TYPE;
}

AuthPlayerLogout_BackendMessage::
  AuthPlayerLogout_BackendMessage(uint32_t id1, uint32_t id2,
				  kinum_t kinum)
    : BackendMessage(AUTH_PLAYER_LOGOUT), m_kinum(htole32(kinum))
{
  setup_header(id1, id2, 4);
}

AuthPlayerLogout_BackendMessage::
  AuthPlayerLogout_BackendMessage(const u_char *inbuf, size_t in_len,
				  bool become_owner)
    : BackendMessage(AUTH_PLAYER_LOGOUT, inbuf, in_len), m_kinum(0)
{
  if (in_len < 20) {
    // XXX serious problem
  }
  m_kinum = read32le(inbuf, 16);
  if (become_owner) {
    delete[] inbuf;
  }
#ifdef DEBUG_ENABLE
  // message should not be queued m_unsafe = false;
#endif
}

u_int AuthPlayerLogout_BackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  START_FILL_TYPE;
  WRITE_4_BYTES(m_kinum, true);
  END_FILL_TYPE;
}

AuthChangePassword_ToBackendMessage::
  AuthChangePassword_ToBackendMessage(uint32_t id1, uint32_t id2,
				      const u_char *uuid,
				      uint32_t reqid, const UruString &name,
				      const u_char *hash)
    : BackendMessage(AUTH_CHANGE_PASSWORD), m_reqid(htole32(reqid)),
      m_name(NULL)
{
  m_name = new UruString(name, true);
  memcpy(m_uuid, uuid, UUID_RAW_LEN);
  memcpy(m_pwhash, hash, 20);
  setup_header(id1, id2, 24+UUID_RAW_LEN+m_name->send_len(true, false, true));
}

AuthChangePassword_ToBackendMessage::
  AuthChangePassword_ToBackendMessage(const u_char *inbuf, size_t in_len,
				      bool become_owner)
    : BackendMessage(AUTH_CHANGE_PASSWORD, inbuf, in_len), m_reqid(0),
      m_name(NULL)
{
  u_int read_at = 16;
  memcpy(m_uuid, inbuf+read_at, UUID_RAW_LEN);
  read_at += UUID_RAW_LEN;
  m_reqid = read32le(inbuf, read_at);
  read_at += 4;
  m_name = new UruString(inbuf+read_at, in_len-read_at,
			 true, false, !become_owner);
  read_at += m_name->arrival_len();
  if (in_len-read_at < 20) {
    // XXX serious problem
  }
  memcpy(m_pwhash, inbuf+read_at, 20);
  if (become_owner) {
    // pointed at by m_name!
    m_buf = const_cast<u_char*>(inbuf);
#ifdef DEBUG_ENABLE
    // message should not be queued m_unsafe = false;
#endif
  }
}

u_int AuthChangePassword_ToBackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  START_FILL_TYPE;
  WRITE_BUFFER(m_uuid, UUID_RAW_LEN, false);
  WRITE_4_BYTES(m_reqid, false);
  WRITE_URU_STRING_PTR(m_name, true, false, true, false, false);
  WRITE_BUFFER(m_pwhash, 20, true);
  END_FILL_TYPE;
}

AuthChangePassword_FromBackendMessage::
  AuthChangePassword_FromBackendMessage(uint32_t id1, uint32_t id2,
					uint32_t reqid, status_code_t result)
    : BackendMessage(AUTH_CHANGE_PASSWORD|FROM_SERVER),
      m_reqid(htole32(reqid)), m_result(htole32(result))
{
  setup_header(id1, id2, 8);
}

AuthChangePassword_FromBackendMessage::
  AuthChangePassword_FromBackendMessage(const u_char *inbuf, size_t in_len,
					bool become_owner)
    : BackendMessage(AUTH_CHANGE_PASSWORD|FROM_SERVER, inbuf, in_len),
      m_reqid(0), m_result(ERROR_INTERNAL)
{
  m_reqid = read32le(inbuf, 16);
  m_result = read32le(inbuf, 20);
  if (become_owner) {
    delete[] inbuf;
  }
#ifdef DEBUG_ENABLE
  // message should not be queued m_unsafe = false;
#endif
}

u_int AuthChangePassword_FromBackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  START_FILL_TYPE;
  WRITE_4_BYTES(m_reqid, false);
  WRITE_4_BYTES(m_result, true);
  END_FILL_TYPE;
}

VaultPlayerCreate_ToBackendMessage::
  VaultPlayerCreate_ToBackendMessage(uint32_t id1, uint32_t id2,
				     uint32_t reqid, u_char *acct_uuid,
				     const UruString &name,
				     const UruString &gender)
    : BackendMessage(VAULT_PLAYER_CREATE), m_reqid(htole32(reqid)),
      m_name(NULL), m_gender(NULL)
{
  m_name = new UruString(name, true);
  m_gender = new UruString(gender, true);
  memcpy(m_uuid, acct_uuid, UUID_RAW_LEN);
  setup_header(id1, id2, 20+m_name->send_len(true, false, true)
			   +m_gender->send_len(true, false, true));
}

VaultPlayerCreate_ToBackendMessage::
  VaultPlayerCreate_ToBackendMessage(const u_char *inbuf, size_t in_len,
				     bool become_owner)
    : BackendMessage(VAULT_PLAYER_CREATE, inbuf, in_len), m_reqid(0),
      m_name(NULL), m_gender(NULL)
{
  u_int read_at = 16;
  m_reqid = read32le(inbuf, read_at);
  read_at += 4;
  memcpy(m_uuid, inbuf+read_at, UUID_RAW_LEN);
  read_at += UUID_RAW_LEN;
  m_name = new UruString(inbuf+read_at, in_len-read_at,
			 true, false, !become_owner);
  read_at += m_name->arrival_len();
  if (in_len-read_at < 2) {
    // XXX serious problem
    m_gender = new UruString();
  }
  else {
    m_gender = new UruString(inbuf+read_at, in_len-read_at,
			     true, false, !become_owner);
  }
  if (become_owner) {
    // pointed at by UruStrings!
    m_buf = const_cast<u_char*>(inbuf);
#ifdef DEBUG_ENABLE
    // message should not be queued m_unsafe = false;
#endif
  }
}

u_int VaultPlayerCreate_ToBackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  START_FILL_TYPE;
  WRITE_4_BYTES(m_reqid, false);
  WRITE_BUFFER(m_uuid, UUID_RAW_LEN, false);
  WRITE_URU_STRING_PTR(m_name, true, false, true, false, false);
  WRITE_URU_STRING_PTR(m_gender, true, false, true, false, true);
  END_FILL_TYPE;
}

VaultPlayerCreate_FromBackendMessage::
  VaultPlayerCreate_FromBackendMessage(uint32_t id1, uint32_t id2,
				       uint32_t reqid, status_code_t result,
				       kinum_t kinum,
				       customer_type_t acct_type, 
				       UruString *name, UruString *gender)
    : BackendMessage(VAULT_PLAYER_CREATE|FROM_SERVER), m_reqid(htole32(reqid)),
      m_result(htole32(result)), m_kinum(htole32(kinum)),
      m_acct_type(htole32(acct_type)), m_name(name), m_gender(gender)
{
  if (result == NO_ERROR) {
    setup_header(id1, id2, 16+name->send_len(true, false, true)
			     +gender->send_len(true, false, true));
  }
  else {
    setup_header(id1, id2, 8);
  }
}

VaultPlayerCreate_FromBackendMessage::
  VaultPlayerCreate_FromBackendMessage(const u_char *inbuf, size_t in_len,
				       bool become_owner)
    : BackendMessage(VAULT_PLAYER_CREATE|FROM_SERVER, inbuf, in_len),
      m_reqid(0), m_result(htole32(ERROR_INTERNAL)), m_kinum(0),
      m_acct_type(htole32(GUEST_CUSTOMER)), m_name(NULL), m_gender(NULL)
{
  m_reqid = read32le(inbuf, 16);
  m_result = read32le(inbuf, 20);
  if (result() == NO_ERROR) {
    m_kinum = read32le(inbuf, 24);
    m_acct_type = read32le(inbuf, 28);
    u_int read_at = 32;
    m_name = new UruString(inbuf+read_at, in_len-read_at,
			   true, false, !become_owner);
    read_at += m_name->arrival_len();
    if (in_len-read_at < 2) {
      // XXX serious problem
      m_gender = new UruString();
    }
    else {
      m_gender = new UruString(inbuf+read_at, in_len-read_at,
			       true, false, !become_owner);
    }
  }
  if (become_owner) {
    // pointed at by UruStrings!
    m_buf = const_cast<u_char*>(inbuf);
#ifdef DEBUG_ENABLE
    // message should not be queued m_unsafe = false;
#endif
  }
}

u_int VaultPlayerCreate_FromBackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  bool has_error = (result() != NO_ERROR);
  START_FILL_TYPE;
  WRITE_4_BYTES(m_reqid, false);
  WRITE_4_BYTES(m_result, has_error);
  if (!has_error) {
    WRITE_4_BYTES(m_kinum, false);
    WRITE_4_BYTES(m_acct_type, false);
    WRITE_URU_STRING_PTR(m_name, true, false, true, false, false);
    WRITE_URU_STRING_PTR(m_gender, true, false, true, false, true);
  }
  END_FILL_TYPE;
}

VaultPlayerDelete_ToBackendMessage::
  VaultPlayerDelete_ToBackendMessage(uint32_t id1, uint32_t id2,
				     uint32_t reqid, kinum_t ki)
    : BackendMessage(VAULT_PLAYER_DELETE),
      m_reqid(htole32(reqid)), m_kinum(htole32(ki))
{
  setup_header(id1, id2, 8);
}

VaultPlayerDelete_ToBackendMessage::
  VaultPlayerDelete_ToBackendMessage(const u_char *inbuf, size_t in_len,
				     bool become_owner)
    : BackendMessage(VAULT_PLAYER_DELETE, inbuf, in_len),
      m_reqid(0), m_kinum(0)
{
  m_reqid = read32le(inbuf, 16);
  m_kinum = read32le(inbuf, 20);
  if (become_owner) {
    delete[] inbuf;
  }
#ifdef DEBUG_ENABLE
  // message should not be queued m_unsafe = false;
#endif
}

u_int VaultPlayerDelete_ToBackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  START_FILL_TYPE;
  WRITE_4_BYTES(m_reqid, false);
  WRITE_4_BYTES(m_kinum, true);
  END_FILL_TYPE;
}

VaultPlayerDelete_FromBackendMessage::
  VaultPlayerDelete_FromBackendMessage(uint32_t id1, uint32_t id2,
				       uint32_t reqid, status_code_t result)
    : BackendMessage(VAULT_PLAYER_DELETE|FROM_SERVER),
      m_reqid(htole32(reqid)), m_result(htole32(result))
{
  setup_header(id1, id2, 8);
}

VaultPlayerDelete_FromBackendMessage::
  VaultPlayerDelete_FromBackendMessage(const u_char *inbuf, size_t in_len,
				       bool become_owner)
    : BackendMessage(VAULT_PLAYER_DELETE|FROM_SERVER, inbuf, in_len),
      m_reqid(0), m_result(htole32(ERROR_INTERNAL))
{
  m_reqid = read32le(inbuf, 16);
  m_result = read32le(inbuf, 20);
  if (become_owner) {
    delete[] inbuf;
  }
#ifdef DEBUG_ENABLE
  // message should not be queued m_unsafe = false;
#endif
}

u_int VaultPlayerDelete_FromBackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  START_FILL_TYPE;
  WRITE_4_BYTES(m_reqid, false);
  WRITE_4_BYTES(m_result, true);
  END_FILL_TYPE;
}

VaultPassthrough_BackendMessage::
  VaultPassthrough_BackendMessage(uint32_t id1, uint32_t id2,
				  const u_char *inbuf, size_t in_len,
				  bool to_server, bool become_owner)
    : BackendMessage(VAULT_PASSTHRU|(to_server ? 0 : FROM_SERVER)),
      m_vault_offset(0), m_msgtype(0)
{
  setup_header(id1, id2, in_len);
  m_buflen = in_len;
  if (!become_owner) {
    m_buf = new u_char[in_len];
    memcpy(m_buf, inbuf, in_len);
  }
  else {
    m_buf = const_cast<u_char*>(inbuf); // safe; we're becoming owner
  }
  if (in_len >= 2) {
    // should always be true
    m_msgtype = read16le(m_buf, 0);
  }
}

VaultPassthrough_BackendMessage::
  VaultPassthrough_BackendMessage(const u_char *inbuf, size_t in_len,
				  bool to_server, bool become_owner)
    : BackendMessage(VAULT_PASSTHRU|(to_server ? 0 : FROM_SERVER),
		     inbuf, in_len),
      m_vault_offset(become_owner ? 16 : 0), m_msgtype(0)

{
  m_buflen = in_len-16;
  if (!become_owner) {
    m_buf = new u_char[m_buflen];
    memcpy(m_buf, inbuf+16, m_buflen);
  }
  else {
    m_buf = const_cast<u_char*>(inbuf); // safe; we're becoming owner
  }
  if (m_buflen >= 2) {
    // should always be true
    m_msgtype = read16le(m_buf, 0);
  }
#ifdef DEBUG_ENABLE
  // XXX we didn't really need to copy the data if it's !FROM_SERVER;
  // if FROM_SERVER, the message is backing an AuthServerVaultMessage
  m_unsafe = false;
#endif
}

VaultPassthrough_BackendMessage::
  VaultPassthrough_BackendMessage(int type, int msgtype)
    : BackendMessage(type), m_vault_offset(0), m_msgtype(htole16(msgtype))
{ }

VaultPassthrough_BackendMessage::
  VaultPassthrough_BackendMessage(int type, const u_char *inbuf,
				  size_t in_len, bool become_owner)
    : BackendMessage(type, inbuf, in_len),
      m_vault_offset(become_owner ? 16 : 0), m_msgtype(0)
{
  m_buflen = in_len-16;
  if (!become_owner) {
    m_buf = new u_char[m_buflen];
    memcpy(m_buf, inbuf+16, m_buflen);
  }
  else {
    m_buf = const_cast<u_char*>(inbuf); // safe; we're becoming owner
  }
  if (m_buflen >= 2) {
    // should always be true
    m_msgtype = read16le(m_buf, m_vault_offset);
  }
#ifdef DEBUG_ENABLE
  // XXX we didn't really need to copy the data
  // message should not be queued m_unsafe = false;
#endif
}

u_int VaultPassthrough_BackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  START_FILL_TYPE;
  u_char *write_where = m_buf+m_vault_offset;
  WRITE_BUFFER(write_where, m_buflen, true);
  END_FILL_TYPE;
}

VaultFetchRefs_ToBackendMessage::
  VaultFetchRefs_ToBackendMessage(const u_char *inbuf,
				  size_t in_len, bool become_owner)
    : VaultPassthrough_BackendMessage(VAULT_FETCHREFS, inbuf, in_len,
				      true/*don't bother to copy*/),
      m_reqid(0), m_node(0)
{
  m_reqid = read32le(m_buf, m_vault_offset+2);
  m_node = read32le(m_buf, m_vault_offset+6);
  m_buf = NULL;
  if (become_owner) {
    delete[] inbuf;
  }
}

u_int VaultFetchRefs_ToBackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
#ifdef DEBUG_ENABLE
  throw std::logic_error("this function should not be called");
#endif
  START_FILL_TYPE;
  WRITE_2_BYTES(m_msgtype, false);
  WRITE_4_BYTES(m_reqid, false);
  WRITE_4_BYTES(m_node, true);
  END_FILL_TYPE;
}

VaultNode_ToBackendMessage::
  VaultNode_ToBackendMessage(const u_char *inbuf, size_t in_len,
			     bool become_owner)
    : VaultPassthrough_BackendMessage(VAULT_PASSTHRU, inbuf, in_len,
				      become_owner),
      m_reqid(0), m_id(0), m_node(NULL)
{
  // fix up type
  switch (uru_msgtype()) {
  case kCli2Auth_VaultNodeFind:
    m_type = VAULT_FINDNODE;
    break;
  case kCli2Auth_VaultNodeSave:
    m_type = VAULT_SAVENODE;
    break;
  case kCli2Auth_VaultNodeCreate:
    m_type = VAULT_CREATENODE;
    break;
  default:
    // shouldn't happen
    ;
  }

  u_int off = 2;
  m_reqid = read32le(m_buf, m_vault_offset+off);
  off += 4;
  if (m_type == VAULT_SAVENODE) {
#if defined(OLD_PROTOCOL) && !defined(OLD_PROTOCOL4)
    // back up, reqid not present
    m_reqid = 0;
    off -= 4;
#endif
    m_id = read32le(m_buf, m_vault_offset+off);
    off += 4;
    memcpy(m_uuid, m_buf+m_vault_offset+off, 16);
    off += 16;
  }
  else {
    memset(m_uuid, 0, UUID_RAW_LEN);
  }
  // VaultNode constructor copies data if second arg is true, but
  // if become_owner was false the VaultPassthrough_BackendMessage
  // constructor already copied the data. So no need to ever copy
  // it in the VaultNode constructor!
  // XXX neither VaultPassthrough_BackendMessage or VaultNode
  // really need to copy the data
  // XXX actually, check on this; do we reuse/save the message or VaultNode
  // for propagating back to clients?
  m_node = new VaultNode(m_buf+off, false);
}

VaultNode_ToBackendMessage::~VaultNode_ToBackendMessage() {
  if (m_node) {
    delete m_node;
  }
}

u_int VaultNode_ToBackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
#ifdef DEBUG_ENABLE
  throw std::logic_error("who is calling this???");
#endif
  START_FILL_TYPE;
  WRITE_2_BYTES(m_msgtype, false);
  WRITE_4_BYTES(m_reqid, false);
  if (m_type == VAULT_SAVENODE) {
    WRITE_4_BYTES(m_id, false);
    WRITE_BUFFER(m_uuid, UUID_RAW_LEN, false);
  }
  if (iovs) {
    return m_node->fill_iovecs(iov+done, iov_ct-done, start_at) + done;
  }
  else {
    return m_node->fill_buffer(buffer+done, buflen-done, start_at, msg_done)
      + done;
  }
}

VaultNodeFetch_ToBackendMessage::
  VaultNodeFetch_ToBackendMessage(const u_char *inbuf,
				  size_t in_len, bool become_owner)
    : VaultPassthrough_BackendMessage(VAULT_FETCH, inbuf, in_len,
				      true/*don't bother to copy*/),
      m_reqid(0), m_node(0)
{
  m_reqid = read32le(m_buf, m_vault_offset+2);
  m_node = read32le(m_buf, m_vault_offset+6);
  m_buf = NULL;
  if (become_owner) {
    delete[] inbuf;
  }
}

u_int VaultNodeFetch_ToBackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
#ifdef DEBUG_ENABLE
  throw std::logic_error("this function should not be called");
#endif
  START_FILL_TYPE;
  WRITE_2_BYTES(m_msgtype, false);
  WRITE_4_BYTES(m_reqid, false);
  WRITE_4_BYTES(m_node, true);
  END_FILL_TYPE;
}

VaultNodeFetch_FromBackendMessage::
  VaultNodeFetch_FromBackendMessage(uint32_t id1, uint32_t id2,
				    uint32_t reqid, status_code_t result,
				    VaultNode *node)
    : VaultPassthrough_BackendMessage(VAULT_PASSTHRU|FROM_SERVER,
				      kAuth2Cli_VaultNodeFetched),
      m_reqid(htole32(reqid)), m_result(htole32(result)), m_node(node)
{
  if (result == NO_ERROR) {
    setup_header(id1, id2, 10+node->message_len());
  }
  else {
    setup_header(id1, id2, 14);
  }
}

VaultNodeFetch_FromBackendMessage::~VaultNodeFetch_FromBackendMessage() {
  if (m_node) {
    delete m_node;
  }
}

u_int VaultNodeFetch_FromBackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  START_FILL_TYPE;
  WRITE_2_BYTES(m_msgtype, false);
  WRITE_4_BYTES(m_reqid, false);
  WRITE_4_BYTES(m_result, false);
  if ((status_code_t)le32toh(m_result) == NO_ERROR) {
    if (iovs) {
      return m_node->fill_iovecs(iov+done, iov_ct-done, start_at) + done;
    }
    else {
      return m_node->fill_buffer(buffer+done, buflen-done, start_at, msg_done)
	+ done;
    }
  }
  else {
    WRITE_4_BYTES(zero, true);
  }
  END_FILL_TYPE;
}

VaultRefChange_ToBackendMessage::
  VaultRefChange_ToBackendMessage(const u_char *inbuf, size_t in_len,
				  bool become_owner)
    : VaultPassthrough_BackendMessage(VAULT_ADDREF, inbuf, in_len,
				      true/*don't bother to copy*/),
      m_owner(0)
{
  // fix up type
  if (!is_add()) {
    m_type = VAULT_REMOVEREF;
  }
  u_int off = m_vault_offset+2;
#if !defined(OLD_PROTOCOL) || defined(OLD_PROTOCOL4)
  m_reqid = read32le(m_buf, off);
  off += 4;
#endif
  m_parent = read32le(m_buf, off);
  off += 4;
  m_child = read32le(m_buf, off);
  off += 4;
  if (is_add()) {
    m_owner = read32le(m_buf, off);
  }
  m_buf = NULL;
  if (become_owner) {
    delete[] inbuf;
  }
}

bool VaultRefChange_ToBackendMessage::is_add() const {
  return (uru_msgtype() == kCli2Auth_VaultNodeAdd);
}

u_int VaultRefChange_ToBackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
#ifdef DEBUG_ENABLE
  throw std::logic_error("this function should not be called");
#endif
  bool add = is_add();
  START_FILL_TYPE;
  WRITE_2_BYTES(m_msgtype, false);
  WRITE_4_BYTES(m_reqid, false);
  WRITE_4_BYTES(m_parent, false);
  WRITE_4_BYTES(m_child, !add);
  if (add) {
    WRITE_4_BYTES(m_owner, true);
  }
  END_FILL_TYPE;
}

VaultInitAge_ToBackendMessage::
  VaultInitAge_ToBackendMessage(const u_char *inbuf, size_t in_len,
				bool become_owner)
    : VaultPassthrough_BackendMessage(VAULT_INIT_AGE, inbuf, in_len,
				      become_owner),
      m_reqid(0), m_filename(NULL), m_instance(NULL), m_username(NULL),
      m_dispname(NULL), m_unk(0), m_id(0)
{
  u_int off = m_vault_offset+2;
  m_reqid = read32le(m_buf, off);
  off += 4;
  memcpy(m_createuuid, m_buf+off, 16);
  off += 16;
  memcpy(m_parentuuid, m_buf+off, 16);
  off += 16;
  m_filename = new UruString(m_buf+off, -1, true, true,
			     false/*backed by m_buf*/);
  off += m_filename->arrival_len();
  m_instance = new UruString(m_buf+off, -1, true, true, false);
  off += m_instance->arrival_len();
  m_username = new UruString(m_buf+off, -1, true, true, false);
  off += m_username->arrival_len();
  m_dispname = new UruString(m_buf+off, -1, true, true, false);
  off += m_dispname->arrival_len();
  m_unk = read32le(m_buf, off);
  off += 4;
  m_id = read32le(m_buf, off);
  off += 4;
  if (off != in_len) {
    // XXX something changed? our length computation is wrong?
  }
}

u_int VaultInitAge_ToBackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
#ifdef DEBUG_ENABLE
  throw std::logic_error("this function should not be called");
#endif
  START_FILL_TYPE;
  WRITE_2_BYTES(m_msgtype, false);
  WRITE_4_BYTES(m_reqid, false);
  WRITE_BUFFER(m_createuuid, UUID_RAW_LEN, false);
  WRITE_BUFFER(m_parentuuid, UUID_RAW_LEN, false);
  WRITE_URU_STRING_PTR(m_filename, true, true, false, false, false);
  WRITE_URU_STRING_PTR(m_instance, true, true, false, false, false);
  WRITE_URU_STRING_PTR(m_username, true, true, false, false, false);
  WRITE_URU_STRING_PTR(m_dispname, true, true, false, false, false);
  WRITE_4_BYTES(m_unk, false);
  WRITE_4_BYTES(m_id, true);
  END_FILL_TYPE;
}

VaultAgeList_ToBackendMessage::
  VaultAgeList_ToBackendMessage(const u_char *inbuf, size_t in_len,
				bool become_owner)
    : VaultPassthrough_BackendMessage(VAULT_AGE_LIST, inbuf, in_len,
				      become_owner),
      m_reqid(0), m_filename(NULL)
{
  u_int off = m_vault_offset+2;
  m_reqid = read32le(m_buf, off);
  off += 4;
  m_filename = new UruString(m_buf+off, in_len-off, true, true,
			     false/*backed by m_buf*/);
  off += m_filename->arrival_len();
  if (off != in_len) {
    // XXX something changed? our length computation is wrong?
  }
}

u_int VaultAgeList_ToBackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
#ifdef DEBUG_ENABLE
  throw std::logic_error("this function should not be called");
#endif
  START_FILL_TYPE;
  WRITE_2_BYTES(m_msgtype, false);
  WRITE_4_BYTES(m_reqid, false);
  WRITE_URU_STRING_PTR(m_filename, true, true, false, false, true);
  END_FILL_TYPE;
}

VaultNodeSend_BackendMessage::
  VaultNodeSend_BackendMessage(const u_char *inbuf,
				  size_t in_len, bool become_owner)
    : VaultPassthrough_BackendMessage(VAULT_SENDNODE, inbuf, in_len,
				      true/*don't bother to copy*/),
      m_player(0), m_nodeid(0)
{
  m_nodeid = read32le(m_buf, m_vault_offset+2);
  m_player = read32le(m_buf, m_vault_offset+6);
  m_buf = NULL;
  if (become_owner) {
    delete[] inbuf;
  }
}

u_int VaultNodeSend_BackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
#ifdef DEBUG_ENABLE
  throw std::logic_error("this function should not be called");
#endif
  START_FILL_TYPE;
  WRITE_2_BYTES(m_msgtype, false);
  WRITE_4_BYTES(m_player, false);
  WRITE_4_BYTES(m_nodeid, true);
  END_FILL_TYPE;
}

VaultSetAgePublic_BackendMessage::
  VaultSetAgePublic_BackendMessage(const u_char *inbuf, size_t in_len,
				   bool become_owner)
    : VaultPassthrough_BackendMessage(VAULT_SET_AGE_PUBLIC, inbuf, in_len,
				      true/*don't bother to copy*/),
      m_nodeid(0), m_public(0)
{
  m_nodeid = read32le(m_buf, m_vault_offset+2);
  m_public = m_buf[m_vault_offset+6];
  m_buf = NULL;
  if (become_owner) {
    delete[] inbuf;
  }
}

u_int VaultSetAgePublic_BackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
#ifdef DEBUG_ENABLE
  throw std::logic_error("this function should not be called");
#endif
  START_FILL_TYPE;
  WRITE_2_BYTES(m_msgtype, false);
  WRITE_4_BYTES(m_nodeid, false);
  WRITE_BUFFER(&m_public, 1, true);
  END_FILL_TYPE;
}

VaultScoreGet_ToBackendMessage::
  VaultScoreGet_ToBackendMessage(const u_char *inbuf, size_t in_len,
				 bool become_owner)
    : VaultPassthrough_BackendMessage(VAULT_SCORE_GET, inbuf, in_len,
				      become_owner),
      m_reqid(0), m_holder(0), m_name(NULL)
{
  m_reqid = read32le(m_buf, m_vault_offset+2);
  m_holder = read32le(m_buf, m_vault_offset+6);
  u_int off = m_vault_offset+10;
  m_name = new UruString(m_buf+off, in_len-off, true, true,
			 false/*backed by m_buf*/);
  off += m_name->arrival_len();
  if (off != in_len) {
    // XXX something changed? our length computation is wrong?
  }
}

u_int VaultScoreGet_ToBackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
#ifdef DEBUG_ENABLE
  throw std::logic_error("this function should not be called");
#endif
  START_FILL_TYPE;
  WRITE_2_BYTES(m_msgtype, false);
  WRITE_4_BYTES(m_reqid, false);
  WRITE_4_BYTES(m_holder, false);
  WRITE_URU_STRING_PTR(m_name, true, true, true, false, true);
  END_FILL_TYPE;
}

VaultScoreGet_FromBackendMessage::
  VaultScoreGet_FromBackendMessage(uint32_t id1, uint32_t id2, uint32_t reqid,
				   status_code_t result)
    : VaultPassthrough_BackendMessage(VAULT_PASSTHRU|FROM_SERVER,
				      kAuth2Cli_ScoreGetScoresReply),
      m_reqid(htole32(reqid)), m_result(htole32(result)),
      m_code(0), m_msglen(0)
{
  setup_header(id1, id2, 18);
}

VaultScoreGet_FromBackendMessage::
  VaultScoreGet_FromBackendMessage(uint32_t id1, uint32_t id2, uint32_t reqid,
				   status_code_t result, uint32_t score_id,
				   kinum_t holder, int32_t create_time,
				   uint32_t type, int32_t score_value,
				   UruString *score_name)
    : VaultPassthrough_BackendMessage(VAULT_PASSTHRU|FROM_SERVER,
				      kAuth2Cli_ScoreGetScoresReply),
      m_reqid(htole32(reqid)), m_result(htole32(result)),
      m_code(htole32(1)), m_msglen(0)
{
  u_int slen = score_name->send_len(false, true, true);
  m_buflen = 24+slen;
  m_buf = new u_char[m_buflen];
  m_msglen = htole32(m_buflen);
  write32(m_buf, 0, score_id);
  write32(m_buf, 4, holder);
  write32(m_buf, 8, create_time);
  write32(m_buf, 12, type);
  write32(m_buf, 16, score_value);
  write32(m_buf, 20, slen);
  memcpy(m_buf+24, score_name->get_str(false, true, true, false), slen);

  setup_header(id1, id2, 18+m_buflen);
}

u_int VaultScoreGet_FromBackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  START_FILL_TYPE;
  WRITE_2_BYTES(m_msgtype, false);
  WRITE_4_BYTES(m_reqid, false);
  WRITE_4_BYTES(m_result, false);
  WRITE_4_BYTES(m_code, false);
  bool nobuf = (m_buf == NULL);
  if (nobuf && m_msglen) {
    // XXX bad programmer error
    m_msglen = 0;
  }
  WRITE_4_BYTES(m_msglen, nobuf);
  if (!nobuf) {
    WRITE_BUFFER(m_buf, m_buflen, true);
  }
  END_FILL_TYPE;
}

VaultScoreCreate_BackendMessage::
  VaultScoreCreate_BackendMessage(const u_char *inbuf, size_t in_len,
				  bool become_owner)
    : VaultPassthrough_BackendMessage(VAULT_SCORE_CREATE, inbuf, in_len,
				      become_owner),
      m_reqid(0), m_holder(0), m_name(NULL), m_type(0), m_value(0)
{
  m_reqid = read32le(m_buf, m_vault_offset+2);
  m_holder = read32le(m_buf, m_vault_offset+6);
  u_int off = m_vault_offset+10;
  m_name = new UruString(m_buf+off, in_len-off, true, true,
			 false/*backed by m_buf*/);
  off += m_name->arrival_len();
  m_type = read32le(m_buf, m_vault_offset+off);
  off += 4;
  m_value = read32le(m_buf, m_vault_offset+off);
  off += 4;
  if (off != in_len) {
    // XXX something changed? our length computation is wrong?
  }
}

u_int VaultScoreCreate_BackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
#ifdef DEBUG_ENABLE
  throw std::logic_error("this function should not be called");
#endif
  START_FILL_TYPE;
  WRITE_2_BYTES(m_msgtype, false);
  WRITE_4_BYTES(m_reqid, false);
  WRITE_4_BYTES(m_holder, false);
  WRITE_URU_STRING_PTR(m_name, true, true, true, false, false);
  WRITE_4_BYTES(m_type, false);
  WRITE_4_BYTES(m_value, true);
  END_FILL_TYPE;
}

VaultScoreAddPoints_BackendMessage::
  VaultScoreAddPoints_BackendMessage(const u_char *inbuf, size_t in_len,
				     bool become_owner)
    : VaultPassthrough_BackendMessage(VAULT_SCORE_ADD, inbuf, in_len,
				      become_owner),
      m_reqid(0), m_scoreid(0), m_delta(0)
{
  m_reqid = read32le(m_buf, m_vault_offset+2);
  m_scoreid = read32le(m_buf, m_vault_offset+6);
  m_delta = read32le(m_buf, m_vault_offset+10);
}

u_int VaultScoreAddPoints_BackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
#ifdef DEBUG_ENABLE
  throw std::logic_error("this function should not be called");
#endif
  START_FILL_TYPE;
  WRITE_2_BYTES(m_msgtype, false);
  WRITE_4_BYTES(m_reqid, false);
  WRITE_4_BYTES(m_scoreid, false);
  WRITE_4_BYTES(m_delta, true);
  END_FILL_TYPE;
}

VaultScoreXferPoints_BackendMessage::
  VaultScoreXferPoints_BackendMessage(const u_char *inbuf, size_t in_len,
				      bool become_owner)
    : VaultPassthrough_BackendMessage(VAULT_SCORE_XFER, inbuf, in_len,
				      become_owner),
      m_reqid(0), m_scoreid(0), m_destid(0), m_delta(0)
{
  m_reqid = read32le(m_buf, m_vault_offset+2);
  m_scoreid = read32le(m_buf, m_vault_offset+6);
  m_destid = read32le(m_buf, m_vault_offset+10);
  m_delta = read32le(m_buf, m_vault_offset+14);
}

u_int VaultScoreXferPoints_BackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
#ifdef DEBUG_ENABLE
  throw std::logic_error("this function should not be called");
#endif
  START_FILL_TYPE;
  WRITE_2_BYTES(m_msgtype, false);
  WRITE_4_BYTES(m_reqid, false);
  WRITE_4_BYTES(m_scoreid, false);
  WRITE_4_BYTES(m_destid, false);
  WRITE_4_BYTES(m_delta, true);
  END_FILL_TYPE;
}

TrackPing_BackendMessage::
  TrackPing_BackendMessage(uint32_t id1, uint32_t id2)
    : BackendMessage(TRACK_PING)
{
  setup_header(id1, id2, 0);
}

TrackPing_BackendMessage::
  TrackPing_BackendMessage(const u_char *inbuf, size_t in_len,
			   bool become_owner)
    : BackendMessage(TRACK_PING, inbuf, in_len)
{
  if (become_owner) {
    delete[] inbuf;
  }
#ifdef DEBUG_ENABLE
  // message should not be queued m_unsafe = false;
#endif
}

TrackDispatcherHello_BackendMessage::
  TrackDispatcherHello_BackendMessage(const u_char *inbuf, size_t in_len,
				      bool become_owner)
    : BackendMessage(TRACK_DISPATCHER_HELLO, inbuf, in_len)
{
  m_restrict_type = read32le(inbuf, 16);
  if (become_owner) {
    delete[] inbuf;
  }
#ifdef DEBUG_ENABLE
  // message should not be queued m_unsafe = false;
#endif
}

TrackDispatcherBye_BackendMessage::
  TrackDispatcherBye_BackendMessage(const u_char *inbuf, size_t in_len,
				    bool become_owner)
    : BackendMessage(TRACK_DISPATCHER_BYE, inbuf, in_len)
{
  if (become_owner) {
    delete[] inbuf;
  }
#ifdef DEBUG_ENABLE
  // message should not be queued m_unsafe = false;
#endif
}

TrackServiceTypes_BackendMessage::
  TrackServiceTypes_BackendMessage(uint32_t id1, uint32_t id2,
				   bool auth_enabled, bool file_enabled,
				   bool game_enabled, uint32_t ip_address)
    : BackendMessage(TRACK_SERVICE_TYPES), m_auth(auth_enabled? 1 : 0),
      m_file(file_enabled ? 1 : 0), m_game(game_enabled ? 1 : 0),
      m_addrtype(ST_IPADDR), m_address(ip_address), m_hostname(NULL),
      m_request_pushes(0), m_restrict_type(0)
{
  setup_header(id1, id2, 16);
}

TrackServiceTypes_BackendMessage::
  TrackServiceTypes_BackendMessage(uint32_t id1, uint32_t id2,
				   bool auth_enabled, bool file_enabled,
				   bool game_enabled,
				   const char *resolve_address)
    : BackendMessage(TRACK_SERVICE_TYPES), m_auth(auth_enabled ? 1 : 0),
      m_file(file_enabled ? 1 : 0), m_game(game_enabled ? 1 : 0),
      m_addrtype(ST_HOSTNAME), m_address(0),
      m_request_pushes(0), m_restrict_type(0)
{
  m_hostname = new UruString(resolve_address); // copy string
  setup_header(id1, id2, 12+m_hostname->send_len(true, false, true));
}

TrackServiceTypes_BackendMessage::
  TrackServiceTypes_BackendMessage(const u_char *inbuf, size_t in_len,
				   bool become_owner)
    : BackendMessage(TRACK_SERVICE_TYPES, inbuf, in_len),
      m_address(0), m_hostname(NULL)
{
  m_auth = inbuf[16];
  m_file = inbuf[17];
  m_game = inbuf[18];
  m_addrtype = inbuf[19];
  u_int offset = 20;
  if (addrtype() == ST_HOSTNAME) {
    m_hostname = new UruString(inbuf+20, in_len-28, true, false,
			       !become_owner);
    offset += m_hostname->arrival_len();
  }
  else {
    m_address = read32le(inbuf, 20); // really big-endian
    offset = 24;
  }
  m_request_pushes = read32le(inbuf, offset);
  offset += 4;
  m_restrict_type = read32le(inbuf, offset);
  if (become_owner) {
    m_buf = const_cast<u_char*>(inbuf); // safe; we're becoming owner
#ifdef DEBUG_ENABLE
    // message should not be queued m_unsafe = false;
#endif
  }
}

u_int TrackServiceTypes_BackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  START_FILL_TYPE;
  WRITE_1_BYTE(m_auth, false);
  WRITE_1_BYTE(m_file, false);
  WRITE_1_BYTE(m_game, false);
  WRITE_1_BYTE(m_addrtype, false);
  if (addrtype() == ST_HOSTNAME) {
    WRITE_URU_STRING_PTR(m_hostname, true, false, true, false, false);
  }
  else {
    WRITE_4_BYTES(m_address, false);
  }
  WRITE_4_BYTES(m_request_pushes, false);
  WRITE_4_BYTES(m_restrict_type, true);
  END_FILL_TYPE;
}

TrackFindService_ToBackendMessage::
  TrackFindService_ToBackendMessage(uint32_t id1, uint32_t id2,
				    uint32_t reqid, uint32_t reqid2,
				    bool want_file)
    : BackendMessage(TRACK_FIND_SERVICE), m_reqid(htole32(reqid)),
      m_reqid2(htole32(reqid2)), m_want_file(want_file ? 1 : 0)
{
  setup_header(id1, id2, 9);
}

TrackFindService_ToBackendMessage::
  TrackFindService_ToBackendMessage(const u_char *inbuf, size_t in_len,
				    bool become_owner)
    : BackendMessage(TRACK_FIND_SERVICE, inbuf, in_len)
{
  m_reqid = read32le(inbuf, 16);
  m_reqid2 = read32le(inbuf, 20);
  m_want_file = inbuf[24];
  if (become_owner) {
    delete[] inbuf;
  }
#ifdef DEBUG_ENABLE
  // message should not be queued m_unsafe = false;
#endif
}

u_int TrackFindService_ToBackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  START_FILL_TYPE;
  WRITE_4_BYTES(m_reqid, false);
  WRITE_4_BYTES(m_reqid2, false);
  WRITE_1_BYTE(m_want_file, true);
  END_FILL_TYPE;
}

TrackFindService_FromBackendMessage::
  TrackFindService_FromBackendMessage(uint32_t id1, uint32_t id2,
				      uint32_t reqid, uint32_t reqid2,
				      bool is_file, uint32_t ip_address)
    : BackendMessage(TRACK_FIND_SERVICE|FROM_SERVER), m_reqid(htole32(reqid)),
      m_reqid2(htole32(reqid2)), m_is_file(is_file ? 1 : 0),
      m_addrtype((char)ST_IPADDR), m_address(ip_address), m_hostname(NULL)
{
  setup_header(id1, id2, 16);
}

TrackFindService_FromBackendMessage::
  TrackFindService_FromBackendMessage(uint32_t id1, uint32_t id2,
				      uint32_t reqid, uint32_t reqid2,
				      bool is_file,
				      const char *resolve_address)
    : BackendMessage(TRACK_FIND_SERVICE|FROM_SERVER), m_reqid(htole32(reqid)),
      m_reqid2(htole32(reqid2)), m_is_file(is_file ? 1 : 0),
      m_addrtype((char)ST_HOSTNAME), m_address(0)
{
  m_hostname = new UruString(resolve_address); // copy string
  setup_header(id1, id2, 12+m_hostname->send_len(true, false, true));
}

TrackFindService_FromBackendMessage::
  TrackFindService_FromBackendMessage(uint32_t id1, uint32_t id2,
				      uint32_t reqid, uint32_t reqid2,
				      bool is_file)
    : BackendMessage(TRACK_FIND_SERVICE|FROM_SERVER), m_reqid(htole32(reqid)),
      m_reqid2(htole32(reqid2)), m_is_file(is_file ? 1 : 0),
      m_addrtype((char)ST_NONE), m_address(0), m_hostname(NULL)
{
  setup_header(id1, id2, 16);
}

TrackFindService_FromBackendMessage::
  TrackFindService_FromBackendMessage(const u_char *inbuf, size_t in_len,
				      bool become_owner)
    : BackendMessage(TRACK_FIND_SERVICE|FROM_SERVER, inbuf, in_len),
      m_reqid(0), m_reqid2(0), m_address(0), m_hostname(NULL)
{
  m_reqid = read32le(inbuf, 16);
  m_reqid2 = read32le(inbuf, 20);
  m_is_file = inbuf[24];
  m_addrtype = inbuf[27];
  if (addrtype() == ST_HOSTNAME) {
    m_hostname = new UruString(inbuf+28, in_len-28, true, false,
			       !become_owner);
  }
  else {
    m_address = read32le(inbuf, 28); // really big-endian
  }
  if (become_owner) {
    m_buf = const_cast<u_char*>(inbuf); // safe; we're becoming owner
#ifdef DEBUG_ENABLE
    // message should not be queued m_unsafe = false;
#endif
  }
}

u_int TrackFindService_FromBackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  START_FILL_TYPE;
  WRITE_4_BYTES(m_reqid, false);
  WRITE_4_BYTES(m_reqid2, false);
  WRITE_1_BYTE(m_is_file, false);
  WRITE_2_BYTES(zero, false);
  WRITE_1_BYTE(m_addrtype, false);
  if (addrtype() == ST_HOSTNAME) {
    WRITE_URU_STRING_PTR(m_hostname, true, false, true, false, true);
  }
  else {
    WRITE_4_BYTES(m_address, true);
  }
  END_FILL_TYPE;
}

TrackGameHello_BackendMessage::
  TrackGameHello_BackendMessage(uint32_t id1, uint32_t id2,
				const u_char *uuid, uint32_t server_id,
				uint32_t connect_ipaddr)
    : BackendMessage(TRACK_GAME_HELLO), m_id(htole32(server_id)),
      m_ipaddr(connect_ipaddr)
{
  setup_header(id1, id2, UUID_RAW_LEN+8);
  memcpy(m_uuid, uuid, UUID_RAW_LEN);
}

TrackGameHello_BackendMessage::
  TrackGameHello_BackendMessage(const u_char *inbuf, size_t in_len,
				bool become_owner)
    : BackendMessage(TRACK_GAME_HELLO, inbuf, in_len), m_id(0), m_ipaddr(0)
{
  memcpy(m_uuid, inbuf+16, UUID_RAW_LEN);
  m_id = read32le(inbuf, 16+UUID_RAW_LEN);
  m_ipaddr = read32le(inbuf, 20+UUID_RAW_LEN);
  if (become_owner) {
    delete[] inbuf;
  }
#ifdef DEBUG_ENABLE
  // message should not be queued m_unsafe = false;
#endif
}

u_int TrackGameHello_BackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  START_FILL_TYPE;
  WRITE_BUFFER(m_uuid, UUID_RAW_LEN, false);
  WRITE_4_BYTES(m_id, false);
  WRITE_4_BYTES(m_ipaddr, true);
  END_FILL_TYPE;
}

TrackGameBye_ToBackendMessage::
  TrackGameBye_ToBackendMessage(uint32_t id1, uint32_t id2, bool final)
    : BackendMessage(TRACK_GAME_BYE), m_final(final)
{
  setup_header(id1, id2, 4);
}

TrackGameBye_ToBackendMessage::
  TrackGameBye_ToBackendMessage(const u_char *inbuf, size_t in_len,
				bool become_owner)
    : BackendMessage(TRACK_GAME_BYE, inbuf, in_len), m_final(0)
{
  m_final = read32le(inbuf, 16);
  if (become_owner) {
    delete[] inbuf;
  }
#ifdef DEBUG_ENABLE
  // message should not be queued m_unsafe = false;
#endif
}

u_int TrackGameBye_ToBackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  START_FILL_TYPE;
  WRITE_4_BYTES(m_final, true);
  END_FILL_TYPE;
}

TrackGameBye_FromBackendMessage::
  TrackGameBye_FromBackendMessage(uint32_t id1, uint32_t id2)
    : BackendMessage(TRACK_GAME_BYE|FROM_SERVER)
{
  setup_header(id1, id2, 0);
}

TrackGameBye_FromBackendMessage::
  TrackGameBye_FromBackendMessage(const u_char *inbuf, size_t in_len,
				  bool become_owner)
    : BackendMessage(TRACK_GAME_BYE|FROM_SERVER, inbuf, in_len)
{
  if (become_owner) {
    delete[] inbuf;
  }
#ifdef DEBUG_ENABLE
  // message should not be queued m_unsafe = false;
#endif
}

TrackGamePlayerInfo_BackendMessage::
  TrackGamePlayerInfo_BackendMessage(uint32_t id1, uint32_t id2,
				     kinum_t kinum, bool present)
    : BackendMessage(TRACK_GAME_PLAYERINFO),
      m_kinum(htole32(kinum)), m_present(present ? 1 : 0)
{
  setup_header(id1, id2, 5);
}

TrackGamePlayerInfo_BackendMessage::
  TrackGamePlayerInfo_BackendMessage(const u_char *inbuf, size_t in_len,
				     bool become_owner)
    : BackendMessage(TRACK_GAME_PLAYERINFO, inbuf, in_len),
      m_kinum(0), m_present(false)
{
  m_kinum = read32le(inbuf, 16);
  m_present = inbuf[20];
  if (become_owner) {
    delete[] inbuf;
  }
#ifdef DEBUG_ENABLE
  // message should not be queued m_unsafe = false;
#endif
}

u_int TrackGamePlayerInfo_BackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  START_FILL_TYPE;
  WRITE_4_BYTES(m_kinum, false);
  WRITE_BUFFER(&m_present, 1, true);
  END_FILL_TYPE;
}

TrackMsgForward_BackendMessage::
  TrackMsgForward_BackendMessage(uint32_t id1, uint32_t id2,
				 NetworkMessage *msg_to_fwd, u_int recips_at)
    : BackendMessage(TRACK_INTERAGE_FWD), m_recip_offset(htole32(recips_at)),
      m_msg(msg_to_fwd)
{
  m_msg->add_ref();
  if (m_msg->type() & CLASS_TRACK) {
    m_msg_offset = 20;
    m_type |= FROM_SERVER;
  }
  else {
    m_msg_offset = 0;
  }
  setup_header(id1, id2, 4+m_msg->message_len()-m_msg_offset);
}

TrackMsgForward_BackendMessage::
  TrackMsgForward_BackendMessage(const u_char *inbuf, size_t in_len,
				 int msg_type, bool become_owner)
    : BackendMessage(msg_type, inbuf, in_len), m_msg(NULL)
{
  m_recip_offset = read32le(inbuf, 16);
  m_buflen = m_total_len-20;
  if (become_owner) {
    m_buf = const_cast<u_char*>(inbuf); // safe; we're becoming owner
    m_msg_offset = 20;
  }
  else {
    m_buf = new u_char[m_buflen];
    memcpy(m_buf, inbuf+20, m_buflen);
    m_msg_offset = 0;
  }
#ifdef DEBUG_ENABLE
  m_unsafe = false; // data was copied
#endif
}

TrackMsgForward_BackendMessage::~TrackMsgForward_BackendMessage() {
  if (m_msg) {
    if (m_msg->del_ref() < 1) {
      delete m_msg;
    }
  }
  else if (m_buf) {
    delete[] m_buf;
  }
}

const u_char * TrackMsgForward_BackendMessage::fwd_msg() const {
  if (m_msg) {
    return m_msg->buffer()+m_msg_offset;
  }
  else {
    return m_buf+m_msg_offset;
  }
}

u_int TrackMsgForward_BackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  START_FILL_TYPE;
  WRITE_4_BYTES(m_recip_offset, false);
  if (m_msg) {
    if (iovs) {
      done += m_msg->fill_iovecs(iov+done, iov_ct-done, start_at+m_msg_offset);
    }
    else {
      done += m_msg->fill_buffer(buffer+done, buflen-done,
				 start_at+m_msg_offset, msg_done);
    }
    return done;
  }
  else {
    WRITE_BUFFER((m_buf+m_msg_offset), m_buflen, true);
  }
  END_FILL_TYPE;
}

TrackSDLUpdate_BackendMessage::
  TrackSDLUpdate_BackendMessage(uint32_t id1, uint32_t id2, kinum_t from_ki,
				uint32_t from_id1, uint32_t from_id2,
				const u_char *sdl_buf, size_t sdl_len,
				sdl_type_t update_type)
    : BackendMessage(TRACK_SDL_UPDATE|FROM_SERVER),
      m_kinum(htole32(from_ki)), m_from_id1(htole32(from_id1)),
      m_from_id2(htole32(from_id2)), m_data_off(0),
      m_datalen(htole32(sdl_len)), m_sdl_type(htole32(update_type))
{
  m_buf = new u_char[sdl_len];
  memcpy(m_buf, sdl_buf, sdl_len);
  setup_header(id1, id2, 20+sdl_len);
}

TrackSDLUpdate_BackendMessage::
  TrackSDLUpdate_BackendMessage(const u_char *inbuf, size_t in_len,
				bool become_owner)
    : BackendMessage(TRACK_SDL_UPDATE|FROM_SERVER, inbuf, in_len),
      m_kinum(0), m_from_id1(0), m_from_id2(0),
      m_data_off(0), m_datalen(0), m_sdl_type(htole32(INVALID))
{
  m_kinum = read32le(inbuf, 16);
  m_from_id1 = read32le(inbuf, 20);
  m_from_id2 = read32le(inbuf, 24);
  m_sdl_type = read32le(inbuf, 28);
  m_datalen = read32le(inbuf, 32);
  size_t sdl_len = le32toh(m_datalen);
  if (become_owner) {
    m_buf = const_cast<u_char*>(inbuf); // safe; we're becoming owner
    m_data_off = 36;
  }
  else {
    m_buf = new u_char[sdl_len];
    memcpy(m_buf, inbuf+36, sdl_len);
  }
#ifdef DEBUG_ENABLE
  // message should not be queued m_unsafe = false; // data was copied
#endif
}

u_int TrackSDLUpdate_BackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  START_FILL_TYPE;
  WRITE_4_BYTES(m_kinum, false);
  WRITE_4_BYTES(m_from_id1, false);
  WRITE_4_BYTES(m_from_id2, false);
  WRITE_4_BYTES(m_sdl_type, false);
  WRITE_4_BYTES(m_datalen, false);
  WRITE_BUFFER((m_buf+m_data_off), sdl_len(), true);
  END_FILL_TYPE;
}

TrackNextGameID_BackendMessage::
  TrackNextGameID_BackendMessage(uint32_t id1, uint32_t id2, bool server,
				 u_int howmany, u_int start)
    : BackendMessage((server ? TRACK_NEXT_GAMEID|FROM_SERVER
			     : TRACK_NEXT_GAMEID)),
      m_number(htole32(howmany)), m_start(htole32(start))
{
  setup_header(id1, id2, server ? 8 : 4);
}

TrackNextGameID_BackendMessage::
  TrackNextGameID_BackendMessage(const u_char *inbuf, size_t in_len,
				 int msg_type, bool become_owner)
    : BackendMessage(msg_type, inbuf, in_len), m_start(0)
{
  m_number = read32le(inbuf, 16);
  if (msg_type & FROM_SERVER) {
    m_start = read32le(inbuf, 20);
  }
  if (become_owner) {
    delete[] inbuf;
  }
#ifdef DEBUG_ENABLE
  m_unsafe = false;
#endif
}

u_int TrackNextGameID_BackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  bool not_server = ((m_type & FROM_SERVER) ? false : true);
  START_FILL_TYPE;
  WRITE_4_BYTES(m_number, not_server);
  if (!not_server) {
    WRITE_4_BYTES(m_start, true);
  }
  END_FILL_TYPE;
}

TrackAgeRequest_ToBackendMessage::
  TrackAgeRequest_ToBackendMessage(uint32_t id1, uint32_t id2,
				   uint32_t reqid, const UruString &agename,
				   const u_char *ageuuid)
    : BackendMessage(TRACK_FIND_GAME),
      m_reqid(htole32(reqid)), m_filename(NULL)
{
  m_filename = new UruString(agename, true);
  memcpy(m_uuid, ageuuid, UUID_RAW_LEN);
  setup_header(id1, id2,
	       4+UUID_RAW_LEN+m_filename->send_len(true, false, true));
}

TrackAgeRequest_ToBackendMessage::
  TrackAgeRequest_ToBackendMessage(const u_char *inbuf, size_t in_len,
				   bool become_owner)
    : BackendMessage(TRACK_FIND_GAME, inbuf, in_len),
      m_reqid(0), m_filename(NULL)
{
  m_reqid = read32le(inbuf, 16);
  memcpy(m_uuid, inbuf+20, UUID_RAW_LEN);
  m_filename = new UruString(inbuf+20+UUID_RAW_LEN, in_len-(20+UUID_RAW_LEN),
			     true, false, true);
  if (become_owner) {
    delete[] inbuf;
  }
#ifdef DEBUG_ENABLE
  // XXX we didn't really need to copy the data
  // message should not be queued m_unsafe = false;
#endif
}

u_int TrackAgeRequest_ToBackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  START_FILL_TYPE;
  WRITE_4_BYTES(m_reqid, false);
  WRITE_BUFFER(m_uuid, UUID_RAW_LEN, false);
  WRITE_URU_STRING_PTR(m_filename, true, false, true, false, true);
  END_FILL_TYPE;
}

TrackAgeRequest_FromBackendMessage::
  TrackAgeRequest_FromBackendMessage(uint32_t id1, uint32_t id2,
				     uint32_t reqid, status_code_t result,
				     const u_char *uuid, uint32_t server_id,
				     uint32_t age_node, uint32_t ipaddr)
    : BackendMessage(TRACK_FIND_GAME|FROM_SERVER),
      m_reqid(htole32(reqid)), m_result(htole32(result))
{
  setup_header(id1, id2, 20+UUID_RAW_LEN);
  write32(m_body, 0, server_id);
  if (uuid) {
    memcpy(m_body+4, uuid, UUID_RAW_LEN);
  }
  else {
    memset(m_body+4, 0, UUID_RAW_LEN);
  }
  write32(m_body, 4+UUID_RAW_LEN, age_node);
  write32(m_body, 8+UUID_RAW_LEN, ipaddr);
}

TrackAgeRequest_FromBackendMessage::
  TrackAgeRequest_FromBackendMessage(const u_char *inbuf, size_t in_len,
				     bool become_owner)
    : BackendMessage(TRACK_FIND_GAME|FROM_SERVER, inbuf, in_len)
{
  m_reqid = read32le(inbuf, 16);
  m_result = read32le(inbuf, 20);
  memcpy(m_body, inbuf+24, 28);
  if (become_owner) {
    delete[] inbuf;
  }
#ifdef DEBUG_ENABLE
  // XXX we didn't really need to copy the data
  // message should not be queued m_unsafe = false;
#endif
}

u_int TrackAgeRequest_FromBackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  START_FILL_TYPE;
  WRITE_4_BYTES(m_reqid, false);
  WRITE_4_BYTES(m_result, false);
  WRITE_BUFFER(m_body, 28, true);
  END_FILL_TYPE;
}

TrackStartAge_FromBackendMessage::
  TrackStartAge_FromBackendMessage(uint32_t id1, uint32_t id2,
				   UruString *agename, const u_char *ageuuid)
   : BackendMessage(TRACK_START_GAME|FROM_SERVER), m_filename(agename)
{
  memcpy(m_ageuuid, ageuuid, UUID_RAW_LEN);
  setup_header(id1, id2,
	       UUID_RAW_LEN+agename->send_len(true, false, true));
}

TrackStartAge_FromBackendMessage::
  TrackStartAge_FromBackendMessage(const u_char *inbuf, size_t in_len,
				   bool become_owner)
    : BackendMessage(TRACK_START_GAME|FROM_SERVER, inbuf, in_len),
      m_filename(NULL)
{
  memcpy(m_ageuuid, inbuf+16, UUID_RAW_LEN);
  m_filename = new UruString(inbuf+16+UUID_RAW_LEN, in_len-(16+UUID_RAW_LEN),
			     true, false, true);
  if (become_owner) {
    delete[] inbuf;
  }
#ifdef DEBUG_ENABLE
  // XXX we didn't really need to copy the data
  // message should not be queued m_unsafe = false;
#endif
}

u_int TrackStartAge_FromBackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  START_FILL_TYPE;
  WRITE_BUFFER(m_ageuuid, UUID_RAW_LEN, false);
  WRITE_URU_STRING_PTR(m_filename, true, false, true, false, true);
  END_FILL_TYPE;
}

TrackStartAge_ToBackendMessage::
  TrackStartAge_ToBackendMessage(uint32_t id1, uint32_t id2,
				 const u_char *ageuuid,
				 TrackStartAge_ToBackendMessage::problem_t p)
   : BackendMessage(TRACK_START_GAME), m_problem(htole32(p))
{
  memcpy(m_ageuuid, ageuuid, UUID_RAW_LEN);
  setup_header(id1, id2, 4+UUID_RAW_LEN);
}

TrackStartAge_ToBackendMessage::
  TrackStartAge_ToBackendMessage(const u_char *inbuf, size_t in_len,
				 bool become_owner)
    : BackendMessage(TRACK_START_GAME, inbuf, in_len)
{
  m_problem = read32le(inbuf, 16);
  memcpy(m_ageuuid, inbuf+20, UUID_RAW_LEN);
  if (become_owner) {
    delete[] inbuf;
  }
#ifdef DEBUG_ENABLE
  // XXX we didn't really need to copy the data
  // message should not be queued m_unsafe = false;
#endif
}

u_int TrackStartAge_ToBackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  START_FILL_TYPE;
  WRITE_4_BYTES(m_problem, false);
  WRITE_BUFFER(m_ageuuid, UUID_RAW_LEN, true);
  END_FILL_TYPE;
}

TrackAddPlayer_FromBackendMessage::
  TrackAddPlayer_FromBackendMessage(uint32_t id1, uint32_t id2, kinum_t kinum,
				    const UruString &player_name,
				    const u_char *uuid)
    : BackendMessage(TRACK_ADD_PLAYER|FROM_SERVER), m_kinum(htole32(kinum)),
      m_name(NULL)
{
  memcpy(m_uuid, uuid, UUID_RAW_LEN);
  m_name = new UruString(player_name, true); // copy string
  setup_header(id1, id2, 4+UUID_RAW_LEN+m_name->send_len(true, false, true));
}

TrackAddPlayer_FromBackendMessage::
  TrackAddPlayer_FromBackendMessage(const u_char *inbuf, size_t in_len,
				    bool become_owner)
    : BackendMessage(TRACK_ADD_PLAYER|FROM_SERVER, inbuf, in_len)
{
  m_kinum = read32le(inbuf, 16);
  memcpy(m_uuid, inbuf+20, UUID_RAW_LEN);
  m_name = new UruString(inbuf+20+UUID_RAW_LEN, in_len-(20+UUID_RAW_LEN),
			 true, false, true);
  if (become_owner) {
    delete[] inbuf;
  }
#ifdef DEBUG_ENABLE
  // XXX we didn't really need to copy the data
  // message should not be queued m_unsafe = false;
#endif
}

u_int TrackAddPlayer_FromBackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  START_FILL_TYPE;
  WRITE_4_BYTES(m_kinum, false);
  WRITE_BUFFER(m_uuid, UUID_RAW_LEN, false);
  WRITE_URU_STRING_PTR(m_name, true, false, true, false, true);
  END_FILL_TYPE;
}

TrackAddPlayer_ToBackendMessage::
  TrackAddPlayer_ToBackendMessage(uint32_t id1, uint32_t id2,
				  kinum_t kinum, status_code_t result)
    : BackendMessage(TRACK_ADD_PLAYER),
      m_kinum(htole32(kinum)), m_result(htole32(result))
{
  setup_header(id1, id2, 8);
}

TrackAddPlayer_ToBackendMessage::
  TrackAddPlayer_ToBackendMessage(const u_char *inbuf, size_t in_len,
				  bool become_owner)
    : BackendMessage(TRACK_ADD_PLAYER, inbuf, in_len)
{
  m_kinum = read32le(inbuf, 16);
  m_result = read32le(inbuf, 20);
  if (become_owner) {
    delete[] inbuf;
  }
#ifdef DEBUG_ENABLE
  // message should not be queued m_unsafe = false;
#endif
}

u_int TrackAddPlayer_ToBackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  START_FILL_TYPE;
  WRITE_4_BYTES(m_kinum, false);
  WRITE_4_BYTES(m_result, true);
  END_FILL_TYPE;
}

void Marker_BackendMessage::change_to_server() {
  m_type |= FROM_SERVER;
  write32(m_header, 4, m_type);
}

MarkerGetGame_BackendMessage::
  MarkerGetGame_BackendMessage(uint32_t id1, uint32_t id2, bool server,
			       uint32_t gameid, bool exists,
			       uint32_t player_or_localid, char type,
			       const u_char *uuid, UruString *name)
    : Marker_BackendMessage((server ? MARKER_NEWGAME|FROM_SERVER
				    : MARKER_NEWGAME),
			    gameid, player_or_localid),
      m_game_exists(!!exists), m_game_type(type), m_name(NULL)
{
  if (uuid) {
    memcpy(m_template, uuid, UUID_RAW_LEN);
  }
  else {
    memset(m_template, 0, UUID_RAW_LEN);
  }
  if (name) {
    m_name = new UruString(*name, true);
  }
  else {
    m_name = new UruString();
  }
  setup_header(id1, id2, 10+UUID_RAW_LEN+m_name->send_len(true, false, true));
}

MarkerGetGame_BackendMessage::
  MarkerGetGame_BackendMessage(const u_char *inbuf, size_t in_len,
			       int msg_type, bool become_owner)
    : Marker_BackendMessage(msg_type, inbuf, in_len), m_name(NULL)
{
  m_game_exists = inbuf[24];
  m_game_type = inbuf[25];
  memcpy(m_template, inbuf+26, UUID_RAW_LEN);
  if (become_owner) {
    m_buf = const_cast<u_char*>(inbuf); // safe; we're becoming owner
#ifdef DEBUG_ENABLE
    // message should not be queued m_unsafe = false;
#endif
  }
  m_name = new UruString(inbuf+(26+UUID_RAW_LEN), in_len-(26+UUID_RAW_LEN),
			 true, false, !become_owner);
}

u_int MarkerGetGame_BackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  START_FILL_TYPE;
  WRITE_4_BYTES(m_requester, false);
  WRITE_4_BYTES(m_localid, false);
  WRITE_1_BYTE(m_game_exists, false);
  WRITE_1_BYTE(m_game_type, false);
  WRITE_BUFFER(m_template, UUID_RAW_LEN, false);
  WRITE_URU_STRING_PTR(m_name, true, false, true, false, true);
  END_FILL_TYPE;
}

MarkerAdd_BackendMessage::
  MarkerAdd_BackendMessage(uint32_t id1, uint32_t id2, bool server,
			   uint32_t gameid, uint32_t localid,
			   double x, double y, double z,
			   const UruString &name, const UruString &age,
			   int number)
    : Marker_BackendMessage((server ? MARKER_ADD|FROM_SERVER
			            : MARKER_ADD), gameid, localid),
      m_name(NULL), m_agename(NULL)
{
  m_buf = new u_char[sizeof(marker_data_t)];
  m_data = (marker_data_t*)m_buf;
  m_data->x = x;
  m_data->y = y;
  m_data->z = z;
  m_data->number = htole32(number);
  m_name = new UruString(name, true);
  m_agename = new UruString(age, true);
  setup_header(id1, id2, 8+marker_data_len
			  +m_name->send_len(true, false, true)
			  +m_agename->send_len(true, false, true));
}

MarkerAdd_BackendMessage::
  MarkerAdd_BackendMessage(const u_char *inbuf, size_t in_len,
			   int msg_type, bool become_owner)
    : Marker_BackendMessage(msg_type, inbuf, in_len),
      m_name(NULL), m_agename(NULL)
{
  if (become_owner) {
    m_buf = const_cast<u_char*>(inbuf); // safe; we're becoming owner
    m_data = (marker_data_t*)(m_buf+24);
  }
  else {
    m_buf = new u_char[sizeof(marker_data_t)];
    m_data = (marker_data_t*)(m_buf);
    memcpy(m_buf, inbuf+24, marker_data_len);
  }
  u_int off = 24+marker_data_len;
  m_name = new UruString(inbuf+off, in_len-(off+2), true, false,
			 !become_owner);
  off += m_name->arrival_len();
  m_agename = new UruString(inbuf+off, in_len-off, true, false,
			    !become_owner);
#ifdef DEBUG_ENABLE
  m_unsafe = false;
#endif
}

u_int MarkerAdd_BackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  u_char *fakebuf;
  START_FILL_TYPE;
  WRITE_4_BYTES(m_requester, false);
  WRITE_4_BYTES(m_localid, false);
  fakebuf = (u_char*)&m_data->x;
  WRITE_BUFFER(fakebuf, 8, false);
  fakebuf = (u_char*)&m_data->y;
  WRITE_BUFFER(fakebuf, 8, false);
  fakebuf = (u_char*)&m_data->z;
  WRITE_BUFFER(fakebuf, 8, false);
  WRITE_4_BYTES(m_data->number, false);
  WRITE_URU_STRING_PTR(m_name, true, false, true, false, false);
  WRITE_URU_STRING_PTR(m_agename, true, false, true, false, true);
  END_FILL_TYPE;
}

MarkersAll_BackendMessage::
  MarkersAll_BackendMessage(uint32_t id1, uint32_t id2, uint32_t localid,
			    uint32_t gameid, size_t num_entries)
    : Marker_BackendMessage(MARKER_DUMP|FROM_SERVER, gameid, localid),
      m_listlen(0), m_index(0), m_current(NULL), m_name(NULL), m_agename(NULL)
{
  m_list.resize(num_entries); // use resize() to initialize all elements
  // this is for zero markers
  setup_header(id1, id2, 12);
}

MarkersAll_BackendMessage::
  MarkersAll_BackendMessage(const u_char *inbuf, size_t in_len,
			    bool become_owner)
    : Marker_BackendMessage(MARKER_DUMP|FROM_SERVER, inbuf, in_len),
      m_index(0), m_name(NULL), m_agename(NULL)
{
  m_listlen = read32le(inbuf, 24);
  m_buflen = in_len-28;
  if (become_owner) {
    m_buf = const_cast<u_char*>(inbuf); // safe; we're becoming owner
    m_bufp = inbuf+28;
  }
  else {
    // we are copying this data so the storage can be used by the game
    // server to send its messages
    m_buf = new u_char[m_buflen];
    memcpy(m_buf, inbuf+28, m_buflen);
    m_bufp = m_buf;
  }

  // now set up for iterating through the markers
  m_current = (marker_data_t*)m_bufp;
  m_name = new UruString(m_bufp+marker_data_len,
			 -1/*assumes backend is behaving*/, true, false,
			 false/*backed by m_buf*/);
  m_agename = new UruString(m_bufp+marker_data_len+m_name->arrival_len(),
			    -1, true, false, false);
#ifdef DEBUG_ENABLE
  m_unsafe = false;
#endif
}

void MarkersAll_BackendMessage::add_marker(int32_t number,
					   double x, double y, double z,
					   UruString &name, UruString &age) {
  struct marker_info &marker = m_list[m_index++];
  marker.data.x = x;
  marker.data.y = y;
  marker.data.z = z;
  marker.data.number = htole32(number);
  // these assignments are safe since name and age will have copied their
  // data already (assigned from C strings), so operator= copies again
  marker.markername = name;
  marker.agename = age;
  marker.info_size = marker_data_len+name.send_len(true, false, false)
				    +age.send_len(true, false, false);
}

void MarkersAll_BackendMessage::finalize() {
  if (m_index > 0) {
    m_listlen = htole32(m_index);
    size_t total = 12;
    for (u_int i = 0; i < m_index; i++) {
      total += m_list[i].info_size;
    }
    setup_header(get_id1(), get_id2(), total);
  }
}

void MarkersAll_BackendMessage::advance_index() {
  if (!m_buf) {
    // programmer error
#ifdef DEBUG_ENABLE
    throw std::logic_error("MarkersAll is not designed to be \"read\" "
			   "on the sender side");
#endif
  }
  if (++m_index < size()) {
    m_bufp += marker_data_len;
    m_bufp += m_name->arrival_len() + m_agename->arrival_len();
    delete m_name;
    delete m_agename;
    m_current = (marker_data_t*)m_bufp;
    m_name = new UruString(m_bufp+marker_data_len,
			   -1, true, false, false);
    m_agename =
      new UruString(m_bufp+marker_data_len+m_name->arrival_len(),
		    -1, true, false, false);
  }
  else {
    // I would rather re-read markers than read bad memory
#ifdef DEBUG_ENABLE
    // a simple for loop will cause m_index == size() but go no further,
    // so allow for that
    if (m_index > size()) {
      throw std::logic_error("advanced MarkersAll index past end of list");
    }
#endif
  }
}

u_int MarkersAll_BackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  if (m_buf) {
    // programmer error
#ifdef DEBUG_ENABLE
    throw std::logic_error("MarkersAll is not designed to be \"written\" "
			   "on the receiver side");
#endif
  }
  START_FILL_TYPE;
  WRITE_4_BYTES(m_requester, false);
  WRITE_4_BYTES(m_localid, false);
  if (m_index > 0) {
    WRITE_4_BYTES(m_listlen, false);
    for (u_int i = 0; i < m_index; i++) {
      struct marker_info &marker = m_list[i];
      u_char *asbuf = (u_char*)&marker.data;
      WRITE_BUFFER(asbuf, marker_data_len, false);
      UruString *str = &marker.markername;
      WRITE_URU_STRING_PTR(str, true, false, false, false, false);
      str = &marker.agename;
      WRITE_URU_STRING_PTR(str, true, false, false, false,
			   (i+1 == m_index ? true : false));
    }
  }
  else {
    WRITE_4_BYTES(m_listlen, true);
  }
  END_FILL_TYPE;
}

MarkersCaptured_BackendMessage::
  MarkersCaptured_BackendMessage(uint32_t id1, uint32_t id2, uint32_t localid,
				 uint32_t gameid, size_t num_entries)
    : Marker_BackendMessage(MARKER_STATE|FROM_SERVER, gameid, localid),
      m_listlen(htole32(num_entries)), m_index(0)
{
  if (num_entries > 0) {
    m_buflen = 8*num_entries;
    m_buf = new u_char[m_buflen];
  }
  // this is for zero markers
  setup_header(id1, id2, 12);
}

MarkersCaptured_BackendMessage::
  MarkersCaptured_BackendMessage(const u_char *inbuf, size_t in_len,
				 bool become_owner)
    : Marker_BackendMessage(MARKER_STATE|FROM_SERVER, inbuf, in_len),
      m_index(0)
{
  m_listlen = read32le(inbuf, 24);
  if (become_owner) {
    m_buf = const_cast<u_char*>(inbuf); // safe; we're becoming owner
#ifdef DEBUG_ENABLE
    // message should not be queued m_unsafe = false;
#endif
    m_bufp = m_buf+28;
  }
  else {
    m_bufp = const_cast<u_char*>(inbuf+28); // less safe, don't use add_marker!
  }
}

void MarkersCaptured_BackendMessage::add_marker(int32_t number,
						int32_t value) {
  if (m_index < size()) {
    u_int offset = (m_index*8/*2 4-byte integers per element*/);
    write32(m_buf, offset, number);
    offset += 4;
    write32(m_buf, offset, value);
    m_index++;
  }
}

void MarkersCaptured_BackendMessage::finalize() {
  if (m_index != size()) {
    // this just means fewer markers were added than expected; it's a DB
    // problem but not harmful here
    m_listlen = le32toh(m_index);
  }
  if (m_index > 0) {
    setup_header(get_id1(), get_id2(), 12+(m_index*8));
  }
}

u_int MarkersCaptured_BackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  START_FILL_TYPE;
  WRITE_4_BYTES(m_requester, false);
  WRITE_4_BYTES(m_localid, false);
  if (m_index > 0) {
    WRITE_4_BYTES(m_listlen, false);
    size_t bufsize = m_index*8;
    WRITE_BUFFER(m_buf, bufsize, true);
  }
  else {
    WRITE_4_BYTES(m_listlen, true);
  }
  END_FILL_TYPE;
}

MarkerGameRename_BackendMessage::
  MarkerGameRename_BackendMessage(uint32_t id1, uint32_t id2, bool server,
				  uint32_t gameid, uint32_t localid,
				  const UruString &name)
    : Marker_BackendMessage((server ? MARKER_GAME_RENAME|FROM_SERVER
			            : MARKER_GAME_RENAME), gameid, localid),
      m_name(NULL)
{
  m_name = new UruString(name, true);
  setup_header(id1, id2, 8+m_name->send_len(true, false, true));
}

MarkerGameRename_BackendMessage::
  MarkerGameRename_BackendMessage(const u_char *inbuf, size_t in_len,
				  int msg_type, bool become_owner)
    : Marker_BackendMessage(msg_type, inbuf, in_len), m_name(NULL)
{
  m_name = new UruString(inbuf+24, in_len-24, true, false, !become_owner);
  if (become_owner) {
    m_buf = const_cast<u_char*>(inbuf); // safe; we're becoming owner
  }
#ifdef DEBUG_ENABLE
  m_unsafe = false;
#endif
}

u_int MarkerGameRename_BackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  START_FILL_TYPE;
  WRITE_4_BYTES(m_requester, false);
  WRITE_4_BYTES(m_localid, false);
  WRITE_URU_STRING_PTR(m_name, true, false, true, false, true);
  END_FILL_TYPE;
}

MarkerGameDelete_BackendMessage::
  MarkerGameDelete_BackendMessage(uint32_t id1, uint32_t id2, bool server,
				  uint32_t gameid, uint32_t localid)
    : Marker_BackendMessage((server ? MARKER_GAME_DELETE|FROM_SERVER
			            : MARKER_GAME_DELETE), gameid, localid)
{
  setup_header(id1, id2, 8);
}

MarkerGameDelete_BackendMessage::
  MarkerGameDelete_BackendMessage(const u_char *inbuf, size_t in_len,
				  int msg_type, bool become_owner)
    : Marker_BackendMessage(msg_type, inbuf, in_len)
{
  if (become_owner) {
    delete[] inbuf;
  }
#ifdef DEBUG_ENABLE
  m_unsafe = false;
#endif
}

u_int MarkerGameDelete_BackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  START_FILL_TYPE;
  WRITE_4_BYTES(m_requester, false);
  WRITE_4_BYTES(m_localid, true);
  END_FILL_TYPE;
}

MarkerGameRenameMarker_BackendMessage::
  MarkerGameRenameMarker_BackendMessage(uint32_t id1, uint32_t id2,
					bool server, uint32_t gameid,
					uint32_t localid, int32_t number,
					const UruString &name)
    : Marker_BackendMessage((server ? MARKER_RENAME|FROM_SERVER
			            : MARKER_RENAME), gameid, localid),
      m_number(htole32(number)), m_name(NULL)
{
  m_name = new UruString(name, true);
  setup_header(id1, id2, 12+m_name->send_len(true, false, true));
}

MarkerGameRenameMarker_BackendMessage::
  MarkerGameRenameMarker_BackendMessage(const u_char *inbuf, size_t in_len,
					int msg_type, bool become_owner)
    : Marker_BackendMessage(msg_type, inbuf, in_len), m_name(NULL)
{
  m_number = read32le(inbuf, 24);
  m_name = new UruString(inbuf+28, in_len-28, true, false, !become_owner);
  if (become_owner) {
    m_buf = const_cast<u_char*>(inbuf); // safe; we're becoming owner
  }
#ifdef DEBUG_ENABLE
  m_unsafe = false;
#endif
}

u_int MarkerGameRenameMarker_BackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  START_FILL_TYPE;
  WRITE_4_BYTES(m_requester, false);
  WRITE_4_BYTES(m_localid, false);
  WRITE_4_BYTES(m_number, false);
  WRITE_URU_STRING_PTR(m_name, true, false, true, false, true);
  END_FILL_TYPE;
}

MarkerGameDeleteMarker_BackendMessage::
  MarkerGameDeleteMarker_BackendMessage(uint32_t id1, uint32_t id2,
					bool server, uint32_t gameid,
					uint32_t localid, int32_t number)
    : Marker_BackendMessage((server ? MARKER_DELETE|FROM_SERVER
			            : MARKER_DELETE), gameid, localid),
      m_number(htole32(number))
{
  setup_header(id1, id2, 12);
}

MarkerGameDeleteMarker_BackendMessage::
  MarkerGameDeleteMarker_BackendMessage(const u_char *inbuf, size_t in_len,
					int msg_type, bool become_owner)
    : Marker_BackendMessage(msg_type, inbuf, in_len)
{
  m_number = read32le(inbuf, 24);
  if (become_owner) {
    delete[] inbuf;
  }
#ifdef DEBUG_ENABLE
  m_unsafe = false;
#endif
}

u_int MarkerGameDeleteMarker_BackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  START_FILL_TYPE;
  WRITE_4_BYTES(m_requester, false);
  WRITE_4_BYTES(m_localid, false);
  WRITE_4_BYTES(m_number, true);
  END_FILL_TYPE;
}

MarkerGameCaptureMarker_BackendMessage::
  MarkerGameCaptureMarker_BackendMessage(uint32_t id1, uint32_t id2,
					 bool server, uint32_t gameid,
					 uint32_t localid, kinum_t player,
					 int32_t number, int32_t newvalue)
    : Marker_BackendMessage((server ? MARKER_CAPTURE|FROM_SERVER
			            : MARKER_CAPTURE), gameid, localid),
      m_player(htole32(player)), m_number(htole32(number)),
      m_value(htole32(newvalue))
{
  setup_header(id1, id2, 20);
}

MarkerGameCaptureMarker_BackendMessage::
  MarkerGameCaptureMarker_BackendMessage(const u_char *inbuf, size_t in_len,
					int msg_type, bool become_owner)
    : Marker_BackendMessage(msg_type, inbuf, in_len)
{
  m_player = read32le(inbuf, 24);
  m_number = read32le(inbuf, 28);
  m_value = read32le(inbuf, 32);
  if (become_owner) {
    delete[] inbuf;
  }
#ifdef DEBUG_ENABLE
  m_unsafe = false;
#endif
}

u_int MarkerGameCaptureMarker_BackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  START_FILL_TYPE;
  WRITE_4_BYTES(m_requester, false);
  WRITE_4_BYTES(m_localid, false);
  WRITE_4_BYTES(m_player, false);
  WRITE_4_BYTES(m_number, false);
  WRITE_4_BYTES(m_value, true);
  END_FILL_TYPE;
}

MarkerGameStop_BackendMessage::
  MarkerGameStop_BackendMessage(uint32_t id1, uint32_t id2, bool server,
				uint32_t gameid, uint32_t localid,
				kinum_t player)
    : Marker_BackendMessage((server ? MARKER_GAME_STOP|FROM_SERVER
			            : MARKER_GAME_STOP), gameid, localid),
      m_player(htole32(player))
{
  setup_header(id1, id2, 12);
}

MarkerGameStop_BackendMessage::
  MarkerGameStop_BackendMessage(const u_char *inbuf, size_t in_len,
				int msg_type, bool become_owner)
    : Marker_BackendMessage(msg_type, inbuf, in_len)
{
  m_player = read32le(inbuf, 24);
  if (become_owner) {
    delete[] inbuf;
  }
#ifdef DEBUG_ENABLE
  m_unsafe = false;
#endif
}

u_int MarkerGameStop_BackendMessage::
  fill_type(bool iovs, u_int start_at, bool *msg_done,
	    struct iovec *iov, u_int iov_ct, u_char *buffer, size_t buflen) {
  START_FILL_TYPE;
  WRITE_4_BYTES(m_requester, false);
  WRITE_4_BYTES(m_localid, false);
  WRITE_4_BYTES(m_player, true);
  END_FILL_TYPE;
}
