/* -*- c++ -*- */

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

/*
 * This file includes the game server messages. There are very few, but
 * PropagateBuffer in turn carries many, many more, and those are here too.
 */

//#include <sys/uio.h> /* for struct iovec */
//
//#include <stdexcept>
//#include <list>
//
//#include "msg_typecodes.h"
//#include "PlKey.h"
//
//#include "Logger.h"
//#include "SDL.h"
//#include "NetworkMessage.h"
//#include "BackendMessage.h"

#ifndef _GAME_MESSAGE_H_
#define _GAME_MESSAGE_H_

class GameMessage : public NetworkMessage {
public:
  // want_len should be filled in to the total length of the message, if
  // known, otherwise it should be set to -1
  static NetworkMessage * make_if_enough(const u_char *buf, size_t len,
					 int *want_len,
					 bool become_owner=false);

  virtual ~GameMessage() { }

protected:
  GameMessage(const u_char *msg_buf, size_t msg_len, int msg_type)
    : NetworkMessage(msg_buf, msg_len, msg_type) { }
  GameMessage(int type) : NetworkMessage(type) { }
};

class GamePingMessage : public GameMessage {
public:
  /*
   * This class copies the buffer passed in.
   */
  GamePingMessage(const u_char *msg_buf, size_t len)
    : GameMessage(kGame2Cli_PingReply)
  {
    m_buf = new u_char[len];
    m_buflen = len;
    memcpy(m_buf, msg_buf, len);
  }
  virtual ~GamePingMessage() { if (m_buf) delete[] m_buf; }

  // the message is only made if it's long enough
  virtual bool check_useable() const { return true; }

  u_int fill_iovecs(struct iovec *iov, u_int iov_ct, u_int start_at);
  u_int iovecs_written_bytes(u_int byte_ct, u_int start_at, bool *msg_done);
  u_int fill_buffer(u_char *buffer, size_t len, u_int start_at,
		    bool *msg_done);

#ifdef DEBUG_ENABLE
  virtual bool persistable() const { return true; } // copies buffer
#endif
};

class GameJoinRequest : public GameMessage {
public:
  static NetworkMessage * make_if_enough(const u_char *buf, size_t len,
					 int *want_len);

  virtual bool check_useable() const { return true; }

  virtual size_t message_len() const { return 30; }

  /*
   * Additional accessors
   */
  uint32_t reqid() const { return m_reqid; }
  uint32_t server_id() const { return m_serverid; }
  const u_char * uuid() const { return m_uuid; }
  kinum_t kinum() const { return m_ki; }

protected:
  uint32_t m_reqid;
  uint32_t m_serverid;
  u_char m_uuid[UUID_RAW_LEN]; // client UUID
  kinum_t m_ki;

  GameJoinRequest(uint32_t reqid, uint32_t serverid, const u_char *uuid,
		  kinum_t ki)
    : GameMessage(kCli2Game_JoinAgeRequest), m_reqid(reqid),
      m_serverid(serverid), m_ki(ki)
  {
    memcpy(m_uuid, uuid, UUID_RAW_LEN);
  }

#ifdef DEBUG_ENABLE
public:
  virtual bool persistable() const { return true; } // copies data
#endif
};

class GameJoinReply : public GameMessage {
public:
  GameJoinReply(uint32_t reqid, status_code_t result)
    : GameMessage(kGame2Cli_JoinAgeReply), m_reqid(reqid), m_result(result)
  { }
  virtual ~GameJoinReply() { if (m_buf) delete[] m_buf; }

  virtual u_int fill_iovecs(struct iovec *iov, u_int iov_ct, u_int start_at);
  virtual u_int iovecs_written_bytes(u_int byte_ct, u_int start_at,
				     bool *msg_done);
  virtual u_int fill_buffer(u_char *buffer, size_t len, u_int start_at,
			    bool *msg_done);
protected:
  uint32_t m_reqid;
  status_code_t m_result;

#ifdef DEBUG_ENABLE
public:
  virtual bool persistable() const { return true; } // copies data
#endif
};

class SharedGameMessage : public GameMessage {
public:
  static NetworkMessage * make_if_enough(const u_char *buf, size_t len,
					 int *want_len,
					 bool become_owner=false);

  virtual ~SharedGameMessage() {
    if (m_sbuf) {
      delete m_sbuf;
    }
    pthread_mutex_destroy(&m_mutex);
  }

  virtual const u_char * buffer() const {
    return (m_sbuf ? m_sbuf->buffer() : NULL);
  }

  virtual u_int fill_iovecs(struct iovec *iov, u_int iov_ct, u_int start_at);
  virtual u_int iovecs_written_bytes(u_int byte_ct, u_int start_at,
				     bool *msg_done);
  virtual u_int fill_buffer(u_char *buffer, size_t len, u_int start_at,
			    bool *msg_done);

  /* 
   * These messages are refcounted; some may be kept around in the game
   * server (e.g. clones, SDL); most may be on multiple MessageQueues (to
   * multiple clients).
   */
  // returns new refcount
  virtual int add_ref() {
    int ret;

    // XXX use atomic instructions instead?
    pthread_mutex_lock(&m_mutex);
    ret = ++m_refct;
    pthread_mutex_unlock(&m_mutex);
    return ret;
  }
  virtual int del_ref() {
    int ret;

    pthread_mutex_lock(&m_mutex);
    ret = --m_refct;
    pthread_mutex_unlock(&m_mutex);
    return ret;
  }

  /*
   * These messages may be kept around longer than those processed and
   * handled immediately, so there must be a way to convert a message from
   * not "owning" the buffer to owning it.
   */
  virtual void make_own_copy();

protected:
  Buffer *m_sbuf;
  pthread_mutex_t m_mutex;
  int m_refct;

  SharedGameMessage(int type, const u_char *buf, size_t len, bool become_owner)
    : GameMessage(type), m_sbuf(NULL), m_refct(1)
  {
    if (pthread_mutex_init(&m_mutex, NULL)) {
      throw std::bad_alloc();
    }
    m_sbuf = new Buffer(len, buf, !become_owner);
    m_buflen = len;
    if (become_owner) {
      m_sbuf->make_owned();
    }
  }
  // constructor for making new messages server-side
  SharedGameMessage(int type) : GameMessage(type), m_sbuf(NULL), m_refct(1) {
    if (pthread_mutex_init(&m_mutex, NULL)) {
      throw std::bad_alloc();
    }
  }

private:
  SharedGameMessage();
  SharedGameMessage(SharedGameMessage&);

#ifdef DEBUG_ENABLE
public:
  virtual bool persistable() const { return (!m_sbuf) || m_sbuf->is_owned(); }
#endif
};

class PropagateBufferMessage : public SharedGameMessage {
public:
  static NetworkMessage * make_if_enough(const u_char *buf, size_t len,
					 int *want_len,
					 bool become_owner=false);

  virtual ~PropagateBufferMessage() { }

  /*
   * Additional accessors
   */
  uint16_t subtype() const { return m_subtype; }
  u_int body_offset() const;
  kinum_t kinum() const;
  // this must be called each time before queuing the message on a queue --
  // note only needs to be called once if the message is put on more than one
  // queue at once
  void set_timestamp() const;

protected:
  uint16_t m_subtype;

  PropagateBufferMessage(uint16_t subtype,
			 const u_char *buf, size_t len, bool become_owner)
    : SharedGameMessage(kCli2Game_PropagateBuffer, buf, len, become_owner),
      m_subtype(subtype) { }
  /*
   * Functions for making new messages server-side
   */
  // constructor
  PropagateBufferMessage() : SharedGameMessage(kGame2Cli_PropagateBuffer) { }
  // this returns the offset given a set of flags
  static u_int body_offset(uint32_t flags);
  // this fills in the header in the message's buffer
  // REQUIRES: m_sbuf exists and is big enough for the header
  u_int format_header(uint16_t subtype, u_int message_len, uint32_t flags,
		      kinum_t ki=0);
};

class GameMgrMessage : public SharedGameMessage {
public:
  // for receiving messages
  static NetworkMessage * make_if_enough(const u_char *buf, size_t len,
					 int *want_len,
					 bool become_owner=false);
  virtual bool check_useable() const;

  virtual ~GameMgrMessage() { }

  /*
   * Additional accessors
   */
  uint32_t msgtype() const { return m_msgtype; }
  uint32_t reqid() const { return m_reqid; }
  // this is actually the game ID only if is_setup() is false
  uint32_t gameid() const { return m_gameid; }

  bool is_setup() const { return (m_reqid != 0); }

  // use this only if is_setup() is true; otherwise the message might not
  // even be this long!
  const u_char *setup_uuid() const {
    if (m_msgtype == 0) { return m_sbuf->buffer()+header_len; }
    else { return m_sbuf->buffer()+header_len+8; }
  }
  // use only if is_setup() is true
  u_int setup_data() const {
    if (m_msgtype == 0) { return header_len+UUID_RAW_LEN+4; }
    else { return header_len+UUID_RAW_LEN+4+8; }
  }
  // use only if is_setup() is false
  u_int body_data() const { return header_len; }

  // be careful using this, make sure we are done reading the message, and
  // that make_own_copy() has been called
  void clobber_msgtype(uint32_t newtype);

protected:
  uint32_t m_msgtype;
  uint32_t m_reqid;
  uint32_t m_gameid;

  // for received messages
  GameMgrMessage(const u_char *buf, size_t len, bool become_owner);
  /*
   * Functions for making new messages server-side
   */
  // for subclasses
  GameMgrMessage(uint32_t msgtype, uint32_t reqid, uint32_t gameid)
    : SharedGameMessage(kGame2Cli_GameMgrMsg),
      m_msgtype(msgtype), m_reqid(reqid), m_gameid(gameid) { }
  static const u_int header_len = 22;
  // this fills in the common header in the message's buffer
  // REQUIRES: m_sbuf exists and is big enough for the header
  u_int format_header(size_t body_len);
};

class PlNetMsgGroupOwner : public PropagateBufferMessage {
public:
  // constructor sets the NetMsg header timestamp
  PlNetMsgGroupOwner(bool is_owner);
};

class PlNetMsgSDLState : public PropagateBufferMessage {
public:
  // constructor sets the NetMsg header timestamp if use_timestamp is true
  PlNetMsgSDLState(SDLState *sdl, bool is_initial_sdl,
		   bool use_timestamp=true);
};

class PlNetMsgInitialAgeStateSent : public PropagateBufferMessage {
public:
  // constructor sets the NetMsg header timestamp
  PlNetMsgInitialAgeStateSent(u_int howmany);
};

class PlNetMsgMembersMsg : public PropagateBufferMessage {
public:
  PlNetMsgMembersMsg(kinum_t requester_ki);
#ifndef STANDALONE
  // call this for each member
  // XXX reseng "hidden" flag not supported
  void addMember(kinum_t ki, UruString *name=NULL,
		 const PlKey *key=NULL, bool pagein=false);
  // you MUST call this before sending the message -- list_or_update is true
  // for plNetMsgMembersList, false for plNetMsgMemberUpdate
  // finalize() also sets the NetMsg header timestamp
  void finalize(bool list_or_update);
protected:
  //static const int kAccountUUID = 0x0001;
  static const int kPlayerID = 0x0002;
  //static const int kTempPlayerID = 0x0004;
  static const int kCCRLevel = 0x0008;
  //static const int kProtectedLogin = 0x0010;
  //static const int kBuildType = 0x0020;
  static const int kPlayerName = 0x0040;
  //static const int kSrcAddr = 0x0080;
  //static const int kSrcPort = 0x0100;
  //static const int kReserved = 0x0200;
  //static const int kClientKey = 0x0400;
  struct info {
    kinum_t ki;
    UruString *name;
    const PlKey *key;
    bool pagein;
  };
  kinum_t m_requester_ki;
  std::list<struct info> m_members;
#endif
};

class PlNetMsgGameMessage : public PropagateBufferMessage {
public:
  /*
   * These two methods are meant to provide data about received messages;
   * PropagateBufferMessage objects can be cast to PlNetMsgGameMessage to
   * use these -- they are const and safe.
   */
  uint16_t msg_type() const;
  // the return value of this includes body_offset()
  // soo many layers, maybe the cake everyone is talking about is a layer cake!
  u_int msg_offset() const;

protected:
  // for constructing new messages server-side
  PlNetMsgGameMessage() : PropagateBufferMessage() { }
  // this builds the entire message, including the PropagateBufferMessage
  // header (via format_header()), it is the real constructor, called by
  // subclasses after they have set up their message-specific data
  // build_msg() also sets the NetMsg header timestamp (if present)
  //
  // (note that only a small amount of data is msg_type specific, hence all
  // the arguments)
  void build_msg(uint32_t propagate_flags, kinum_t propagate_ki,
		 const u_char *msg_buf, size_t msg_len,
		 uint16_t msg_type, uint32_t msg_flags,
		 u_char end_thing, PlKey *object=NULL,
		 PlKey** subobjects=NULL, u_int subobject_count=0,
		 bool no_compress=false);
};

class PlServerReplyMsg : public PlNetMsgGameMessage {
public:
  // constructor sets the NetMsg header timestamp
  PlServerReplyMsg(bool grant, PlKey &key);
};

class PlNetMsgLoadClone : public PlNetMsgGameMessage {
public:
  // this copies the buffer
  // constructor sets the NetMsg header timestamp
  PlNetMsgLoadClone(const u_char *clonebuf, size_t clonelen, PlKey &obj_name,
		    kinum_t kinum, bool is_load, u_int player);
  // notes: these are the possible clone messages and how they look
  // client->server link in		load: 1 end thing: 0
  // client->server link out		- not in MOUL -
  // server->client initial age state	load: 1 end thing: 1
  // server->client other link in	load: 1 end thing: 0
  // server->client other link out	load: 0 end thing: 0
};

class PlNetMsgGameMessageDirected : public PlNetMsgGameMessage {
public:
  PlNetMsgGameMessageDirected(TrackMsgForward_BackendMessage *track_fwded);
  virtual ~PlNetMsgGameMessageDirected();
protected:
  TrackMsgForward_BackendMessage *m_msg;

#ifdef DEBUG_ENABLE
  // need special function here, because m_sbuf is backed by the
  // TrackMsgForward_BackendMessage
public:
  virtual bool persistable() const { return (!m_msg) || m_msg->persistable(); }
#endif
};

class GameMgr_Setup_Reply : public GameMgrMessage {
public:
  GameMgr_Setup_Reply(uint32_t gameid, uint32_t reqid, kinum_t clientid,
		      const u_char *uuid);
};

class GameMgr_Simple_Message : public GameMgrMessage {
public:
  // for sending messages with no game-specific body
  GameMgr_Simple_Message(uint32_t gameid, uint32_t mgr_type);
};

class GameMgr_OneByte_Message : public GameMgrMessage {
public:
  // for sending simple messages with one byte of game-specific body
  GameMgr_OneByte_Message(uint32_t gameid, uint32_t mgr_type, u_char data);
};

class GameMgr_FourByte_Message : public GameMgrMessage {
public:
  // for sending simple messages with one int of game-specific body
  GameMgr_FourByte_Message(uint32_t gameid, uint32_t mgr_type, uint32_t data);
};

class GameMgr_VarSync_VarCreated_Message : public GameMgrMessage {
public:
  GameMgr_VarSync_VarCreated_Message(uint32_t gameid, u_int idx,
				     UruString &name, double value);
};

class GameMgr_Marker_GameCreated_Message : public GameMgrMessage {
public:
  GameMgr_Marker_GameCreated_Message(uint32_t gameid, const u_char *uuid);
};

class GameMgr_Marker_GameNameChanged_Message : public GameMgrMessage {
public:
  GameMgr_Marker_GameNameChanged_Message(uint32_t gameid, UruString *name);
};

class GameMgr_Marker_MarkerAdded_Message : public GameMgrMessage {
public:
  GameMgr_Marker_MarkerAdded_Message(uint32_t gameid,
			const Marker_BackendMessage::marker_data_t *data,
			UruString *name, UruString *age,
			BackendMessage *orig_msg);

  virtual ~GameMgr_Marker_MarkerAdded_Message();

  virtual u_int fill_iovecs(struct iovec *iov, u_int iov_ct, u_int start_at);
  virtual u_int iovecs_written_bytes(u_int byte_ct, u_int start_at,
				     bool *msg_done);
  virtual u_int fill_buffer(u_char *buffer, size_t len, u_int start_at,
			    bool *msg_done);

protected:
  const Marker_BackendMessage::marker_data_t *m_data; // do not delete
  UruString m_marker_name;
  UruString m_age_name;
  BackendMessage *m_backing_msg;
  u_char *m_zeros;
};

class GameMgr_Marker_MarkerCaptured_Message : public GameMgrMessage {
public:
  GameMgr_Marker_MarkerCaptured_Message(uint32_t gameid,
					int32_t marker, char value);
};

class GameMgr_Marker_MarkerNameChanged_Message : public GameMgrMessage {
public:
  GameMgr_Marker_MarkerNameChanged_Message(uint32_t gameid, int32_t marker,
					   UruString *name);
};

class GameMgr_BlueSpiral_ClothOrder_Message : public GameMgrMessage {
public:
  GameMgr_BlueSpiral_ClothOrder_Message(uint32_t gameid, const u_char *order);
};

class GameMgr_Heek_PlayGame_Message : public GameMgrMessage {
public:
  GameMgr_Heek_PlayGame_Message(uint32_t gameid, bool playing, bool single,
				bool enable);
};

class GameMgr_Heek_Welcome_Message : public GameMgrMessage {
public:
  // this copies the name
  GameMgr_Heek_Welcome_Message(uint32_t gameid, int32_t score, uint32_t rank,
			       UruString &name);
};

class GameMgr_Heek_PointUpdate_Message : public GameMgrMessage {
public:
  GameMgr_Heek_PointUpdate_Message(uint32_t gameid, bool send_message,
				   int32_t score, uint32_t rank);
};

class GameMgr_Heek_WinLose_Message : public GameMgrMessage {
public:
  GameMgr_Heek_WinLose_Message(uint32_t gameid, bool win, u_char choice);
};

class GameMgr_Heek_Lights_Message : public GameMgrMessage {
public:
  typedef enum {
    On = 0,
    Off = 1,
    Flash = 2
  } type_t;
  GameMgr_Heek_Lights_Message(uint32_t gameid, u_int light, type_t type);
};

#endif /* _GAME_MESSAGE_H_ */
