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
 * Typecodes for backend messages. They are composed of a class code and
 * an ID per class. The class code is so that, if someday there is more than
 * one backend server, dispatch can be done based on the class code.
 */

#ifndef _BACKEND_TYPECODES_H_
#define _BACKEND_TYPECODES_H_

#define CLASS_AUTH		0x4000000
#define CLASS_VAULT		0x2000000
#define CLASS_ADMIN		0x1000000
#define CLASS_TRACK		0x8000000
#define CLASS_MARKER		0x800000

#define FROM_SERVER		0x80000000

/*
 * Do NOT change the version without a major protocol change.
 *
 * A "major protocol change" would mean adding a new message type that
 * requires the backend to reply to the frontend. (The backend simply drops
 * unrecognized messages. If the frontend does not mind that for a new message
 * type, it is _not_ a major protocol change.) Adding new data onto the end of
 * current messages is also _not_ a major protocol change. But the servers
 * should be able to handle messages without that new data.
 *
 * If you change this, you should make the frontend capable of recognizing and
 * working with older-version backends (that is, use the older protocol). You
 * should make the backend understand messages from older-version frontends.
 */
#define BACKEND_PROTOCOL_VERSION 0


/* (if we had CCR, etc. those would probably be auth too) */
#define AUTH_ACCT_LOGIN 	(CLASS_AUTH|0x03)
#define AUTH_KI_VALIDATE	(CLASS_AUTH|0x06)
#define AUTH_PLAYER_LOGOUT	(CLASS_AUTH|0x17)
#define AUTH_CHANGE_PASSWORD	(CLASS_AUTH|0x08)

#define VAULT_PLAYER_CREATE	(CLASS_VAULT|0x10)
#define VAULT_PLAYER_DELETE	(CLASS_VAULT|0x11)
#define VAULT_PASSTHRU		CLASS_VAULT
/*
  client		server			async server

NodeCreate 0x19		NodeCreated 0x17
NodeFetch 0x1A		NodeFetched 0x18
NodeSave 0x1B		SaveNodeReply 0x20	NodeChanged 0x19
NodeAdd 0x1D		AddNodeReply 0x21	NodeAdded 0x1B
NodeRemove 0x1E		RemoveNodeReply 0x22	NodeRemoved 0x1C
FetchNodeRefs 0x1F	NodeRefsFetched 0x1D
InitAge 0x20		InitAgeReply 0x1E
NodeFind 0x21		NodeFindReply 0x1F
SetSeen 0x22 ???
SendNode 0x23
						NodeDeleted 0x1A ???
 */
#define VAULT_FETCHREFS 	(CLASS_VAULT|0x1D)
#define VAULT_FINDNODE		(CLASS_VAULT|0x1F)
#define VAULT_FETCH		(CLASS_VAULT|0x18)
#define VAULT_SAVENODE		(CLASS_VAULT|0x20)
#define VAULT_CREATENODE	(CLASS_VAULT|0x17)
#define VAULT_ADDREF		(CLASS_VAULT|0x21)
#define VAULT_REMOVEREF 	(CLASS_VAULT|0x22)
#define VAULT_INIT_AGE		(CLASS_VAULT|0x1E)
#define VAULT_AGE_LIST		(CLASS_VAULT|0x28)
#define VAULT_SENDNODE		(CLASS_VAULT|0x8001) /* no reply */
#define VAULT_SET_AGE_PUBLIC	(CLASS_VAULT|0x8002) /* no reply */
#define VAULT_SET_SEEN		(CLASS_VAULT|0x8003) /* unimplemented */
// server-only
#define VAULT_NODE_CHANGED	(CLASS_VAULT|0x19)
#define VAULT_REF_ADDED 	(CLASS_VAULT|0x1B)
#define VAULT_REF_REMOVED	(CLASS_VAULT|0x1C)
// scores
#define VAULT_SCORE_CREATE	(CLASS_VAULT|0x29)
#define VAULT_SCORE_GET 	(CLASS_VAULT|0x2B)
#define VAULT_SCORE_ADD 	(CLASS_VAULT|0x2C)
#define VAULT_SCORE_XFER	(CLASS_VAULT|0x2D)

#define MARKER_NEWGAME		(CLASS_MARKER|0x04)
#define MARKER_ADD		(CLASS_MARKER|0x0E)
#define MARKER_GAME_RENAME	(CLASS_MARKER|0x0B)
#define MARKER_GAME_DELETE	(CLASS_MARKER|0x0D)
#define MARKER_RENAME		(CLASS_MARKER|0x10)
#define MARKER_DELETE		(CLASS_MARKER|0x0F)
#define MARKER_CAPTURE		(CLASS_MARKER|0x11)
#define MARKER_GAME_STOP	(CLASS_MARKER|0x09)
// server-only
#define MARKER_DUMP		(CLASS_MARKER|0x00)
#define MARKER_STATE		(CLASS_MARKER|0x03)

#define ADMIN_HELLO		(CLASS_ADMIN|0x00)
#define ADMIN_KILL_CLIENT	(CLASS_ADMIN|0x27)
// this next message will be used if multiple "connections" are merged into
// one TCP connection
#define ADMIN_BYE		(CLASS_ADMIN|0xff)

/* frontend servers must tell tracking server about themselves */
#define TRACK_PING		(CLASS_TRACK|0x00)
#define TRACK_DISPATCHER_HELLO	(CLASS_TRACK|0x01) /* obsolete */
#define TRACK_DISPATCHER_BYE	(CLASS_TRACK|0x02) /* obsolete */
#define TRACK_GAME_HELLO	(CLASS_TRACK|0x03)
#define TRACK_GAME_BYE		(CLASS_TRACK|0x04)
// for load-balancing if we ever need it
#define TRACK_STATUS		(CLASS_TRACK|0x05) /* unimplemented */
// for tracking what age a player is in (the info is also in the vault,
// the client puts the intended age and its UUID in the vault before starting
// the link, but this form is more direct)
#define TRACK_GAME_PLAYERINFO	(CLASS_TRACK|0x06)
// for interage NetMsgGameMessageDirected
#define TRACK_INTERAGE_FWD	(CLASS_TRACK|0x07)
// for pushing vault-related SDL to game servers
#define TRACK_SDL_UPDATE	(CLASS_TRACK|0x08)
// for guaranteeing unique GameMgr IDs
#define TRACK_NEXT_GAMEID	(CLASS_TRACK|0x09)
// dispatchers tell backend about what server types they provide
#define TRACK_SERVICE_TYPES	(CLASS_TRACK|0x13)
// gatekeeper asking where to go for a service
#define TRACK_FIND_SERVICE	(CLASS_TRACK|0x14)
// (backend pushing service destinations to gatekeeper)
#define TRACK_SERVICE_UPDATE	(CLASS_TRACK|0x15) /* unimplemented */

// auth <-> backend
#define TRACK_FIND_GAME		(CLASS_TRACK|0x10)
// backend <-> dispatcher
#define TRACK_START_GAME	(CLASS_TRACK|0x11)
// backend <-> game
#define TRACK_ADD_PLAYER	(CLASS_TRACK|0x12)

#endif /* _BACKEND_TYPECODES_H_ */
