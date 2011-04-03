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
 * Various protocol values.
 */

#ifndef _PROTOCOL_H_
#define _PROTOCOL_H_

typedef uint32_t kinum_t;

/* 
 * 1: "Internal Error"
 * 2: "No Response From Server"
 * 3: "Invalid Server Data"
 * 4: "Age Not Found"
 * 5: "Unable to connect to Myst Online."
 * 6: "Disconnected from Myst Online."
 * 7: "File Not Found"
 * 8: "Old Build"
 * 9: "Remote Shutdown"
 * 10: "Database Timeout"
 * 11: "Account Already Exists"
 * 12: "Player Already Exists"
 * 13: "Account Not Found."
 * 14: "Player Not Found"
 * 15: "Invalid Parameter"
 * 16: "Name Lookup Failed"
 * 17: "Logged In Elsewhere"
 * 18: "Vault Node Not Found"
 * 19: "Max Players On Account"
 * 20: "Incorrect password.\nMake sure CAPS LOCK is not on."
 * 21: "State Object Not Found"
 * 22: "Login Denied"
 * 23: "Circular Reference"
 * 24: "Account Not Activated."
 * 25: "Key Already Used"
 * 26: "Key Not Found"
 * 27: "Activation Code Not Found"
 * 28: "Player Name Invalid"
 * 29: "Not Supported"
 * 30: "Service Forbidden"
 * 31: "Auth Token Too Old"
 * 32: "Must Use GameTap Client"
 * 33: "Too Many Failed Logins"
 * 34: "Unable to connect to GameTap, please try again in a few minutes."
 * 35: "GameTap: Too Many Auth Options"
 * 36: "GameTap: Missing Parameter"
 * 37: see 34
 * 38: "Your account has been banned from accessing Myst Online.  If you are unsure as to why this happened please contact customer support."
 * 39: "Account kicked by CCR"
 * 40: "Wrong score type for operation"
 * 41: "Not enough points"
 * 42: "Non-fixed score already exists"
 * 43: "No score data found"
 * 44: "Invite: Couldn't find player"
 * 45: "Invite: Too many hoods"
 * >= 46: "Unknown error"
 * -1: "Pending"
 */
typedef enum {
  NO_ERROR			= 0x0,
  ERROR_INTERNAL		= 0x1,
  ERROR_NO_RESPONSE		= 0x2,
  ERROR_INVALID_DATA		= 0x3,
  ERROR_AGE_NOT_FOUND		= 0x4,
  ERROR_DISCONNECTED		= 0x6,
  ERROR_FILE_NOT_FOUND		= 0x7,
  ERROR_REMOTE_SHUTDOWN 	= 0x9,
  ERROR_DB_TIMEOUT		= 0xa,
  ERROR_PLAYER_EXISTS		= 0xc,
  ERROR_ACCT_NOT_FOUND		= 0xd,
  ERROR_PLAYER_NOT_FOUND	= 0xe,
  ERROR_INVALID_PARAM		= 0xf,
  ERROR_NAME_LOOKUP		= 0x10,
  ERROR_LOGGED_IN_ELSEWHERE	= 0x11,
  ERROR_NODE_NOT_FOUND		= 0x12,
  ERROR_MAX_PLAYERS		= 0x13,
  ERROR_BAD_PASSWD		= 0x14,
  ERROR_LOGIN_DENIED		= 0x16,
  ERROR_KEY_NOT_FOUND		= 0x1a,
  ERROR_NAME_INVALID		= 0x1c,
  ERROR_NOT_SUPPORTED		= 0x1d,
  ERROR_FORBIDDEN		= 0x1e,
  ERROR_AUTH_TOO_OLD		= 0x1f,
  ERROR_TOO_MANY_FAILURES	= 0x21,
  ERROR_BANNED			= 0x26,
  ERROR_KICKED			= 0x27,
  ERROR_BAD_SCORE_TYPE		= 0x28,
  ERROR_SCORE_TOO_SMALL		= 0x29,
  ERROR_SCORE_EXISTS		= 0x2a,
  ERROR_NO_SCORE		= 0x2b
} status_code_t;

/*
 * Visitor/paying status (accounts and players)
 */ 
typedef enum {
  GUEST_CUSTOMER		= 0x0,
  PAYING_CUSTOMER		= 0x1
} customer_type_t;

/*
 * Vault bitfield values
 */
  
typedef enum {
  NodeID		= 0x00000001,		// 4 bytes
  CreateTime		= 0x00000002,		// 4 bytes
  ModifyTime		= 0x00000004,		// 4 bytes
  CreateAgeName		= 0x00000008,		// 4-byte len + widestring
  CreateAgeUUID		= 0x00000010,		// UUID (16 bytes)
  CreatorAcctID		= 0x00000020,		// UUID (16 bytes)
  CreatorID		= 0x00000040,		// 4 bytes
  NodeType		= 0x00000080,		// 4 bytes
  Int32_1		= 0x00000100,		// 4 bytes
  Int32_2		= 0x00000200,		// 4 bytes
  Int32_3		= 0x00000400,		// 4 bytes
  Int32_4		= 0x00000800,		// 4 bytes
  UInt32_1		= 0x00001000,		// 4 bytes
  UInt32_2		= 0x00002000,		// 4 bytes
  UInt32_3		= 0x00004000,		// 4 bytes
  UInt32_4		= 0x00008000,		// 4 bytes
  UUID_1		= 0x00010000,		// UUID (16 bytes)
  UUID_2		= 0x00020000,		// UUID (16 bytes)
  UUID_3		= 0x00040000,		// UUID (16 bytes)
  UUID_4		= 0x00080000,		// UUID (16 bytes)
  String64_1		= 0x00100000,		// 4-byte len + widestring
  String64_2		= 0x00200000,		// 4-byte len + widestring
  String64_3		= 0x00400000,		// 4-byte len + widestring
  String64_4		= 0x00800000,		// 4-byte len + widestring
  String64_5		= 0x01000000,		// 4-byte len + widestring
  String64_6		= 0x02000000,		// 4-byte len + widestring
  IString64_1		= 0x04000000,		// 4-byte len + widestring
  IString64_2		= 0x08000000,		// 4-byte len + widestring
  Text_1		= 0x10000000,		// 4-byte len + widestring
  Text_2		= 0x20000000,		// 4-byte len + widestring
  Blob_1		= 0x40000000,		// 4-byte len + blob
  Blob_2		= 0x80000000		// 4-byte len + blob
  // second bitfield unused??
} vault_bitfield_t;

/*
 * plNetMsg flags
 */
#define kHasTimeSent		0x1	/* Alcugs: plNetTimestamp */
#define kHasGameMsgRcvrs	0x2	/* plFlagsMaybeNotify below */
#define kEchoBackToSender	0x4
#define kRequestP2P		0x8
#define kAllowTimeOut		0x10	/* XXX Alcugs: plNetIP */
#define kIndirectMember		0x20	/* Alcugs: plNetFirewalled */
#define kPublicIPClient		0x40
#define kHasContext		0x80
#define kAskVaultForGameState	0x100
#define kHasTransactionID	0x200	/* Alcugs: plNetX */
#define kNewSDLState		0x400	/* Alcugs: plNetBcast */
#define kInitialAgeStateRequest	0x800	/* Alcugs: plNetStateReq */
#define kHasPlayerID		0x1000	/* Alcugs: plNetKi */
#define kUseRelevanceRegions	0x2000	/* plFlagsMaybeAvatarState below */
#define kHasAcctUUID		0x4000	/* Alcugs: plNetGUI */
#define kInterAgeRouting	0x8000	/* Alcugs: plNetDirected */
#define kHasVersion		0x10000	/* Alcugs: plNetVersion */
#define kIsSystemMessage	0x20000	/* Alcugs: plNetCustom */
#define kNeedsReliableSend	0x40000	/* Alcugs: plNetAck */
#define kRouteToAllPlayers	0x80000
/*
 * no pl* type
 */
#define no_plType		0x8000

/*
 * compression flags
 */
#define kCompressionNone	0
#define kCompressionFailed	1
#define kCompressionZlib	2
#define kCompressionDont	3

/*
 * GameMgrMsg types
 */
#define kGameCliPlayerJoinedMsg 0x00
#define kGameCliPlayerLeftMsg 0x01
#define kGameCliInviteFailedMsg 0x02
#define kGameCliOwnerChangeMsg 0x03

// server->client

#define kVarSyncStringVarChanged 0x04
#define kVarSyncNumericVarChanged 0x05
#define kVarSyncAllVarsSent 0x06
#define kVarSyncStringVarCreated 0x07
#define kVarSyncNumericVarCreated 0x08

#define kBlueSpiralClothOrder 0x04
#define kBlueSpiralSuccessfulHit 0x05
#define kBlueSpiralGameWon 0x06
#define kBlueSpiralGameOver 0x07
#define kBlueSpiralGameStarted 0x08

#define kMarkerTemplateCreated 0x04
#define kMarkerTeamAssigned 0x05
#define kMarkerGameType 0x06
#define kMarkerGameStarted 0x07
#define kMarkerGamePaused 0x08
#define kMarkerGameReset 0x09
#define kMarkerGameOver 0x0a
#define kMarkerGameNameChanged 0x0b
#define kMarkerTimeLimitChanged 0x0c
#define kMarkerGameDeleted 0x0d
#define kMarkerMarkerAdded 0x0e
#define kMarkerMarkerDeleted 0x0f
#define kMarkerMarkerNameChanged 0x10
#define kMarkerMarkerCaptured 0x11

#define kHeekPlayGame 0x04
#define kHeekGoodbye 0x05
#define kHeekWelcome 0x06
#define kHeekDrop 0x07
#define kHeekSetup 0x08
#define kHeekLightState 0x09
#define kHeekInterfaceState 0x0a
#define kHeekCountdownState 0x0b
#define kHeekWinLose 0x0c
#define kHeekGameWin 0x0d
#define kHeekPointUpdate 0x0e

// constants

#define kGameInviteSuccess 0x00
#define kGameInviteErrNotOwner 0x01
#define kGameInviteErrAlreadyInvited 0x02
#define kGameInviteErrAlreadyJoined 0x03
#define kGameInviteErrGameStarted 0x04
#define kGameInviteErrGameOver 0x05
#define kGameInviteErrGameFull 0x06
#define kGameInviteErrNoJoin 0x07

#define kMarkerGameQuest 0x00
#define kMarkerGameCGZ 0x01
#define kMarkerGameCapture 0x02
#define kMarkerGameCaptureAndHold 0x03

/* These are backwards from PlasmaConstants.py */
#define kMarkerNotCaptured 0x00 /* name made up */
#define kMarkerCaptured 0x01

#define kHeekCountdownStart 0x00
#define kHeekCountdownStop 0x01
#define kHeekCountdownIdle 0x02

#define kHeekGameChoiceRock 0x00
#define kHeekGameChoicePaper 0x01
#define kHeekGameChoiceScissors 0x02

#define kHeekGameSeqCountdown 0x00
#define kHeekGameSeqChoiceAnim 0x01
#define kHeekGameSeqGameWinAnim 0x02

#define kHeekLightOn 0x00
#define kHeekLightOff 0x01
#define kHeekLightFlash 0x02

// client->server

#define kVarSyncNumericVarChange 0x04
#define kVarSyncNumericVarCreate 0x07

#define kBlueSpiralGameStart 0x03
#define kBlueSpiralClothHit 0x04

#define kMarkerGameStart 0x03
#define kMarkerGamePause 0x04
#define kMarkerGameResetReq 0x05
#define kMarkerGameNameChange 0x06
#define kMarkerTimeLimitChange 0x07  /* no sample - a guess here */
#define kMarkerGameDelete 0x08
#define kMarkerMarkerAdd 0x09
#define kMarkerMarkerDelete 0x0a
#define kMarkerMarkerNameChange 0x0b
#define kMarkerMarkerCapture 0x0c

#define kHeekPlayGameReq 0x03
#define kHeekGoodbyeReq 0x04
#define kHeekChoice 0x05
#define kHeekAnimationFinished 0x06

#endif /* _PROTOCOL_H_ */
