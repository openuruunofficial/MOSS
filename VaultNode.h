/* -*- c++ -*- */

/*
  MOSS - A server for the Myst Online: Uru Live client/protocol
  Copyright (C) 2008,2011  a'moaca'

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
 * This class represents a vault node. It also encapsulates the information
 * needed to convert what is in the DB to and from what is sent on the wire.
 * This way, vault knowledge should be in one place rather than sprinkled
 * through the request handlers.
 */

//#include <stdlib.h>
//#include <string.h>
//#include <sys/uio.h> /* for struct iovec */
//
//#include "protocol.h"
//#include "UruString.h"

#ifndef _VAULT_NODE_H_
#define _VAULT_NODE_H_

class VaultNode {
public:
  typedef enum {
    InvalidNode		= 0,
    CCRNode		= 0x1,
    PlayerNode		= 0x2,
    AgeNode		= 0x3,
    FolderNode		= 0x16,
    PlayerInfoNode	= 0x17,
    SystemNode		= 0x18,
    ImageNode		= 0x19,
    TextNoteNode	= 0x1a,
    SDLNode		= 0x1b,
    AgeLinkNode		= 0x1c,
    ChronicleNode	= 0x1d,
    PlayerInfoListNode	= 0x1e,
    AgeInfoNode		= 0x21,
    AgeInfoListNode	= 0x22,
    MarkergameNode	= 0x23
  } vault_nodetype_t;
  typedef enum {
    INT,
    UINT,
    UUID,
    STRING,
    BLOB
  } datatype_t;
  typedef struct {
    vault_bitfield_t bit;
    datatype_t datatype;
    const char *col_name;
    const char *fetch_name;
    bool fetch_required;
  } ColumnSpec;

  // when called, buf+0 is the location of the length value (4 bytes before
  // the first bitfield ("mask" in Alcugs and therefore the Wireshark plugin))
  // but len is the actual buffer length (which should be equal to the 
  // length value + 4)
  static bool check_len_by_bitfields(const u_char *buf, size_t len);

  // This constructor is for building a node up from data (e.g. from the DB).
  VaultNode();
  // This constructor will parse a buffer to build the whole object with the
  // length value at inbuf+0.
  // NOTE that it is expected the buffer is long enough for the data in it,
  // i.e., check_len_by_bitfields() returns true.
  // NOTE also that if copy_data is false, the VaultNode will be backed by
  // inbuf without a direct pointer to it, so other code must take care to
  // delete[] that buffer, and after the VaultNode is done. Also it is
  // expected that calling code will NOT use uuid_ptr() or data_ptr() to
  // write data to the node.
  VaultNode(const u_char *inbuf, bool copy_data=true);
  virtual ~VaultNode();

  // if we ever find a use of bitfield2, we'll have to add an argument to
  // these next six functions

  // these are for finding out what data is possible for a node type
  static uint32_t all_bits_for_type(vault_nodetype_t type);
  static const ColumnSpec * get_spec(vault_nodetype_t type,
				     vault_bitfield_t bit);

  /*
   * Accessors for changing or reading data. Calling one of the first three
   * functions implicitly sets the bit in the bitfield, and the node's idea
   * of its size is adjusted accordingly. The second three functions are
   * for read access and do not set bits or the size.
   */
  // this returns a reference to make life with pqxx easier; make sure the
  // value is in little-endian (transmission) order
  uint32_t & num_ref(vault_bitfield_t bit);
  // the returned buffer will have UUID_RAW_LEN bytes
  u_char * uuid_ptr(vault_bitfield_t bit);
  // the returned buffer will have len bytes; the len should not include the
  // four-byte length value, which will be placed in the first four bytes of
  // what is allocated and the buffer after it is returned -- note for
  // widestrings this length is (char count)*2 and the string should be
  // null-terminated, so len is (strlen(string)+1)*2
  u_char * data_ptr(vault_bitfield_t bit, u_int len);

  const uint32_t num_val(vault_bitfield_t bit) const; // host order
  const u_char * const_uuid_ptr(vault_bitfield_t bit) const;
  // the returned buffer includes the length as the first four bytes
  const u_char * const_data_ptr(vault_bitfield_t bit) const;

  // accessors
  vault_nodetype_t type() const;
  uint32_t bitfield1() const { return m_bits1; }
  uint32_t bitfield2() const { return m_bits2; }
  // this includes the four bytes for the length value itself
  u_int message_len() const { return m_length + 4; }

  static const char * tablename_for_type(vault_nodetype_t type);

  // these have the standard meaning
  u_int fill_iovecs(struct iovec *iov, u_int iov_ct, u_int start_at);
  u_int iovecs_written_bytes(u_int byte_ct, u_int start_at, bool *msg_done);
  u_int fill_buffer(u_char *buffer, size_t len, u_int start_at,
		    bool *msg_done) const;

protected:
  typedef union {
    uint32_t intval;
    u_char *bufval;
  } field_t;

  u_int m_length;
  uint32_t m_bits1;
  uint32_t m_bits2;
  field_t m_fields1[32]; // or, an STL list might be better, but it's unclear
  bool m_owns_bufs;
  u_char m_header[12];
};

#endif /* _VAULT_NODE_H_ */
