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
 * This class is used by FileServerMessage and AuthServerFileMessage to
 * know what to write at write time. Instances are created and managed by
 * the FileServer or AuthServer, which creates a FileServerMessage or
 * AuthServerFileMessage for each chunk at the appropriate time.
 *
 * XXX This code is okay, but it would not scale well to large numbers
 * of downloads. Of course there is a problem with every download having
 * a file descriptor, but additionally, if every file is independently
 * mmapped, we'll run out of 32-bit address space with enough concurrent
 * connections. Not using mmap would help but then there would be a lot more
 * I/O if there are partial writes, unless we stopped using writev() and
 * switched to writing from a buffer, introducing an extra copy.
 *
 * This can be fixed by having at most one file descriptor, and one
 * mmap'd region or buffer, per file (both file and auth servers). For that,
 * FileTransaction could have a static hash table of filename->data mappings,
 * and init() would just retrieve the shared data. This means that to get
 * the server to use new files from disk, you would have to be able to kick
 * the server with a signal or something. (Of course a complete restart works
 * too but that's really pretty lame.)
 */

//#include <sys/uio.h> /* for struct iovec */
//
//#include "protocol.h"
//
//#include "Logger.h"

#ifndef _FILE_TRANSACTION_H_
#define _FILE_TRANSACTION_H_

class FileTransaction {
public:
  FileTransaction(uint32_t request_id, Logger *logger,
		  bool is_manifest, bool is_auth);
  virtual ~FileTransaction();

  // returns non-zero if the file does not exist or is unreadable
  int init(const char *dirname, char *fname);

  uint32_t request_id() const { return m_id; }
  size_t file_len() const;
  status_code_t status() const { return m_status; }

  // tells the FileTransaction that the current chunk was acked; returns
  // nonzero for a read error
  int chunk_acked();
  // asks if there are any more chunks
  bool file_complete() const;
  // as if we are currently writing the last chunk
  bool in_last_chunk() const;
  // length of current chunk
  u_int chunk_length() const;
  // offset of current chunk
  u_int chunk_offset() const;

  // returns how many iovecs were filled in, -1 for an error
  u_int fill_iovecs(struct iovec *iov, u_int iov_ct, u_int *start_at);
  // returns how many bytes from byte_ct were left over, -1 for an error
  u_int iovecs_written_bytes(u_int byte_ct, u_int start_at, bool *chunk_done);
  // returns how many bytes were filled into the buffer, -1 for an error
  u_int fill_buffer(u_char *buffer, size_t len, u_int *start_at,
		    bool *chunk_done);

protected:
  Logger *m_log;
  uint32_t m_id; // host order
  bool m_manifest;
  bool m_auth;
  u_int m_file_ct;

  int m_fd;
  size_t m_filesize;
  u_char *m_mapped;

  status_code_t m_status;
  u_int m_offset;
  u_int m_chunk_remaining;
  u_int m_real_offset; // for manifests only

  u_char *m_backup_buf;
  size_t m_backup_len;
  u_int m_backup_fill;
};

#endif /* _FILE_TRANSACTION_H_ */
