/*
   Bacula® - The Network Backup Solution

   Copyright (C) 2002-2009 Free Software Foundation Europe e.V.

   The main author of Bacula is Kern Sibbald, with contributions from
   many others, a complete list can be found in the file AUTHORS.
   This program is Free Software; you can redistribute it and/or
   modify it under the terms of version three of the GNU Affero General Public
   License as published by the Free Software Foundation and included
   in the file LICENSE.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
   General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
   02110-1301, USA.

   Bacula® is a registered trademark of Kern Sibbald.
   The licensor of Bacula is the Free Software Foundation Europe
   (FSFE), Fiduciary Program, Sumatrastrasse 25, 8006 Zürich,
   Switzerland, email:ftf@fsfeurope.org.
*/
/*
 *  Encode and decode standard Unix attributes and
 *   Extended attributes for Win32 and
 *   other non-Unix systems, ...
 */
/*
 *  Some of these functions come from src/findlib/attribs.c in bacula-5.0.3.
 *  Hence, the copyright notice above is retained.
 *   Graham Keeling, 2014
 */

#include "burp.h"
#include "attribs.h"
#include "alloc.h"
#include "base64.h"
#include "berrno.h"
#include "cmd.h"
#include "cntr.h"
#include "log.h"
#include "sbuf.h"

// Encode a stat structure into a base64 character string.
int attribs_encode(struct sbuf *sb)
{
	static char *p;
	static struct stat *statp;

	if(!sb->attr.buf)
	{
		sb->attr.cmd=CMD_ATTRIBS; // should not be needed
		if(!(sb->attr.buf=(char *)malloc_w(256, __func__)))
			return -1;
	}
	p=sb->attr.buf;
	statp=&sb->statp;

	p += to_base64(statp->st_dev, p);
	*p++ = ' ';
	p += to_base64(statp->st_ino, p);
	*p++ = ' ';
	p += to_base64(statp->st_mode, p);
	*p++ = ' ';
	p += to_base64(statp->st_nlink, p);
	*p++ = ' ';
	p += to_base64(statp->st_uid, p);
	*p++ = ' ';
	p += to_base64(statp->st_gid, p);
	*p++ = ' ';
	p += to_base64(statp->st_rdev, p);
	*p++ = ' ';
	p += to_base64(statp->st_size, p);
	*p++ = ' ';
#ifdef HAVE_WIN32
	p += to_base64(0, p); // place holder
	*p++ = ' ';
	p += to_base64(0, p); // place holder
#else
	p += to_base64(statp->st_blksize, p);
	*p++ = ' ';
	p += to_base64(statp->st_blocks, p);
#endif
	*p++ = ' ';
	p += to_base64(statp->st_atime, p);
	*p++ = ' ';
	p += to_base64(statp->st_mtime, p);
	*p++ = ' ';
	p += to_base64(statp->st_ctime, p);
	*p++ = ' ';

#ifdef HAVE_CHFLAGS
	// chflags is a FreeBSD function.
	p += to_base64(statp->st_flags, p);
#else
	p += to_base64(0, p); // place holder
#endif
	*p++ = ' ';

	p += to_base64(sb->winattr, p);

	if(sb->protocol1)
	{
		// Protocol1 puts compression/encryption at the end.
		*p++ = ' ';
		p += to_base64(sb->compression, p);
		*p++ = ' ';
		p += to_base64(sb->encryption, p);
		*p++ = ' ';
		p += to_base64(sb->protocol1->salt, p);
	}

	*p = 0;

	sb->attr.len=p-sb->attr.buf;

	return 0;
}

// Do casting according to unknown type to keep compiler happy.
#define plug(st, val) st = (__typeof__(st))(val)

// Decode a stat packet from base64 characters.
void attribs_decode(struct sbuf *sb)
{
	static const char *p;
	static int64_t val;
	static struct stat *statp;
	static int eaten;

	if(!(p=sb->attr.buf)) return;
	statp=&sb->statp;

	if(!(eaten=from_base64(&val, p)))
		return;
	p+=eaten;
	plug(statp->st_dev, val);

	if(!(eaten=from_base64(&val, p)))
		return;
	p+=eaten;
	plug(statp->st_ino, val);

	if(!(eaten=from_base64(&val, p)))
		return;
	p+=eaten;
	plug(statp->st_mode, val);

	if(!(eaten=from_base64(&val, p)))
		return;
	p+=eaten;
	plug(statp->st_nlink, val);

	if(!(eaten=from_base64(&val, p)))
		return;
	p+=eaten;
	plug(statp->st_uid, val);

	if(!(eaten=from_base64(&val, p)))
		return;
	p+=eaten;
	plug(statp->st_gid, val);

	if(!(eaten=from_base64(&val, p)))
		return;
	p+=eaten;
	plug(statp->st_rdev, val);

	if(!(eaten=from_base64(&val, p)))
		return;
	p+=eaten;
	plug(statp->st_size, val);

	if(!(eaten=from_base64(&val, p)))
		return;
	p+=eaten;
#ifdef HAVE_WIN32
	//   plug(statp->st_blksize, val);

	if(!(eaten=from_base64(&val, p)))
		return;
	p+=eaten;
	//   plug(statp->st_blocks, val);
#else
	plug(statp->st_blksize, val);

	if(!(eaten=from_base64(&val, p)))
		return;
	p+=eaten;
	plug(statp->st_blocks, val);
#endif

	if(!(eaten=from_base64(&val, p)))
		return;
	p+=eaten;
	plug(statp->st_atime, val);

	if(!(eaten=from_base64(&val, p)))
		return;
	p+=eaten;
	plug(statp->st_mtime, val);

	if(!(eaten=from_base64(&val, p)))
		return;
	p+=eaten;
	plug(statp->st_ctime, val);

	// FreeBSD user flags.
	if(!(eaten=from_base64(&val, p)))
		return;
	p+=eaten;
#ifdef HAVE_CHFLAGS
	statp->st_flags=0;
	plug(statp->st_flags, val);
#endif

	// Look for winattr.
	sb->winattr=0;
	if(!(eaten=from_base64(&val, p)))
		return;
	p+=eaten;
	sb->winattr=val;

	if(sb->protocol1)
	{
		sb->compression=-1;
		sb->encryption=ENCRYPTION_UNSET;

		// Compression for protocol1.
		if(!(eaten=from_base64(&val, p)))
			return;
		p+=eaten;
		sb->compression=val;

		// Encryption for protocol1.
		if(!(eaten=from_base64(&val, p)))
			return;
		p+=eaten;
		sb->encryption=val;

		// Salt for protocol1.
		if(!(eaten=from_base64(&val, p)))
			return;
		p+=eaten;
		sb->protocol1->salt=val;
	}
}

int attribs_set_file_times(struct asfd *asfd,
	const char *path, struct stat *statp,
	struct cntr *cntr)
{
	int e;

#ifdef HAVE_WIN32
	// You (probably) cannot set times on Windows junction points.
	if(statp->st_rdev==WIN32_JUNCTION_POINT)
		return 0;

	// The mingw64 utime() appears not to work on read-only files.
	// Use the utime() from bacula instead.
	e=win32_utime(path, statp);
#elif HAVE_LUTIMES
	struct timeval t[2];
	t[0].tv_sec = statp->st_atime;
	t[0].tv_usec = 0;
	t[1].tv_sec = statp->st_mtime;
	t[1].tv_usec = 0;
	e=lutimes(path, t);
#else
	struct timespec ts[2];
	ts[0].tv_sec=statp->st_atime;
	ts[0].tv_nsec=0;
	ts[1].tv_sec=statp->st_mtime;
	ts[1].tv_nsec=0;
	e=utimensat(AT_FDCWD, path, ts, AT_SYMLINK_NOFOLLOW);
#endif
	if(e<0)
	{
		struct berrno be;
		berrno_init(&be);
		logw(asfd, cntr, "Unable to set file times %s: ERR=%s\n",
			path, berrno_bstrerror(&be, errno));
		return -1;
	}
	return 0;
}

uint64_t decode_file_no(struct iobuf *iobuf)
{
	int64_t val=0;
	from_base64(&val, iobuf->buf);
	return (uint64_t)val;
}

uint64_t decode_file_no_and_save_path(struct iobuf *iobuf, char **save_path)
{
	int64_t val;
	int eaten;
	char *p=iobuf->buf;
	if(!(eaten=from_base64(&val, iobuf->buf)))
		return 0;
	*save_path=p+eaten+1;
	return (uint64_t)val;
}

int attribs_set(struct asfd *asfd, const char *path,
	struct stat *statp, uint64_t winattr, struct cntr *cntr)
{
#ifdef HAVE_WIN32
	win32_chmod(path, statp->st_mode, winattr);
	attribs_set_file_times(asfd, path, statp, cntr);
	return 0;
#else
	if(lchown(path, statp->st_uid, statp->st_gid)<0)
	{
		struct berrno be;
		berrno_init(&be);
		char msg[256]="";

		snprintf(msg, sizeof(msg),
			"Unable to set file owner of %s to %d:%d: ERR=%s",
			path, statp->st_uid, statp->st_gid,
			berrno_bstrerror(&be, errno));

		if(errno==EPERM)
		{
			static int do_owner_warning=1;
			if(getuid()!=0)
			{
				if(!do_owner_warning)
					return -1;

				logw(asfd, cntr, "%s - possibly because you are not root. Will suppress subsequent messages of this type.\n", msg);
				do_owner_warning=0;
				return -1;
			}
		}
		logw(asfd, cntr, "%s\n", msg);

		return -1;
	}

	/* Watch out, a metadata restore will have cmd set to CMD_METADATA or
	   CMD_ENC_META, but that is OK at the moment because we are not doing
	   meta stuff on links. */
	if(S_ISLNK(statp->st_mode))
	{
		if(attribs_set_file_times(asfd, path, statp, cntr))
			return -1;
	}
	else
	{
		if(chmod(path, statp->st_mode) < 0)
		{
			struct berrno be;
			berrno_init(&be);
			logw(asfd, cntr,
				"Unable to set file modes %s: ERR=%s\n",
				path, berrno_bstrerror(&be, errno));
			return -1;
		}

		if(attribs_set_file_times(asfd, path, statp, cntr))
			return -1;
#ifdef HAVE_CHFLAGS
		/*
		 * FreeBSD user flags
		 *
		 * Note, this should really be done before the utime() above,
		 *  but if the immutable bit is set, it will make the utimes()
		 *  fail.
		 */
		if(chflags(path, statp->st_flags)<0)
		{
			struct berrno be;
			berrno_init(&be);
			logw(asfd, cntr,
				"Unable to set file flags %s: ERR=%s\n",
				path, berrno_bstrerror(&be, errno));
			return -1;
		}
#endif
	}

	return 0;
#endif
}
