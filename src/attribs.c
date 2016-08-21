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

	if(sb->protocol2)
	{
		// Protocol1 does not have this field.
		p += to_base64(sb->protocol2->index, p);
		*p++ = ' ';
		// Protocol2 puts compression near the beginning.
		p += to_base64(sb->compression, p);
		*p++ = ' ';
		// Protocol1 does not have this field.
		p += to_base64(sb->protocol2->encryption, p);
		*p++ = ' ';
	}
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
		// Protocol1 puts compression at the end.
		*p++ = ' ';
		p += to_base64(sb->compression, p);
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

	if(!(p=sb->attr.buf)) return;
	statp=&sb->statp;

	if(sb->protocol2)
	{
		// Protocol1 does not have this field.
		p += from_base64(&val, p);
		sb->protocol2->index=val;
		p++;
		// Compression for protocol2.
		p += from_base64(&val, p);
		sb->compression=val;
		p++;
		// Protocol1 does not have this field.
		p += from_base64(&val, p);
		sb->protocol2->encryption=val;
		p++;
	}
	p += from_base64(&val, p);
	plug(statp->st_dev, val);
	p++;
	p += from_base64(&val, p);
	plug(statp->st_ino, val);
	p++;
	p += from_base64(&val, p);
	plug(statp->st_mode, val);
	p++;
	p += from_base64(&val, p);
	plug(statp->st_nlink, val);
	p++;
	p += from_base64(&val, p);
	plug(statp->st_uid, val);
	p++;
	p += from_base64(&val, p);
	plug(statp->st_gid, val);
	p++;
	p += from_base64(&val, p);
	plug(statp->st_rdev, val);
	p++;
	p += from_base64(&val, p);
	plug(statp->st_size, val);
	p++;
	p += from_base64(&val, p);
#ifdef HAVE_WIN32
	//   plug(statp->st_blksize, val);
	p++;
	p += from_base64(&val, p);
	//   plug(statp->st_blocks, val);
#else
	plug(statp->st_blksize, val);
	p++;
	p += from_base64(&val, p);
	plug(statp->st_blocks, val);
#endif
	p++;
	p += from_base64(&val, p);
	plug(statp->st_atime, val);
	p++;
	p += from_base64(&val, p);
	plug(statp->st_mtime, val);
	p++;
	p += from_base64(&val, p);
	plug(statp->st_ctime, val);

	// FreeBSD user flags.
	if(*p == ' ' || (*p != 0 && *(p+1) == ' '))
	{
		p++;
		if(!*p) return;
		p += from_base64(&val, p);
#ifdef HAVE_CHFLAGS
		plug(statp->st_flags, val);
	}
	else
	{
		statp->st_flags  = 0;
#endif
	}

	// Look for winattr.
	if(*p == ' ' || (*p != 0 && *(p+1) == ' '))
	{
		p++;
		p += from_base64(&val, p);
	}
	else
		val = 0;
	sb->winattr=val;

	// Compression for protocol1.
	if(sb->protocol1)
	{
		if(*p == ' ' || (*p != 0 && *(p+1) == ' '))
		{
			p++;
			if(!*p) return;
			p += from_base64(&val, p);
			sb->compression=val;
		}
		else
			sb->compression=-1;
	}
}

static int set_file_times(struct asfd *asfd,
	const char *path, struct utimbuf *ut,
	struct stat *statp, struct cntr *cntr)
{
	int e;
// The mingw64 utime() appears not to work on read-only files.
// Use the utime() from bacula instead.
#ifdef HAVE_WIN32
	//e=utime(path, ut);
	e=win32_utime(path, ut);
#else
	e=utime(path, ut);
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
	int64_t val;
	from_base64(&val, iobuf->buf);
	return (uint64_t)val;
}

uint64_t decode_file_no_and_save_path(struct iobuf *iobuf, char **save_path)
{
	int64_t val;
	char *p=iobuf->buf;
	p+=from_base64(&val, iobuf->buf);
	*save_path=p+1;
	return (uint64_t)val;
}

#ifdef HAVE_LUTIMES
static int do_lutimes(const char *path, struct stat *statp)
{
	struct timeval t[2];
	t[0].tv_sec = statp->st_atime;
	t[0].tv_usec = 0;
	t[1].tv_sec = statp->st_mtime;
	t[1].tv_usec = 0;
	return lutimes(path, t);
}
#endif

int attribs_set(struct asfd *asfd, const char *path,
	struct stat *statp, uint64_t winattr, struct cntr *cntr)
{
	struct utimbuf ut;

	ut.actime=statp->st_atime;
	ut.modtime=statp->st_mtime;

#ifdef HAVE_WIN32
	win32_chmod(path, statp->st_mode, winattr);
	set_file_times(asfd, path, &ut, statp, cntr);
	return 0;
#endif

	if(lchown(path, statp->st_uid, statp->st_gid)<0)
	{
		struct berrno be;
		berrno_init(&be);
		logw(asfd, cntr,
			"Unable to set file owner of %s to %d:%d: ERR=%s\n",
			path, statp->st_uid, statp->st_gid,
			berrno_bstrerror(&be, errno));
		return -1;
	}

	/* Watch out, a metadata restore will have cmd set to CMD_METADATA or
	   CMD_ENC_META, but that is OK at the moment because we are not doing
	   meta stuff on links. */
	if(S_ISLNK(statp->st_mode))
	{
#ifdef HAVE_LUTIMES
		if(do_lutimes(path, statp)) {
			struct berrno be;
			berrno_init(&be);
			logw(asfd, cntr, "Unable to set lutimes %s: ERR=%s\n",
				path, berrno_bstrerror(&be, errno));
			return -1;
		}
#endif
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

		if(set_file_times(asfd, path, &ut, statp, cntr))
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
}
