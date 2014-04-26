/*
 *  Encode and decode standard Unix attributes and
 *   Extended attributes for Win32 and
 *   other non-Unix systems, or Unix systems with ACLs, ...
 */

#include "include.h"

// Encode a stat structure into a base64 character string.
int attribs_encode(struct sbuf *sb)
{
	static char *p;
	static struct stat *statp;

	if(!sb->attr.buf)
	{
		sb->attr.cmd=CMD_ATTRIBS; // should not be needed
		if(!(sb->attr.buf=(char *)malloc(128)))
		{
			log_out_of_memory(__FUNCTION__);
			return -1;
		}
	}
	p=sb->attr.buf;
	statp=&sb->statp;

	if(sb->burp2)
	{
		// Burp1 does not have this field.
		p += to_base64(sb->burp2->index, p);
		*p++ = ' ';
		// Burp2 puts compression near the beginning.
		p += to_base64(sb->compression, p);
		*p++ = ' ';
		// Burp1 does not have this field.
		p += to_base64(sb->burp2->encryption, p);
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

#ifdef HAVE_WIN32
	p += to_base64(sb->winattr, p);
#else
	p += to_base64(0, p); // place holder
#endif

	if(sb->burp1)
	{
		// Burp1 puts compression at the end.
		*p++ = ' ';
		p += to_base64(sb->compression, p);
	}

	*p = 0;

	sb->attr.len=p-sb->attr.buf;

	return 0;
}

// Do casting according to unknown type to keep compiler happy.
#ifdef HAVE_TYPEOF
	#define plug(st, val) st = (typeof st)val
#else
	#if !HAVE_GCC & HAVE_SUN_OS
		// Sun compiler does not handle templates correctly.
		#define plug(st, val) st = val
	#elif __sgi
		#define plug(st, val) st = val
	#else
		// Use templates to do the casting.
		template <class T> void plug(T &st, uint64_t val)
		{ st = static_cast<T>(val); }
	#endif
#endif

// Decode a stat packet from base64 characters.
void attribs_decode(struct sbuf *sb)
{
	static const char *p;
	static int64_t val;
	static struct stat *statp;

	p=sb->attr.buf;
	statp=&sb->statp;

	if(sb->burp2)
	{
		// Burp1 does not have this field.
		p += from_base64(&val, p);
		sb->burp2->index=val;
		p++;
		// Compression for burp2.
		p += from_base64(&val, p);
		sb->compression=val;
		p++;
		// Burp1 does not have this field.
		p += from_base64(&val, p);
		sb->burp2->encryption=val;
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

	// Compression for burp1.
	if(sb->burp1)
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

static int set_file_times(struct async *as,
	const char *path, struct utimbuf *ut,
	struct stat *statp, struct conf *conf)
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
		berrno be;
		logw(as, conf, "Unable to set file times %s: ERR=%s",
			path, be.bstrerror());
		return -1;
	}
	return 0;
}

uint64_t decode_file_no(struct sbuf *sb)
{
	int64_t val;
	from_base64(&val, sb->attr.buf);
	return (uint64_t)val;
}

int attribs_set(struct async *as, const char *path,
	struct stat *statp, uint64_t winattr, struct conf *conf)
{
	struct utimbuf ut;

	ut.actime=statp->st_atime;
	ut.modtime=statp->st_mtime;

#ifdef HAVE_WIN32
	win32_chmod(path, statp->st_mode, winattr);
	set_file_times(as, path, &ut, statp, conf);
	return 0;
#endif

	/* ***FIXME**** optimize -- don't do if already correct */
	/*
	 * For link, change owner of link using lchown, but don't
	 *   try to do a chmod as that will update the file behind it.
	 */

	/* Watch out, a metadata restore will have cmd set to CMD_METADATA or
	   CMD_ENC_META, but that is OK at the moment because we are not doing
	   meta stuff on links. */
	if(S_ISLNK(statp->st_mode))
	{
		// Change owner of link, not of real file.
		if(lchown(path, statp->st_uid, statp->st_gid)<0)
		{
			berrno be;
			logw(as, conf, "Unable to set file owner %s: ERR=%s",
				path, be.bstrerror());
			return -1;
		}
	}
	else
	{
		if(chown(path, statp->st_uid, statp->st_gid)<0)
		{
			berrno be;
			logw(as, conf, "Unable to set file owner %s: ERR=%s",
				path, be.bstrerror());
			return -1;
		}
		if(chmod(path, statp->st_mode) < 0)
		{
			berrno be;
			logw(as, conf, "Unable to set file modes %s: ERR=%s",
				path, be.bstrerror());
			return -1;
		}

		if(set_file_times(as, path, &ut, statp, conf))
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
			berrno be;
			logw(conf, "Unable to set file flags %s: ERR=%s",
				path, be.bstrerror());
			return -1;
		}
#endif
	}

	return 0;
}
