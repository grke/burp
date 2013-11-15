/*
 *  Encode and decode standard Unix attributes and
 *   Extended attributes for Win32 and
 *   other non-Unix systems, or Unix systems with ACLs, ...
 */

#include "include.h"

// Encode a stat structure into a base64 character string.
// FIX THIS: Do compression from sb and put it near the beginning, before
// it gets too entrenched in burp2.
int attribs_encode(struct sbuf *sb, int compression)
{
	char *p;
	struct stat *statp=&sb->statp;

	if(!(sb->abuf.buf=(char *)malloc(128)))
	{
		log_out_of_memory(__FUNCTION__);
		return -1;
	}
	p=sb->abuf.buf;

	p += to_base64(sb->index, p);
	*p++ = ' ';
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
	*p++ = ' ';

	p += to_base64(compression, p);

	*p = 0;

	sb->abuf.len=p-sb->abuf.buf;

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
// FIX THIS: Do everything with a struct sb.
void attribs_decode_low_level(struct stat *statp, const char *attribs, uint64_t *index, uint64_t *winattr, int *compression)
{
	const char *p=attribs;
	int64_t val;

	p += from_base64(&val, p);
	*index=val;
	p++;
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
	*winattr=val;

	// Compression.
	if(*p == ' ' || (*p != 0 && *(p+1) == ' '))
	{
		p++;
		if(!*p) return;
		p += from_base64(&val, p);
		*compression=val;
	}
	else
		*compression=-1;
}

void attribs_decode(struct sbuf *sb, int *compression)
{
	uint64_t index;
	uint64_t winattr;
	attribs_decode_low_level(&sb->statp, sb->abuf.buf,
		&index, &winattr, compression);
	sb->index=index;
	sb->winattr=winattr;
}

static int set_file_times(const char *path, struct utimbuf *ut, struct stat *statp, struct cntr *cntr)
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
		logw(cntr, "Unable to set file times %s: ERR=%s",
			path, be.bstrerror());
		return -1;
	}
	return 0;
}

uint64_t decode_file_no(struct sbuf *sb)
{
	int64_t val;
	from_base64(&val, sb->abuf.buf);
	return (uint64_t)val;
}

int attribs_set(const char *path, struct stat *statp, int64_t winattr, struct config *conf)
{
	struct utimbuf ut;

	ut.actime=statp->st_atime;
	ut.modtime=statp->st_mtime;

#ifdef HAVE_WIN32
	win32_chmod(path, statp->st_mode, winattr);
	set_file_times(path, &ut, statp, conf->cntr);
	return true;
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
			logw(conf->cntr, "Unable to set file owner %s: ERR=%s",
				path, be.bstrerror());
			return -1;
		}
	}
	else
	{
		if(chown(path, statp->st_uid, statp->st_gid)<0)
		{
			berrno be;
			logw(conf->cntr, "Unable to set file owner %s: ERR=%s",
				path, be.bstrerror());
			return -1;
		}
		if(chmod(path, statp->st_mode) < 0)
		{
			berrno be;
			logw(conf->cntr, "Unable to set file modes %s: ERR=%s",
				path, be.bstrerror());
			return -1;
		}

		if(set_file_times(path, &ut, statp, conf->cntr))
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
			logw(conf->cntr, "Unable to set file flags %s: ERR=%s",
				path, be.bstrerror());
			return -1;
		}
#endif
	}

	return 0;
}
