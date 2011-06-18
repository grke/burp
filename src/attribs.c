/*
 *  Encode and decode standard Unix attributes and
 *   Extended attributes for Win32 and
 *   other non-Unix systems, or Unix systems with ACLs, ...
 */

#include "burp.h"
#include "base64.h"
#include "prog.h"
#include "find.h"
#include "cmd.h"
#include "berrno.h"

/*
 * Encode a stat structure into a base64 character string
 *   All systems must create such a structure.
 */
void encode_stat(char *buf, struct stat *statp, int extrameta)
{
   char *p = buf;

   /*
    *  Encode a stat packet.  I should have done this more intelligently
    *   with a length so that it could be easily expanded.
    */
   p += to_base64((int64_t)statp->st_dev, p);
   *p++ = ' ';                        /* separate fields with a space */
   p += to_base64((int64_t)statp->st_ino, p);
   *p++ = ' ';
   p += to_base64((int64_t)statp->st_mode, p);
   *p++ = ' ';
   p += to_base64((int64_t)statp->st_nlink, p);
   *p++ = ' ';
   p += to_base64((int64_t)statp->st_uid, p);
   *p++ = ' ';
   p += to_base64((int64_t)statp->st_gid, p);
   *p++ = ' ';
   p += to_base64((int64_t)statp->st_rdev, p);
   *p++ = ' ';
   p += to_base64((int64_t)statp->st_size, p);
   *p++ = ' ';
#ifndef HAVE_MINGW
   p += to_base64((int64_t)statp->st_blksize, p);
   *p++ = ' ';
   p += to_base64((int64_t)statp->st_blocks, p);
   *p++ = ' ';
#else
   p += to_base64((int64_t)0, p); /* output place holder */
   *p++ = ' ';
   p += to_base64((int64_t)0, p); /* output place holder */
   *p++ = ' ';
#endif
   p += to_base64((int64_t)statp->st_atime, p);
   *p++ = ' ';
   p += to_base64((int64_t)statp->st_mtime, p);
   *p++ = ' ';
   p += to_base64((int64_t)statp->st_ctime, p);
   *p++ = ' ';

#ifdef HAVE_CHFLAGS
   /* FreeBSD function */
   p += to_base64((int64_t)statp->st_flags, p);  /* output st_flags */
#else
   p += to_base64((int64_t)0, p);     /* output place holder */
#endif
   *p++ = ' ';

   /* Set to indicate that there is more meta data stored in a separate file
      to the main file data. */
   p += to_base64((int64_t)extrameta, p);
   *p = 0;
   return;
}


/* Do casting according to unknown type to keep compiler happy */
#ifdef HAVE_TYPEOF
  #define plug(st, val) st = (typeof st)val
#else
  #if !HAVE_GCC & HAVE_SUN_OS
    /* Sun compiler does not handle templates correctly */
    #define plug(st, val) st = val
  #elif __sgi
    #define plug(st, val) st = val
  #else
    /* Use templates to do the casting */
    template <class T> void plug(T &st, uint64_t val)
      { st = static_cast<T>(val); }
  #endif
#endif


/* Decode a stat packet from base64 characters */
void decode_stat(const char *buf, struct stat *statp, int *extrameta)
{
   const char *p = buf;
   int64_t val;

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
#ifndef HAVE_MINGW
   p += from_base64(&val, p);
   plug(statp->st_blksize, val);
   p++;
   p += from_base64(&val, p);
   plug(statp->st_blocks, val);
   p++;
#else
   p += from_base64(&val, p);
//   plug(statp->st_blksize, val);
   p++;
   p += from_base64(&val, p);
//   plug(statp->st_blocks, val);
   p++;
#endif
   p += from_base64(&val, p);
   plug(statp->st_atime, val);
   p++;
   p += from_base64(&val, p);
   plug(statp->st_mtime, val);
   p++;
   p += from_base64(&val, p);
   plug(statp->st_ctime, val);

   /* FreeBSD user flags */
   if (*p == ' ' || (*p != 0 && *(p+1) == ' ')) {
      p++;
      p += from_base64(&val, p);
#ifdef HAVE_CHFLAGS
      plug(statp->st_flags, val);
   } else {
      statp->st_flags  = 0;
#endif
   }

   p++;
   p += from_base64(&val, p);
   plug(*extrameta, val);
}

static uid_t my_uid=1;
static gid_t my_gid=1;
static bool uid_set=false;

bool set_attributes(const char *path, char cmd, struct stat *statp)
{
   struct utimbuf ut;
   mode_t old_mask;
   bool ok = true;
 
   if (uid_set) {
      my_uid = getuid();
      my_gid = getgid();
      uid_set = true;
   }

   old_mask = umask(0);

   ut.actime = statp->st_atime;
   ut.modtime = statp->st_mtime;

   /* ***FIXME**** optimize -- don't do if already correct */
   /*
    * For link, change owner of link using lchown, but don't
    *   try to do a chmod as that will update the file behind it.
    */
   if (cmd==CMD_SOFT_LINK) {
      /* Change owner of link, not of real file */
      if (lchown(path, statp->st_uid, statp->st_gid) < 0 && my_uid == 0) {
         berrno be;
         fprintf(stderr, _("Unable to set file owner %s: ERR=%s\n"),
            path, be.bstrerror());
         ok = false;
      }
   } else {
      if (chown(path, statp->st_uid, statp->st_gid) < 0 && my_uid == 0) {
         berrno be;
         fprintf(stderr, _("Unable to set file owner %s: ERR=%s\n"),
            path, be.bstrerror());
         ok = false;
      }
      if (chmod(path, statp->st_mode) < 0 && my_uid == 0) {
         berrno be;
         fprintf(stderr, _("Unable to set file modes %s: ERR=%s\n"),
            path, be.bstrerror());
         ok = false;
      }

      /*
       * Reset file times.
       */
      if (utime(path, &ut) < 0 && my_uid == 0) {
         berrno be;
         fprintf(stderr, _("Unable to set file times %s: ERR=%s\n"),
            path, be.bstrerror());
         ok = false;
      }
#ifdef HAVE_CHFLAGS
      /*
       * FreeBSD user flags
       *
       * Note, this should really be done before the utime() above,
       *  but if the immutable bit is set, it will make the utimes()
       *  fail.
       */
      if (chflags(path, statp->st_flags) < 0 && my_uid == 0) {
         berrno be;
         fprintf(stderr, _("Unable to set file flags %s: ERR=%s\n"),
            path, be.bstrerror());
         ok = false;
      }
#endif
   }

   return ok;
}
