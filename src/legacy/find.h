#ifndef __FILES_H
#define __FILES_H

#include "include.h"

#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif

#include <sys/file.h>
#include <sys/param.h>
#if HAVE_UTIME_H
#include <utime.h>
#else
struct utimbuf {
    long actime;
    long modtime;
};
#endif

#define MODE_RALL (S_IRUSR|S_IRGRP|S_IROTH)

#ifdef HAVE_REGEX_H
#include <regex.h>
#endif

#ifndef HAVE_READDIR_R
int readdir_r(DIR *dirp, struct dirent *entry, struct dirent **result);
#endif

/*  
 * Options saved int "options" of the include/exclude lists.
 * They are directly jammed ito  "flag" of ff packet
 */
/* Graham says: most of these can be deleted, being bacula debris. */
//#define FO_MD5          (1<<1)        /* Do MD5 checksum */
#define FO_GZIP         (1<<2)        /* Do Zlib compression */
#define FO_NO_RECURSION (1<<3)        /* no recursion in directories */
#define FO_MULTIFS      (1<<4)        /* multiple file systems */
#define FO_SPARSE       (1<<5)        /* do sparse file checking */
#define FO_IF_NEWER     (1<<6)        /* replace if newer */
#define FO_NOREPLACE    (1<<7)        /* never replace */
//#define FO_READFIFO     (1<<8)        /* read data from fifo */
//#define FO_SHA1         (1<<9)        /* Do SHA1 checksum */
//#define FO_PORTABLE     (1<<10)       /* Use portable data format -- no BackupWrite */
#define FO_MTIMEONLY    (1<<11)       /* Use mtime rather than mtime & ctime */
//#define FO_KEEPATIME    (1<<12)       /* Reset access time */
#define FO_EXCLUDE      (1<<13)       /* Exclude file */
#define FO_ACL          (1<<14)       /* Backup ACLs */
#define FO_NO_HARDLINK  (1<<15)       /* don't handle hard links */
#define FO_IGNORECASE   (1<<16)       /* Ignore file name case */
#define FO_HFSPLUS      (1<<17)       /* Resource forks and Finder Info */
#define FO_WIN32DECOMP  (1<<18)       /* Use BackupRead decomposition */
//#define FO_SHA256       (1<<19)       /* Do SHA256 checksum */
//#define FO_SHA512       (1<<20)       /* Do SHA512 checksum */
//#define FO_ENCRYPT      (1<<21)       /* Encrypt data stream */
#define FO_NOATIME      (1<<22)       /* Use O_NOATIME to prevent atime change */
#define FO_ENHANCEDWILD (1<<23)       /* Enhanced wild card processing */
#define FO_CHKCHANGES   (1<<24)       /* Check if file have been modified during backup */
#define FO_STRIPPATH    (1<<25)       /* Check for stripping path */
#define FO_HONOR_NODUMP (1<<26)       /* honor NODUMP flag */
#define FO_XATTR        (1<<27)       /* Backup Extended Attributes */

/* FileSet definitions very similar to the resource
 *  contained in the Director because the components
 *  of the structure are passed by the Director to the
 *  File daemon and recompiled back into this structure
 */
#undef  MAX_FOPTS
#define MAX_FOPTS 30

#ifdef HAVE_DARWIN_OS
struct HFSPLUS_INFO {
   unsigned long length;              /* Mandatory field */
   char fndrinfo[32];                 /* Finder Info */
   off_t rsrclength;                  /* Size of resource fork */
};
#endif

/*
 * Definition of the find_files packet passed as the
 * first argument to the find_files callback subroutine.
 */
struct FF_PKT {
   char *top_fname;                   /* full filename before descending */
   char *fname;                       /* full filename */
   long flen;                         /* length of name component */
   char *link;                        /* link if file linked */
   struct stat statp;                 /* stat packet */
   int64_t winattr;                   /* windows attributes */
   int32_t FileIndex;                 /* FileIndex of this file */
   int32_t LinkFI;                    /* FileIndex of main hard linked file */
   struct f_link *linked;             /* Set if this file is hard linked */
   int type;                          /* FT_ type from above */
   int ff_errno;                      /* errno */
   time_t save_time;                  /* start of incremental time */

   /* Values set by accept_file while processing Options */
   uint32_t flags;                    /* backup options */
   int strip_path;                    /* strip path count */

   /* List of all hard linked files found */
   struct f_link **linkhash;          /* hard linked files */

   /* Darwin specific things.
    * To avoid clutter, we always include rsrc_bfd and volhas_attrlist */
   bool volhas_attrlist;              /* Volume supports getattrlist() */
#ifdef HAVE_DARWIN_OS
   struct HFSPLUS_INFO hfsinfo;       /* Finder Info and resource fork size */
#endif
};

FF_PKT *init_find_files(void);
int term_find_files(FF_PKT *ff);
int find_files_begin(FF_PKT *ff_pkt, struct config *conf, char *fname, struct cntr *cntr);
int pathcmp(const char *a, const char *b);
int file_is_included(struct strlist **ielist, int iecount,
	struct strlist **incext, int incount,
	struct strlist **excext, int excount,
	struct strlist **increg, int ircount,
	struct strlist **excreg, int ercount,
	const char *fname, bool top_level);
int in_include_regex(struct strlist **incre, int incount, const char *fname);
int in_exclude_regex(struct strlist **excre, int excount, const char *fname);
// Returns the level of compression.
int in_exclude_comp(struct strlist **excom, int excmcount, const char *fname, int compression);

/* from attribs.c */
void encode_stat(char *buf, struct stat *statp, int64_t winattr, int compression);
void decode_stat(const char *buf, struct stat *statp, int64_t *winattr, int *compression);
bool set_attributes(const char *path, char cmd, struct stat *statp, int64_t winattr, struct cntr *cntr);

#endif
