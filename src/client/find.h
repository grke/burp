/*
   Bacula® - The Network Backup Solution

   Copyright (C) 2001-2010 Free Software Foundation Europe e.V.

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
 * File types as returned by find_files()
 *
 *     Kern Sibbald MMI
 */
/*
 * This file contains fragments from bacula-5.0.3:src/findlib/find.h, hence
 * retaining the copyright notice above. At some point, the fragments will be
 * removed because the burp sbuf code will take over completely.
 *     Graham Keeling, 2014
 */

#ifndef _FIND_H
#define _FIND_H

#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif

#include <sys/file.h>
#include <sys/param.h>
#if HAVE_UTIME_H
#include <utime.h>
#else
struct utimbuf
{
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

#define FT_LNK_H	1  // hard link to file already saved.
#define FT_REG		3  // Regular file.
#define FT_LNK_S	4  // Soft Link.
#define FT_DIR		5  // Directory.
#define FT_SPEC		6  // Special file -- chr, blk, fifo, sock.
#define FT_NOFOLLOW	8  // Could not follow link.
#define FT_NOSTAT	9  // Could not stat file.
#define FT_NOFSCHG	14  // Different file system, prohibited.
#define FT_NOOPEN	15  // Could not open directory.
#define FT_RAW		16  // Raw block device.
#define FT_FIFO		17  // Raw fifo device.
#define FT_REPARSE	21  // Win NTFS reparse point.
#define FT_JUNCTION	26  // Win32 Junction point.

/*
 * Definition of the find_files packet passed as the
 * first argument to the find_files callback subroutine.
 */
struct FF_PKT
{
	char *fname;		/* full filename */
	long flen;		/* length of name component */
	char *link;		/* link if file linked */
	struct stat statp;	/* stat packet */
	uint64_t winattr;	/* windows attributes */
	int type;		/* FT_ type from above */
};

extern FF_PKT *find_files_init(void);
extern void find_files_free(FF_PKT *ff);
extern int find_files_begin(struct asfd *asfd,
	FF_PKT *ff_pkt, struct conf **confs, char *fname);
// Returns the level of compression.
extern int in_exclude_comp(struct strlist *excom, const char *fname,
	int compression);

#endif
