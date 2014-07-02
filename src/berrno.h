/*
   Bacula® - The Network Backup Solution

   Copyright (C) 2004-2009 Free Software Foundation Europe e.V.

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
 * Kern Sibbald, July MMIV
 */
/*
 * Originally from bacula-5.0.3:src/lib/berrno.h. Heavily reduced in size and
 * converted to be C instead of a C++ class.
 *    Graham Keeling, 2014.
 */

#ifndef _BERRNO_H
#define _BERRNO_H

#include <errno.h>

// Extra bits set to interpret errno value differently from errno
#ifdef HAVE_WIN32
	#define b_errno_win32 (1<<29)	// User reserved bit.
#else
	#define b_errno_win32 0		// On Unix/Linix system.
#endif

/*
 * A more generalized way of handling errno that works with Unix and Windows.
 *
 * It works by picking up errno and creating a memory pool buffer
 *  for editing the message. strerror() does the actual editing, and
 *  it is thread safe.
 *
 * If bit 29 in m_berrno is set then it is a Win32 error, and we
 *  must do a GetLastError() to get the error code for formatting.
 * If bit 29 in m_berrno is not set, then it is a Unix errno.
 *
 */
struct berrno
{
	char m_buf[256];
	int m_berrno;
};

extern void berrno_init(struct berrno *b);
extern const char *berrno_bstrerror(struct berrno *b, int errnum);

#endif
