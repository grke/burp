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
 *   Kern Sibbald, July MMIV
 */
/*
 * Originally from bacula-5.0.3:src/lib/berrno.h.
 * Converted to be C instead of a C++ class.
 *    Graham Keeling, 2014.
 */

#include "burp.h"
#include "berrno.h"

void berrno_init(struct berrno *b)
{
	b->m_berrno=errno;
	*(b->m_buf)=0;
	errno=b->m_berrno;
}

static int bstrerror(int errnum, char *buf, size_t bufsiz)
{
	int stat=0;
	const char *msg;

	if(!(msg=strerror(errnum)))
	{
		msg="Bad errno";
		stat=-1;
	}
	snprintf(buf, bufsiz, "%s", msg);
	return stat;
}

#ifdef HAVE_WIN32
static void format_win32_message(struct berrno *b)
{
	LPVOID msg;
	FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		GetLastError(),
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&msg,
		0,
		NULL);
	snprintf(b->m_buf, sizeof(b->m_buf), "%s", (const char *)msg);
	LocalFree(msg);
}
#endif

const char *berrno_bstrerror(struct berrno *b, int errnum)
{
	b->m_berrno=errnum;

	*(b->m_buf)=0;
#ifdef HAVE_WIN32
	if(b->m_berrno & b_errno_win32)
	{
		format_win32_message(b);
		return (const char *)(b->m_buf);
	}
#endif
	// Normal errno.
	if(bstrerror(b->m_berrno, b->m_buf, sizeof(b->m_buf))<0)
		return "Invalid errno. No error message possible.";

	return b->m_buf;
}
