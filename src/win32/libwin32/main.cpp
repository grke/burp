/*
   Bacula® - The Network Backup Solution

   Copyright (C) 2007-2008 Free Software Foundation Europe e.V.

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
 *  Kern Sibbald, August 2007
 *
 * Note, some of the original Bacula Windows startup and service handling code
 *  was derived from VNC code that was used in apcupsd then ported to
 *  Bacula.  However, since then the code has been significantly enhanced
 *  and largely rewritten.
 *
 * Evidently due to the nature of Windows startup code and service
 *  handling code, certain similarities remain. Thanks to the original
 *  VNC authors.
 *
 * This is a generic main routine, which is used by all three
 *  of the daemons. Each one compiles it with slightly different
 *  #defines.
 */

#include "burp.h"
#include "libwin32.h"
#include <signal.h>

#undef  _WIN32_IE
#define _WIN32_IE 0x0501
#undef  _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#include <commctrl.h>

// Globals
HINSTANCE appInstance;
bool have_service_api;

// Main Windows entry point.
int main(int argc, char *argv[])
{
	int ret;

	InitWinAPIWrapper();

	// Start up Volume Shadow Copy.
	if(VSSInit()) return 1;

	// Startup networking
	WSA_Init();

	// Set this process to be the last application to be shut down.
	if(p_SetProcessShutdownParameters)
		p_SetProcessShutdownParameters(0x100, 0);

	// Call the Unix Burp daemon
	ret=BurpMain(argc, argv);

	// Terminate our main message loop
	PostQuitMessage(0);

	WSACleanup();
	return ret;
}
