/*
   Bacula® - The Network Backup Solution

   Copyright (C) 2007-2007 Free Software Foundation Europe e.V.

   The main author of Bacula is Kern Sibbald, with contributions from
   many others, a complete list can be found in the file AUTHORS.
   This program is Free Software; you can redistribute it and/or
   modify it under the terms of version three of the GNU Affero General Public
   License as published by the Free Software Foundation, which is
   listed in the file LICENSE.

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
 * Kern Sibbald, August 2007
 */

#include "burp.h"
#include <signal.h>

#undef  _WIN32_IE
#define _WIN32_IE 0x0501
#undef  _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#include <commctrl.h>

#include <vss.h>

// Globals
HINSTANCE appInstance;
bool have_service_api;

extern int UtestMain(int argc, char *argv[], char *envp[]);

// Main Windows entry point.
int main(int argc, char *argv[], char *envp[])
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

	// Call the main code
	ret=UtestMain(argc, argv, envp);

	// Terminate our main message loop
	PostQuitMessage(0);

	WSACleanup();
	return ret;
}
