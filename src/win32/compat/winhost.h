/*
 * Define Host machine
 */
/*
   This program is Free Software; you can redistribute it and/or
   modify it under the terms of version two of the GNU General Public
   License as published by the Free Software Foundation and included
   in the file LICENSE.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
   02110-1301, USA.
*/

//#include "host.h"
#undef HOST_OS
#undef DISTNAME
#undef DISTVER

#ifdef HAVE_MINGW

#define HOST_OS  "Linux"
#define DISTNAME "Cross-compile"
#define BURP "Burp"
#ifdef _WIN64
# define DISTVER "Win64"
#else
# define DISTVER "Win32"
#endif

#else

extern DLL_IMP_EXP char WIN_VERSION_LONG[];
extern DLL_IMP_EXP char WIN_VERSION[];

#define HOST_OS  WIN_VERSION_LONG
#define DISTNAME "MVS"
#define DISTVER  WIN_VERSION

#endif
