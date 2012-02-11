#include "burp.h"
#include "win32.h"
#include <signal.h>

#undef  _WIN32_IE
#define _WIN32_IE 0x0501
#undef  _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#include <commctrl.h>

/* Globals */
HINSTANCE appInstance;
bool have_service_api;


/*
 *
 * Main Windows entry point.
 *
 */
int main(int argc, char *argv[])
{
   //int i=0;

   //for(i=0; i<argc; i++)
   //{
//	printf("argv[%d]: %s\n", i, argv[i]);
//	fflush(stdout);
//   }

   OSDependentInit();

   /* Start up Volume Shadow Copy (only on FD) */
   VSSInit();

   /* Startup networking */
   WSA_Init();

   /* Set this process to be the last application to be shut down. */
   if (p_SetProcessShutdownParameters) {
      p_SetProcessShutdownParameters(0x100, 0);
   }

   /* Call the Unix Burp daemon */
   BurpMain(argc, argv);
   PostQuitMessage(0);                /* terminate our main message loop */

   WSACleanup();
   _exit(0);
}
