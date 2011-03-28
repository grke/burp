#ifndef _CLIENT_VSS_H
#define _CLIENT_VSS_H

#if defined(WIN32_VSS)
extern int win32_start_vss(struct config *conf);
extern int win32_stop_vss(void);
#endif // WIN32_VSS

#if defined(HAVE_WIN32)
extern int win32_enable_backup_privileges(int ignore_errors);
#endif  /* HAVE_WIN32 */


#endif // _CLIENT_VSS_H
