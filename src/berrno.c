#include "include.h"

static int b_strerror(int errnum, char *buf, size_t bufsiz)
{
    int stat = 0;
    const char *msg;

    msg = strerror(errnum);
    if (!msg) {
       msg = _("Bad errno");
       stat = -1;
    }
    snprintf(buf, bufsiz, "%s", msg);
    return stat;
}

const char *berrno::bstrerror()
{
   *m_buf = 0;
#ifdef HAVE_WIN32
//   if (m_berrno & b_errno_win32) {
      format_win32_message();
      return (const char *)m_buf;
//   }
#endif
   /* Normal errno */
   if (b_strerror(m_berrno, m_buf, sizeof(m_buf)) < 0) {
      return _("Invalid errno. No error message possible.");
   }
   return m_buf;
}

void berrno::format_win32_message()
{
#ifdef HAVE_WIN32
   LPVOID msg;
   FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER |
       FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
       NULL,
       GetLastError(),
       MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
       (LPTSTR)&msg,
       0,
       NULL);
   snprintf(m_buf, sizeof(m_buf), "%s", (const char *)msg);
   LocalFree(msg);
#endif
}
