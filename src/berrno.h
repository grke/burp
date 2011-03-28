/*
 * Extra bits set to interpret errno value differently from errno
 */
#ifdef HAVE_WIN32
#define b_errno_win32  (1<<29)        /* user reserved bit */
#else
#define b_errno_win32  0              /* On Unix/Linix system */
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
class berrno {
   char m_buf[256];
   int m_berrno;
   void format_win32_message();
public:
   berrno();
   ~berrno();
   const char *bstrerror();
   const char *bstrerror(int errnum);
};

/* Constructor */
inline berrno::berrno()
{
   m_berrno = errno;
   *m_buf = 0;
   errno = m_berrno;
}

inline berrno::~berrno()
{
}

inline const char *berrno::bstrerror(int errnum)
{
   m_berrno = errnum;
   return berrno::bstrerror();
}
