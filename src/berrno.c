#include "include.h"

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
		msg=_("Bad errno");
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
		return _("Invalid errno. No error message possible.");

	return b->m_buf;
}
