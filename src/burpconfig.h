#ifndef _BURPCONFIG_H
#define _BURPCONFIG_H

// Graham says: probably most of this stuff can be deleted - it is debris
// left from Bacula.

#define ASSERT(x)

#ifdef HAVE_WIN32
	#define WIN32_REPARSE_POINT  1 // Any odd dir except the next two.
	#define WIN32_MOUNT_POINT    2 // Directory link to Volume.
	#define WIN32_JUNCTION_POINT 3 // Directory link to a directory.

	void InitWinAPIWrapper();

	#ifdef BUILDING_DLL
		#define DLL_IMP_EXP _declspec(dllexport)
	#elif defined(USING_DLL)
		#define DLL_IMP_EXP _declspec(dllimport)
	#endif

	#ifdef USING_CATS
		#define CATS_IMP_EXP _declspec(dllimport)
	#endif
#endif

#ifndef S_ISLNK
#define S_ISLNK(m) (((m) & S_IFM) == S_IFLNK)
#endif

#ifndef O_BINARY
	#define O_BINARY 0
#endif

inline uint8_t IsPathSeparator(int ch)
{
	return
#ifdef HAVE_WIN32
	ch == '\\' ||
#endif
	ch == '/';
}

#endif
