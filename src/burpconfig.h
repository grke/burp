#ifndef _BURPCONFIG_H
#define _BURPCONFIG_H

// Graham says: probably most of this stuff can be deleted - it is debris
// left from Bacula.

#define ASSERT(x)

// MAX_PATH is Windows constatnt, usually 260, maybe changed in some Win10 update.
// PATH_MAX is Posix constant
// right method - it to call pathconf(), but such case lead to reworking lots of code;
// and some buffers are better to allocate on stack, not on heap
#ifndef MAX_PATH
    #ifdef PATH_MAX
        #define MAX_PATH           PATH_MAX
    #else
        #define MAX_PATH           260
    #endif
#endif

// unicode enabling of win 32 needs some defines and functions

// using an average of 3 bytes per character is probably fine in
// practice but I believe that Windows actually uses UTF-16 encoding
// as opposed to UCS2 which means characters 0x10000-0x10ffff are
// valid and result in 4 byte UTF-8 encodings.
#define MAX_PATH_UTF8    MAX_PATH*4  // strict upper bound on UTF-16 to UTF-8 conversion

// from
// http://msdn.microsoft.com/library/default.asp?url=/library/en-us/fileio/fs/getfileattributesex.asp
// In the ANSI version of this function, the name is limited to
// MAX_PATH characters. To extend this limit to 32,767 wide
// characters, call the Unicode version of the function and prepend
// "\\?\" to the path. For more information, see Naming a File.
#define MAX_PATH_W 32767

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

#ifndef O_BINARY
	#define O_BINARY 0
#endif

static inline uint8_t IsPathSeparator(int ch)
{
	return
#ifdef HAVE_WIN32
	ch == '\\' ||
#endif
	ch == '/';
}

#endif
