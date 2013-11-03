/*
 * Define Host machine
 */
#undef HOST_OS
#undef DISTNAME
#undef DISTVER

#define HOST_OS  "Linux"
#define DISTNAME "Cross-compile"
#define BURP "Burp"
#ifdef _WIN64
	#define DISTVER "Win64"
#else
	#define DISTVER "Win32"
#endif
