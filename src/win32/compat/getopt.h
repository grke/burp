#ifndef _GETOPT_H_
#define _GETOPT_H_

#ifdef __cplusplus
extern "C" {
#endif

int getopt(int argc, char * const argv[], const char *optstring);

extern char *optarg;
extern int optind, opterr, optopt;

#ifdef __cplusplus
}
#endif

#endif
