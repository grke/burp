#ifndef __DLFCN_H_
#define __DLFCN_H_

#define RTDL_NOW 2

void *dlopen(const char *file, int mode);
void *dlsym(void *handle, const char *name);
int dlclose(void *handle);
char *dlerror(void);

#endif
