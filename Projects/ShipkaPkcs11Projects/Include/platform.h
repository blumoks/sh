#ifndef _PLATFORM_H_
#define _PLATFORM_H_

#ifndef unix

#include <windows.h>
#include <tchar.h>
#include <windef.h>

#ifdef _UNICODE
#define LIBNAME L"shpkcs11.dll"
#else
#define LIBNAME "shpkcs11.dll"
#endif

#define PrintLastError() do { \
	cout << "Failed to load library! Error code = 0x" << hex << GetLastError() << endl; \
}  while(0)

#else

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <pthread.h>
#include <errno.h>
//#include "CoCreateGuid.h"
#include "wintype.h"

#define _countof(a) (sizeof(a)/sizeof(*(a)))
#define ARRAYSIZE(x) (sizeof(x) / sizeof(x[0]))
#define LIBNAME "libshpkcs11.so"
#define LoadLibrary(name) dlopen(name, RTLD_NOW)
#define GetProcAddress(h, name) dlsym(h, name)
#define FreeLibrary(h) dlclose(h)
#define _tmain main
#define GetLastError() errno

#ifndef min
#define min(a, b) ({ \
	const typeof(a) _a = (a); \
	const typeof(b) _b = (b); \
	(_a < _b) ? _a : _b; \
})
#endif

#define memcpy_s(dest, dest_size, src, src_size) ({ \
	memcpy((dest), (src), min((dest_size), (src_size))); \
	0; \
})

static inline void rand_s(unsigned int *val)
{
	FILE *fp = fopen("/dev/urandom", "r");
	assert(fp);
	assert(fread(val, 1, sizeof(*val), fp) == sizeof(*val));
	fclose(fp);
}

#define _snprintf snprintf
#define wvsprintf vsprintf
#define OutputDebugString(str) ({ \
	fprintf(stderr, "%s", str); \
})

#define PrintLastError() do { \
	cout << "Failed to load library! " << dlerror() << endl; \
}  while(0)

#endif

#endif
