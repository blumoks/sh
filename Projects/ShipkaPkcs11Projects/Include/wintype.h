#ifndef _WINTYPE_H__
#define _WINTYPE_H__

#include <wchar.h>

#ifndef CITRIX_VC

typedef int             INT;
typedef void            *HANDLE;
typedef unsigned char   BYTE;
typedef unsigned char   byte;
typedef unsigned short  WORD;
typedef unsigned short  *LPWORD;
typedef BYTE            BOOLEAN;
typedef BYTE            *PBYTE;
typedef unsigned long   DWORD;
typedef unsigned char   UCHAR;
typedef unsigned short  USHORT;
typedef unsigned long   OSCI_RV;
typedef unsigned long   DWORD_PTR;
typedef unsigned long   *PULONG;
typedef unsigned short  *PUSHORT;
typedef unsigned char   *PUCHAR;
typedef void            *PVOID;
typedef void            *LPVOID;
typedef unsigned long   ULONG;
typedef int             HRESULT;
typedef unsigned char   *LPBYTE;
typedef long            LONG;
typedef long            *LONG_PTR;

typedef char            CHAR;
typedef char            *PCHAR;
typedef char            *LPSTR;
typedef const char      *LPCSTR;
typedef wchar_t         WCHAR;
typedef wchar_t         *PWCHAR;
typedef wchar_t         *LPWSTR;
typedef const wchar_t   *LPCWSTR;
typedef char            TCHAR;
typedef char            *PTCHAR;
typedef char            *LPTSTR;
typedef const char      *LPCTSTR;

#define LONGLONG        long long
#define ULONGLONG       unsigned long long
#define UINT            unsigned int

#endif /* CITRIX_VC */

typedef unsigned int    rsize_t;

typedef void* HINSTANCE;
typedef void* FARPROC;
typedef unsigned long HCRYPTPROV;
typedef unsigned long HCRYPTHASH;
typedef unsigned int  BOOL;

#define _TCHAR char
#define errno_t int
#define TCHAR	char

#define    S_OK    0

#define ERROR_SUCCESS                     0L
#define ERROR_INVALID_FUNCTION            1L
#define ERROR_INVALID_HANDLE              6L
#define ERROR_NOT_ENOUGH_MEMORY           8L
#define ERROR_INVALID_DATA               13L
#define ERROR_BAD_LENGTH                 24L
#define ERROR_GEN_FAILURE                31L
#define ERROR_NOT_SUPPORTED              50L
#define ERROR_ADAP_HDW_ERR               57L
#define ERROR_INVALID_PARAMETER          87L
#define ERROR_INSUFFICIENT_BUFFER       122L
#define ERROR_BAD_PATHNAME              161L
#define ERROR_MORE_DATA                 234L
#define ERROR_SERVICE_DOES_NOT_EXIST   1060L
#define ERROR_ALREADY_REGISTERED       1242L
#define RPC_S_INVALID_TAG              1733L
#define ERROR_TAG_NOT_PRESENT          2013L

#ifndef TRUE
#define TRUE    1
#endif
#ifndef FALSE
#define FALSE    0
#endif

#define INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1)

#define sscanf_s(buffer, format, ...) sscanf(buffer, format, ##__VA_ARGS__)
#define sprintf_s(buffer, sizeOfBuffer, format, ...) sprintf(buffer, format, ##__VA_ARGS__)

#ifdef __cplusplus
extern "C" {
#endif

extern DWORD GetLastError();
extern void SetLastError(DWORD error);
extern int memcpy_s(void * Dst, size_t DstSize, const void * Src, size_t MaxCount);

#ifdef __cplusplus
}
#endif

#endif
