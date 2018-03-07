#ifndef _OSCI_EXTENSION_PKCS11_H_
#define _OSCI_EXTENSION_PKCS11_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

#include "OSCI_ExtensionPkcs11t.h"

#define __PASTE(x,y)      x##y


/* ==============================================================
 * Define the "extern" form of all the entry points.
 * ==============================================================
 */

#define CK_NEED_ARG_LIST  1
#define CK_PKCS11_FUNCTION_INFO(name) \
  extern CK_DECLARE_FUNCTION(CK_RV, name)

#include "OSCI_ExtensionPkcs11f.h"

#undef CK_NEED_ARG_LIST
#undef CK_PKCS11_FUNCTION_INFO


/* ==============================================================
 * Define the typedef form of all the entry points.  That is, for
 * each Cryptoki function C_XXX, define a type CK_C_XXX which is
 * a pointer to that kind of function.
 * ==============================================================
 */

#define CK_NEED_ARG_LIST  1
#define CK_PKCS11_FUNCTION_INFO(name) \
  typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, __PASTE(CK_,name))

/* pkcs11f.h has all the information about the Cryptoki
 * function prototypes. */
#include "OSCI_ExtensionPkcs11f.h"

#undef CK_NEED_ARG_LIST
#undef CK_PKCS11_FUNCTION_INFO

/* ==============================================================
 * 
 * ==============================================================
 */
#define CK_PKCS11_FUNCTION_INFO(name) \
  __PASTE(CK_,name) name;
  
struct _CK_SHEX_FUNCTION_LIST {

  CK_VERSION    version;

#include "OSCI_ExtensionPkcs11f.h"
};

#undef CK_PKCS11_FUNCTION_INFO



#undef __PASTE

#ifdef __cplusplus
}
#endif

#endif