#ifndef KEY_MANAGMENT_LIB_H
#define KEY_MANAGMENT_LIB_H

#include "KeyManagment.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "KeyManagmentLibt.h"

#define __PASTE(x,y)      x##y

/* ==============================================================
 * Define the "extern" form of all the entry points.
 * ==============================================================
 */

#define CK_NEED_ARG_LIST  1
#define CK_KM_FUNCTION_INFO(name) \
  extern KM_DECLARE_FUNCTION(CK_RV, name)

#include "KeyManagmentLibf.h"

#undef CK_NEED_ARG_LIST
#undef CK_KM_FUNCTION_INFO


/* ==============================================================
 * Define the typedef form of all the entry points.  That is, for
 * each Cryptoki function C_XXX, define a type CK_C_XXX which is
 * a pointer to that kind of function.
 * ==============================================================
 */

#define CK_NEED_ARG_LIST  1
#define CK_KM_FUNCTION_INFO(name) \
  typedef KM_DECLARE_FUNCTION_POINTER(CK_RV, __PASTE(CK_,name))

/* pkcs11f.h has all the information about the Cryptoki
 * function prototypes. */
#include "KeyManagmentLibf.h"

#undef CK_NEED_ARG_LIST
#undef CK_KM_FUNCTION_INFO

/* ==============================================================
 * 
 * ==============================================================
 */

#define CK_KM_FUNCTION_INFO(name) \
  __PASTE(CK_,name) name;
  
struct KM_FUNCTION_LIST {

  CK_VERSION    version;

#include "KeyManagmentLibf.h"
};

#undef CK_KM_FUNCTION_INFO

#undef __PASTE

#ifdef __cplusplus
}
#endif


#endif