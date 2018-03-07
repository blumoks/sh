#ifndef SH_ENC_SIG_LIB_H
#define SH_ENC_SIG_LIB_H

#include "ShEncSig.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "ShEncSigLibt.h"

#define __PASTE(x,y)      x##y

/* ==============================================================
 * Define the "extern" form of all the entry points.
 * ==============================================================
 */

#define CK_NEED_ARG_LIST  1
#define CK_ES_FUNCTION_INFO(name) \
  extern ES_DECLARE_FUNCTION(CK_RV, name)

#include "ShEncSigLibf.h"

#undef CK_NEED_ARG_LIST
#undef CK_ES_FUNCTION_INFO


/* ==============================================================
 * Define the typedef form of all the entry points.
 * ==============================================================
 */

#define CK_NEED_ARG_LIST  1
#define CK_ES_FUNCTION_INFO(name) \
  typedef ES_DECLARE_FUNCTION_POINTER(CK_RV, __PASTE(CK_,name))

#include "ShEncSigLibf.h"

#undef CK_NEED_ARG_LIST
#undef CK_ES_FUNCTION_INFO

/* ==============================================================
 * 
 * ==============================================================
 */

#define CK_ES_FUNCTION_INFO(name) \
  __PASTE(CK_,name) name;
  
struct ES_FUNCTION_LIST {

  CK_VERSION    version;

#include "ShEncSigLibf.h"
};

#undef CK_ES_FUNCTION_INFO

#undef __PASTE

#ifdef __cplusplus
}
#endif


#endif