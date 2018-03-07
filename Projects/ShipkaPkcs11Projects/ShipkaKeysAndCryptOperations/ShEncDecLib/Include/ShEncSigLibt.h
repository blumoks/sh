#ifndef _SH_ENC_SIG_LIB_T_
#define _SH_ENC_SIG_LIB_T_
typedef struct ES_FUNCTION_LIST ES_FUNCTION_LIST;

typedef ES_FUNCTION_LIST * ES_FUNCTION_LIST_PTR;

typedef ES_FUNCTION_LIST_PTR * ES_FUNCTION_LIST_PTR_PTR;

 #ifdef SHENCDECLIB_EXPORTS
  /* Specified that the function is an exported DLL entry point. */
  #define ES_EXPORT_SPEC __declspec(dllexport) 
 #else
  #define ES_EXPORT_SPEC CK_IMPORT_SPEC 
 #endif

#define ES_DECLARE_FUNCTION(returnType, name) \
  returnType ES_EXPORT_SPEC CK_CALL_SPEC name

#define ES_DECLARE_FUNCTION_POINTER(returnType, name) \
  returnType CK_IMPORT_SPEC (CK_CALL_SPEC CK_PTR name)

#endif