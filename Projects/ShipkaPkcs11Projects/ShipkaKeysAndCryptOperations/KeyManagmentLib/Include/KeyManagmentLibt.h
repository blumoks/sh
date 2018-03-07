#ifndef _KEY_MANAGMENT_LIB_T_
#define _KEY_MANAGMENT_LIB_T_
typedef struct KM_FUNCTION_LIST KM_FUNCTION_LIST;

typedef KM_FUNCTION_LIST * KM_FUNCTION_LIST_PTR;

typedef KM_FUNCTION_LIST_PTR * KM_FUNCTION_LIST_PTR_PTR;

 #ifdef KEYMANAGMENTLIB_EXPORTS
  /* Specified that the function is an exported DLL entry point. */
  #define KM_EXPORT_SPEC __declspec(dllexport) 
 #else
  #define KM_EXPORT_SPEC CK_IMPORT_SPEC 
 #endif

#define KM_DECLARE_FUNCTION(returnType, name) \
  returnType KM_EXPORT_SPEC CK_CALL_SPEC name

#define KM_DECLARE_FUNCTION_POINTER(returnType, name) \
  returnType CK_IMPORT_SPEC (CK_CALL_SPEC CK_PTR name)

#endif