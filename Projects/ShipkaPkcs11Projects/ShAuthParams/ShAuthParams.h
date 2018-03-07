#ifndef AUTH_PARAMS
#define AUTH_PARAMS

#include "low_layer_func.h"

class AuthParamsInit:public BaseClass {
public:
	AuthParamsInit();
	~AuthParamsInit();
	
	void ChangeSOPIN(char *pcDeviceID, char *pcOldSOPIN, CK_ULONG ulOldSOPinLen, char *pcNewSOPIN, CK_ULONG ulNewSOPinLen);
	/**
	*/
	void SetAuthParams (bool bForOneDevice, char *pcDeviceID, CK_ULONG ulSOPinLen, char *pcSOPIN, 
						bool bWithPUK, CK_ULONG ulPukLen, CK_ULONG ulNumOfPukAttempts, CK_ULONG ulNumOfPinAttempts,
						CK_ULONG ulAlphabetFlag, CK_ULONG ulMinPinLen, CK_ULONG ulMaxPinLen, bool bMakeConstant);
	void BlockFormatting(char *pcDeviceID, char *pcSOPIN, CK_ULONG ulSOPinLen);
	void UnblockFormatting(char *pcDeviceID, char *pcSOPIN, CK_ULONG ulSOPinLen);
};
#endif