#ifndef AUTH_CMD_AND_PARAMS
#define AUTH_CMD_AND_PARAMS

#define CHANGE_SO_PIN			("ChangeSoPassword")
#define SET_IA_PARAMS			("SetParams")
#define LOCK_FORMATTING			("Lock")
#define UNLOCK_FORMATTING		("Unlock")
#define GET_DEVICE_INFO			("GetDeviceInfo")
#define GET_DEVICE_LIST			("GetDeviceList")
#define CHANGE_LANGUAGE			("ChangeLanguage")
#define USE_HELP				("-h")

#define SO_PIN					("SoPassword=")
#define PIN_LEN_PARAM			("PinLen=")
#define PUK_LEN_PARAM			("PukLen=")
#define PIN_ATTEMPTS_NUM		("PinAtt=")
#define PUK_ATTEMPTS_NUM		("PukAtt=")
#define PIN_CHAR_PARAM			("PinChar=")

#define ALL_DEVICES_PARAM		("-all")
#define FORMAT_WITH_PUK			("WithPUK")
#define FORMAT_WITHOUT_PUK		("WithoutPUK")
#define DIGITS_PARAM			("-d")
#define UPPER_CASE_PARAM		("-u")
#define LOWER_CASE_PARAM		("-l")
#define WILDCARD_CHAR_PARAM		("-w")

#define MAKE_CONSTANT			("MakeConstant")

#define DIGITS_FLAG				(0x01)
#define UPPER_CASE_FLAG			(0x02)
#define LOWER_CASE_FLAG			(0x04)
#define WILDCARD_CHAR_FLAG		(0x08)
#endif