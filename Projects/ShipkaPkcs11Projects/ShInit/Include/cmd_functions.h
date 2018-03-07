#pragma once
#include "Init_y_Format.h"

#define CHANGE_DEVICE_PIN	("ChangePIN")
#define CHECK_DEVICE_PIN	("CheckPIN")
#define UNBLOCK_DEVICE		("Unblock")
#define FORMAT_DEVICE		("Format")
#define GET_DEVICE_INFO		("GetDeviceInfo")
#define GET_DEVICE_LIST		("GetDeviceList")
#define CHANGE_LANGUAGE		("ChangeLanguage")

#define FORMAT_WITH_PUK		("WithPUK")
#define FORMAT_WITHOUT_PUK	("WithoutPUK")
#define SAVE_TO_FILE		("SaveTo")
#define DEFAULT_ATTR		("Default")
#ifdef unix
#define DEFAULT_PUK_FILE	("~/OKBSAPR/log.txt")
#else
#define DEFAULT_PUK_FILE	("C:/log.txt")
#endif

#define DIFFERENT_NEW_PINS	(0x133)

class CommandLineWork:public InitializationClass {
public:
	CommandLineWork();
	~CommandLineWork();
	
	bool GetCommandFromCommandLine(int argc, char **argv);
private:
	void PrintWorkResult(char *InFunction);
	void PrintDeviceInfo(CK_SLOT_ID ulSlotID);
	void PrintDeviceInfoEx(CK_SLOT_ID ulSlotID);
};
