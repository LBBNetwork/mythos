GO_EASY_ON_ME = 1
include theos/makefiles/common.mk

TOOL_NAME = restored
ADDITIONAL_CFLAGS = -I. -I../../xpwntool
LDFLAGS = -Wl,-e,_main
TARGET_CODESIGN = ldid -a armv6
restored_FILES = main.c crtsup.c plist.c abstractfile.c
restored_FRAMEWORKS = IOKit CoreFoundation

include $(THEOS_MAKE_PATH)/tool.mk
