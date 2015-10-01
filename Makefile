include theos/makefiles/common.mk

TOOL_NAME = postinst
postinst_FILES = main.mm
postinst_LIBRARIES = MobileGestalt

postinst_ARCHS = armv7 arm64
export ARCHS = armv7 arm64

include $(THEOS_MAKE_PATH)/tool.mk
