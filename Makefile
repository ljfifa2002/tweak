ARCHS = arm64 arm64e
TARGET = iphone:clang:latest:15.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = MonitorTweak
MonitorTweak_FILES = Tweak.x MonitorFiles.x SocketReporter.m
MonitorTweak_FRAMEWORKS = Foundation UIKit CoreLocation Contacts Photos \
                           AVFoundation AdSupport CoreTelephony
MonitorTweak_CFLAGS = -fobjc-arc -fvisibility=hidden
MonitorTweak_LDFLAGS = -lsubstrate
MonitorTweak_CODESIGN_FLAGS = -Sentitlements.plist

include $(THEOS_MAKE_PATH)/tweak.mk
