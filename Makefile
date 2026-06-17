ARCHS = arm64 arm64e
TARGET = iphone:clang:latest:15.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = MonitorTweak
MonitorTweak_FILES = Tweak.x MonitorFiles.x SocketReporter.m RestoreSymbol.m
MonitorTweak_FRAMEWORKS = Foundation UIKit CoreLocation Contacts Photos \
                           AVFoundation AdSupport CoreTelephony WebKit
MonitorTweak_CFLAGS = -fobjc-arc -fvisibility=hidden
MonitorTweak_LDFLAGS = -lsubstrate
# No entitlements: iOS only honours the MAIN binary's entitlements, so signing an
# injected dylib with them does nothing useful and trips AMFI ("has entitlements
# but is not a main binary"). Theos default codesign (ldid -S fakesign, no
# entitlements) is what we want. The loopback 127.0.0.1:9190 socket needs none.

include $(THEOS_MAKE_PATH)/tweak.mk
