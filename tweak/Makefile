TARGET := iphone:clang:latest:16.0
ARCHS := arm64
FINALPACKAGE := 1
# Logos's .x.m output is kept: an .x object depends on it, and Theos otherwise deletes it after compiling,
# so every .x file would compile again on every build.
KEEP_LOGOS_INTERMEDIATES := 1

# version.txt at the repo root is the one version, bumped by Release Please's release PR. Theos
# stamps PACKAGE_VERSION into the .deb (control has no Version line) and reads it while common.mk
# loads, so it is set above the include.
SG_VERSION := $(or $(shell cat ../version.txt 2>/dev/null),0.0.0)
# A pre-release's hyphen becomes a tilde in the .deb, so dpkg sorts 1.0.0~beta.1 before 1.0.0.
PACKAGE_VERSION := $(subst -,~,$(SG_VERSION))

include $(THEOS)/makefiles/common.mk

# The What's new sheet's text, this version's section of CHANGELOG.md, as a gitignored header that
# App/Onboarding/WhatsNew.m reads. A copy of tweak/ without the scripts beside it builds without it.
ifneq ($(wildcard ../scripts/whats-new.sh),)
$(shell ../scripts/whats-new.sh $(SG_VERSION) ../CHANGELOG.md Sources/App/Onboarding/SGWhatsNewNotes.h)
endif

TWEAK_NAME := spotifyglass

# Every source under Sources/, so a new feature needs no Makefile edit. Shared/Flags/SGFlagList.m
# is generated from the IPA by scripts/extract-flags.py.
spotifyglass_FILES := $(shell find Sources -name '*.m' -o -name '*.x' -o -name '*.swift' | sort)
WIREGUARD ?= 0
ifneq ($(WIREGUARD),1)
spotifyglass_FILES := $(filter-out Sources/Shared/WireGuard/%,$(spotifyglass_FILES))
endif
spotifyglass_CFLAGS := -DSG_WIREGUARD=$(WIREGUARD) -fobjc-arc -ISources -DSG_VERSION=\"$(SG_VERSION)\"
# The phone driver (Diagnostics/Driver.m) goes only into builds that carry FLEX: scripts/pipeline.sh sets
# SG_DRIVER=1 for those, and every other build (make release, the release workflow's .deb) leaves it out.
SG_DRIVER ?= 0
spotifyglass_CFLAGS += -DSG_DRIVER=$(SG_DRIVER)
spotifyglass_FRAMEWORKS := UIKit QuartzCore UniformTypeIdentifiers PhotosUI MediaPlayer CoreImage AudioToolbox AVFoundation AVKit CoreMedia CoreVideo CoreHaptics Accelerate CoreMotion CoreML CoreText OSLog Metal ReplayKit
# zlib unpacks KuGou's KRC lyrics (Shared/LyricsSources/KuGou.m).
spotifyglass_LIBRARIES := z
# Runtime swizzling instead of Substrate so the dylib has no extra dependency inside the IPA.
spotifyglass_LOGOS_DEFAULT_GENERATOR := internal

# The audio effects' third-party C (vendor/audio: libbs2b, WDL's EEL2) is built by its own Makefile into a
# static library with its own flags, out of this one's -Werror and with its symbols hidden, into
# vendor/audio/build/ios/, which `clean` leaves alone and later builds only update. Listed as an object file
# it is a prerequisite of the link and linked in; only the two files using it see its headers.
SG_AUDIO := ../vendor/audio
spotifyglass_OBJ_FILES := $(SG_AUDIO)/build/ios/libsgaudio.a
Sources/Shared/AudioEffects/SGDSPCrossfeed.m_CFLAGS := -isystem $(SG_AUDIO)/libbs2b
Sources/Shared/AudioEffects/SGDSPLiveprog.m_CFLAGS := -isystem $(SG_AUDIO)/wdl/eel2

ifeq ($(WIREGUARD),1)
spotifyglass_OBJ_FILES += ../WireGuard/build/libsgwg.a
spotifyglass_FRAMEWORKS += Network Security CoreFoundation
spotifyglass_LIBRARIES += resolv
spotifyglass.all.tweak.variables: sg-wireguard
.PHONY: sg-wireguard
sg-wireguard:
	@if [ "$${SG_WG_PREBUILT:-0}" = 1 ] && [ -s ../WireGuard/build/libsgwg.a ] && [ -s ../WireGuard/build/libsgwg.h ]; then \
		echo "==> reusing cached WireGuard library"; \
	else ../WireGuard/build-ios.sh; fi

after-stage::
	@mkdir -p "$(THEOS_STAGING_DIR)$(THEOS_PACKAGE_INSTALL_PREFIX)/Library/Application Support/Vitrine.bundle"
	@cp ../WireGuard/THIRD_PARTY_LICENSES.txt "$(THEOS_STAGING_DIR)$(THEOS_PACKAGE_INSTALL_PREFIX)/Library/Application Support/Vitrine.bundle/WireGuard-THIRD_PARTY_LICENSES.txt"
endif

include $(THEOS_MAKE_PATH)/tweak.mk

# The library is brought up to date before the tweak's instance builds, so the link finds it current.
spotifyglass.all.tweak.variables: sg-audio
.PHONY: sg-audio
sg-audio:
	@$(MAKE) --no-print-directory -C $(SG_AUDIO) PLATFORM=ios

# The layers of Sources/ stay apart (scripts/check-layers.sh): an import across them fails the build.
# A copy of tweak/ made without the scripts beside it builds unchecked.
before-all::
	@if [ -x ../scripts/check-layers.sh ]; then ../scripts/check-layers.sh Sources; fi
