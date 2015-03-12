# Copyright (C) 2009 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#
LOCAL_PATH := $(call my-dir)
ROOT_PATH := $(LOCAL_PATH)

########################################################
## system
########################################################

include $(CLEAR_VARS)

LOCAL_MODULE:= encryptor
LOCAL_C_INCLUDES := $(LOCAL_PATH)/openssl/include/ \
					$(LOCAL_PATH)/libsodium/include/ \
					$(LOCAL_PATH)/

LOCAL_SRC_FILES:= \
	system.cpp \
	encrypt.c


LOCAL_LDLIBS := -ldl -llog

LOCAL_STATIC_LIBRARIES := cpufeatures \
	libsodium \
	libcrypto \
	libssl


include $(BUILD_SHARED_LIBRARY)

#######################################################
## libsodium
#######################################################
include $(CLEAR_VARS)

LOCAL_MODULE := libsodium
LOCAL_SRC_FILES := $(TARGET_ARCH_ABI)/libsodium.a
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/libsodium/include/

include $(PREBUILT_STATIC_LIBRARY)
#######################################################
## OpenSSL
#######################################################
openssl_subdirs := $(addprefix $(LOCAL_PATH)/openssl/,$(addsuffix /Android.mk, \
	crypto \
	ssl \
	))
include $(openssl_subdirs)

$(call import-module,android/cpufeatures)
