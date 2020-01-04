#
# "main" pseudo-component makefile.
#
# (Uses default behaviour of compiling all source files in directory, adding 'include' to include path.)

# Try to avoid warnings about deprecated declarations
CFLAGS += -Wno-deprecated-declarations
CXXFLAGS += -Wno-deprecated-declarations

# COMMON_WARNING_FLAGS = -Wall -Werror=all \
# 	-Wno-error=unused-function \
# 	-Wno-error=unused-but-set-variable \
# 	-Wno-deprecated -Wno-deprecated-declarations \
# 	-Wno-error=unused-variable \
# 	-Wextra \
# 	-Wno-unused-parameter -Wno-sign-compare

#
# Derive numeric version macros to pass to both the C and C++ preprocessor
#
MY_IDF_VER := $(shell cd ${IDF_PATH} && git describe --always --tags --dirty)
MY_CFLAGS = $(shell echo ${MY_IDF_VER} | awk -f ${COMPONENT_PATH}/idf-version.awk)
CFLAGS += ${MY_CFLAGS}
CXXFLAGS += ${MY_CFLAGS}

COMPONENT_SRCDIRS += ../libraries \
	../libraries/arduinojson \
	../libraries/acmeclient \
	../libraries/ftpclient/src

COMPONENT_ADD_INCLUDEDIRS := ../libraries \
	../libraries/arduinojson \
	../libraries/acmeclient \
	../libraries/ftpclient/include \
	.

COMPONENT_EXTRA_CLEAN := build.c

$(COMPONENT_BUILD_DIR)/build.o:	build.c
	$(CC) -c -o $(COMPONENT_BUILD_DIR)/build.o build.c
	echo "ADDED CFLAGS" ${CFLAGS}

$(COMPONENT_LIBRARY):	$(COMPONENT_BUILD_DIR)/build.o

COMPONENT_EMBED_TXTFILES :=

#
# These lines were copied from make/component_wrapper.mk in the esp-idf distro
# Obviously renamed COMPONENT_OBJS to MY_COMPONENT_OBJS
#
# Currently a copy from the v3.1.3 version
#
MY_COMPONENT_OBJS := $(foreach compsrcdir,$(COMPONENT_SRCDIRS),$(patsubst %.c,%.o,$(wildcard $(COMPONENT_PATH)/$(compsrcdir)/*.c)))
MY_COMPONENT_OBJS += $(foreach compsrcdir,$(COMPONENT_SRCDIRS),$(patsubst %.cpp,%.o,$(wildcard $(COMPONENT_PATH)/$(compsrcdir)/*.cpp)))
MY_COMPONENT_OBJS += $(foreach compsrcdir,$(COMPONENT_SRCDIRS),$(patsubst %.cc,%.o,$(wildcard $(COMPONENT_PATH)/$(compsrcdir)/*.cc)))
MY_COMPONENT_OBJS += $(foreach compsrcdir,$(COMPONENT_SRCDIRS),$(patsubst %.S,%.o,$(wildcard $(COMPONENT_PATH)/$(compsrcdir)/*.S)))
# Make relative by removing COMPONENT_PATH from all found object paths
MY_COMPONENT_OBJS := $(patsubst $(COMPONENT_PATH)/%,%,$(MY_COMPONENT_OBJS))
MY_COMPONENT_OBJS := $(call stripLeadingParentDirs,$(MY_COMPONENT_OBJS))
MY_COMPONENT_OBJS := $(foreach obj,$(MY_COMPONENT_OBJS),$(if $(filter $(abspath $(obj)),$(abspath $(COMPONENT_OBJEXCLUDE))), ,$(obj)))
MY_COMPONENT_OBJS := $(call uniq,$(MY_COMPONENT_OBJS))

build.c:	${MY_COMPONENT_OBJS}
	echo "Regenerating build timestamp .."
	echo -n "const char *build = \"" >build.c
	echo -n `date '+%Y/%m/%d %T'` >>build.c
	echo "\";" >>build.c

#
# Rules to build the certificates
#
RSA_BITS=	2048

Secure.o:	private_key.h my-ca.crt alarm.crt client.crt client2.crt

my-ca.key:
	openssl genrsa -out my-ca.key ${RSA_BITS}

alarm.key:
	openssl genrsa -out alarm.key ${RSA_BITS}

alarm.csr:	alarm.key ${COMPONENT_PATH}/alarm.conf
	openssl req -new -key alarm.key -out alarm.csr -config ${COMPONENT_PATH}/alarm.conf

my-ca.srl:
	echo "01" >my-ca.srl

my-ca.crt:	my-ca.key ${COMPONENT_PATH}/my-ca.conf
	openssl req -new -x509 -days 3650 -key my-ca.key -out my-ca.crt -config ${COMPONENT_PATH}/my-ca.conf

alarm.crt:	my-ca.crt my-ca.key alarm.csr
	openssl x509 -days 3650 -CA my-ca.crt -CAkey my-ca.key -in alarm.csr -req -out alarm.crt

all::	my-ca.crt alarm.crt
	openssl verify -CAfile my-ca.crt alarm.crt

alarm.key.DER:	alarm.key
	openssl rsa -in alarm.key -outform DER -out alarm.key.DER

my-ca.crt.DER:	my-ca.crt
	openssl x509 -in my-ca.crt -outform DER -out my-ca.crt.DER

alarm.crt.DER:	alarm.crt my-ca.srl
	openssl x509 -in alarm.crt -outform DER -out alarm.crt.DER

private_key.h:	alarm.key.DER alarm.crt.DER my-ca.crt.DER
	echo "#ifndef PRIVATE_KEY_H_" > private_key.h
	echo "#define PRIVATE_KEY_H_" >> private_key.h
	xxd -i -c 16 alarm.crt.DER >> private_key.h
	xxd -i -c 16 my-ca.crt.DER >> private_key.h
	xxd -i -c 16 alarm.key.DER >> private_key.h
	echo "#endif" >> private_key.h

client.key:
	openssl genrsa -out client.key ${RSA_BITS}

client2.key:
	openssl genrsa -out client2.key ${RSA_BITS}

client.csr:	client.key ${COMPONENT_PATH}/client.conf
	openssl req -new -key client.key -out client.csr -config ${COMPONENT_PATH}/client.conf

client2.csr:	client2.key ${COMPONENT_PATH}/client2.conf
	openssl req -new -key client2.key -out client2.csr -config ${COMPONENT_PATH}/client2.conf

client.crt:	client.csr my-ca.crt my-ca.key
	openssl x509 -days 3650 -CA my-ca.crt -CAkey my-ca.key -in client.csr -req -out client.crt

client2.crt:	client2.csr my-ca.crt my-ca.key
	openssl x509 -days 3650 -CA my-ca.crt -CAkey my-ca.key -in client2.csr -req -out client2.crt
