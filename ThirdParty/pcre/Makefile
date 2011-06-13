PCRE_ROOT := $(shell pwd)
P4_ROOT ?= $(shell cd $(PCRE_ROOT)/../..; pwd)
MAKE ?= make
MAKEARGS ?= -j2

BUILD_PLATFORM ?= $(shell sh $(P4_ROOT)/ZimbraBuild/rpmconf/Build/get_plat_tag.sh)
BUILD_TYPE := none

ZIMBRA_HOME ?= /opt/zimbra

ifdef BETA
	include $(PCRE_ROOT)/../beta_versions.def
else
	include $(PCRE_ROOT)/../versions.def
endif

ifeq (MACOSXx86,$(findstring MACOSXx86,$(BUILD_PLATFORM)))
	ENVMOD := env LIBS="-lresolv" 
	BUILD_TYPE := $(BUILD_PLATFORM)
endif

ifeq ($(BUILD_PLATFORM), MACOSX)
	ENVMOD := env LIBS="-lresolv" 
	BUILD_TYPE := $(BUILD_PLATFORM)
endif

PCRE_TGZ_TARGET := \
	$(P4_ROOT)/ThirdPartyBuilds/$(BUILD_PLATFORM)/pcre/pcre-$(PCRE_VERSION).tgz

files	:= $(wildcard src/pcre-$(PCRE_VERSION).tar.gz)

all: checksrc build_$(BUILD_TYPE) 

checksrc:
	$(if $(files), @echo "", exit 1)

build:
	(tar xfz src/pcre-$(PCRE_VERSION).tar.gz; \
	cd pcre-$(PCRE_VERSION); \
	CFLAGS="-g -O2 -D_REENTRANT" \
	CCFLAGS="-g -O2 -D_REENTRANT" \
	$(ENVMOD) ./configure --prefix=/opt/zimbra --disable-shared; \
	$(MAKE) $(MAKEARGS); \
	$(MAKE) install STRIP=""; \
	rm -rf $(ZIMBRA_HOME)/share; \
	rm -rf $(ZIMBRA_HOME)/lib/pkgconfig; \
	rm -rf $(ZIMBRA_HOME)/bin)
	(cd $(ZIMBRA_HOME); \
	mkdir -p $(P4_ROOT)/ThirdPartyBuilds/$(BUILD_PLATFORM)/pcre; \
	tar cfz $(PCRE_TGZ_TARGET) lib/libpcre* include/pcre*)

build_MACOSXx86: allclean build

build_MACOSXx86_10.5: allclean build

build_MACOSXx86_10.6: allclean build

build_MACOSX: allclean build

build_none: ;

p4edit: $(PCRE_TGZ_TARGET)
	p4 edit $(PCRE_TGZ_TARGET)

clean: 
	/bin/rm -rf pcre-$(PCRE_VERSION)

allclean: clean
	/bin/rm -rf $(ZIMBRA_HOME)/lib/libpcre*
	/bin/rm -rf $(ZIMBRA_HOME)/include/pcre*
	rm -f $(PCRE_TGZ_TARGET)
