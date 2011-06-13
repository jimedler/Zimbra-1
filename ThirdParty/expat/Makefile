EXPAT_ROOT := $(shell pwd)
P4_ROOT ?= $(shell cd $(EXPAT_ROOT)/../..; pwd)
MAKE ?= make
MAKEARGS ?= -j2

BUILD_PLATFORM ?= $(shell sh $(P4_ROOT)/ZimbraBuild/rpmconf/Build/get_plat_tag.sh)
BUILD_TYPE := none

ZIMBRA_HOME ?= /opt/zimbra

ifdef BETA
	include $(EXPAT_ROOT)/../beta_versions.def
else
	include $(EXPAT_ROOT)/../versions.def
endif

ifeq (MACOSXx86,$(findstring MACOSXx86,$(BUILD_PLATFORM)))
	ENVMOD := env LIBS="-lresolv"
	BUILD_TYPE := $(BUILD_PLATFORM)
endif

ifeq ($(BUILD_PLATFORM), MACOSX)
	ENVMOD := env LIBS="-lresolv"
	BUILD_TYPE := $(BUILD_PLATFORM)
endif

EXPAT_TGZ_TARGET := $(P4_ROOT)/ThirdPartyBuilds/$(BUILD_PLATFORM)/expat/expat-$(EXPAT_VERSION).tgz

files	:= $(wildcard src/expat-$(EXPAT_VERSION).tar.gz)

all: checksrc build_$(BUILD_TYPE)

checksrc:
	$(if $(files), @echo "", exit 1)

check:
	@echo "Verifying expat build...";
	$(EXPAT_ROOT)/../zmcheck.pl -l $(ZIMBRA_HOME)/lib/libexpat.a

build:
	(tar xfz src/expat-$(EXPAT_VERSION).tar.gz; \
	cd expat-$(EXPAT_VERSION); \
	CFLAGS="-g -O2 -D_REENTRANT" \
	CCFLAGS="-g -O2 -D_REENTRANT" \
	$(ENVMOD) ./configure --prefix=/opt/zimbra; \
	$(MAKE) $(MAKEARGS); \
	$(MAKE) installlib STRIP="")
	(cd $(ZIMBRA_HOME); \
	mkdir -p $(P4_ROOT)/ThirdPartyBuilds/$(BUILD_PLATFORM)/expat; \
	tar cfz $(EXPAT_TGZ_TARGET) lib/libexpat* include/expat*)

build_MACOSXx86: allclean build check

build_MACOSXx86_10.5: allclean build check

build_MACOSXx86_10.6: allclean build check

build_MACOSX: allclean build check

build_none: ;

p4edit: $(EXPAT_TGZ_TARGET)
	p4 edit $(EXPAT_TGZ_TARGET)

clean:
	/bin/rm -rf expat-$(EXPAT_VERSION)

allclean: clean
	/bin/rm -rf $(ZIMBRA_HOME)/lib/libexpat*
	/bin/rm -rf $(ZIMBRA_HOME)/include/expat*
	rm -f $(EXPAT_TGZ_TARGET)
