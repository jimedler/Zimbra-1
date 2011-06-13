# URL http://rpm5.org/files/popt/
POPT_ROOT := $(shell pwd)
P4_ROOT ?= $(shell cd $(POPT_ROOT)/../..; pwd)
MAKE ?= make
MAKEARGS ?= -j2

BUILD_PLATFORM ?= $(shell sh $(P4_ROOT)/ZimbraBuild/rpmconf/Build/get_plat_tag.sh)
BUILD_TYPE := none

ZIMBRA_HOME ?= /opt/zimbra

ifdef BETA
	include $(POPT_ROOT)/../beta_versions.def
else
	include $(POPT_ROOT)/../versions.def
endif

ifeq (MACOSXx86,$(findstring MACOSXx86,$(BUILD_PLATFORM)))
	ENVMOD := env LIBS="-lresolv" 
	BUILD_TYPE := $(BUILD_PLATFORM)
endif

ifeq ($(BUILD_PLATFORM), MACOSX)
	ENVMOD := env LIBS="-lresolv" 
	BUILD_TYPE := $(BUILD_PLATFORM)
endif

POPT_TGZ_TARGET := $(P4_ROOT)/ThirdPartyBuilds/$(BUILD_PLATFORM)/popt/popt-$(POPT_VERSION).tgz

files	:= $(wildcard src/popt-$(POPT_VERSION).tar.gz)

all: checksrc build_$(BUILD_TYPE) 

checksrc:
	$(if $(files), @echo "", exit 1)

build:
	(tar xfz src/popt-$(POPT_VERSION).tar.gz; \
	cd popt-$(POPT_VERSION); \
	CFLAGS="-g -O2 -D_REENTRANT" \
	CCFLAGS="-g -O2 -D_REENTRANT" \
	$(ENVMOD) ./configure --prefix=/opt/zimbra; \
	$(MAKE) $(MAKEARGS); \
	$(MAKE) install-usrlibLTLIBRARIES STRIP=""; \
	$(MAKE) install-includeHEADERS STRIP="")
	(cd $(ZIMBRA_HOME); \
	mkdir -p $(P4_ROOT)/ThirdPartyBuilds/$(BUILD_PLATFORM)/popt; \
	tar cfz $(POPT_TGZ_TARGET) lib/libpopt* include/popt*)

build_MACOSXx86: allclean build

build_MACOSXx86_10.5: allclean build

build_MACOSXx86_10.6: allclean build

build_MACOSX: allclean build

build_none: ;

p4edit: $(POPT_TGZ_TARGET)
	p4 edit $(POPT_TGZ_TARGET)

clean:
	/bin/rm -rf popt-$(POPT_VERSION)

allclean: clean
	/bin/rm -rf $(ZIMBRA_HOME)/lib/libpopt*
	/bin/rm -rf $(ZIMBRA_HOME)/include/popt*
	rm -f $(POPT_TGZ_TARGET)
