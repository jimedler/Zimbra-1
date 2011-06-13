MYSQL_ROOT := $(shell pwd)
P4_ROOT ?= $(shell cd $(MYSQL_ROOT)/../..; pwd)

BUILD_PLATFORM ?= $(shell sh $(P4_ROOT)/ZimbraBuild/rpmconf/Build/get_plat_tag.sh)

MAKE ?= make
MAKEARGS ?= -j2

ifeq ($(BUILD_PLATFORM), )
	BUILD_PLATFORM := "UNKNOWN"
endif

ZIMBRA_HOME ?= /opt/zimbra

ifdef BETA
	include $(MYSQL_ROOT)/../beta_versions.def
else
	include $(MYSQL_ROOT)/../versions.def
endif

MYSQL_VERSION ?= standard-$(MYSQL_VERSION_STRING)-pc-linux-gnu-i686-glibc23

ifeq ($(BUILD_PLATFORM), MACOSXx86_10.6)
	OS_RELEASE ?= 10
	OS_PLATFORM ?= $(shell uname -p)
	PLAT_CFLAGS ?= -fast -arch x86_64 -fno-common -isysroot /Developer/SDKs/MacOSX10.6.sdk
	PLAT_CXXFLAGS ?= -fast -arch x86_64 -fno-common -isysroot /Developer/SDKs/MacOSX10.6.sdk
	PLAT_LDFLAGS ?= -fast -arch x86_64
	MAC_TARGET ?= MACOSX_DEPLOYMENT_TARGET=10.6
	MYSQL_VERSION := standard-$(MYSQL_VERSION_STRING)-apple-darwin$(OS_RELEASE)-$(OS_PLATFORM)
endif

ifeq (MACOSXx86,$(findstring MACOSXx86,$(BUILD_PLATFORM)))
	OS_RELEASE ?= 8.2.0
	OS_PLATFORM ?= i686
	MYSQL_VERSION := standard-$(MYSQL_VERSION_STRING)-apple-darwin$(OS_RELEASE)-$(OS_PLATFORM)
endif


ifeq ($(BUILD_PLATFORM), MACOSX)
	MYSQL_VERSION := standard-$(MYSQL_VERSION_STRING)-apple-darwin8.2.0-powerpc
endif

MYSQL_TGZ_TARGET := \
	$(P4_ROOT)/ThirdPartyBuilds/$(BUILD_PLATFORM)/mysql/mysql-$(MYSQL_VERSION).tar.gz

MYSQL_LIB_TGZ_TARGET := \
	$(P4_ROOT)/ThirdPartyBuilds/$(BUILD_PLATFORM)/mysql/mysql-libs-$(MYSQL_VERSION).tgz

files   := $(wildcard src/mysql-$(MYSQL_VERSION_STRING).tar.gz)

all: checksrc allclean build tar

checksrc:
	$(if $(files), @echo "", exit 1)

clean:
	rm -rf mysql-$(MYSQL_VERSION_STRING)

build:
	echo $(OS_RELEASE) $(OS_PLATFORM)
	mkdir -p $(ZIMBRA_HOME)
	rm -rf mysql-$(MYSQL_VERSION_STRING)
	tar xzf src/mysql-$(MYSQL_VERSION_STRING).tar.gz
	(cd mysql-$(MYSQL_VERSION_STRING); \
	patch -g0 -N -p1 < ../patches/openssl.patch; \
	$(MAC_TARGET) CFLAGS="-g -O3 $(PLAT_CFLAGS)" CXX=gcc CXXFLAGS="-g -O3 $(PLAT_CXX_FLAGS) -felide-constructors -fno-exceptions -fno-rtti" \
	LDFLAGS="$(PLAT_LDFLAGS) -L$(ZIMBRA_HOME)/mysql-$(MYSQL_VERSION)/lib -L$(ZIMBRA_HOME)/mysql-$(MYSQL_VERSION)/lib/mysql -R$(ZIMBRA_HOME)/mysql-$(MYSQL_VERSION)/lib -R$(ZIMBRA_HOME)/mysql-$(MYSQL_VERSION)/lib/mysql -R$(ZIMBRA_HOME)/lib -R$(OPENSSL_LIB_DIR)" \
	./configure --enable-local-infile --enable-assembler --with-extra-charsets=complex --with-fast-mutexes --enable-community-features --enable-profiling --enable-thread-safe-client --with-readline --libdir=/opt/zimbra/mysql-$(MYSQL_VERSION)/lib --prefix=/opt/zimbra/mysql-$(MYSQL_VERSION) --with-ssl=/opt/zimbra/openssl-$(OPENSSL_VERSION); \
	LD_RUN_PATH=$(OPENSSL_LIB_DIR) $(MAKE) $(MAKEARGS); \
	$(MAKE) install)
	(cd $(ZIMBRA_HOME); rm -f mysql; ln -s mysql-$(MYSQL_VERSION) mysql)

tar:
	-mkdir -p $(shell dirname $(MYSQL_TGZ_TARGET))
	(cd $(ZIMBRA_HOME); tar czvf $(MYSQL_LIB_TGZ_TARGET) mysql-$(MYSQL_VERSION)/lib)
	(cd $(ZIMBRA_HOME); tar czvf $(MYSQL_TGZ_TARGET) mysql-$(MYSQL_VERSION)/bin mysql-$(MYSQL_VERSION)/include mysql-$(MYSQL_VERSION)/libexec mysql-$(MYSQL_VERSION)/mysql-test mysql-$(MYSQL_VERSION)/share mysql-$(MYSQL_VERSION)/sql-bench)

p4edit: $(MYSQL_TGZ_TARGET) 
	p4 add $(MYSQL_TGZ_TARGET) $(MYSQL_LIB_TGZ_TARGET)
	p4 edit $(MYSQL_TGZ_TARGET) $(MYSQL_LIB_TGZ_TARGET)

allclean: clean
	rm -rf $(ZIMBRA_HOME)/mysql-$(MYSQL_VERSION)
	rm -rf $(ZIMBRA_HOME)/mysql
	rm -rf $(ZIMBRA_HOME)/mysql-$(MYSQL_VERSION)
	rm -f $(MYSQL_TGZ_TARGET)
	rm -f $(MYSQL_LIB_TGZ_TARGET)
