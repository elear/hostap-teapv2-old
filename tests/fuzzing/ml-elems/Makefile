ALL=ml-elems
include ../rules.include

CFLAGS += -DCONFIG_IEEE80211BE

OBJS += $(SRC)/common/ieee802_11_common.o
OBJS += $(SRC)/utils/common.o
OBJS += $(SRC)/utils/os_unix.o
OBJS += $(SRC)/utils/wpa_debug.o
OBJS += $(SRC)/utils/wpabuf.o

OBJS += ml-elems.o

_OBJS_VAR := OBJS
include ../../../src/objs.mk

_OBJS_VAR := LIBS
include ../../../src/objs.mk

ml-elems: $(OBJS) $(LIBS)
	$(LDO) $(LDFLAGS) -o $@ $^ $(LIBS) $(ELIBS)

clean: common-clean
	rm -f ml-elems *~ *.o *.d ../*~ ../*.o ../*.d
