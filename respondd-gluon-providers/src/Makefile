all: respondd.so

CFLAGS += -Wall

SOURCES = respondd.c respondd-statistics.c respondd-nodeinfo.c respondd-common.c

respondd.so: $(SOURCES) respondd-statistics.h respondd-nodeinfo.h respondd-common.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -shared -fPIC -fvisibility=hidden -D_GNU_SOURCE -o $@ $(SOURCES) $(LDLIBS) -luci -liwinfo
