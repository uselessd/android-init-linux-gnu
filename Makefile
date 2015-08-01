CC=g++
CFLAGS=-Wall -Wextra -Wno-unused-parameter -Wno-write-strings \
		 -Wno-missing-field-initializers \
		 -std=c++11
LDLIBS=-lpthread -lrt
    
INIT_SRCS = \
       bootchart.cpp builtins.cpp devices.cpp init.cpp init_parser.cpp \
       log.cpp parser.cpp signal_handler.cpp util.cpp
UEVENTD_SRCS = ueventd_parser.cpp ueventd.cpp
UTIL_SRCS = klog.cpp stringprintf.cpp file.cpp strings.cpp android_reboot.cpp \
				partition_utils.cpp iosched_policy.cpp multiuser.cpp uevent.cpp \
				fs_mgr.cpp fs_mgr_fstab.cpp strlcat.cpp strlcpy.cpp logwrap.cpp

INIT_OBJS = $(SRCS:.c=.o)

INIT_MAIN = init
       
all: default

default: $(OBJS) 
	$(CC) $(CFLAGS) $(INIT_SRCS) $(UTIL_SRCS) -o $(INIT_MAIN) $(INIT_OBJS) $(LDLIBS)

watchdog: 
	$(CC) $(CFLAGS) $(UTIL_SRCS) watchdogd.cpp -o watchdogd
