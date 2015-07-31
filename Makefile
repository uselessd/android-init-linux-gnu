CC=g++
PROGS=init ueventd watchdogd
CFLAGS=-Wall -Wextra -Werror -Wno-unused-parameter \
		 -std=c++11
#LDLIBS=-lselinux
    
INIT_SRCS = \
       bootchart.cpp builtins.cpp devices.cpp init.cpp init_parser.cpp \
       log.cpp parser.cpp signal_handler.cpp util.cpp
UEVENTD_SRCS = ueventd_parser.cpp ueventd.cpp
WATCHDOGD_SRCS = watchdogd.cpp
UTIL_SRCS = klog.cpp stringprintf.cpp file.cpp strings.cpp android_reboot.cpp \
				partition_utils.cpp iosched_policy.cpp multiuser.cpp uevent.cpp

INIT_OBJS = $(SRCS:.c=.o)

INIT_MAIN = init
       
all: default

default: $(OBJS) 
	$(CC) $(CFLAGS) $(INIT_SRCS) $(UTIL_SRCS) -o $(INIT_MAIN) $(INIT_OBJS) $(LDLIBS)
