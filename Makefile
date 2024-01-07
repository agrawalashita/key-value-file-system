#
# Tony Givargis
# Copyright (C), 2023
# University of California, Irvine
#
# CS 238P - Operating Systems
# Makefile
#

CC     = gcc
CFLAGS = -ansi -pedantic -Wall -Wextra -Wfatal-errors -fpic -D_FILE_OFFSET_BITS=64
LDLIBS = -lpthread
DEST   = cs238
SRCS  := $(wildcard *.c)
OBJS  := $(SRCS:.c=.o)

all: $(OBJS)
	@echo "[LN]" $(DEST)
	@$(CC) -g -o $(DEST) $(OBJS) $(LDLIBS) -D_FILE_OFFSET_BITS=64

%.o: %.c
	@echo "[CC]" $<
	@$(CC) -g $(CFLAGS) -c $<
	@$(CC) -g $(CFLAGS) -MM $< > $*.d

clean:
	@rm -f $(DEST) *.so *.o *.d *~ *#

-include $(OBJS:.o=.d)
