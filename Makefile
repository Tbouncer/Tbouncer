# Makefile for compiling all .c files in subdirectories

CC = gcc
CFLAGS = -Wall -g

SRCS := $(shell find . -type f -name '*.c')

OBJS := $(SRCS:.c=.o)

TARGET = my_program

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean

