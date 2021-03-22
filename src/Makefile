#!/usr/bin/make -f

SRCDIR		:= pam_vyatta_passwd
MY_CFLAGS	:= -fPIC
MY_CFLAGS	+= -Wall -Wextra -Werror

CFLAGS += $(MY_CFLAGS)

LDFLAGS	+= -shared
SRC	:= $(SRCDIR)/pam_vyatta_passwd.c
OBJ	:= $(SRCDIR)/pam_vyatta_passwd.o

TARGET_LIB	:= $(SRCDIR)/pam_vyatta_passwd.so

all: $(TARGET_LIB)

$(TARGET_LIB): $(OBJ)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(OBJ) -o $(TARGET_LIB) $(LDFLAGS) $(LDLIBS)

%.o : %.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

install: $(TARGET_LIB)
	mkdir -p $(DESTDIR)/lib/x86_64-linux-gnu/security
	install -m644 $(TARGET_LIB) $(DESTDIR)/lib/x86_64-linux-gnu/security

clean:
	rm -f $(OBJ) $(TARGET_LIB)
