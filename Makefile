# for Solaris
EXTRALIBS=-lnsl -lsocket
AFSDIR=/usr/local/src/sunx86_58/dest
CC=gcc

all:
	$(CC) -c pam_aklog.c -o pam_aklog.o -I$(AFSDIR)/include
	$(CC) -G pam_aklog.o -o pam_aklog.so -L$(AFSDIR)/lib/afs -lsys -L$(AFSDIR)/lib -lrx -llwp $(EXTRALIBS) -lpam

install:
	strip pam_aklog.so
	cp pam_aklog.so /lib/security/pam_aklog.so.1
	ln -s pam_aklog.so.1 /lib/security/pam_aklog.so

clean:
	rm *.o *.so
