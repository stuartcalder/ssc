CC = g++
CXXFLAGS = -std=c++17 -c -O3 -pipe -Wall -fPIC
LIBPATH = /usr/local/include/ssc

clean:
	$(RM) *.o
arg_mapping.o:
	$(CC) $(CXXFLAGS) $(LIBPATH)/general/arg_mapping.cc
base64.o:
	$(CC) $(CXXFLAGS) $(LIBPATH)/general/base64.cc
print.o:
	$(CC) $(CXXFLAGS) $(LIBPATH)/general/print.cc
files.o:
	$(CC) $(CXXFLAGS) $(LIBPATH)/files/files.cc
interface.o:
	$(CC) $(CXXFLAGS) -lncurses $(LIBPATH)/interface/terminal.cc
operations.o: files.o
	$(CC) $(CXXFLAGS) $(LIBPATH)/crypto/operations.cc
sspkdf.o:
	$(CC) $(CXXFLAGS) $(LIBPATH)/crypto/sspkdf.cc
libssc.a:
	ar rcs $@ $^

all: arg_mapping.o base64.o print.o files.o interface.o operations.o sspkdf.o
	strip -s *.o
install:


	#install -s -m 0755 \
		$(LIBPATH)/crypto/*.o \
		$(LIBPATH)/files/*.o \
		$(LIBPATH)/general/*.o \
		$(LIBPATH)/interface/*.o \
		$(LIBPATH)/obj/
