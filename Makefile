CC = g++
CXXFLAGS = -c -O3 -fpipe -Wall -fPIC
LIBPATH = /usr/local/include/ssc

clean:
	$(RM) $(LIBPAH)/general/*.o
	$(RM) $(LIBPAH)/files/*.o
	$(RM) $(LIBPAH)/interface/*.o
	$(RM) $(LIBPAH)/crypto/*.o
general:
	$(CC) $(CXXFLAGS) $(LIBPATH)/general/arg_mapping.cc
	$(CC) $(CXXFLAGS) $(LIBPATH)/general/base64.cc
	$(CC) $(CXXFLAGS) $(LIBPATH)/general/print.cc
files:
	$(CC) $(CXXFLAGS) $(LIBPATH)/files/files.cc
interface:
	$(CC) $(CXXFLAGS) -lncurses $(LIBPATH)/interface/terminal.cc
crypto: files
	$(CC) $(CXXFLAGS) $(LIBPATH)/crypto/operations.cc
	$(CC) $(CXXFLAGS) $(LIBPATH)/crypto/sspkdf.cc
all: general files interface crypto
	
install:
	install -s -m 0755 \
		$(LIBPATH)/crypto/*.o \
		$(LIBPATH)/files/*.o \
		$(LIBPATH)/general/*.o \
		$(LIBPATH)/interface/*.o \
		$(LIBPATH)/obj/
