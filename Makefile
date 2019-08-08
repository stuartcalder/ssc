CC = g++
CXXFLAGS = -std=c++17 -O3 -pipe -Wall -fno-exceptions -fvisibility=hidden
OBJFLAGS = -c -fPIC
LINKOPTS = -Wl,--no-undefined
LIBPATH = /usr/lib
LINKFLAGS = -lncurses -ltinfo

clean:
	$(RM) *.o *.so
arg_mapping.o:
	$(CC) $(CXXFLAGS) $(OBJFLAGS) \
		general/arg_mapping.cc
base64.o:
	$(CC) $(CXXFLAGS) $(OBJFLAGS) \
		general/base64.cc
print.o:
	$(CC) $(CXXFLAGS) $(OBJFLAGS) \
		general/print.cc
files.o:
	$(CC) $(CXXFLAGS) $(OBJFLAGS) \
		files/files.cc
terminal.o:
	$(CC) $(CXXFLAGS) $(OBJFLAGS) \
		interface/terminal.cc
operations.o:
	$(CC) $(CXXFLAGS) $(OBJFLAGS) \
		crypto/operations.cc
sspkdf.o: 
	$(CC) $(CXXFLAGS) $(OBJFLAGS) \
		crypto/sspkdf.cc
error_conditions.o:
	$(CC) $(CXXFLAGS) $(OBJFLAGS) \
		general/error_conditions.cc
threefish.o:
	$(CC) $(CXXFLAGS) $(OBJFLAGS) \
		crypto/threefish.cc
cbc.o: threefish.o
	$(CC) $(CXXFLAGS) $(OBJFLAGS) \
		crypto/cbc.cc
libssc.so: arg_mapping.o base64.o print.o files.o terminal.o operations.o sspkdf.o error_conditions.o cbc.o threefish.o
	$(CC) $(LINKOPTS) $(CXXFLAGS) -shared -o $@ \
		arg_mapping.o base64.o print.o \
		files.o terminal.o sspkdf.o \
		operations.o error_conditions.o \
		cbc.o threefish.o \
		$(LINKFLAGS)
install: libssc.so
	install -s -m 0755 libssc.so $(LIBPATH)
	ldconfig
