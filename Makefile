CC = g++
CXXFLAGS = -std=c++17 -O3 -pipe -Wall -fno-exceptions
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
	$(CC) $(CXXFLAGS) $(LINKOPTS) $(OBJFLAGS) \
		interface/terminal.cc
operations.o:
	$(CC) $(CXXFLAGS) $(OBJFLAGS) \
		crypto/operations.cc
sspkdf.o: 
	$(CC) $(CXXFLAGS) $(OBJFLAGS) \
		crypto/sspkdf.cc
libssc.so: arg_mapping.o base64.o print.o files.o terminal.o operations.o sspkdf.o
	$(CC) $(LINKOPTS) $(CXXFLAGS) -shared -o $@ \
		arg_mapping.o base64.o print.o files.o terminal.o sspkdf.o operations.o \
		$(LINKFLAGS)
install: libssc.so
	install -s -m 0755 libssc.so $(LIBPATH)
	ldconfig
