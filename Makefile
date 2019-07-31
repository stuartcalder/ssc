CC = g++
CXXFLAGS = -std=c++17 -c -O3 -pipe -Wall -fPIC -fno-exceptions
LINKOPTS = -Wl,--no-undefined
LIBPATH = /usr/lib
LINKFLAGS = -lncurses -ltinfo

clean:
	$(RM) *.o *.so
arg_mapping.o:
	$(CC) $(CXXFLAGS) general/arg_mapping.cc
base64.o:
	$(CC) $(CXXFLAGS) general/base64.cc
print.o:
	$(CC) $(CXXFLAGS) general/print.cc
files.o:
	$(CC) $(CXXFLAGS) files/files.cc
terminal.o:
	$(CC) $(CXXFLAGS) $(LINKOPTS) interface/terminal.cc
operations.o: files.o
	$(CC) $(CXXFLAGS) crypto/operations.cc
sspkdf.o: operations.o
	$(CC) $(CXXFLAGS) crypto/sspkdf.cc
libssc.so: arg_mapping.o base64.o print.o files.o terminal.o operations.o sspkdf.o
	$(CC) $(LINKOPTS) -std=c++17 -pipe -fPIC -O3 -fno-exceptions -shared -o $@ \
		arg_mapping.o base64.o print.o files.o terminal.o sspkdf.o operations.o $(LINKFLAGS)
install: libssc.so
	install -m 0755 libssc.so $(LIBPATH)
	ldconfig
