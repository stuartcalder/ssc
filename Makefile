CC = g++
CXXFLAGS = -std=c++17 -c -O3 -pipe -Wall -fPIC
LIBPATH = /usr/lib

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
	$(CC) $(CXXFLAGS) interface/terminal.cc -lncurses
operations.o: files.o
	$(CC) $(CXXFLAGS) crypto/operations.cc
sspkdf.o:
	$(CC) $(CXXFLAGS) crypto/sspkdf.cc
libssc.so: arg_mapping.o base64.o print.o files.o terminal.o operations.o sspkdf.o
	$(CC) -fPIC -shared -o $@ \
		arg_mapping.o base64.o print.o files.o terminal.o operations.o sspkdf.o
install: libssc.so
	install -s -m 0755 libssc.so $(LIBPATH)
	ldconfig
