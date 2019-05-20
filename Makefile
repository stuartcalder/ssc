CC = g++
CXXFLAGS = -std=c++17 -c -O3 -pipe -Wall -fPIC
LIBPATH = /usr/local/lib

clean:
	$(RM) *.o
arg_mapping.o:
	$(CC) $(CXXFLAGS) general/arg_mapping.cc
base64.o:
	$(CC) $(CXXFLAGS) general/base64.cc
print.o:
	$(CC) $(CXXFLAGS) general/print.cc
files.o:
	$(CC) $(CXXFLAGS) files/files.cc
terminal.o:
	$(CC) $(CXXFLAGS) -lncurses interface/terminal.cc
operations.o: files.o
	$(CC) $(CXXFLAGS) crypto/operations.cc
sspkdf.o:
	$(CC) $(CXXFLAGS) crypto/sspkdf.cc
#libssc.a: arg_mapping.o base64.o print.o files.o terminal.o operations.o sspkdf.o \
#	strip -s *.o \
#	ar rcs $@ $^
libssc.so: arg_mapping.o base64.o print.o files.o terminal.o operations.o sspkdf.o
	$(CC) -fPIC -shared -o $@ \
		arg_mapping.o base64.o print.o files.o terminal.o operations.o sspkdf.o
all: libssc.so
install: all
	install -m 0755 libssc.so $(LIBPATH)

	#install -s -m 0755 \
		#$(LIBPATH)/crypto/*.o \
		#$(LIBPATH)/files/*.o \
		#$(LIBPATH)/general/*.o \
		#$(LIBPATH)/interface/*.o \
		#$(LIBPATH)/obj/
