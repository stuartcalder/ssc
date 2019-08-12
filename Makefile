CC = g++
CXXFLAGS = -std=c++17 -O3 -pipe -Wall -fno-exceptions -fvisibility=hidden -march=native -flto
OBJFLAGS = -c -fPIC
LINKOPTS = -Wl,--no-undefined
LIBPATH = /usr/lib64
LINKFLAGS = -lncurses -ltinfo

clean:
	$(RM) *.o *.so
arg_mapping.o: 	general/arg_mapping.cc general/arg_mapping.hh
	$(CC) $(CXXFLAGS) $(OBJFLAGS) \
		general/arg_mapping.cc
base64.o:      	general/base64.cc general/base64.hh
	$(CC) $(CXXFLAGS) $(OBJFLAGS) \
		general/base64.cc
print.o:		general/print.cc general/print.hh
	$(CC) $(CXXFLAGS) $(OBJFLAGS) \
		general/print.cc
files.o:		files/files.cc files/files.hh
	$(CC) $(CXXFLAGS) $(OBJFLAGS) \
		files/files.cc
terminal.o:		interface/terminal.cc interface/terminal.hh
	$(CC) $(CXXFLAGS) $(OBJFLAGS) \
		interface/terminal.cc
operations.o:	crypto/operations.cc crypto/operations.hh \
	            general/integers.hh general/error_conditions.hh
	$(CC) $(CXXFLAGS) $(OBJFLAGS) \
		crypto/operations.cc
sspkdf.o: 		crypto/sspkdf.cc crypto/sspkdf.hh crypto/skein.hh \
				crypto/operations.hh crypto/operations.cc general/integers.hh
	$(CC) $(CXXFLAGS) $(OBJFLAGS) \
		crypto/sspkdf.cc
error_conditions.o: general/error_conditions.cc general/error_conditions.hh
	$(CC) $(CXXFLAGS) $(OBJFLAGS) \
		general/error_conditions.cc
libssc.so: 	arg_mapping.o base64.o print.o \
			files.o terminal.o operations.o \
			sspkdf.o error_conditions.o
	$(CC) $(LINKOPTS) $(CXXFLAGS) -shared -o $@ \
		arg_mapping.o base64.o print.o \
		files.o terminal.o sspkdf.o \
		operations.o error_conditions.o \
		$(LINKFLAGS)
install: libssc.so
	install -s -m 0755 libssc.so $(LIBPATH)
	ldconfig
