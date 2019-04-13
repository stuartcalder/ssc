CC = g++
CPPFLAGS = -std=c++17 -fPIC -O2 -march=native -pipe -fno-exceptions

base64.hpp.gch: base64.hpp
	$(CC) $(CPPFLAGS) -c base64.hpp

print.hpp.gch: print.hpp
	$(CC) $(CPPFLAGS) -c print.hpp

print.o: print.hpp
	$(CC) $(CPPFLAGS) -c print.cpp

all: base64.hpp.gch print.hpp.gch print.o

clean:
	$(RM) *.o *.gch
