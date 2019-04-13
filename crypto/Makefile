CC = g++
CPPFLAGS = -std=c++17 -fPIC -O2 -march=native -pipe -fno-exceptions

aes.gch: aes.hpp
	$(CC) $(CPPFLAGS) -c aes.hpp

cbc.gch: cbc.hpp
	$(CC) $(CPPFLAGS) -c cbc.hpp
	
ctr.gch: ctr.hpp testing.hpp
	$(CC) $(CPPFLAGS) -c ctr.hpp testing.hpp

operations.gch: operations.hpp
	$(CC) $(CPPFLAGS) -c operations.hpp

testing.gch: testing.hpp
	$(CC) $(CPPFLAGS) -c testing.hpp

threefish.gch: threefish.hpp operations.hpp
	$(CC) $(CPPFLAGS) -c threefish.hpp operations.hpp

all: aes.gch cbc.gch ctr.gch operations.gch testing.gch threefish.gch

clean:
	$(RM) *.o *.gch
