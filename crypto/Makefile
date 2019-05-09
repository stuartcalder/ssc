CC = g++
CPPFLAGS = -std=c++17 -fPIC -O2 -march=native -pipe -fno-exceptions
INSTALL_DIR = '/home/stuart/src/library/'

aes.gch: aes.hh
	$(CC) $(CPPFLAGS) -c aes.hh

cbc.gch: cbc.hh
	$(CC) $(CPPFLAGS) -c cbc.hh
	
ctr.gch: ctr.hh testing.hh
	$(CC) $(CPPFLAGS) -c ctr.hh testing.hh

operations.gch: operations.hh
	$(CC) $(CPPFLAGS) -c operations.hh

testing.gch: testing.hh
	$(CC) $(CPPFLAGS) -c testing.hh

threefish.gch: threefish.hh operations.hh
	$(CC) $(CPPFLAGS) -c threefish.hh operations.hh

all: aes.gch cbc.gch ctr.gch operations.gch testing.gch threefish.gch

clean:
	$(RM) *.o *.gch

install:
	cp *.o $(INSTALL_DIR)
