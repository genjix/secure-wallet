CC = g++ -fPIC -Wall -ansi `pkg-config --cflags libbitcoin` -I/usr/include/python2.7 

default:
	$(CC) -c genaddr.cpp -o genaddr.o
	$(CC) -shared -Wl,-soname,_genaddr.so genaddr.o -lpython2.7 -lboost_python `pkg-config --libs libbitcoin` -lboost_thread -o _genaddr.so

