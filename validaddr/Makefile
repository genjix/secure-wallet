CC = g++ -fPIC -Wall -ansi `pkg-config --cflags libbitcoin` -I/usr/include/python2.7 

default:
	$(CC) -c validaddr.cpp -o validaddr.o
	$(CC) -shared -Wl,-soname,_validaddr.so validaddr.o -lpython2.7 -lboost_python `pkg-config --libs libbitcoin` -lboost_thread -o _validaddr.so

