CC = g++ -fPIC -Wall -ansi `pkg-config --cflags libbitcoin` -I/usr/include/python2.7 

default:
	$(CC) -c detwallet.cpp -o detwallet.o
	$(CC) -shared -Wl,-soname,_detwallet.so detwallet.o -lpython2.7 -lboost_python `pkg-config --libs libbitcoin` -lboost_thread -o _detwallet.so

