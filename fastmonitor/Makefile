CC = g++ -fPIC -Wall -ansi `pkg-config --cflags libbitcoin` -I/usr/include/python2.7 

default:
	$(CC) -c monitor.cpp -o monitor.o
	$(CC) -shared -Wl,-soname,fastmonitor.so monitor.o -lpython2.7 -lboost_python `pkg-config --libs libbitcoin` -lboost_thread -o fastmonitor.so

