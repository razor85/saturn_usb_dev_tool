ROOTDIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
CC=g++
CFLAGS=-fpermissive -std=c++17 -I$(ROOTDIR)/libusb-win32-1.2.6.0/include/ 
LDFLAGS=-L$(ROOTDIR)/libusb-win32-1.2.6.0/lib/ -lusb -lstdc++fs
OBJ = $(ROOTDIR)/crc.o $(ROOTDIR)/ftdi.o $(ROOTDIR)/main.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

%.o: %.cpp $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

usb_dev_tool: $(OBJ)
	$(CC) -o $(ROOTDIR)/$@ $^ $(LDFLAGS) 
	cp $(ROOTDIR)/$@ ./

clean:
	rm -rf $(ROOTDIR)/crc.o $(ROOTDIR)/ftdi.o $(ROOTDIR)/main.o $(ROOTDIR)/usb_dev_tool.exe
