
obj-m = pchar.o

modules:
	make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- -C /home/rucha/Desktop/BB/linux/ M=`pwd` modules

clean:
	make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- -C /home/rucha/Desktop/BB/linux/ M=`pwd` clean

.phony : clean
