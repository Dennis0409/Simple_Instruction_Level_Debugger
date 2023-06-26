
CC	= gcc
CXX	= g++
CFLAGS	= -Wall -g
LDFLAGS =

ASM64	= yasm -f elf64 -DYASM -D__x86_64__
#ASM64	= nasm -f elf64 -DNASM -D__x86_64__






%.o: %.cpp
	$(CXX) -c $(CFLAGS) $<


sdb: sdb.o ptools.o
	$(CXX) -o $@ $^ $(LDFLAGS) -lcapstone


clean:
	rm -f *.o *~ $(PROGS)
	make -C tests clean

