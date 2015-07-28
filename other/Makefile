CFLAGS	= -g -O2 -Wall -fPIC

librandmalloc.so: randmalloc.o
	$(CC) $(CFLAGS) -shared -o $(@) $(>)

clean:
	rm -f librandmalloc.so *.o
