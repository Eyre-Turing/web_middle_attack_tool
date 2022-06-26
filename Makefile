TARGET = main
OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))
LDFLAG = -lpthread -lm -lssl -lcrypto

${TARGET}: ${OBJECTS}
	gcc -g $^ -o $@ ${LDFLAG}

%.o: %.c
	gcc -g -c $< -o $@

.PHONY: clean

clean:
	rm -f *.o
