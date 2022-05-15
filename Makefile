TARGET = main
OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))
LDFLAG = -lpthread -lm

${TARGET}: ${OBJECTS}
	gcc $^ -o $@ ${LDFLAG}

%.o: %.c
	gcc -c $< -o $@

.PHONY: clean

clean:
	rm -f *.o
