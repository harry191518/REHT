CC = gcc
CFLAGS = -O4
INC = -I include
INC_PATH = include

a.out: main.o rangeop.o readroute.o readrule.o REHT.o search.o
	${CC} main.o rangeop.o readroute.o readrule.o REHT.o search.o ${CFLAGS} ${INC} -o a.out
main.o: main.c ${INC_PATH}/readroute.h
	${CC} main.c ${CFLAGS} ${INC} -c
rangeop.o: rangeop.c ${INC_PATH}/rangeop.h
	${CC} rangeop.c ${CFLAGS} ${INC} -c
readroute.o: readroute.c ${INC_PATH}/readroute.h ${INC_PATH}/rangeop.h
	${CC} readroute.c ${CFLAGS} ${INC} -c
readrule.o: readrule.c ${INC_PATH}/readroute.h ${INC_PATH}/rangeop.h ${INC_PATH}/readrule.h
	${CC} readrule.c ${CFLAGS} ${INC} -c
REHT.o: REHT.c ${INC_PATH}/readroute.h ${INC_PATH}/rangeop.h ${INC_PATH}/readrule.h ${INC_PATH}/REHT.h
	${CC} REHT.c ${CFLAGS} ${INC} -c
search.o: search.c ${INC_PATH}/readroute.h ${INC_PATH}/rangeop.h ${INC_PATH}/readrule.h ${INC_PATH}/REHT.h ${INC_PATH}/search.h
	${CC} search.c ${CFLAGS} ${INC} -c

clean:
	@rm -rf *.o a.out
