CC=gcc
CFLAGS=-g
TARGET:test.exe
LIBS=-lpthread -L ./CommandParser -lcli 
OBJS=glueThread/glthread.o	\
		graph.o				\
		topologies.o		\
		testapp.o			\
		net.o				\
		nwcli.o				\
		comm.o

test.exe:${OBJS} CommandParser/libcli.a
	${CC} ${CFLAGS} ${OBJS} -o test.exe ${LIBS}

testapp.o:testapp.c
	${CC} ${CFLAGS} -c testapp.c -I . -o testapp.o

glueThread/glthread.o:glueThread/glthread.c
	${CC} ${CFLAGS} -c glueThread/glthread.c -I glueThread -o glueThread/glthread.o 

graph.o:graph.c
	${CC} ${CFLAGS} -c graph.c -I . -o graph.o

topologies.o:topologies.c
	${CC} ${CFLAGS} -c topologies.c -I . -o topologies.o

net.o:net.c
	${CC} ${CFLAGS} -c net.c -I . -o net.o

nwcli.o:nwcli.c
	${CC} ${CFLAGS} -c nwcli.c -I . -o nwcli.o

comm.o:comm.c
	${CC} ${CFLAGS} -c comm.c -I . -o comm.o

CommandParser/libcli.a:
	(cd CommandParser; make)

clean:
	rm *.o
	rm glueThread/glthread.o
	rm *.exe
	(cd CommandParser; make clean)

all:
	make
	(cd CommandParser; make)
