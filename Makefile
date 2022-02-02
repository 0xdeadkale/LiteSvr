#Cflags used for compiling.
CFLAGS += -g -I. -Wall -Werror -std=c99
#LDFLAGS 
LDFLAGS += -L.
#LDLIBS libraries to link to the project.
LDLIBS += -lpthread


LIB1 = src/server/net_lib.c
LIB2 = src/server/file_lib.c
LIB3 = src/server/hash_table.c
LIB4 = src/server/cmd_lib.c

BIN = src/server/server.c build/cmd_lib.a build/net_lib.a build/file_lib.a build/hash_table.a 

PORT = 53673

all: setup lib server

#Creates all needed directories.
setup:
	@mkdir -p bin build doc include src test test/client test/server
	sudo apt install gcc valgrind -y

#lib will generate the librarys in the build folder.
lib:
	@gcc $(CFLAGS) -fpic -shared -o build/net_lib.a $(LIB1)
	@gcc $(CFLAGS) -fpic -shared -o build/file_lib.a $(LIB2)
	@gcc $(CFLAGS) -fpic -shared -o build/hash_table.a $(LIB3)
	@gcc $(CFLAGS) -fpic -shared -o build/cmd_lib.a $(LIB4)

server:
	gcc $(CFLAGS) $(LDFLAGS) -o bin/capstone $(BIN) $(LDLIBS) -lm

#server will generate ftp server binary in bin. 
valgrind: lib
	@gcc $(CFLAGS) $(LDFLAGS) -o bin/capstone $(BIN) $(LDLIBS) -lm
	valgrind --leak-check=full bin/capstone -p $(PORT) -d / -t 50

clean:
	@$(RM) -rf bin/* build/*

clean_all:
	@$(RM) -rf bin/* build/* src/client/debug.out src/client/__pycache__
