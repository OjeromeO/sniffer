CC = gcc
LFLAGS = -g -W -Wall -Wmissing-declarations -Wmissing-prototypes -Wredundant-decls -Wshadow -Wbad-function-cast -Wcast-qual -Werror
CFLAGS = -g -W -Wall -Wmissing-declarations -Wmissing-prototypes -Wredundant-decls -Wshadow -Wbad-function-cast -Wcast-qual -Werror
SRC = main.c callback.c display.c
OBJ = $(SRC:.c=.o)
EXEC = sniffer



all : $(EXEC)

sniffer : $(OBJ)
	$(CC) $(LFLAGS) -o $@ $^ -lpcap
main.o : main.c callback.h
	$(CC) -c $(CFLAGS) $<
callback.o : callback.c callback.h display.h bootp.h dns.h
	$(CC) -c $(CFLAGS) $<
display.o : display.c display.h bootp.h dns.h
	$(CC) -c $(CFLAGS) $<

clean :
	@ rm -f $(OBJ)
mrproper : clean
	@ rm -f $(EXEC)

