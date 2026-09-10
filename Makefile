CC = gcc # C compiler
CFLAGS = -Wall -Wextra -g # Warning flags and debug info
LDLIBS = -lpcap # External libraries needed for the final program

SRC = main.c sniff.c find_packet.c queue.c # Variable that links compiled files
OBJ = $(SRC:.c=.o) # Replaces .c with .o to create object files

sniffer: $(OBJ) # Need these files to...
	$(CC) $(CFLAGS) $(OBJ) -o sniffer $(LDLIBS) 
clean:
	rm -f $(OBJ) sniffer

# This is equivelent to the command line: 
# gcc -Wall -Wextra -g main.o sniff.o find_packet.o queue.o -o sniffer -lpcap

# Clean command removes all object files and the final executable

# https://chatgpt.com/share/6aa2ba5d-f598-83eb-bf3c-52401e18f342