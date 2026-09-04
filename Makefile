CC = gcc
CFLAGS = -Iinclude -Wall
LDFLAGS = -lpcap
SRC = main.c src/utils/capture.c src/utils/error.c src/utils/protocols.c src/parsers/ethernet.c src/parsers/ip.c 
		
OBJ = $(SRC:.c=.o)
EXEC = main

# Default target
all: $(EXEC)

# Link object files to create executable
$(EXEC): $(OBJ)
	@$(CC) $(OBJ) -o $(EXEC) $(LDFLAGS)

# Compile .c files to .o object files
%.o: %.c
	@$(CC) $(CFLAGS) -c $< -o $@

# Clean up generated files
clean:
	@rm -f $(OBJ) $(EXEC)

# Run the program
run: $(EXEC)
	@./$(EXEC)

# Test the compilation
test: $(EXEC)
	@echo "Build successful, run with './main'."
