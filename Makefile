CC = gcc
CFLAGS = -Wall -Wextra -O2 -Iinclude
LIBS = -lpcap
TARGET = miniids
OBJ_DIR = obj
SRC = src/main.c src/packet.c src/rules.c src/detect.c src/utils.c
OBJ = $(patsubst src/%.c,$(OBJ_DIR)/%.o,$(SRC))

all: $(OBJ_DIR) $(TARGET)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

$(OBJ_DIR)/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR) $(TARGET) logs/alerts.log

install:
	sudo cp $(TARGET) /usr/local/bin/

run: $(TARGET)
	sudo ./$(TARGET)

.PHONY: all clean install run