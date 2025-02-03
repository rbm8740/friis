CC = gcc
CFLAGS = -Wall -shared -fPIC
LDFLAGS = -shared

PAYLOAD_DIR = config/payloads
PROJECTS = $(wildcard $(PAYLOAD_DIR)/*)

# Targets
all: generate build

generate:
    go generate

build: generate
    @for dir in $(PROJECTS); do \
        if [ -d $$dir ]; then \
            $(MAKE) -C $$dir; \
        fi; \
    done
    go build .

clean:
    @for dir in $(PROJECTS); do \
        if [ -d $$dir ]; then \
            $(MAKE) -C $$dir clean; \
        fi; \
    done
    del /f $(wildcard $(PAYLOAD_DIR)/**/*.o) $(wildcard $(PAYLOAD_DIR)/**/*.dll)

# Rules
$(PAYLOAD_DIR)/%/$(DLL): $(PAYLOAD_DIR)/%/$(OBJ)
	$(CC) $^ -o $@ $(LDFLAGS)

$(PAYLOAD_DIR)/%/$(OBJ): $(PAYLOAD_DIR)/%/myfile.c
	$(CC) $(CFLAGS) -o $@ -c $<

