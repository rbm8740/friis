CC = gcc
CFLAGS = -Wall -shared -fPIC
LDFLAGS = -shared

PAYLOAD_DIR = config/payloads
PROJECTS = $(wildcard $(PAYLOAD_DIR)/*)

# Targets
all: build generate

generate:
	go generate ./config

.PHONY: generate

build:
	@for dir in $(PROJECTS); do \
		if [ -d $$dir ]; then \
			payload_name=$$(basename $$dir); \
			echo "Building $$payload_name..."; \
			go build -o $$dir/$$payload_name.dll -buildmode=c-shared $$dir/$$payload_name.go; \
		fi; \
	done

clean:
	@for dir in $(PROJECTS); do \
		if [ -d $$dir ]; then \
			if [ -f $$dir/Makefile ] && grep -q 'clean' $$dir/Makefile; then \
				$(MAKE) -C $$dir clean; \
			fi; \
		fi; \
	done
	rm -f $(wildcard $(PAYLOAD_DIR)/**/*.o) $(wildcard $(PAYLOAD_DIR)/**/*.dll)
