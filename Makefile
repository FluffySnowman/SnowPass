MAKEFLAGS += --no-print-directory

.SILENT:
.PHONY: all, build, watchexec, buildwatch, snowrun, snowpass, src, run, run-devel, target, build, rc, rs, r, b, bc, watch, w, clean, c, install, i, watchexec, we, help, lo

GO := go

CURRENT_DIR := $(shell pwd)

SRC_DIR := $(CURRENT_DIR)/src
OUTPUT_DIR := $(CURRENT_DIR)/_out
BIN_OUTPUT_FILENAME := snowpass

# shorthands
b: build
th: test-help
wb: watchexec-build
eb: entr-build
c: clean

build:
	@echo "Building Snowpass..."
	cd $(SRC_DIR); \
		echo "Entered directory |> " $$PWD; \
		echo "Building (trimpath)..."; \
		go build -ldflags "-s -w" -trimpath -o $(OUTPUT_DIR)/$(BIN_OUTPUT_FILENAME) main.go;
	@echo "Build should be done ig idk"

watchexec-build:
	@echo "Watching for changes & building shit (watchexec)..."
	watchexec -w "./src/" make build

entr-build:
	@echo "Watching for changes & building shit (entr)..."
	find . -wholename '**/*.go' | entr -c make build

test-help:
	cd $(OUTPUT_DIR) \
		&& ./$(BIN_OUTPUT_FILENAME) help | head -n 10

clean:
	rm -rdf $(OUTPUT_DIR)

