.PHONY: build run clean tidy migrations migrations-init execute test

APP_NAME ?= sso
BUILD_DIR ?= build
OUTPUT := $(BUILD_DIR)/$(APP_NAME)
MAIN_FILE := ./cmd/sso
CONFIG_FILE := ./config/config_local_tests.yaml

MIGRATOR_NAME ?= migrator
MIGRATOR_MAIN_FILE := ./cmd/migrator
STORAGE_PATH := ./storage/sso.db
MIGRATIONS_PATH := ./migrations

TEST_PKG := sso/tests
TEST_WORKDIR := /home/myr/Documents/sso/tests
TEST_CONFIG_PATH := /home/myr/Documents/sso/tests/../config/config_local_tests.yaml

build:
	mkdir -p $(BUILD_DIR)
	go build -ldflags="-s -w" -o $(OUTPUT) $(MAIN_FILE)

run: build
	$(OUTPUT) --config=$(CONFIG_FILE)

migrations-init:
	go run $(MIGRATOR_MAIN_FILE) --storage-path=$(STORAGE_PATH) --migrations-path=$(MIGRATIONS_PATH)

clean:
	rm -rf $(BUILD_DIR)

tidy:
	go mod tidy

execute: build
	./$(OUTPUT) --config=$(CONFIG_FILE)

test:
	CONFIG_PATH=$(TEST_CONFIG_PATH) \
	WORKDIR=$(TEST_WORKDIR) \
	go test -v $(TEST_PKG)
