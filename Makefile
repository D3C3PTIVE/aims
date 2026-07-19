#
# AIMS Makefile
#

GO ?= go

# The build only needs the Go toolchain. The protoc/buf codegen tools are
# required by the `gen` target alone, so they are checked there rather than
# gating every invocation (which previously broke `make build`).
EXECUTABLES = $(GO)
K := $(foreach exec,$(EXECUTABLES),\
        $(if $(shell which $(exec)),some string,$(error "No $(exec) in PATH")))


#
# Targets
#
.ONESHELL:
	# Applies to all targets in the file. Runs all recipes
	# in a single instantiation of the shell (enables cd)

.PHONY: build
build:
	# Build the aims binary. GOWORK=off is required because this module is
	# commented out of the surrounding go.work (plain `go build` errors).
	GOWORK=off $(GO) build -o aims ./cmd/aims

.PHONY: deps
deps:
	# Install protoc plugins
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install github.com/favadi/protoc-go-inject-tag@latest

.PHONY: gen
gen:
	# cd proto

	# Generate the code for Protobuf definitions
	buf generate --template buf.gen-gorm.yaml
	buf generate --template buf.gen-grpc.yaml

	# Generate struct tags on Go code
	./maltego-tags.sh

