#
# AIMS Makefile
#

EXECUTABLES = protoc protoc-gen-go protoc-go-inject-tag $(GO)
K := $(foreach exec,$(EXECUTABLES),\
        $(if $(shell which $(exec)),some string,$(error "No $(exec) in PATH")))


#
# Targets
#
.ONESHELL:
	# Applies to all targets in the file. Runs all recipes
	# in a single instantiation of the shell (enables cd)

.PHONY: deps
deps:
	# Install protoc plugins
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install github.com/favadi/protoc-go-inject-tag@latest

.PHONY: gen
gen:
	cd proto

	# Generate the code for Protobuf definitions
	buf generate --template buf.gen-gorm.yaml
	buf generate --template buf.gen-grpc.yaml

	# Generate struct tags on Go code
	./maltego-tags.sh

