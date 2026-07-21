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
	# Build the aims binary. All deps are published (no local replaces), so a
	# plain build works. On a machine with an ancestor go.work that excludes
	# this module, a local go.work (`use .`, git-ignored) shadows it.
	$(GO) build -o aims ./cmd/aims

.PHONY: install
install:
	# Install the aims binary into $(GOBIN) (or $(GOPATH)/bin).
	$(GO) install ./cmd/aims

.PHONY: deps
deps:
	# Install protoc plugins. protoc-gen-gorm is pinned to v1.1.5 on purpose:
	# v1.0.1 (the go.mod dependency, used only for its .proto option definitions)
	# emits GORM-v1 `jinzhu/gorm` tags, whereas the committed ORM code is GORM-v2
	# `gorm.io/gorm` — only v1.1.5 reproduces it.
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	go install github.com/infobloxopen/protoc-gen-gorm@v1.1.5
	go install moul.io/protoc-gen-gotemplate@latest
	go install github.com/favadi/protoc-go-inject-tag@latest

.PHONY: gen
gen:
	# cd proto

	# Generate the code for Protobuf definitions (buf; needs Buf Schema Registry
	# auth for the gorm options module — use `make pb` for an offline equivalent).
	buf generate --template buf.gen-gorm.yaml
	buf generate --template buf.gen-grpc.yaml

	# Generate struct tags on Go code
	./maltego-tags.sh

.PHONY: pb
pb:
	# Offline equivalent of `gen`: regenerate every *.pb.go / *.pb.gorm.go /
	# *.proto.gorm.go straight from the domain .proto files with protoc — no buf,
	# no Buf Schema Registry auth. It resolves the infobloxopen gorm proto options
	# from the module cache and spells out buf's managed-mode go_package as protoc
	# M-flags (buf injects those automatically; protoc needs them explicit).
	# Requires the plugins from `make deps`.
	GORM_PROTO="$$(go list -m -f '{{.Dir}}' github.com/infobloxopen/protoc-gen-gorm)/proto"
	PROTOS="$$(find . -name '*.proto' -not -path './proto/template/*' | sed 's#^\./##')"
	RPC="$$(find . -path '*/rpc/*.proto' | sed 's#^\./##')"
	# Managed-mode go_package mapping: first-party protos -> module path + dir; the
	# gorm options/types -> their infobloxopen packages.
	MF="Moptions/gorm.proto=github.com/infobloxopen/protoc-gen-gorm/options,Mtypes/types.proto=github.com/infobloxopen/protoc-gen-gorm/types"
	for p in $$PROTOS; do MF="$$MF,M$$p=github.com/d3c3ptive/aims/$$(dirname $$p)"; done

	# go (messages) + gorm (ORM twins) + gotemplate (DB helper *.proto.gorm.go).
	protoc -I. -I"$$GORM_PROTO" -I/usr/local/include \
		--go_out=. --go_opt=paths=source_relative,$$MF \
		--gorm_out=. --gorm_opt=paths=source_relative,$$MF \
		--gotemplate_out=template_dir=./proto/template,all=true,single-package-mode=true:. \
		$$PROTOS

	# gRPC services (the */rpc/ protos only).
	protoc -I. -I"$$GORM_PROTO" -I/usr/local/include \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative,$$MF \
		$$RPC

	# Inject the // @gotags struct tags (xml/display/readonly/strict).
	./maltego-tags.sh

