
# current version
VERSION=0.1.0

# Protocol buffers args
PB_PROTO   := $(wildcard discover/protobuf/*.proto)
PB_GO      := $(patsubst %.proto,%.pb.go,$(PB_PROTO))
PB_GO_TEST := $(patsubst %.proto,%pb_test.go,$(PB_PROTO))

PROTOC_ARGS = --proto_path=${GOPATH}/src \
			  --proto_path=${GOPATH}/src/code.google.com/p/gogoprotobuf/protobuf \
			  --proto_path=.

#################################################################
# main

all: simple_dis

simple_dis: $(PB_GO) FORCE
	@echo "Building discover"
	go build github.com/inercia/discover/cmd/simple_dis

test: simple_dis
	go test ./...

clean:
	@echo "Cleaning discover"
	@go clean
	rm -f simple_dis $(PB_GO) $(PB_GO_TEST) *~ */*~

${GOPATH}/bin/protoc-gen-gogo:
	@echo "Installing $$GOPATH/bin/protoc-gen-gogo"
	go get code.google.com/p/gogoprotobuf/proto
	go get code.google.com/p/gogoprotobuf/protoc-gen-gogo
	go get code.google.com/p/gogoprotobuf/gogoproto

%.pb.go %pb_test.go : %.proto  ${GOPATH}/bin/protoc-gen-gogo
	@echo "Generating code for Protocol Buffers definition: $<"
	PATH=${GOPATH}/bin:${PATH} protoc $(PROTOC_ARGS) --gogo_out=. $<

#################################################################
# deps

get: deps
deps:
	@echo "Getting all dependencies..."
	go get -d ./...

distclean-deps:
	for PKG in $$GOPATH/src/*/* ; do \
		if [ -d $$PKG ] ; then \
			[ `basename $$PKG` != "inercia" ] && rm -rf $$PKG ; \
		fi ; \
	done
	rm -rf $$GOPATH/pkg

FORCE:
