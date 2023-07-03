// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v3.18.1
// source: rpc/hosts/hosts.proto

package hosts

import (
	host "github.com/maxlandon/aims/proto/host"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type CreateHostRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Hosts []*host.Host `protobuf:"bytes,1,rep,name=Hosts,proto3" json:"Hosts,omitempty"`
}

func (x *CreateHostRequest) Reset() {
	*x = CreateHostRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpc_hosts_hosts_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateHostRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateHostRequest) ProtoMessage() {}

func (x *CreateHostRequest) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_hosts_hosts_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateHostRequest.ProtoReflect.Descriptor instead.
func (*CreateHostRequest) Descriptor() ([]byte, []int) {
	return file_rpc_hosts_hosts_proto_rawDescGZIP(), []int{0}
}

func (x *CreateHostRequest) GetHosts() []*host.Host {
	if x != nil {
		return x.Hosts
	}
	return nil
}

type CreateHostResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Hosts []*host.Host `protobuf:"bytes,1,rep,name=Hosts,proto3" json:"Hosts,omitempty"`
}

func (x *CreateHostResponse) Reset() {
	*x = CreateHostResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpc_hosts_hosts_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateHostResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateHostResponse) ProtoMessage() {}

func (x *CreateHostResponse) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_hosts_hosts_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateHostResponse.ProtoReflect.Descriptor instead.
func (*CreateHostResponse) Descriptor() ([]byte, []int) {
	return file_rpc_hosts_hosts_proto_rawDescGZIP(), []int{1}
}

func (x *CreateHostResponse) GetHosts() []*host.Host {
	if x != nil {
		return x.Hosts
	}
	return nil
}

type ReadHostRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Host *host.Host `protobuf:"bytes,1,opt,name=Host,proto3" json:"Host,omitempty"`
}

func (x *ReadHostRequest) Reset() {
	*x = ReadHostRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpc_hosts_hosts_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ReadHostRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReadHostRequest) ProtoMessage() {}

func (x *ReadHostRequest) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_hosts_hosts_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReadHostRequest.ProtoReflect.Descriptor instead.
func (*ReadHostRequest) Descriptor() ([]byte, []int) {
	return file_rpc_hosts_hosts_proto_rawDescGZIP(), []int{2}
}

func (x *ReadHostRequest) GetHost() *host.Host {
	if x != nil {
		return x.Host
	}
	return nil
}

type ReadHostResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Hosts []*host.Host `protobuf:"bytes,1,rep,name=Hosts,proto3" json:"Hosts,omitempty"`
}

func (x *ReadHostResponse) Reset() {
	*x = ReadHostResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpc_hosts_hosts_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ReadHostResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReadHostResponse) ProtoMessage() {}

func (x *ReadHostResponse) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_hosts_hosts_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReadHostResponse.ProtoReflect.Descriptor instead.
func (*ReadHostResponse) Descriptor() ([]byte, []int) {
	return file_rpc_hosts_hosts_proto_rawDescGZIP(), []int{3}
}

func (x *ReadHostResponse) GetHosts() []*host.Host {
	if x != nil {
		return x.Hosts
	}
	return nil
}

type ReadHostManyRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Host *host.Host `protobuf:"bytes,1,opt,name=Host,proto3" json:"Host,omitempty"`
}

func (x *ReadHostManyRequest) Reset() {
	*x = ReadHostManyRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpc_hosts_hosts_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ReadHostManyRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReadHostManyRequest) ProtoMessage() {}

func (x *ReadHostManyRequest) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_hosts_hosts_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReadHostManyRequest.ProtoReflect.Descriptor instead.
func (*ReadHostManyRequest) Descriptor() ([]byte, []int) {
	return file_rpc_hosts_hosts_proto_rawDescGZIP(), []int{4}
}

func (x *ReadHostManyRequest) GetHost() *host.Host {
	if x != nil {
		return x.Host
	}
	return nil
}

type ReadHostManyResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Hosts []*host.Host `protobuf:"bytes,1,rep,name=Hosts,proto3" json:"Hosts,omitempty"`
}

func (x *ReadHostManyResponse) Reset() {
	*x = ReadHostManyResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpc_hosts_hosts_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ReadHostManyResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReadHostManyResponse) ProtoMessage() {}

func (x *ReadHostManyResponse) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_hosts_hosts_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReadHostManyResponse.ProtoReflect.Descriptor instead.
func (*ReadHostManyResponse) Descriptor() ([]byte, []int) {
	return file_rpc_hosts_hosts_proto_rawDescGZIP(), []int{5}
}

func (x *ReadHostManyResponse) GetHosts() []*host.Host {
	if x != nil {
		return x.Hosts
	}
	return nil
}

type UpsertHostRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Hosts []*host.Host `protobuf:"bytes,1,rep,name=Hosts,proto3" json:"Hosts,omitempty"`
}

func (x *UpsertHostRequest) Reset() {
	*x = UpsertHostRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpc_hosts_hosts_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpsertHostRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpsertHostRequest) ProtoMessage() {}

func (x *UpsertHostRequest) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_hosts_hosts_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpsertHostRequest.ProtoReflect.Descriptor instead.
func (*UpsertHostRequest) Descriptor() ([]byte, []int) {
	return file_rpc_hosts_hosts_proto_rawDescGZIP(), []int{6}
}

func (x *UpsertHostRequest) GetHosts() []*host.Host {
	if x != nil {
		return x.Hosts
	}
	return nil
}

type UpsertHostResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Hosts []*host.Host `protobuf:"bytes,1,rep,name=Hosts,proto3" json:"Hosts,omitempty"`
}

func (x *UpsertHostResponse) Reset() {
	*x = UpsertHostResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpc_hosts_hosts_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpsertHostResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpsertHostResponse) ProtoMessage() {}

func (x *UpsertHostResponse) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_hosts_hosts_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpsertHostResponse.ProtoReflect.Descriptor instead.
func (*UpsertHostResponse) Descriptor() ([]byte, []int) {
	return file_rpc_hosts_hosts_proto_rawDescGZIP(), []int{7}
}

func (x *UpsertHostResponse) GetHosts() []*host.Host {
	if x != nil {
		return x.Hosts
	}
	return nil
}

type DeleteHostRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Hosts []*host.Host `protobuf:"bytes,1,rep,name=Hosts,proto3" json:"Hosts,omitempty"`
}

func (x *DeleteHostRequest) Reset() {
	*x = DeleteHostRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpc_hosts_hosts_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteHostRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteHostRequest) ProtoMessage() {}

func (x *DeleteHostRequest) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_hosts_hosts_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteHostRequest.ProtoReflect.Descriptor instead.
func (*DeleteHostRequest) Descriptor() ([]byte, []int) {
	return file_rpc_hosts_hosts_proto_rawDescGZIP(), []int{8}
}

func (x *DeleteHostRequest) GetHosts() []*host.Host {
	if x != nil {
		return x.Hosts
	}
	return nil
}

type DeleteHostResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Hosts []*host.Host `protobuf:"bytes,1,rep,name=Hosts,proto3" json:"Hosts,omitempty"`
}

func (x *DeleteHostResponse) Reset() {
	*x = DeleteHostResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpc_hosts_hosts_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteHostResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteHostResponse) ProtoMessage() {}

func (x *DeleteHostResponse) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_hosts_hosts_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteHostResponse.ProtoReflect.Descriptor instead.
func (*DeleteHostResponse) Descriptor() ([]byte, []int) {
	return file_rpc_hosts_hosts_proto_rawDescGZIP(), []int{9}
}

func (x *DeleteHostResponse) GetHosts() []*host.Host {
	if x != nil {
		return x.Hosts
	}
	return nil
}

var File_rpc_hosts_hosts_proto protoreflect.FileDescriptor

var file_rpc_hosts_hosts_proto_rawDesc = []byte{
	0x0a, 0x15, 0x72, 0x70, 0x63, 0x2f, 0x68, 0x6f, 0x73, 0x74, 0x73, 0x2f, 0x68, 0x6f, 0x73, 0x74,
	0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x05, 0x68, 0x6f, 0x73, 0x74, 0x73, 0x1a, 0x0f,
	0x68, 0x6f, 0x73, 0x74, 0x2f, 0x68, 0x6f, 0x73, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0x35, 0x0a, 0x11, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x48, 0x6f, 0x73, 0x74, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x20, 0x0a, 0x05, 0x48, 0x6f, 0x73, 0x74, 0x73, 0x18, 0x01, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x0a, 0x2e, 0x68, 0x6f, 0x73, 0x74, 0x2e, 0x48, 0x6f, 0x73, 0x74, 0x52,
	0x05, 0x48, 0x6f, 0x73, 0x74, 0x73, 0x22, 0x36, 0x0a, 0x12, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65,
	0x48, 0x6f, 0x73, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x20, 0x0a, 0x05,
	0x48, 0x6f, 0x73, 0x74, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0a, 0x2e, 0x68, 0x6f,
	0x73, 0x74, 0x2e, 0x48, 0x6f, 0x73, 0x74, 0x52, 0x05, 0x48, 0x6f, 0x73, 0x74, 0x73, 0x22, 0x31,
	0x0a, 0x0f, 0x52, 0x65, 0x61, 0x64, 0x48, 0x6f, 0x73, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x12, 0x1e, 0x0a, 0x04, 0x48, 0x6f, 0x73, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x0a, 0x2e, 0x68, 0x6f, 0x73, 0x74, 0x2e, 0x48, 0x6f, 0x73, 0x74, 0x52, 0x04, 0x48, 0x6f, 0x73,
	0x74, 0x22, 0x34, 0x0a, 0x10, 0x52, 0x65, 0x61, 0x64, 0x48, 0x6f, 0x73, 0x74, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x20, 0x0a, 0x05, 0x48, 0x6f, 0x73, 0x74, 0x73, 0x18, 0x01,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x0a, 0x2e, 0x68, 0x6f, 0x73, 0x74, 0x2e, 0x48, 0x6f, 0x73, 0x74,
	0x52, 0x05, 0x48, 0x6f, 0x73, 0x74, 0x73, 0x22, 0x35, 0x0a, 0x13, 0x52, 0x65, 0x61, 0x64, 0x48,
	0x6f, 0x73, 0x74, 0x4d, 0x61, 0x6e, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1e,
	0x0a, 0x04, 0x48, 0x6f, 0x73, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0a, 0x2e, 0x68,
	0x6f, 0x73, 0x74, 0x2e, 0x48, 0x6f, 0x73, 0x74, 0x52, 0x04, 0x48, 0x6f, 0x73, 0x74, 0x22, 0x38,
	0x0a, 0x14, 0x52, 0x65, 0x61, 0x64, 0x48, 0x6f, 0x73, 0x74, 0x4d, 0x61, 0x6e, 0x79, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x20, 0x0a, 0x05, 0x48, 0x6f, 0x73, 0x74, 0x73, 0x18,
	0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0a, 0x2e, 0x68, 0x6f, 0x73, 0x74, 0x2e, 0x48, 0x6f, 0x73,
	0x74, 0x52, 0x05, 0x48, 0x6f, 0x73, 0x74, 0x73, 0x22, 0x35, 0x0a, 0x11, 0x55, 0x70, 0x73, 0x65,
	0x72, 0x74, 0x48, 0x6f, 0x73, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x20, 0x0a,
	0x05, 0x48, 0x6f, 0x73, 0x74, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0a, 0x2e, 0x68,
	0x6f, 0x73, 0x74, 0x2e, 0x48, 0x6f, 0x73, 0x74, 0x52, 0x05, 0x48, 0x6f, 0x73, 0x74, 0x73, 0x22,
	0x36, 0x0a, 0x12, 0x55, 0x70, 0x73, 0x65, 0x72, 0x74, 0x48, 0x6f, 0x73, 0x74, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x20, 0x0a, 0x05, 0x48, 0x6f, 0x73, 0x74, 0x73, 0x18, 0x01,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x0a, 0x2e, 0x68, 0x6f, 0x73, 0x74, 0x2e, 0x48, 0x6f, 0x73, 0x74,
	0x52, 0x05, 0x48, 0x6f, 0x73, 0x74, 0x73, 0x22, 0x35, 0x0a, 0x11, 0x44, 0x65, 0x6c, 0x65, 0x74,
	0x65, 0x48, 0x6f, 0x73, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x20, 0x0a, 0x05,
	0x48, 0x6f, 0x73, 0x74, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0a, 0x2e, 0x68, 0x6f,
	0x73, 0x74, 0x2e, 0x48, 0x6f, 0x73, 0x74, 0x52, 0x05, 0x48, 0x6f, 0x73, 0x74, 0x73, 0x22, 0x36,
	0x0a, 0x12, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x48, 0x6f, 0x73, 0x74, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x12, 0x20, 0x0a, 0x05, 0x48, 0x6f, 0x73, 0x74, 0x73, 0x18, 0x01, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x0a, 0x2e, 0x68, 0x6f, 0x73, 0x74, 0x2e, 0x48, 0x6f, 0x73, 0x74, 0x52,
	0x05, 0x48, 0x6f, 0x73, 0x74, 0x73, 0x32, 0xc0, 0x02, 0x0a, 0x05, 0x48, 0x6f, 0x73, 0x74, 0x73,
	0x12, 0x3f, 0x0a, 0x06, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x12, 0x18, 0x2e, 0x68, 0x6f, 0x73,
	0x74, 0x73, 0x2e, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x48, 0x6f, 0x73, 0x74, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x1a, 0x19, 0x2e, 0x68, 0x6f, 0x73, 0x74, 0x73, 0x2e, 0x43, 0x72, 0x65,
	0x61, 0x74, 0x65, 0x48, 0x6f, 0x73, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22,
	0x00, 0x12, 0x39, 0x0a, 0x04, 0x52, 0x65, 0x61, 0x64, 0x12, 0x16, 0x2e, 0x68, 0x6f, 0x73, 0x74,
	0x73, 0x2e, 0x52, 0x65, 0x61, 0x64, 0x48, 0x6f, 0x73, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x17, 0x2e, 0x68, 0x6f, 0x73, 0x74, 0x73, 0x2e, 0x52, 0x65, 0x61, 0x64, 0x48, 0x6f,
	0x73, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x39, 0x0a, 0x04,
	0x4c, 0x69, 0x73, 0x74, 0x12, 0x16, 0x2e, 0x68, 0x6f, 0x73, 0x74, 0x73, 0x2e, 0x52, 0x65, 0x61,
	0x64, 0x48, 0x6f, 0x73, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x17, 0x2e, 0x68,
	0x6f, 0x73, 0x74, 0x73, 0x2e, 0x52, 0x65, 0x61, 0x64, 0x48, 0x6f, 0x73, 0x74, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x3f, 0x0a, 0x06, 0x55, 0x70, 0x73, 0x65, 0x72,
	0x74, 0x12, 0x18, 0x2e, 0x68, 0x6f, 0x73, 0x74, 0x73, 0x2e, 0x55, 0x70, 0x73, 0x65, 0x72, 0x74,
	0x48, 0x6f, 0x73, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x19, 0x2e, 0x68, 0x6f,
	0x73, 0x74, 0x73, 0x2e, 0x55, 0x70, 0x73, 0x65, 0x72, 0x74, 0x48, 0x6f, 0x73, 0x74, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x3f, 0x0a, 0x06, 0x44, 0x65, 0x6c, 0x65,
	0x74, 0x65, 0x12, 0x18, 0x2e, 0x68, 0x6f, 0x73, 0x74, 0x73, 0x2e, 0x44, 0x65, 0x6c, 0x65, 0x74,
	0x65, 0x48, 0x6f, 0x73, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x19, 0x2e, 0x68,
	0x6f, 0x73, 0x74, 0x73, 0x2e, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x48, 0x6f, 0x73, 0x74, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x42, 0x76, 0x0a, 0x09, 0x63, 0x6f, 0x6d,
	0x2e, 0x68, 0x6f, 0x73, 0x74, 0x73, 0x42, 0x0a, 0x48, 0x6f, 0x73, 0x74, 0x73, 0x50, 0x72, 0x6f,
	0x74, 0x6f, 0x50, 0x01, 0x5a, 0x29, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x6d, 0x61, 0x78, 0x6c, 0x61, 0x6e, 0x64, 0x6f, 0x6e, 0x2f, 0x61, 0x69, 0x6d, 0x73, 0x2f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x72, 0x70, 0x63, 0x2f, 0x68, 0x6f, 0x73, 0x74, 0x73, 0xa2,
	0x02, 0x03, 0x48, 0x58, 0x58, 0xaa, 0x02, 0x05, 0x48, 0x6f, 0x73, 0x74, 0x73, 0xca, 0x02, 0x05,
	0x48, 0x6f, 0x73, 0x74, 0x73, 0xe2, 0x02, 0x11, 0x48, 0x6f, 0x73, 0x74, 0x73, 0x5c, 0x47, 0x50,
	0x42, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0xea, 0x02, 0x05, 0x48, 0x6f, 0x73, 0x74,
	0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_rpc_hosts_hosts_proto_rawDescOnce sync.Once
	file_rpc_hosts_hosts_proto_rawDescData = file_rpc_hosts_hosts_proto_rawDesc
)

func file_rpc_hosts_hosts_proto_rawDescGZIP() []byte {
	file_rpc_hosts_hosts_proto_rawDescOnce.Do(func() {
		file_rpc_hosts_hosts_proto_rawDescData = protoimpl.X.CompressGZIP(file_rpc_hosts_hosts_proto_rawDescData)
	})
	return file_rpc_hosts_hosts_proto_rawDescData
}

var file_rpc_hosts_hosts_proto_msgTypes = make([]protoimpl.MessageInfo, 10)
var file_rpc_hosts_hosts_proto_goTypes = []interface{}{
	(*CreateHostRequest)(nil),    // 0: hosts.CreateHostRequest
	(*CreateHostResponse)(nil),   // 1: hosts.CreateHostResponse
	(*ReadHostRequest)(nil),      // 2: hosts.ReadHostRequest
	(*ReadHostResponse)(nil),     // 3: hosts.ReadHostResponse
	(*ReadHostManyRequest)(nil),  // 4: hosts.ReadHostManyRequest
	(*ReadHostManyResponse)(nil), // 5: hosts.ReadHostManyResponse
	(*UpsertHostRequest)(nil),    // 6: hosts.UpsertHostRequest
	(*UpsertHostResponse)(nil),   // 7: hosts.UpsertHostResponse
	(*DeleteHostRequest)(nil),    // 8: hosts.DeleteHostRequest
	(*DeleteHostResponse)(nil),   // 9: hosts.DeleteHostResponse
	(*host.Host)(nil),            // 10: host.Host
}
var file_rpc_hosts_hosts_proto_depIdxs = []int32{
	10, // 0: hosts.CreateHostRequest.Hosts:type_name -> host.Host
	10, // 1: hosts.CreateHostResponse.Hosts:type_name -> host.Host
	10, // 2: hosts.ReadHostRequest.Host:type_name -> host.Host
	10, // 3: hosts.ReadHostResponse.Hosts:type_name -> host.Host
	10, // 4: hosts.ReadHostManyRequest.Host:type_name -> host.Host
	10, // 5: hosts.ReadHostManyResponse.Hosts:type_name -> host.Host
	10, // 6: hosts.UpsertHostRequest.Hosts:type_name -> host.Host
	10, // 7: hosts.UpsertHostResponse.Hosts:type_name -> host.Host
	10, // 8: hosts.DeleteHostRequest.Hosts:type_name -> host.Host
	10, // 9: hosts.DeleteHostResponse.Hosts:type_name -> host.Host
	0,  // 10: hosts.Hosts.Create:input_type -> hosts.CreateHostRequest
	2,  // 11: hosts.Hosts.Read:input_type -> hosts.ReadHostRequest
	2,  // 12: hosts.Hosts.List:input_type -> hosts.ReadHostRequest
	6,  // 13: hosts.Hosts.Upsert:input_type -> hosts.UpsertHostRequest
	8,  // 14: hosts.Hosts.Delete:input_type -> hosts.DeleteHostRequest
	1,  // 15: hosts.Hosts.Create:output_type -> hosts.CreateHostResponse
	3,  // 16: hosts.Hosts.Read:output_type -> hosts.ReadHostResponse
	3,  // 17: hosts.Hosts.List:output_type -> hosts.ReadHostResponse
	7,  // 18: hosts.Hosts.Upsert:output_type -> hosts.UpsertHostResponse
	9,  // 19: hosts.Hosts.Delete:output_type -> hosts.DeleteHostResponse
	15, // [15:20] is the sub-list for method output_type
	10, // [10:15] is the sub-list for method input_type
	10, // [10:10] is the sub-list for extension type_name
	10, // [10:10] is the sub-list for extension extendee
	0,  // [0:10] is the sub-list for field type_name
}

func init() { file_rpc_hosts_hosts_proto_init() }
func file_rpc_hosts_hosts_proto_init() {
	if File_rpc_hosts_hosts_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_rpc_hosts_hosts_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateHostRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_rpc_hosts_hosts_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateHostResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_rpc_hosts_hosts_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ReadHostRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_rpc_hosts_hosts_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ReadHostResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_rpc_hosts_hosts_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ReadHostManyRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_rpc_hosts_hosts_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ReadHostManyResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_rpc_hosts_hosts_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpsertHostRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_rpc_hosts_hosts_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpsertHostResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_rpc_hosts_hosts_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeleteHostRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_rpc_hosts_hosts_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeleteHostResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_rpc_hosts_hosts_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   10,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_rpc_hosts_hosts_proto_goTypes,
		DependencyIndexes: file_rpc_hosts_hosts_proto_depIdxs,
		MessageInfos:      file_rpc_hosts_hosts_proto_msgTypes,
	}.Build()
	File_rpc_hosts_hosts_proto = out.File
	file_rpc_hosts_hosts_proto_rawDesc = nil
	file_rpc_hosts_hosts_proto_goTypes = nil
	file_rpc_hosts_hosts_proto_depIdxs = nil
}
