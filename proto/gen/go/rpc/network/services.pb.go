// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v3.18.1
// source: rpc/network/services.proto

package network

import (
	network "github.com/maxlandon/aims/proto/gen/go/network"
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

type CreateServiceRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Services []*network.Service `protobuf:"bytes,1,rep,name=Services,proto3" json:"Services,omitempty"`
}

func (x *CreateServiceRequest) Reset() {
	*x = CreateServiceRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpc_network_services_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateServiceRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateServiceRequest) ProtoMessage() {}

func (x *CreateServiceRequest) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_network_services_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateServiceRequest.ProtoReflect.Descriptor instead.
func (*CreateServiceRequest) Descriptor() ([]byte, []int) {
	return file_rpc_network_services_proto_rawDescGZIP(), []int{0}
}

func (x *CreateServiceRequest) GetServices() []*network.Service {
	if x != nil {
		return x.Services
	}
	return nil
}

type CreateServiceResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Services []*network.Service `protobuf:"bytes,1,rep,name=Services,proto3" json:"Services,omitempty"`
}

func (x *CreateServiceResponse) Reset() {
	*x = CreateServiceResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpc_network_services_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateServiceResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateServiceResponse) ProtoMessage() {}

func (x *CreateServiceResponse) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_network_services_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateServiceResponse.ProtoReflect.Descriptor instead.
func (*CreateServiceResponse) Descriptor() ([]byte, []int) {
	return file_rpc_network_services_proto_rawDescGZIP(), []int{1}
}

func (x *CreateServiceResponse) GetServices() []*network.Service {
	if x != nil {
		return x.Services
	}
	return nil
}

type ReadServiceRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Service *network.Service `protobuf:"bytes,1,opt,name=Service,proto3" json:"Service,omitempty"`
}

func (x *ReadServiceRequest) Reset() {
	*x = ReadServiceRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpc_network_services_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ReadServiceRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReadServiceRequest) ProtoMessage() {}

func (x *ReadServiceRequest) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_network_services_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReadServiceRequest.ProtoReflect.Descriptor instead.
func (*ReadServiceRequest) Descriptor() ([]byte, []int) {
	return file_rpc_network_services_proto_rawDescGZIP(), []int{2}
}

func (x *ReadServiceRequest) GetService() *network.Service {
	if x != nil {
		return x.Service
	}
	return nil
}

type ReadServiceResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Services []*network.Service `protobuf:"bytes,1,rep,name=Services,proto3" json:"Services,omitempty"`
}

func (x *ReadServiceResponse) Reset() {
	*x = ReadServiceResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpc_network_services_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ReadServiceResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReadServiceResponse) ProtoMessage() {}

func (x *ReadServiceResponse) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_network_services_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReadServiceResponse.ProtoReflect.Descriptor instead.
func (*ReadServiceResponse) Descriptor() ([]byte, []int) {
	return file_rpc_network_services_proto_rawDescGZIP(), []int{3}
}

func (x *ReadServiceResponse) GetServices() []*network.Service {
	if x != nil {
		return x.Services
	}
	return nil
}

type ReadServiceManyRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Service *network.Service `protobuf:"bytes,1,opt,name=Service,proto3" json:"Service,omitempty"`
}

func (x *ReadServiceManyRequest) Reset() {
	*x = ReadServiceManyRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpc_network_services_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ReadServiceManyRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReadServiceManyRequest) ProtoMessage() {}

func (x *ReadServiceManyRequest) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_network_services_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReadServiceManyRequest.ProtoReflect.Descriptor instead.
func (*ReadServiceManyRequest) Descriptor() ([]byte, []int) {
	return file_rpc_network_services_proto_rawDescGZIP(), []int{4}
}

func (x *ReadServiceManyRequest) GetService() *network.Service {
	if x != nil {
		return x.Service
	}
	return nil
}

type ReadServiceManyResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Services []*network.Service `protobuf:"bytes,1,rep,name=Services,proto3" json:"Services,omitempty"`
}

func (x *ReadServiceManyResponse) Reset() {
	*x = ReadServiceManyResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpc_network_services_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ReadServiceManyResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReadServiceManyResponse) ProtoMessage() {}

func (x *ReadServiceManyResponse) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_network_services_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReadServiceManyResponse.ProtoReflect.Descriptor instead.
func (*ReadServiceManyResponse) Descriptor() ([]byte, []int) {
	return file_rpc_network_services_proto_rawDescGZIP(), []int{5}
}

func (x *ReadServiceManyResponse) GetServices() []*network.Service {
	if x != nil {
		return x.Services
	}
	return nil
}

type UpsertServiceRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Services []*network.Service `protobuf:"bytes,1,rep,name=Services,proto3" json:"Services,omitempty"`
}

func (x *UpsertServiceRequest) Reset() {
	*x = UpsertServiceRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpc_network_services_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpsertServiceRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpsertServiceRequest) ProtoMessage() {}

func (x *UpsertServiceRequest) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_network_services_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpsertServiceRequest.ProtoReflect.Descriptor instead.
func (*UpsertServiceRequest) Descriptor() ([]byte, []int) {
	return file_rpc_network_services_proto_rawDescGZIP(), []int{6}
}

func (x *UpsertServiceRequest) GetServices() []*network.Service {
	if x != nil {
		return x.Services
	}
	return nil
}

type UpsertServiceResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Services []*network.Service `protobuf:"bytes,1,rep,name=Services,proto3" json:"Services,omitempty"`
}

func (x *UpsertServiceResponse) Reset() {
	*x = UpsertServiceResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpc_network_services_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpsertServiceResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpsertServiceResponse) ProtoMessage() {}

func (x *UpsertServiceResponse) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_network_services_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpsertServiceResponse.ProtoReflect.Descriptor instead.
func (*UpsertServiceResponse) Descriptor() ([]byte, []int) {
	return file_rpc_network_services_proto_rawDescGZIP(), []int{7}
}

func (x *UpsertServiceResponse) GetServices() []*network.Service {
	if x != nil {
		return x.Services
	}
	return nil
}

type DeleteServiceRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Services []*network.Service `protobuf:"bytes,1,rep,name=Services,proto3" json:"Services,omitempty"`
}

func (x *DeleteServiceRequest) Reset() {
	*x = DeleteServiceRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpc_network_services_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteServiceRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteServiceRequest) ProtoMessage() {}

func (x *DeleteServiceRequest) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_network_services_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteServiceRequest.ProtoReflect.Descriptor instead.
func (*DeleteServiceRequest) Descriptor() ([]byte, []int) {
	return file_rpc_network_services_proto_rawDescGZIP(), []int{8}
}

func (x *DeleteServiceRequest) GetServices() []*network.Service {
	if x != nil {
		return x.Services
	}
	return nil
}

type DeleteServiceResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Services []*network.Service `protobuf:"bytes,1,rep,name=Services,proto3" json:"Services,omitempty"`
}

func (x *DeleteServiceResponse) Reset() {
	*x = DeleteServiceResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpc_network_services_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteServiceResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteServiceResponse) ProtoMessage() {}

func (x *DeleteServiceResponse) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_network_services_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteServiceResponse.ProtoReflect.Descriptor instead.
func (*DeleteServiceResponse) Descriptor() ([]byte, []int) {
	return file_rpc_network_services_proto_rawDescGZIP(), []int{9}
}

func (x *DeleteServiceResponse) GetServices() []*network.Service {
	if x != nil {
		return x.Services
	}
	return nil
}

var File_rpc_network_services_proto protoreflect.FileDescriptor

var file_rpc_network_services_proto_rawDesc = []byte{
	0x0a, 0x1a, 0x72, 0x70, 0x63, 0x2f, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2f, 0x73, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x07, 0x6e, 0x65,
	0x74, 0x77, 0x6f, 0x72, 0x6b, 0x1a, 0x15, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2f, 0x73,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x44, 0x0a, 0x14,
	0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x2c, 0x0a, 0x08, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73,
	0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b,
	0x2e, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x52, 0x08, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x73, 0x22, 0x45, 0x0a, 0x15, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x53, 0x65, 0x72, 0x76,
	0x69, 0x63, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x2c, 0x0a, 0x08, 0x53,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x10, 0x2e,
	0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2e, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x52,
	0x08, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x22, 0x40, 0x0a, 0x12, 0x52, 0x65, 0x61,
	0x64, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12,
	0x2a, 0x0a, 0x07, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x10, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2e, 0x53, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x52, 0x07, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x22, 0x43, 0x0a, 0x13, 0x52,
	0x65, 0x61, 0x64, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x12, 0x2c, 0x0a, 0x08, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x18, 0x01,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2e, 0x53,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x52, 0x08, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73,
	0x22, 0x44, 0x0a, 0x16, 0x52, 0x65, 0x61, 0x64, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x4d,
	0x61, 0x6e, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x2a, 0x0a, 0x07, 0x53, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x6e, 0x65,
	0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2e, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x52, 0x07, 0x53,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x22, 0x47, 0x0a, 0x17, 0x52, 0x65, 0x61, 0x64, 0x53, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x4d, 0x61, 0x6e, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x12, 0x2c, 0x0a, 0x08, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x18, 0x01, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2e, 0x53, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x52, 0x08, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x22,
	0x44, 0x0a, 0x14, 0x55, 0x70, 0x73, 0x65, 0x72, 0x74, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x2c, 0x0a, 0x08, 0x53, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x6e, 0x65, 0x74, 0x77,
	0x6f, 0x72, 0x6b, 0x2e, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x52, 0x08, 0x53, 0x65, 0x72,
	0x76, 0x69, 0x63, 0x65, 0x73, 0x22, 0x45, 0x0a, 0x15, 0x55, 0x70, 0x73, 0x65, 0x72, 0x74, 0x53,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x2c,
	0x0a, 0x08, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x10, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2e, 0x53, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x52, 0x08, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x22, 0x44, 0x0a, 0x14,
	0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x2c, 0x0a, 0x08, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73,
	0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b,
	0x2e, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x52, 0x08, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x73, 0x22, 0x45, 0x0a, 0x15, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x53, 0x65, 0x72, 0x76,
	0x69, 0x63, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x2c, 0x0a, 0x08, 0x53,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x10, 0x2e,
	0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2e, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x52,
	0x08, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x32, 0x9a, 0x03, 0x0a, 0x08, 0x53, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x12, 0x50, 0x0a, 0x0d, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65,
	0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x1d, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72,
	0x6b, 0x2e, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1e, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b,
	0x2e, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x49, 0x0a, 0x0a, 0x47, 0x65, 0x74, 0x53,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x1b, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b,
	0x2e, 0x52, 0x65, 0x61, 0x64, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x1a, 0x1c, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2e, 0x52, 0x65,
	0x61, 0x64, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x22, 0x00, 0x12, 0x4d, 0x0a, 0x0e, 0x47, 0x65, 0x74, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x4d, 0x61, 0x6e, 0x79, 0x12, 0x1b, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2e,
	0x52, 0x65, 0x61, 0x64, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x1a, 0x1c, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2e, 0x52, 0x65, 0x61,
	0x64, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x22, 0x00, 0x12, 0x50, 0x0a, 0x0d, 0x55, 0x70, 0x73, 0x65, 0x72, 0x74, 0x53, 0x65, 0x72, 0x76,
	0x69, 0x63, 0x65, 0x12, 0x1d, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2e, 0x55, 0x70,
	0x73, 0x65, 0x72, 0x74, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x1a, 0x1e, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2e, 0x55, 0x70, 0x73,
	0x65, 0x72, 0x74, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x22, 0x00, 0x12, 0x50, 0x0a, 0x0d, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x53, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x1d, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2e,
	0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x1a, 0x1e, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2e, 0x44,
	0x65, 0x6c, 0x65, 0x74, 0x65, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x42, 0x8c, 0x01, 0x0a, 0x0b, 0x63, 0x6f, 0x6d, 0x2e, 0x6e,
	0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x42, 0x0d, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73,
	0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x32, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e,
	0x63, 0x6f, 0x6d, 0x2f, 0x6d, 0x61, 0x78, 0x6c, 0x61, 0x6e, 0x64, 0x6f, 0x6e, 0x2f, 0x61, 0x69,
	0x6d, 0x73, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x67, 0x6f, 0x2f,
	0x72, 0x70, 0x63, 0x2f, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0xa2, 0x02, 0x03, 0x4e, 0x58,
	0x58, 0xaa, 0x02, 0x07, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0xca, 0x02, 0x07, 0x4e, 0x65,
	0x74, 0x77, 0x6f, 0x72, 0x6b, 0xe2, 0x02, 0x13, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x5c,
	0x47, 0x50, 0x42, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0xea, 0x02, 0x07, 0x4e, 0x65,
	0x74, 0x77, 0x6f, 0x72, 0x6b, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_rpc_network_services_proto_rawDescOnce sync.Once
	file_rpc_network_services_proto_rawDescData = file_rpc_network_services_proto_rawDesc
)

func file_rpc_network_services_proto_rawDescGZIP() []byte {
	file_rpc_network_services_proto_rawDescOnce.Do(func() {
		file_rpc_network_services_proto_rawDescData = protoimpl.X.CompressGZIP(file_rpc_network_services_proto_rawDescData)
	})
	return file_rpc_network_services_proto_rawDescData
}

var file_rpc_network_services_proto_msgTypes = make([]protoimpl.MessageInfo, 10)
var file_rpc_network_services_proto_goTypes = []interface{}{
	(*CreateServiceRequest)(nil),    // 0: network.CreateServiceRequest
	(*CreateServiceResponse)(nil),   // 1: network.CreateServiceResponse
	(*ReadServiceRequest)(nil),      // 2: network.ReadServiceRequest
	(*ReadServiceResponse)(nil),     // 3: network.ReadServiceResponse
	(*ReadServiceManyRequest)(nil),  // 4: network.ReadServiceManyRequest
	(*ReadServiceManyResponse)(nil), // 5: network.ReadServiceManyResponse
	(*UpsertServiceRequest)(nil),    // 6: network.UpsertServiceRequest
	(*UpsertServiceResponse)(nil),   // 7: network.UpsertServiceResponse
	(*DeleteServiceRequest)(nil),    // 8: network.DeleteServiceRequest
	(*DeleteServiceResponse)(nil),   // 9: network.DeleteServiceResponse
	(*network.Service)(nil),         // 10: network.Service
}
var file_rpc_network_services_proto_depIdxs = []int32{
	10, // 0: network.CreateServiceRequest.Services:type_name -> network.Service
	10, // 1: network.CreateServiceResponse.Services:type_name -> network.Service
	10, // 2: network.ReadServiceRequest.Service:type_name -> network.Service
	10, // 3: network.ReadServiceResponse.Services:type_name -> network.Service
	10, // 4: network.ReadServiceManyRequest.Service:type_name -> network.Service
	10, // 5: network.ReadServiceManyResponse.Services:type_name -> network.Service
	10, // 6: network.UpsertServiceRequest.Services:type_name -> network.Service
	10, // 7: network.UpsertServiceResponse.Services:type_name -> network.Service
	10, // 8: network.DeleteServiceRequest.Services:type_name -> network.Service
	10, // 9: network.DeleteServiceResponse.Services:type_name -> network.Service
	0,  // 10: network.Services.CreateService:input_type -> network.CreateServiceRequest
	2,  // 11: network.Services.GetService:input_type -> network.ReadServiceRequest
	2,  // 12: network.Services.GetServiceMany:input_type -> network.ReadServiceRequest
	6,  // 13: network.Services.UpsertService:input_type -> network.UpsertServiceRequest
	8,  // 14: network.Services.DeleteService:input_type -> network.DeleteServiceRequest
	1,  // 15: network.Services.CreateService:output_type -> network.CreateServiceResponse
	3,  // 16: network.Services.GetService:output_type -> network.ReadServiceResponse
	3,  // 17: network.Services.GetServiceMany:output_type -> network.ReadServiceResponse
	7,  // 18: network.Services.UpsertService:output_type -> network.UpsertServiceResponse
	9,  // 19: network.Services.DeleteService:output_type -> network.DeleteServiceResponse
	15, // [15:20] is the sub-list for method output_type
	10, // [10:15] is the sub-list for method input_type
	10, // [10:10] is the sub-list for extension type_name
	10, // [10:10] is the sub-list for extension extendee
	0,  // [0:10] is the sub-list for field type_name
}

func init() { file_rpc_network_services_proto_init() }
func file_rpc_network_services_proto_init() {
	if File_rpc_network_services_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_rpc_network_services_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateServiceRequest); i {
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
		file_rpc_network_services_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateServiceResponse); i {
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
		file_rpc_network_services_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ReadServiceRequest); i {
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
		file_rpc_network_services_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ReadServiceResponse); i {
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
		file_rpc_network_services_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ReadServiceManyRequest); i {
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
		file_rpc_network_services_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ReadServiceManyResponse); i {
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
		file_rpc_network_services_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpsertServiceRequest); i {
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
		file_rpc_network_services_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpsertServiceResponse); i {
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
		file_rpc_network_services_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeleteServiceRequest); i {
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
		file_rpc_network_services_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeleteServiceResponse); i {
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
			RawDescriptor: file_rpc_network_services_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   10,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_rpc_network_services_proto_goTypes,
		DependencyIndexes: file_rpc_network_services_proto_depIdxs,
		MessageInfos:      file_rpc_network_services_proto_msgTypes,
	}.Build()
	File_rpc_network_services_proto = out.File
	file_rpc_network_services_proto_rawDesc = nil
	file_rpc_network_services_proto_goTypes = nil
	file_rpc_network_services_proto_depIdxs = nil
}