// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v3.18.1
// source: rpc/scans/scans.proto

package scans

import (
	scan "github.com/maxlandon/aims/proto/scan"
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

type CreateScanRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Scans []*scan.Run `protobuf:"bytes,1,rep,name=Scans,proto3" json:"Scans,omitempty"`
}

func (x *CreateScanRequest) Reset() {
	*x = CreateScanRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpc_scans_scans_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateScanRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateScanRequest) ProtoMessage() {}

func (x *CreateScanRequest) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_scans_scans_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateScanRequest.ProtoReflect.Descriptor instead.
func (*CreateScanRequest) Descriptor() ([]byte, []int) {
	return file_rpc_scans_scans_proto_rawDescGZIP(), []int{0}
}

func (x *CreateScanRequest) GetScans() []*scan.Run {
	if x != nil {
		return x.Scans
	}
	return nil
}

type CreateScanResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Scans []*scan.Run `protobuf:"bytes,1,rep,name=Scans,proto3" json:"Scans,omitempty"`
}

func (x *CreateScanResponse) Reset() {
	*x = CreateScanResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpc_scans_scans_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateScanResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateScanResponse) ProtoMessage() {}

func (x *CreateScanResponse) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_scans_scans_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateScanResponse.ProtoReflect.Descriptor instead.
func (*CreateScanResponse) Descriptor() ([]byte, []int) {
	return file_rpc_scans_scans_proto_rawDescGZIP(), []int{1}
}

func (x *CreateScanResponse) GetScans() []*scan.Run {
	if x != nil {
		return x.Scans
	}
	return nil
}

type ReadScanRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Scan *scan.Run `protobuf:"bytes,1,opt,name=Scan,proto3" json:"Scan,omitempty"`
}

func (x *ReadScanRequest) Reset() {
	*x = ReadScanRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpc_scans_scans_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ReadScanRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReadScanRequest) ProtoMessage() {}

func (x *ReadScanRequest) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_scans_scans_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReadScanRequest.ProtoReflect.Descriptor instead.
func (*ReadScanRequest) Descriptor() ([]byte, []int) {
	return file_rpc_scans_scans_proto_rawDescGZIP(), []int{2}
}

func (x *ReadScanRequest) GetScan() *scan.Run {
	if x != nil {
		return x.Scan
	}
	return nil
}

type ReadScanResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Scans []*scan.Run `protobuf:"bytes,1,rep,name=Scans,proto3" json:"Scans,omitempty"`
}

func (x *ReadScanResponse) Reset() {
	*x = ReadScanResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpc_scans_scans_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ReadScanResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReadScanResponse) ProtoMessage() {}

func (x *ReadScanResponse) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_scans_scans_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReadScanResponse.ProtoReflect.Descriptor instead.
func (*ReadScanResponse) Descriptor() ([]byte, []int) {
	return file_rpc_scans_scans_proto_rawDescGZIP(), []int{3}
}

func (x *ReadScanResponse) GetScans() []*scan.Run {
	if x != nil {
		return x.Scans
	}
	return nil
}

type ReadScanManyRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Scan *scan.Run `protobuf:"bytes,1,opt,name=Scan,proto3" json:"Scan,omitempty"`
}

func (x *ReadScanManyRequest) Reset() {
	*x = ReadScanManyRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpc_scans_scans_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ReadScanManyRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReadScanManyRequest) ProtoMessage() {}

func (x *ReadScanManyRequest) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_scans_scans_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReadScanManyRequest.ProtoReflect.Descriptor instead.
func (*ReadScanManyRequest) Descriptor() ([]byte, []int) {
	return file_rpc_scans_scans_proto_rawDescGZIP(), []int{4}
}

func (x *ReadScanManyRequest) GetScan() *scan.Run {
	if x != nil {
		return x.Scan
	}
	return nil
}

type ReadScanManyResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Scans []*scan.Run `protobuf:"bytes,1,rep,name=Scans,proto3" json:"Scans,omitempty"`
}

func (x *ReadScanManyResponse) Reset() {
	*x = ReadScanManyResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpc_scans_scans_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ReadScanManyResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReadScanManyResponse) ProtoMessage() {}

func (x *ReadScanManyResponse) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_scans_scans_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReadScanManyResponse.ProtoReflect.Descriptor instead.
func (*ReadScanManyResponse) Descriptor() ([]byte, []int) {
	return file_rpc_scans_scans_proto_rawDescGZIP(), []int{5}
}

func (x *ReadScanManyResponse) GetScans() []*scan.Run {
	if x != nil {
		return x.Scans
	}
	return nil
}

type UpsertScanRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Scans []*scan.Run `protobuf:"bytes,1,rep,name=Scans,proto3" json:"Scans,omitempty"`
}

func (x *UpsertScanRequest) Reset() {
	*x = UpsertScanRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpc_scans_scans_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpsertScanRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpsertScanRequest) ProtoMessage() {}

func (x *UpsertScanRequest) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_scans_scans_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpsertScanRequest.ProtoReflect.Descriptor instead.
func (*UpsertScanRequest) Descriptor() ([]byte, []int) {
	return file_rpc_scans_scans_proto_rawDescGZIP(), []int{6}
}

func (x *UpsertScanRequest) GetScans() []*scan.Run {
	if x != nil {
		return x.Scans
	}
	return nil
}

type UpsertScanResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Scans []*scan.Run `protobuf:"bytes,1,rep,name=Scans,proto3" json:"Scans,omitempty"`
}

func (x *UpsertScanResponse) Reset() {
	*x = UpsertScanResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpc_scans_scans_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpsertScanResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpsertScanResponse) ProtoMessage() {}

func (x *UpsertScanResponse) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_scans_scans_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpsertScanResponse.ProtoReflect.Descriptor instead.
func (*UpsertScanResponse) Descriptor() ([]byte, []int) {
	return file_rpc_scans_scans_proto_rawDescGZIP(), []int{7}
}

func (x *UpsertScanResponse) GetScans() []*scan.Run {
	if x != nil {
		return x.Scans
	}
	return nil
}

type DeleteScanRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Scans []*scan.Run `protobuf:"bytes,1,rep,name=Scans,proto3" json:"Scans,omitempty"`
}

func (x *DeleteScanRequest) Reset() {
	*x = DeleteScanRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpc_scans_scans_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteScanRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteScanRequest) ProtoMessage() {}

func (x *DeleteScanRequest) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_scans_scans_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteScanRequest.ProtoReflect.Descriptor instead.
func (*DeleteScanRequest) Descriptor() ([]byte, []int) {
	return file_rpc_scans_scans_proto_rawDescGZIP(), []int{8}
}

func (x *DeleteScanRequest) GetScans() []*scan.Run {
	if x != nil {
		return x.Scans
	}
	return nil
}

type DeleteScanResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Scans []*scan.Run `protobuf:"bytes,1,rep,name=Scans,proto3" json:"Scans,omitempty"`
}

func (x *DeleteScanResponse) Reset() {
	*x = DeleteScanResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpc_scans_scans_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteScanResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteScanResponse) ProtoMessage() {}

func (x *DeleteScanResponse) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_scans_scans_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteScanResponse.ProtoReflect.Descriptor instead.
func (*DeleteScanResponse) Descriptor() ([]byte, []int) {
	return file_rpc_scans_scans_proto_rawDescGZIP(), []int{9}
}

func (x *DeleteScanResponse) GetScans() []*scan.Run {
	if x != nil {
		return x.Scans
	}
	return nil
}

var File_rpc_scans_scans_proto protoreflect.FileDescriptor

var file_rpc_scans_scans_proto_rawDesc = []byte{
	0x0a, 0x15, 0x72, 0x70, 0x63, 0x2f, 0x73, 0x63, 0x61, 0x6e, 0x73, 0x2f, 0x73, 0x63, 0x61, 0x6e,
	0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x05, 0x73, 0x63, 0x61, 0x6e, 0x73, 0x1a, 0x0f,
	0x73, 0x63, 0x61, 0x6e, 0x2f, 0x73, 0x63, 0x61, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0x34, 0x0a, 0x11, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x53, 0x63, 0x61, 0x6e, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x1f, 0x0a, 0x05, 0x53, 0x63, 0x61, 0x6e, 0x73, 0x18, 0x01, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x09, 0x2e, 0x73, 0x63, 0x61, 0x6e, 0x2e, 0x52, 0x75, 0x6e, 0x52, 0x05,
	0x53, 0x63, 0x61, 0x6e, 0x73, 0x22, 0x35, 0x0a, 0x12, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x53,
	0x63, 0x61, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x1f, 0x0a, 0x05, 0x53,
	0x63, 0x61, 0x6e, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x09, 0x2e, 0x73, 0x63, 0x61,
	0x6e, 0x2e, 0x52, 0x75, 0x6e, 0x52, 0x05, 0x53, 0x63, 0x61, 0x6e, 0x73, 0x22, 0x30, 0x0a, 0x0f,
	0x52, 0x65, 0x61, 0x64, 0x53, 0x63, 0x61, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12,
	0x1d, 0x0a, 0x04, 0x53, 0x63, 0x61, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x09, 0x2e,
	0x73, 0x63, 0x61, 0x6e, 0x2e, 0x52, 0x75, 0x6e, 0x52, 0x04, 0x53, 0x63, 0x61, 0x6e, 0x22, 0x33,
	0x0a, 0x10, 0x52, 0x65, 0x61, 0x64, 0x53, 0x63, 0x61, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x12, 0x1f, 0x0a, 0x05, 0x53, 0x63, 0x61, 0x6e, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28,
	0x0b, 0x32, 0x09, 0x2e, 0x73, 0x63, 0x61, 0x6e, 0x2e, 0x52, 0x75, 0x6e, 0x52, 0x05, 0x53, 0x63,
	0x61, 0x6e, 0x73, 0x22, 0x34, 0x0a, 0x13, 0x52, 0x65, 0x61, 0x64, 0x53, 0x63, 0x61, 0x6e, 0x4d,
	0x61, 0x6e, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1d, 0x0a, 0x04, 0x53, 0x63,
	0x61, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x09, 0x2e, 0x73, 0x63, 0x61, 0x6e, 0x2e,
	0x52, 0x75, 0x6e, 0x52, 0x04, 0x53, 0x63, 0x61, 0x6e, 0x22, 0x37, 0x0a, 0x14, 0x52, 0x65, 0x61,
	0x64, 0x53, 0x63, 0x61, 0x6e, 0x4d, 0x61, 0x6e, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x12, 0x1f, 0x0a, 0x05, 0x53, 0x63, 0x61, 0x6e, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x09, 0x2e, 0x73, 0x63, 0x61, 0x6e, 0x2e, 0x52, 0x75, 0x6e, 0x52, 0x05, 0x53, 0x63, 0x61,
	0x6e, 0x73, 0x22, 0x34, 0x0a, 0x11, 0x55, 0x70, 0x73, 0x65, 0x72, 0x74, 0x53, 0x63, 0x61, 0x6e,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1f, 0x0a, 0x05, 0x53, 0x63, 0x61, 0x6e, 0x73,
	0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x09, 0x2e, 0x73, 0x63, 0x61, 0x6e, 0x2e, 0x52, 0x75,
	0x6e, 0x52, 0x05, 0x53, 0x63, 0x61, 0x6e, 0x73, 0x22, 0x35, 0x0a, 0x12, 0x55, 0x70, 0x73, 0x65,
	0x72, 0x74, 0x53, 0x63, 0x61, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x1f,
	0x0a, 0x05, 0x53, 0x63, 0x61, 0x6e, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x09, 0x2e,
	0x73, 0x63, 0x61, 0x6e, 0x2e, 0x52, 0x75, 0x6e, 0x52, 0x05, 0x53, 0x63, 0x61, 0x6e, 0x73, 0x22,
	0x34, 0x0a, 0x11, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x53, 0x63, 0x61, 0x6e, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x1f, 0x0a, 0x05, 0x53, 0x63, 0x61, 0x6e, 0x73, 0x18, 0x01, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x09, 0x2e, 0x73, 0x63, 0x61, 0x6e, 0x2e, 0x52, 0x75, 0x6e, 0x52, 0x05,
	0x53, 0x63, 0x61, 0x6e, 0x73, 0x22, 0x35, 0x0a, 0x12, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x53,
	0x63, 0x61, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x1f, 0x0a, 0x05, 0x53,
	0x63, 0x61, 0x6e, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x09, 0x2e, 0x73, 0x63, 0x61,
	0x6e, 0x2e, 0x52, 0x75, 0x6e, 0x52, 0x05, 0x53, 0x63, 0x61, 0x6e, 0x73, 0x32, 0xc0, 0x02, 0x0a,
	0x05, 0x53, 0x63, 0x61, 0x6e, 0x73, 0x12, 0x3f, 0x0a, 0x06, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65,
	0x12, 0x18, 0x2e, 0x73, 0x63, 0x61, 0x6e, 0x73, 0x2e, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x53,
	0x63, 0x61, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x19, 0x2e, 0x73, 0x63, 0x61,
	0x6e, 0x73, 0x2e, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x53, 0x63, 0x61, 0x6e, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x39, 0x0a, 0x04, 0x52, 0x65, 0x61, 0x64, 0x12,
	0x16, 0x2e, 0x73, 0x63, 0x61, 0x6e, 0x73, 0x2e, 0x52, 0x65, 0x61, 0x64, 0x53, 0x63, 0x61, 0x6e,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x17, 0x2e, 0x73, 0x63, 0x61, 0x6e, 0x73, 0x2e,
	0x52, 0x65, 0x61, 0x64, 0x53, 0x63, 0x61, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x22, 0x00, 0x12, 0x39, 0x0a, 0x04, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x16, 0x2e, 0x73, 0x63, 0x61,
	0x6e, 0x73, 0x2e, 0x52, 0x65, 0x61, 0x64, 0x53, 0x63, 0x61, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x1a, 0x17, 0x2e, 0x73, 0x63, 0x61, 0x6e, 0x73, 0x2e, 0x52, 0x65, 0x61, 0x64, 0x53,
	0x63, 0x61, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x3f, 0x0a,
	0x06, 0x55, 0x70, 0x73, 0x65, 0x72, 0x74, 0x12, 0x18, 0x2e, 0x73, 0x63, 0x61, 0x6e, 0x73, 0x2e,
	0x55, 0x70, 0x73, 0x65, 0x72, 0x74, 0x53, 0x63, 0x61, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x19, 0x2e, 0x73, 0x63, 0x61, 0x6e, 0x73, 0x2e, 0x55, 0x70, 0x73, 0x65, 0x72, 0x74,
	0x53, 0x63, 0x61, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x3f,
	0x0a, 0x06, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x12, 0x18, 0x2e, 0x73, 0x63, 0x61, 0x6e, 0x73,
	0x2e, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x53, 0x63, 0x61, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x1a, 0x19, 0x2e, 0x73, 0x63, 0x61, 0x6e, 0x73, 0x2e, 0x44, 0x65, 0x6c, 0x65, 0x74,
	0x65, 0x53, 0x63, 0x61, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x42,
	0x76, 0x0a, 0x09, 0x63, 0x6f, 0x6d, 0x2e, 0x73, 0x63, 0x61, 0x6e, 0x73, 0x42, 0x0a, 0x53, 0x63,
	0x61, 0x6e, 0x73, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x29, 0x67, 0x69, 0x74, 0x68,
	0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6d, 0x61, 0x78, 0x6c, 0x61, 0x6e, 0x64, 0x6f, 0x6e,
	0x2f, 0x61, 0x69, 0x6d, 0x73, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x72, 0x70, 0x63, 0x2f,
	0x73, 0x63, 0x61, 0x6e, 0x73, 0xa2, 0x02, 0x03, 0x53, 0x58, 0x58, 0xaa, 0x02, 0x05, 0x53, 0x63,
	0x61, 0x6e, 0x73, 0xca, 0x02, 0x05, 0x53, 0x63, 0x61, 0x6e, 0x73, 0xe2, 0x02, 0x11, 0x53, 0x63,
	0x61, 0x6e, 0x73, 0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0xea,
	0x02, 0x05, 0x53, 0x63, 0x61, 0x6e, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_rpc_scans_scans_proto_rawDescOnce sync.Once
	file_rpc_scans_scans_proto_rawDescData = file_rpc_scans_scans_proto_rawDesc
)

func file_rpc_scans_scans_proto_rawDescGZIP() []byte {
	file_rpc_scans_scans_proto_rawDescOnce.Do(func() {
		file_rpc_scans_scans_proto_rawDescData = protoimpl.X.CompressGZIP(file_rpc_scans_scans_proto_rawDescData)
	})
	return file_rpc_scans_scans_proto_rawDescData
}

var file_rpc_scans_scans_proto_msgTypes = make([]protoimpl.MessageInfo, 10)
var file_rpc_scans_scans_proto_goTypes = []interface{}{
	(*CreateScanRequest)(nil),    // 0: scans.CreateScanRequest
	(*CreateScanResponse)(nil),   // 1: scans.CreateScanResponse
	(*ReadScanRequest)(nil),      // 2: scans.ReadScanRequest
	(*ReadScanResponse)(nil),     // 3: scans.ReadScanResponse
	(*ReadScanManyRequest)(nil),  // 4: scans.ReadScanManyRequest
	(*ReadScanManyResponse)(nil), // 5: scans.ReadScanManyResponse
	(*UpsertScanRequest)(nil),    // 6: scans.UpsertScanRequest
	(*UpsertScanResponse)(nil),   // 7: scans.UpsertScanResponse
	(*DeleteScanRequest)(nil),    // 8: scans.DeleteScanRequest
	(*DeleteScanResponse)(nil),   // 9: scans.DeleteScanResponse
	(*scan.Run)(nil),             // 10: scan.Run
}
var file_rpc_scans_scans_proto_depIdxs = []int32{
	10, // 0: scans.CreateScanRequest.Scans:type_name -> scan.Run
	10, // 1: scans.CreateScanResponse.Scans:type_name -> scan.Run
	10, // 2: scans.ReadScanRequest.Scan:type_name -> scan.Run
	10, // 3: scans.ReadScanResponse.Scans:type_name -> scan.Run
	10, // 4: scans.ReadScanManyRequest.Scan:type_name -> scan.Run
	10, // 5: scans.ReadScanManyResponse.Scans:type_name -> scan.Run
	10, // 6: scans.UpsertScanRequest.Scans:type_name -> scan.Run
	10, // 7: scans.UpsertScanResponse.Scans:type_name -> scan.Run
	10, // 8: scans.DeleteScanRequest.Scans:type_name -> scan.Run
	10, // 9: scans.DeleteScanResponse.Scans:type_name -> scan.Run
	0,  // 10: scans.Scans.Create:input_type -> scans.CreateScanRequest
	2,  // 11: scans.Scans.Read:input_type -> scans.ReadScanRequest
	2,  // 12: scans.Scans.List:input_type -> scans.ReadScanRequest
	6,  // 13: scans.Scans.Upsert:input_type -> scans.UpsertScanRequest
	8,  // 14: scans.Scans.Delete:input_type -> scans.DeleteScanRequest
	1,  // 15: scans.Scans.Create:output_type -> scans.CreateScanResponse
	3,  // 16: scans.Scans.Read:output_type -> scans.ReadScanResponse
	3,  // 17: scans.Scans.List:output_type -> scans.ReadScanResponse
	7,  // 18: scans.Scans.Upsert:output_type -> scans.UpsertScanResponse
	9,  // 19: scans.Scans.Delete:output_type -> scans.DeleteScanResponse
	15, // [15:20] is the sub-list for method output_type
	10, // [10:15] is the sub-list for method input_type
	10, // [10:10] is the sub-list for extension type_name
	10, // [10:10] is the sub-list for extension extendee
	0,  // [0:10] is the sub-list for field type_name
}

func init() { file_rpc_scans_scans_proto_init() }
func file_rpc_scans_scans_proto_init() {
	if File_rpc_scans_scans_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_rpc_scans_scans_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateScanRequest); i {
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
		file_rpc_scans_scans_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateScanResponse); i {
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
		file_rpc_scans_scans_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ReadScanRequest); i {
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
		file_rpc_scans_scans_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ReadScanResponse); i {
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
		file_rpc_scans_scans_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ReadScanManyRequest); i {
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
		file_rpc_scans_scans_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ReadScanManyResponse); i {
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
		file_rpc_scans_scans_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpsertScanRequest); i {
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
		file_rpc_scans_scans_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpsertScanResponse); i {
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
		file_rpc_scans_scans_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeleteScanRequest); i {
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
		file_rpc_scans_scans_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeleteScanResponse); i {
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
			RawDescriptor: file_rpc_scans_scans_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   10,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_rpc_scans_scans_proto_goTypes,
		DependencyIndexes: file_rpc_scans_scans_proto_depIdxs,
		MessageInfos:      file_rpc_scans_scans_proto_msgTypes,
	}.Build()
	File_rpc_scans_scans_proto = out.File
	file_rpc_scans_scans_proto_rawDesc = nil
	file_rpc_scans_scans_proto_goTypes = nil
	file_rpc_scans_scans_proto_depIdxs = nil
}
