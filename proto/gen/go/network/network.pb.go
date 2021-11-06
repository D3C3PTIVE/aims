// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v3.18.1
// source: network/network.proto

package network

import (
	_ "github.com/infobloxopen/protoc-gen-gorm/options"
	types "github.com/infobloxopen/protoc-gen-gorm/types"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Trace - Represents the trace to a host, including the hops
type Trace struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// @gotags: display:"ID" readonly:"true"
	Id *types.UUID `protobuf:"bytes,1,opt,name=Id,proto3" json:"Id,omitempty" display:"ID" readonly:"true"`
	// @gotags: xml:"proto,attr"
	Protocol string `protobuf:"bytes,10,opt,name=Protocol,proto3" json:"Protocol,omitempty" xml:"proto,attr"`
	// @gotags: xml:"port,attr"
	Port int32 `protobuf:"varint,11,opt,name=Port,proto3" json:"Port,omitempty" xml:"port,attr"`
	// @gotags: xml:"hop"
	Hops []*Hop `protobuf:"bytes,12,rep,name=Hops,proto3" json:"Hops,omitempty" xml:"hop"`
}

func (x *Trace) Reset() {
	*x = Trace{}
	if protoimpl.UnsafeEnabled {
		mi := &file_network_network_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Trace) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Trace) ProtoMessage() {}

func (x *Trace) ProtoReflect() protoreflect.Message {
	mi := &file_network_network_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Trace.ProtoReflect.Descriptor instead.
func (*Trace) Descriptor() ([]byte, []int) {
	return file_network_network_proto_rawDescGZIP(), []int{0}
}

func (x *Trace) GetId() *types.UUID {
	if x != nil {
		return x.Id
	}
	return nil
}

func (x *Trace) GetProtocol() string {
	if x != nil {
		return x.Protocol
	}
	return ""
}

func (x *Trace) GetPort() int32 {
	if x != nil {
		return x.Port
	}
	return 0
}

func (x *Trace) GetHops() []*Hop {
	if x != nil {
		return x.Hops
	}
	return nil
}

// Hop - An IP hop to a host
type Hop struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// @gotags: display:"ID" readonly:"true"
	Id *types.UUID `protobuf:"bytes,1,opt,name=Id,proto3" json:"Id,omitempty" display:"ID" readonly:"true"`
	// @gotags: xml:"ttl,attr"
	TTL float32 `protobuf:"fixed32,11,opt,name=TTL,proto3" json:"TTL,omitempty" xml:"ttl,attr"`
	// @gotags: xml:"rtt,attr"
	RTT string `protobuf:"bytes,12,opt,name=RTT,proto3" json:"RTT,omitempty" xml:"rtt,attr"`
	// @gotags: xml:"ipaddr,attr"
	IPAddr string `protobuf:"bytes,13,opt,name=IPAddr,proto3" json:"IPAddr,omitempty" xml:"ipaddr,attr"`
	// @gotags: xml:"host,attr"
	Host string `protobuf:"bytes,14,opt,name=Host,proto3" json:"Host,omitempty" xml:"host,attr"`
}

func (x *Hop) Reset() {
	*x = Hop{}
	if protoimpl.UnsafeEnabled {
		mi := &file_network_network_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Hop) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Hop) ProtoMessage() {}

func (x *Hop) ProtoReflect() protoreflect.Message {
	mi := &file_network_network_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Hop.ProtoReflect.Descriptor instead.
func (*Hop) Descriptor() ([]byte, []int) {
	return file_network_network_proto_rawDescGZIP(), []int{1}
}

func (x *Hop) GetId() *types.UUID {
	if x != nil {
		return x.Id
	}
	return nil
}

func (x *Hop) GetTTL() float32 {
	if x != nil {
		return x.TTL
	}
	return 0
}

func (x *Hop) GetRTT() string {
	if x != nil {
		return x.RTT
	}
	return ""
}

func (x *Hop) GetIPAddr() string {
	if x != nil {
		return x.IPAddr
	}
	return ""
}

func (x *Hop) GetHost() string {
	if x != nil {
		return x.Host
	}
	return ""
}

// Distance - The number of hops before reaching the host
type Distance struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// @gotags: xml:"value,attr"
	Value int32 `protobuf:"varint,1,opt,name=Value,proto3" json:"Value,omitempty" xml:"value,attr"`
}

func (x *Distance) Reset() {
	*x = Distance{}
	if protoimpl.UnsafeEnabled {
		mi := &file_network_network_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Distance) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Distance) ProtoMessage() {}

func (x *Distance) ProtoReflect() protoreflect.Message {
	mi := &file_network_network_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Distance.ProtoReflect.Descriptor instead.
func (*Distance) Descriptor() ([]byte, []int) {
	return file_network_network_proto_rawDescGZIP(), []int{2}
}

func (x *Distance) GetValue() int32 {
	if x != nil {
		return x.Value
	}
	return 0
}

// Address - A network address
type Address struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// @gotags: display:"ID" readonly:"true"
	Id *types.UUID `protobuf:"bytes,1,opt,name=Id,proto3" json:"Id,omitempty" display:"ID" readonly:"true"`
	// @gotags: display:"Created at" readonly:"true"
	CreatedAt *timestamppb.Timestamp `protobuf:"bytes,4,opt,name=CreatedAt,proto3" json:"CreatedAt,omitempty" display:"Created at" readonly:"true"`
	// @gotags: display:"Updated at" readonly:"true"
	UpdatedAt *timestamppb.Timestamp `protobuf:"bytes,5,opt,name=UpdatedAt,proto3" json:"UpdatedAt,omitempty" display:"Updated at" readonly:"true"` // -------------------------------------
	// @gotags: xml:"addr,attr"
	IP string `protobuf:"bytes,10,opt,name=IP,proto3" json:"IP,omitempty" xml:"addr,attr"`
	// @gotags: xml:"addrtype,attr"
	Type string `protobuf:"bytes,11,opt,name=Type,proto3" json:"Type,omitempty" xml:"addrtype,attr"`
	// @gotags: xml:"vendor,attr"
	Vendor string `protobuf:"bytes,12,opt,name=Vendor,proto3" json:"Vendor,omitempty" xml:"vendor,attr"`
	// We might have two subnets 192.168.1.1/24. How to know, when adding a host,
	// to which subnet it belongs ? We need to check a few things:
	// - Gateway for each address
	Gateway string `protobuf:"bytes,13,opt,name=Gateway,proto3" json:"Gateway,omitempty"`
}

func (x *Address) Reset() {
	*x = Address{}
	if protoimpl.UnsafeEnabled {
		mi := &file_network_network_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Address) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Address) ProtoMessage() {}

func (x *Address) ProtoReflect() protoreflect.Message {
	mi := &file_network_network_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Address.ProtoReflect.Descriptor instead.
func (*Address) Descriptor() ([]byte, []int) {
	return file_network_network_proto_rawDescGZIP(), []int{3}
}

func (x *Address) GetId() *types.UUID {
	if x != nil {
		return x.Id
	}
	return nil
}

func (x *Address) GetCreatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.CreatedAt
	}
	return nil
}

func (x *Address) GetUpdatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.UpdatedAt
	}
	return nil
}

func (x *Address) GetIP() string {
	if x != nil {
		return x.IP
	}
	return ""
}

func (x *Address) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *Address) GetVendor() string {
	if x != nil {
		return x.Vendor
	}
	return ""
}

func (x *Address) GetGateway() string {
	if x != nil {
		return x.Gateway
	}
	return ""
}

var File_network_network_proto protoreflect.FileDescriptor

var file_network_network_proto_rawDesc = []byte{
	0x0a, 0x15, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2f, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72,
	0x6b, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x07, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b,
	0x1a, 0x12, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x67, 0x6f, 0x72, 0x6d, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x11, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2f, 0x74, 0x79, 0x70, 0x65,
	0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61,
	0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x9b, 0x01, 0x0a, 0x05, 0x54, 0x72, 0x61,
	0x63, 0x65, 0x12, 0x30, 0x0a, 0x02, 0x49, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10,
	0x2e, 0x67, 0x6f, 0x72, 0x6d, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x55, 0x55, 0x49, 0x44,
	0x42, 0x0e, 0xba, 0xb9, 0x19, 0x0a, 0x0a, 0x08, 0x12, 0x04, 0x75, 0x75, 0x69, 0x64, 0x28, 0x01,
	0x52, 0x02, 0x49, 0x64, 0x12, 0x1a, 0x0a, 0x08, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c,
	0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c,
	0x12, 0x12, 0x0a, 0x04, 0x50, 0x6f, 0x72, 0x74, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x05, 0x52, 0x04,
	0x50, 0x6f, 0x72, 0x74, 0x12, 0x28, 0x0a, 0x04, 0x48, 0x6f, 0x70, 0x73, 0x18, 0x0c, 0x20, 0x03,
	0x28, 0x0b, 0x32, 0x0c, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2e, 0x48, 0x6f, 0x70,
	0x42, 0x06, 0xba, 0xb9, 0x19, 0x02, 0x22, 0x00, 0x52, 0x04, 0x48, 0x6f, 0x70, 0x73, 0x3a, 0x06,
	0xba, 0xb9, 0x19, 0x02, 0x08, 0x01, 0x22, 0x8f, 0x01, 0x0a, 0x03, 0x48, 0x6f, 0x70, 0x12, 0x30,
	0x0a, 0x02, 0x49, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x67, 0x6f, 0x72,
	0x6d, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x55, 0x55, 0x49, 0x44, 0x42, 0x0e, 0xba, 0xb9,
	0x19, 0x0a, 0x0a, 0x08, 0x12, 0x04, 0x75, 0x75, 0x69, 0x64, 0x28, 0x01, 0x52, 0x02, 0x49, 0x64,
	0x12, 0x10, 0x0a, 0x03, 0x54, 0x54, 0x4c, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x02, 0x52, 0x03, 0x54,
	0x54, 0x4c, 0x12, 0x10, 0x0a, 0x03, 0x52, 0x54, 0x54, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x03, 0x52, 0x54, 0x54, 0x12, 0x16, 0x0a, 0x06, 0x49, 0x50, 0x41, 0x64, 0x64, 0x72, 0x18, 0x0d,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x49, 0x50, 0x41, 0x64, 0x64, 0x72, 0x12, 0x12, 0x0a, 0x04,
	0x48, 0x6f, 0x73, 0x74, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x48, 0x6f, 0x73, 0x74,
	0x3a, 0x06, 0xba, 0xb9, 0x19, 0x02, 0x08, 0x01, 0x22, 0x20, 0x0a, 0x08, 0x44, 0x69, 0x73, 0x74,
	0x61, 0x6e, 0x63, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x05, 0x52, 0x05, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x22, 0x8d, 0x02, 0x0a, 0x07, 0x41,
	0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x30, 0x0a, 0x02, 0x49, 0x64, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x10, 0x2e, 0x67, 0x6f, 0x72, 0x6d, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e,
	0x55, 0x55, 0x49, 0x44, 0x42, 0x0e, 0xba, 0xb9, 0x19, 0x0a, 0x0a, 0x08, 0x12, 0x04, 0x75, 0x75,
	0x69, 0x64, 0x28, 0x01, 0x52, 0x02, 0x49, 0x64, 0x12, 0x38, 0x0a, 0x09, 0x43, 0x72, 0x65, 0x61,
	0x74, 0x65, 0x64, 0x41, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69,
	0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64,
	0x41, 0x74, 0x12, 0x38, 0x0a, 0x09, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x18,
	0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d,
	0x70, 0x52, 0x09, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x12, 0x0e, 0x0a, 0x02,
	0x49, 0x50, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x49, 0x50, 0x12, 0x12, 0x0a, 0x04,
	0x54, 0x79, 0x70, 0x65, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x54, 0x79, 0x70, 0x65,
	0x12, 0x16, 0x0a, 0x06, 0x56, 0x65, 0x6e, 0x64, 0x6f, 0x72, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x06, 0x56, 0x65, 0x6e, 0x64, 0x6f, 0x72, 0x12, 0x18, 0x0a, 0x07, 0x47, 0x61, 0x74, 0x65,
	0x77, 0x61, 0x79, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x47, 0x61, 0x74, 0x65, 0x77,
	0x61, 0x79, 0x3a, 0x06, 0xba, 0xb9, 0x19, 0x02, 0x08, 0x01, 0x42, 0x87, 0x01, 0x0a, 0x0b, 0x63,
	0x6f, 0x6d, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x42, 0x0c, 0x4e, 0x65, 0x74, 0x77,
	0x6f, 0x72, 0x6b, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x2e, 0x67, 0x69, 0x74, 0x68,
	0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6d, 0x61, 0x78, 0x6c, 0x61, 0x6e, 0x64, 0x6f, 0x6e,
	0x2f, 0x61, 0x69, 0x6d, 0x73, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x65, 0x6e, 0x2f,
	0x67, 0x6f, 0x2f, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0xa2, 0x02, 0x03, 0x4e, 0x58, 0x58,
	0xaa, 0x02, 0x07, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0xca, 0x02, 0x07, 0x4e, 0x65, 0x74,
	0x77, 0x6f, 0x72, 0x6b, 0xe2, 0x02, 0x13, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x5c, 0x47,
	0x50, 0x42, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0xea, 0x02, 0x07, 0x4e, 0x65, 0x74,
	0x77, 0x6f, 0x72, 0x6b, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_network_network_proto_rawDescOnce sync.Once
	file_network_network_proto_rawDescData = file_network_network_proto_rawDesc
)

func file_network_network_proto_rawDescGZIP() []byte {
	file_network_network_proto_rawDescOnce.Do(func() {
		file_network_network_proto_rawDescData = protoimpl.X.CompressGZIP(file_network_network_proto_rawDescData)
	})
	return file_network_network_proto_rawDescData
}

var file_network_network_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_network_network_proto_goTypes = []interface{}{
	(*Trace)(nil),                 // 0: network.Trace
	(*Hop)(nil),                   // 1: network.Hop
	(*Distance)(nil),              // 2: network.Distance
	(*Address)(nil),               // 3: network.Address
	(*types.UUID)(nil),            // 4: gorm.types.UUID
	(*timestamppb.Timestamp)(nil), // 5: google.protobuf.Timestamp
}
var file_network_network_proto_depIdxs = []int32{
	4, // 0: network.Trace.Id:type_name -> gorm.types.UUID
	1, // 1: network.Trace.Hops:type_name -> network.Hop
	4, // 2: network.Hop.Id:type_name -> gorm.types.UUID
	4, // 3: network.Address.Id:type_name -> gorm.types.UUID
	5, // 4: network.Address.CreatedAt:type_name -> google.protobuf.Timestamp
	5, // 5: network.Address.UpdatedAt:type_name -> google.protobuf.Timestamp
	6, // [6:6] is the sub-list for method output_type
	6, // [6:6] is the sub-list for method input_type
	6, // [6:6] is the sub-list for extension type_name
	6, // [6:6] is the sub-list for extension extendee
	0, // [0:6] is the sub-list for field type_name
}

func init() { file_network_network_proto_init() }
func file_network_network_proto_init() {
	if File_network_network_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_network_network_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Trace); i {
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
		file_network_network_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Hop); i {
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
		file_network_network_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Distance); i {
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
		file_network_network_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Address); i {
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
			RawDescriptor: file_network_network_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_network_network_proto_goTypes,
		DependencyIndexes: file_network_network_proto_depIdxs,
		MessageInfos:      file_network_network_proto_msgTypes,
	}.Build()
	File_network_network_proto = out.File
	file_network_network_proto_rawDesc = nil
	file_network_network_proto_goTypes = nil
	file_network_network_proto_depIdxs = nil
}
