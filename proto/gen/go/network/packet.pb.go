// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v3.18.1
// source: network/packet.proto

package network

import (
	_ "github.com/infobloxopen/protoc-gen-gorm/options"
	types "github.com/infobloxopen/protoc-gen-gorm/types"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	_ "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// ICMPType - The general type of ICMP response received from a host.
type ICMPType int32

const (
	ICMPType_EchoReply ICMPType = 0
	// 1 and 2 reserved
	ICMPType_DestinationUnreachable ICMPType = 3
	ICMPType_SourceQuench           ICMPType = 4 // Deprecated
	ICMPType_RedirectMessage        ICMPType = 5
	// 6 deprecated
	// 7 reserved
	ICMPType_EchoRequest         ICMPType = 8
	ICMPType_RouterAdvertisement ICMPType = 9
	ICMPType_RouterSolicitation  ICMPType = 10
	ICMPType_TimeExceeded        ICMPType = 11
	ICMPType_BadIPHeader         ICMPType = 12
	ICMPType_Timestamp           ICMPType = 13
	ICMPType_TimestampReply      ICMPType = 14
	// 15-18 deprecated
	// 19,20-29 reserved
	// 30-39 deprecated
	ICMPType_Photuris            ICMPType = 40
	ICMPType_MobilityProto       ICMPType = 41 // Experimental
	ICMPType_ExtendedEchoRequest ICMPType = 42
	ICMPType_ExtendedEchoReply   ICMPType = 43
	// 44-252 reserved
	ICMPType_RFC3692Experiment1 ICMPType = 253
	ICMPType_RFC3692Experiment2 ICMPType = 254 // 255 reserved
)

// Enum value maps for ICMPType.
var (
	ICMPType_name = map[int32]string{
		0:   "EchoReply",
		3:   "DestinationUnreachable",
		4:   "SourceQuench",
		5:   "RedirectMessage",
		8:   "EchoRequest",
		9:   "RouterAdvertisement",
		10:  "RouterSolicitation",
		11:  "TimeExceeded",
		12:  "BadIPHeader",
		13:  "Timestamp",
		14:  "TimestampReply",
		40:  "Photuris",
		41:  "MobilityProto",
		42:  "ExtendedEchoRequest",
		43:  "ExtendedEchoReply",
		253: "RFC3692Experiment1",
		254: "RFC3692Experiment2",
	}
	ICMPType_value = map[string]int32{
		"EchoReply":              0,
		"DestinationUnreachable": 3,
		"SourceQuench":           4,
		"RedirectMessage":        5,
		"EchoRequest":            8,
		"RouterAdvertisement":    9,
		"RouterSolicitation":     10,
		"TimeExceeded":           11,
		"BadIPHeader":            12,
		"Timestamp":              13,
		"TimestampReply":         14,
		"Photuris":               40,
		"MobilityProto":          41,
		"ExtendedEchoRequest":    42,
		"ExtendedEchoReply":      43,
		"RFC3692Experiment1":     253,
		"RFC3692Experiment2":     254,
	}
)

func (x ICMPType) Enum() *ICMPType {
	p := new(ICMPType)
	*p = x
	return p
}

func (x ICMPType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ICMPType) Descriptor() protoreflect.EnumDescriptor {
	return file_network_packet_proto_enumTypes[0].Descriptor()
}

func (ICMPType) Type() protoreflect.EnumType {
	return &file_network_packet_proto_enumTypes[0]
}

func (x ICMPType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ICMPType.Descriptor instead.
func (ICMPType) EnumDescriptor() ([]byte, []int) {
	return file_network_packet_proto_rawDescGZIP(), []int{0}
}

// Sequence - Represents a detected Sequence
type Sequence struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id *types.UUID `protobuf:"bytes,1,opt,name=Id,proto3" json:"Id,omitempty"`
	// @gotags: xml:"class,attr"
	Class string `protobuf:"bytes,10,opt,name=Class,proto3" json:"Class,omitempty" xml:"class,attr"`
	// @gotags: xml:"values,attr"
	Values string `protobuf:"bytes,11,opt,name=Values,proto3" json:"Values,omitempty" xml:"values,attr"`
}

func (x *Sequence) Reset() {
	*x = Sequence{}
	if protoimpl.UnsafeEnabled {
		mi := &file_network_packet_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Sequence) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Sequence) ProtoMessage() {}

func (x *Sequence) ProtoReflect() protoreflect.Message {
	mi := &file_network_packet_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Sequence.ProtoReflect.Descriptor instead.
func (*Sequence) Descriptor() ([]byte, []int) {
	return file_network_packet_proto_rawDescGZIP(), []int{0}
}

func (x *Sequence) GetId() *types.UUID {
	if x != nil {
		return x.Id
	}
	return nil
}

func (x *Sequence) GetClass() string {
	if x != nil {
		return x.Class
	}
	return ""
}

func (x *Sequence) GetValues() string {
	if x != nil {
		return x.Values
	}
	return ""
}

// TCPSequence - Represents a detected TCP Sequence
type TCPSequence struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id *types.UUID `protobuf:"bytes,1,opt,name=Id,proto3" json:"Id,omitempty"`
	// @gotags: xml:"index,attr"
	Index int32 `protobuf:"varint,10,opt,name=Index,proto3" json:"Index,omitempty" xml:"index,attr"`
	// @gotags: xml:"difficulty,attr"
	Difficulty string `protobuf:"bytes,11,opt,name=Difficulty,proto3" json:"Difficulty,omitempty" xml:"difficulty,attr"`
	// @gotags: xml:"values,attr"
	Values string `protobuf:"bytes,12,opt,name=Values,proto3" json:"Values,omitempty" xml:"values,attr"`
}

func (x *TCPSequence) Reset() {
	*x = TCPSequence{}
	if protoimpl.UnsafeEnabled {
		mi := &file_network_packet_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TCPSequence) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TCPSequence) ProtoMessage() {}

func (x *TCPSequence) ProtoReflect() protoreflect.Message {
	mi := &file_network_packet_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TCPSequence.ProtoReflect.Descriptor instead.
func (*TCPSequence) Descriptor() ([]byte, []int) {
	return file_network_packet_proto_rawDescGZIP(), []int{1}
}

func (x *TCPSequence) GetId() *types.UUID {
	if x != nil {
		return x.Id
	}
	return nil
}

func (x *TCPSequence) GetIndex() int32 {
	if x != nil {
		return x.Index
	}
	return 0
}

func (x *TCPSequence) GetDifficulty() string {
	if x != nil {
		return x.Difficulty
	}
	return ""
}

func (x *TCPSequence) GetValues() string {
	if x != nil {
		return x.Values
	}
	return ""
}

// IPIDSequence - Represents a detected IP ID Sequence
type IPIDSequence struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id *types.UUID `protobuf:"bytes,1,opt,name=Id,proto3" json:"Id,omitempty"`
	// @gotags: xml:"index,attr"
	Index int32 `protobuf:"varint,10,opt,name=Index,proto3" json:"Index,omitempty" xml:"index,attr"`
	// @gotags: xml:"difficulty,attr"
	Difficulty string `protobuf:"bytes,11,opt,name=Difficulty,proto3" json:"Difficulty,omitempty" xml:"difficulty,attr"`
	// @gotags: xml:"values,attr"
	Values string `protobuf:"bytes,12,opt,name=Values,proto3" json:"Values,omitempty" xml:"values,attr"`
}

func (x *IPIDSequence) Reset() {
	*x = IPIDSequence{}
	if protoimpl.UnsafeEnabled {
		mi := &file_network_packet_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IPIDSequence) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IPIDSequence) ProtoMessage() {}

func (x *IPIDSequence) ProtoReflect() protoreflect.Message {
	mi := &file_network_packet_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IPIDSequence.ProtoReflect.Descriptor instead.
func (*IPIDSequence) Descriptor() ([]byte, []int) {
	return file_network_packet_proto_rawDescGZIP(), []int{2}
}

func (x *IPIDSequence) GetId() *types.UUID {
	if x != nil {
		return x.Id
	}
	return nil
}

func (x *IPIDSequence) GetIndex() int32 {
	if x != nil {
		return x.Index
	}
	return 0
}

func (x *IPIDSequence) GetDifficulty() string {
	if x != nil {
		return x.Difficulty
	}
	return ""
}

func (x *IPIDSequence) GetValues() string {
	if x != nil {
		return x.Values
	}
	return ""
}

// TCPTSSequence - Represents a detected TCP TS Sequence
type TCPTSSequence struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id *types.UUID `protobuf:"bytes,1,opt,name=Id,proto3" json:"Id,omitempty"`
	// @gotags: xml:"index,attr"
	Index int32 `protobuf:"varint,10,opt,name=Index,proto3" json:"Index,omitempty" xml:"index,attr"`
	// @gotags: xml:"difficulty,attr"
	Difficulty string `protobuf:"bytes,11,opt,name=Difficulty,proto3" json:"Difficulty,omitempty" xml:"difficulty,attr"`
	// @gotags: xml:"values,attr"
	Values string `protobuf:"bytes,12,opt,name=Values,proto3" json:"Values,omitempty" xml:"values,attr"`
}

func (x *TCPTSSequence) Reset() {
	*x = TCPTSSequence{}
	if protoimpl.UnsafeEnabled {
		mi := &file_network_packet_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TCPTSSequence) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TCPTSSequence) ProtoMessage() {}

func (x *TCPTSSequence) ProtoReflect() protoreflect.Message {
	mi := &file_network_packet_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TCPTSSequence.ProtoReflect.Descriptor instead.
func (*TCPTSSequence) Descriptor() ([]byte, []int) {
	return file_network_packet_proto_rawDescGZIP(), []int{3}
}

func (x *TCPTSSequence) GetId() *types.UUID {
	if x != nil {
		return x.Id
	}
	return nil
}

func (x *TCPTSSequence) GetIndex() int32 {
	if x != nil {
		return x.Index
	}
	return 0
}

func (x *TCPTSSequence) GetDifficulty() string {
	if x != nil {
		return x.Difficulty
	}
	return ""
}

func (x *TCPTSSequence) GetValues() string {
	if x != nil {
		return x.Values
	}
	return ""
}

// ICMPResponse - An ICMP response sent by a remote host.
// The TTL given by the response is stored in the Host object
// or the Scan Run object, but is not related to ICMP in anyway.
type ICMPResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Type - The type of response that we received,
	// determines how to interpret the .Code given
	// with it.
	Type ICMPType `protobuf:"varint,1,opt,name=Type,proto3,enum=network.ICMPType" json:"Type,omitempty"`
	// Code - The precise "status" given along with its .ICMPType.
	// The Go generated package also contains a map with many of
	// these codes and their corresponding descriptions.
	Code uint32 `protobuf:"varint,2,opt,name=Code,proto3" json:"Code,omitempty"`
}

func (x *ICMPResponse) Reset() {
	*x = ICMPResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_network_packet_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ICMPResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ICMPResponse) ProtoMessage() {}

func (x *ICMPResponse) ProtoReflect() protoreflect.Message {
	mi := &file_network_packet_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ICMPResponse.ProtoReflect.Descriptor instead.
func (*ICMPResponse) Descriptor() ([]byte, []int) {
	return file_network_packet_proto_rawDescGZIP(), []int{4}
}

func (x *ICMPResponse) GetType() ICMPType {
	if x != nil {
		return x.Type
	}
	return ICMPType_EchoReply
}

func (x *ICMPResponse) GetCode() uint32 {
	if x != nil {
		return x.Code
	}
	return 0
}

var File_network_packet_proto protoreflect.FileDescriptor

var file_network_packet_proto_rawDesc = []byte{
	0x0a, 0x14, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2f, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x74,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x07, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x1a,
	0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x1a, 0x12, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x67, 0x6f, 0x72, 0x6d, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x11, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2f, 0x74, 0x79, 0x70, 0x65,
	0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x72, 0x0a, 0x08, 0x53, 0x65, 0x71, 0x75, 0x65,
	0x6e, 0x63, 0x65, 0x12, 0x30, 0x0a, 0x02, 0x49, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x10, 0x2e, 0x67, 0x6f, 0x72, 0x6d, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x55, 0x55, 0x49,
	0x44, 0x42, 0x0e, 0xba, 0xb9, 0x19, 0x0a, 0x0a, 0x08, 0x12, 0x04, 0x75, 0x75, 0x69, 0x64, 0x28,
	0x01, 0x52, 0x02, 0x49, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x18, 0x0a,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x12, 0x16, 0x0a, 0x06, 0x56,
	0x61, 0x6c, 0x75, 0x65, 0x73, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x56, 0x61, 0x6c,
	0x75, 0x65, 0x73, 0x3a, 0x06, 0xba, 0xb9, 0x19, 0x02, 0x08, 0x01, 0x22, 0x95, 0x01, 0x0a, 0x0b,
	0x54, 0x43, 0x50, 0x53, 0x65, 0x71, 0x75, 0x65, 0x6e, 0x63, 0x65, 0x12, 0x30, 0x0a, 0x02, 0x49,
	0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x67, 0x6f, 0x72, 0x6d, 0x2e, 0x74,
	0x79, 0x70, 0x65, 0x73, 0x2e, 0x55, 0x55, 0x49, 0x44, 0x42, 0x0e, 0xba, 0xb9, 0x19, 0x0a, 0x0a,
	0x08, 0x12, 0x04, 0x75, 0x75, 0x69, 0x64, 0x28, 0x01, 0x52, 0x02, 0x49, 0x64, 0x12, 0x14, 0x0a,
	0x05, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x05, 0x52, 0x05, 0x49, 0x6e,
	0x64, 0x65, 0x78, 0x12, 0x1e, 0x0a, 0x0a, 0x44, 0x69, 0x66, 0x66, 0x69, 0x63, 0x75, 0x6c, 0x74,
	0x79, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x44, 0x69, 0x66, 0x66, 0x69, 0x63, 0x75,
	0x6c, 0x74, 0x79, 0x12, 0x16, 0x0a, 0x06, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x18, 0x0c, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x06, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x3a, 0x06, 0xba, 0xb9, 0x19,
	0x02, 0x08, 0x01, 0x22, 0x96, 0x01, 0x0a, 0x0c, 0x49, 0x50, 0x49, 0x44, 0x53, 0x65, 0x71, 0x75,
	0x65, 0x6e, 0x63, 0x65, 0x12, 0x30, 0x0a, 0x02, 0x49, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x10, 0x2e, 0x67, 0x6f, 0x72, 0x6d, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x55, 0x55,
	0x49, 0x44, 0x42, 0x0e, 0xba, 0xb9, 0x19, 0x0a, 0x0a, 0x08, 0x12, 0x04, 0x75, 0x75, 0x69, 0x64,
	0x28, 0x01, 0x52, 0x02, 0x49, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x18,
	0x0a, 0x20, 0x01, 0x28, 0x05, 0x52, 0x05, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x12, 0x1e, 0x0a, 0x0a,
	0x44, 0x69, 0x66, 0x66, 0x69, 0x63, 0x75, 0x6c, 0x74, 0x79, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x0a, 0x44, 0x69, 0x66, 0x66, 0x69, 0x63, 0x75, 0x6c, 0x74, 0x79, 0x12, 0x16, 0x0a, 0x06,
	0x56, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x56, 0x61,
	0x6c, 0x75, 0x65, 0x73, 0x3a, 0x06, 0xba, 0xb9, 0x19, 0x02, 0x08, 0x01, 0x22, 0x97, 0x01, 0x0a,
	0x0d, 0x54, 0x43, 0x50, 0x54, 0x53, 0x53, 0x65, 0x71, 0x75, 0x65, 0x6e, 0x63, 0x65, 0x12, 0x30,
	0x0a, 0x02, 0x49, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x67, 0x6f, 0x72,
	0x6d, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x55, 0x55, 0x49, 0x44, 0x42, 0x0e, 0xba, 0xb9,
	0x19, 0x0a, 0x0a, 0x08, 0x12, 0x04, 0x75, 0x75, 0x69, 0x64, 0x28, 0x01, 0x52, 0x02, 0x49, 0x64,
	0x12, 0x14, 0x0a, 0x05, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x05, 0x52,
	0x05, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x12, 0x1e, 0x0a, 0x0a, 0x44, 0x69, 0x66, 0x66, 0x69, 0x63,
	0x75, 0x6c, 0x74, 0x79, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x44, 0x69, 0x66, 0x66,
	0x69, 0x63, 0x75, 0x6c, 0x74, 0x79, 0x12, 0x16, 0x0a, 0x06, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x73,
	0x18, 0x0c, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x3a, 0x06,
	0xba, 0xb9, 0x19, 0x02, 0x08, 0x01, 0x22, 0x49, 0x0a, 0x0c, 0x49, 0x43, 0x4d, 0x50, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x25, 0x0a, 0x04, 0x54, 0x79, 0x70, 0x65, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0e, 0x32, 0x11, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2e, 0x49,
	0x43, 0x4d, 0x50, 0x54, 0x79, 0x70, 0x65, 0x52, 0x04, 0x54, 0x79, 0x70, 0x65, 0x12, 0x12, 0x0a,
	0x04, 0x43, 0x6f, 0x64, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x04, 0x43, 0x6f, 0x64,
	0x65, 0x2a, 0xe7, 0x02, 0x0a, 0x08, 0x49, 0x43, 0x4d, 0x50, 0x54, 0x79, 0x70, 0x65, 0x12, 0x0d,
	0x0a, 0x09, 0x45, 0x63, 0x68, 0x6f, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x10, 0x00, 0x12, 0x1a, 0x0a,
	0x16, 0x44, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x55, 0x6e, 0x72, 0x65,
	0x61, 0x63, 0x68, 0x61, 0x62, 0x6c, 0x65, 0x10, 0x03, 0x12, 0x10, 0x0a, 0x0c, 0x53, 0x6f, 0x75,
	0x72, 0x63, 0x65, 0x51, 0x75, 0x65, 0x6e, 0x63, 0x68, 0x10, 0x04, 0x12, 0x13, 0x0a, 0x0f, 0x52,
	0x65, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x10, 0x05,
	0x12, 0x0f, 0x0a, 0x0b, 0x45, 0x63, 0x68, 0x6f, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x10,
	0x08, 0x12, 0x17, 0x0a, 0x13, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x41, 0x64, 0x76, 0x65, 0x72,
	0x74, 0x69, 0x73, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x10, 0x09, 0x12, 0x16, 0x0a, 0x12, 0x52, 0x6f,
	0x75, 0x74, 0x65, 0x72, 0x53, 0x6f, 0x6c, 0x69, 0x63, 0x69, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x10, 0x0a, 0x12, 0x10, 0x0a, 0x0c, 0x54, 0x69, 0x6d, 0x65, 0x45, 0x78, 0x63, 0x65, 0x65, 0x64,
	0x65, 0x64, 0x10, 0x0b, 0x12, 0x0f, 0x0a, 0x0b, 0x42, 0x61, 0x64, 0x49, 0x50, 0x48, 0x65, 0x61,
	0x64, 0x65, 0x72, 0x10, 0x0c, 0x12, 0x0d, 0x0a, 0x09, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61,
	0x6d, 0x70, 0x10, 0x0d, 0x12, 0x12, 0x0a, 0x0e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d,
	0x70, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x10, 0x0e, 0x12, 0x0c, 0x0a, 0x08, 0x50, 0x68, 0x6f, 0x74,
	0x75, 0x72, 0x69, 0x73, 0x10, 0x28, 0x12, 0x11, 0x0a, 0x0d, 0x4d, 0x6f, 0x62, 0x69, 0x6c, 0x69,
	0x74, 0x79, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x10, 0x29, 0x12, 0x17, 0x0a, 0x13, 0x45, 0x78, 0x74,
	0x65, 0x6e, 0x64, 0x65, 0x64, 0x45, 0x63, 0x68, 0x6f, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x10, 0x2a, 0x12, 0x15, 0x0a, 0x11, 0x45, 0x78, 0x74, 0x65, 0x6e, 0x64, 0x65, 0x64, 0x45, 0x63,
	0x68, 0x6f, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x10, 0x2b, 0x12, 0x17, 0x0a, 0x12, 0x52, 0x46, 0x43,
	0x33, 0x36, 0x39, 0x32, 0x45, 0x78, 0x70, 0x65, 0x72, 0x69, 0x6d, 0x65, 0x6e, 0x74, 0x31, 0x10,
	0xfd, 0x01, 0x12, 0x17, 0x0a, 0x12, 0x52, 0x46, 0x43, 0x33, 0x36, 0x39, 0x32, 0x45, 0x78, 0x70,
	0x65, 0x72, 0x69, 0x6d, 0x65, 0x6e, 0x74, 0x32, 0x10, 0xfe, 0x01, 0x42, 0x86, 0x01, 0x0a, 0x0b,
	0x63, 0x6f, 0x6d, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x42, 0x0b, 0x50, 0x61, 0x63,
	0x6b, 0x65, 0x74, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x2e, 0x67, 0x69, 0x74, 0x68,
	0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6d, 0x61, 0x78, 0x6c, 0x61, 0x6e, 0x64, 0x6f, 0x6e,
	0x2f, 0x61, 0x69, 0x6d, 0x73, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x65, 0x6e, 0x2f,
	0x67, 0x6f, 0x2f, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0xa2, 0x02, 0x03, 0x4e, 0x58, 0x58,
	0xaa, 0x02, 0x07, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0xca, 0x02, 0x07, 0x4e, 0x65, 0x74,
	0x77, 0x6f, 0x72, 0x6b, 0xe2, 0x02, 0x13, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x5c, 0x47,
	0x50, 0x42, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0xea, 0x02, 0x07, 0x4e, 0x65, 0x74,
	0x77, 0x6f, 0x72, 0x6b, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_network_packet_proto_rawDescOnce sync.Once
	file_network_packet_proto_rawDescData = file_network_packet_proto_rawDesc
)

func file_network_packet_proto_rawDescGZIP() []byte {
	file_network_packet_proto_rawDescOnce.Do(func() {
		file_network_packet_proto_rawDescData = protoimpl.X.CompressGZIP(file_network_packet_proto_rawDescData)
	})
	return file_network_packet_proto_rawDescData
}

var file_network_packet_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_network_packet_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_network_packet_proto_goTypes = []interface{}{
	(ICMPType)(0),         // 0: network.ICMPType
	(*Sequence)(nil),      // 1: network.Sequence
	(*TCPSequence)(nil),   // 2: network.TCPSequence
	(*IPIDSequence)(nil),  // 3: network.IPIDSequence
	(*TCPTSSequence)(nil), // 4: network.TCPTSSequence
	(*ICMPResponse)(nil),  // 5: network.ICMPResponse
	(*types.UUID)(nil),    // 6: gorm.types.UUID
}
var file_network_packet_proto_depIdxs = []int32{
	6, // 0: network.Sequence.Id:type_name -> gorm.types.UUID
	6, // 1: network.TCPSequence.Id:type_name -> gorm.types.UUID
	6, // 2: network.IPIDSequence.Id:type_name -> gorm.types.UUID
	6, // 3: network.TCPTSSequence.Id:type_name -> gorm.types.UUID
	0, // 4: network.ICMPResponse.Type:type_name -> network.ICMPType
	5, // [5:5] is the sub-list for method output_type
	5, // [5:5] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_network_packet_proto_init() }
func file_network_packet_proto_init() {
	if File_network_packet_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_network_packet_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Sequence); i {
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
		file_network_packet_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TCPSequence); i {
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
		file_network_packet_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IPIDSequence); i {
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
		file_network_packet_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TCPTSSequence); i {
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
		file_network_packet_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ICMPResponse); i {
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
			RawDescriptor: file_network_packet_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_network_packet_proto_goTypes,
		DependencyIndexes: file_network_packet_proto_depIdxs,
		EnumInfos:         file_network_packet_proto_enumTypes,
		MessageInfos:      file_network_packet_proto_msgTypes,
	}.Build()
	File_network_packet_proto = out.File
	file_network_packet_proto_rawDesc = nil
	file_network_packet_proto_goTypes = nil
	file_network_packet_proto_depIdxs = nil
}
