// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v3.18.1
// source: host/port.proto

package host

import (
	_ "github.com/infobloxopen/protoc-gen-gorm/options"
	types "github.com/infobloxopen/protoc-gen-gorm/types"
	network "github.com/maxlandon/aims/proto/gen/go/network"
	scan "github.com/maxlandon/aims/proto/gen/go/scan"
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

// Port - A port on a host
type Port struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// @gotags: display:"ID" readonly:"true"
	Id *types.UUID `protobuf:"bytes,1,opt,name=Id,proto3" json:"Id,omitempty" display:"ID" readonly:"true"`
	// @gotags: display:"Created at" readonly:"true"
	CreatedAt *timestamppb.Timestamp `protobuf:"bytes,4,opt,name=CreatedAt,proto3" json:"CreatedAt,omitempty" display:"Created at" readonly:"true"`
	// @gotags: display:"Updated at" readonly:"true"
	UpdatedAt *timestamppb.Timestamp `protobuf:"bytes,5,opt,name=UpdatedAt,proto3" json:"UpdatedAt,omitempty" display:"Updated at" readonly:"true"`
	// @gotags: xml:"portid,attr"
	Number uint32 `protobuf:"varint,10,opt,name=Number,proto3" json:"Number,omitempty" xml:"portid,attr"`
	// Nmap --------------------------------
	// @gotags: xml:"protocol,attr"
	Protocol string `protobuf:"bytes,11,opt,name=Protocol,proto3" json:"Protocol,omitempty" xml:"protocol,attr"`
	// @gotags: xml:"owner"
	Owner string `protobuf:"bytes,12,opt,name=Owner,proto3" json:"Owner,omitempty" xml:"owner"`
	// @gotags: xml:"service"
	Service *network.Service `protobuf:"bytes,13,opt,name=Service,proto3" json:"Service,omitempty" xml:"service"`
	// @gotags: xml:"state"
	State *State `protobuf:"bytes,14,opt,name=State,proto3" json:"State,omitempty" xml:"state"`
	// @gotags: xml:"script"
	Scripts []*scan.NmapScript `protobuf:"bytes,15,rep,name=Scripts,proto3" json:"Scripts,omitempty" xml:"script"`
	// @gotags: xml:"count"
	Count int32 `protobuf:"varint,20,opt,name=Count,proto3" json:"Count,omitempty" xml:"count"`
	// @gotags: xml:"extrareasons"
	Reasons []*Reason `protobuf:"bytes,21,rep,name=Reasons,proto3" json:"Reasons,omitempty" xml:"extrareasons"`
}

func (x *Port) Reset() {
	*x = Port{}
	if protoimpl.UnsafeEnabled {
		mi := &file_host_port_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Port) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Port) ProtoMessage() {}

func (x *Port) ProtoReflect() protoreflect.Message {
	mi := &file_host_port_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Port.ProtoReflect.Descriptor instead.
func (*Port) Descriptor() ([]byte, []int) {
	return file_host_port_proto_rawDescGZIP(), []int{0}
}

func (x *Port) GetId() *types.UUID {
	if x != nil {
		return x.Id
	}
	return nil
}

func (x *Port) GetCreatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.CreatedAt
	}
	return nil
}

func (x *Port) GetUpdatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.UpdatedAt
	}
	return nil
}

func (x *Port) GetNumber() uint32 {
	if x != nil {
		return x.Number
	}
	return 0
}

func (x *Port) GetProtocol() string {
	if x != nil {
		return x.Protocol
	}
	return ""
}

func (x *Port) GetOwner() string {
	if x != nil {
		return x.Owner
	}
	return ""
}

func (x *Port) GetService() *network.Service {
	if x != nil {
		return x.Service
	}
	return nil
}

func (x *Port) GetState() *State {
	if x != nil {
		return x.State
	}
	return nil
}

func (x *Port) GetScripts() []*scan.NmapScript {
	if x != nil {
		return x.Scripts
	}
	return nil
}

func (x *Port) GetCount() int32 {
	if x != nil {
		return x.Count
	}
	return 0
}

func (x *Port) GetReasons() []*Reason {
	if x != nil {
		return x.Reasons
	}
	return nil
}

// Reason - Extra information on a closed/filtered port
type Reason struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// @gotags: xml:"reason"
	Reason string `protobuf:"bytes,3,opt,name=Reason,proto3" json:"Reason,omitempty" xml:"reason"`
	// @gotags: xml:"count"
	Count int32 `protobuf:"varint,4,opt,name=Count,proto3" json:"Count,omitempty" xml:"count"`
}

func (x *Reason) Reset() {
	*x = Reason{}
	if protoimpl.UnsafeEnabled {
		mi := &file_host_port_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Reason) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Reason) ProtoMessage() {}

func (x *Reason) ProtoReflect() protoreflect.Message {
	mi := &file_host_port_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Reason.ProtoReflect.Descriptor instead.
func (*Reason) Descriptor() ([]byte, []int) {
	return file_host_port_proto_rawDescGZIP(), []int{1}
}

func (x *Reason) GetReason() string {
	if x != nil {
		return x.Reason
	}
	return ""
}

func (x *Reason) GetCount() int32 {
	if x != nil {
		return x.Count
	}
	return 0
}

// State - Contains information about a given's port status
type State struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// @gotags: display:"ID" readonly:"true"
	Id *types.UUID `protobuf:"bytes,1,opt,name=Id,proto3" json:"Id,omitempty" display:"ID" readonly:"true"`
	// @gotags: display:"Created at" readonly:"true"
	CreatedAt *timestamppb.Timestamp `protobuf:"bytes,4,opt,name=CreatedAt,proto3" json:"CreatedAt,omitempty" display:"Created at" readonly:"true"`
	// @gotags: display:"Updated at" readonly:"true"
	UpdatedAt *timestamppb.Timestamp `protobuf:"bytes,5,opt,name=UpdatedAt,proto3" json:"UpdatedAt,omitempty" display:"Updated at" readonly:"true"`
	// Nmap
	// @gotags: xml:"state,attr"
	State string `protobuf:"bytes,10,opt,name=State,proto3" json:"State,omitempty" xml:"state,attr"`
	// @gotags: xml:"reason,attr"
	Reason string `protobuf:"bytes,11,opt,name=Reason,proto3" json:"Reason,omitempty" xml:"reason,attr"`
	// @gotags: xml:"reason_ip,attr"
	ReasonIP string `protobuf:"bytes,12,opt,name=ReasonIP,proto3" json:"ReasonIP,omitempty" xml:"reason_ip,attr"`
	// @gotags: xml:"reason_ttl,attr"
	ReasonTTL float32 `protobuf:"fixed32,13,opt,name=ReasonTTL,proto3" json:"ReasonTTL,omitempty" xml:"reason_ttl,attr"`
}

func (x *State) Reset() {
	*x = State{}
	if protoimpl.UnsafeEnabled {
		mi := &file_host_port_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *State) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*State) ProtoMessage() {}

func (x *State) ProtoReflect() protoreflect.Message {
	mi := &file_host_port_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use State.ProtoReflect.Descriptor instead.
func (*State) Descriptor() ([]byte, []int) {
	return file_host_port_proto_rawDescGZIP(), []int{2}
}

func (x *State) GetId() *types.UUID {
	if x != nil {
		return x.Id
	}
	return nil
}

func (x *State) GetCreatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.CreatedAt
	}
	return nil
}

func (x *State) GetUpdatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.UpdatedAt
	}
	return nil
}

func (x *State) GetState() string {
	if x != nil {
		return x.State
	}
	return ""
}

func (x *State) GetReason() string {
	if x != nil {
		return x.Reason
	}
	return ""
}

func (x *State) GetReasonIP() string {
	if x != nil {
		return x.ReasonIP
	}
	return ""
}

func (x *State) GetReasonTTL() float32 {
	if x != nil {
		return x.ReasonTTL
	}
	return 0
}

var File_host_port_proto protoreflect.FileDescriptor

var file_host_port_proto_rawDesc = []byte{
	0x0a, 0x0f, 0x68, 0x6f, 0x73, 0x74, 0x2f, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61,
	0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x12, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x2f, 0x67, 0x6f, 0x72, 0x6d, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x11, 0x74, 0x79,
	0x70, 0x65, 0x73, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x15, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x0f, 0x73, 0x63, 0x61, 0x6e, 0x2f, 0x73, 0x63, 0x61,
	0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xc7, 0x03, 0x0a, 0x04, 0x50, 0x6f, 0x72, 0x74,
	0x12, 0x30, 0x0a, 0x02, 0x49, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x67,
	0x6f, 0x72, 0x6d, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x55, 0x55, 0x49, 0x44, 0x42, 0x0e,
	0xba, 0xb9, 0x19, 0x0a, 0x0a, 0x08, 0x12, 0x04, 0x75, 0x75, 0x69, 0x64, 0x28, 0x01, 0x52, 0x02,
	0x49, 0x64, 0x12, 0x38, 0x0a, 0x09, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d,
	0x70, 0x52, 0x09, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x12, 0x38, 0x0a, 0x09,
	0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x55, 0x70, 0x64,
	0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x12, 0x16, 0x0a, 0x06, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72,
	0x18, 0x0a, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x06, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x12, 0x1a,
	0x0a, 0x08, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x08, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x12, 0x14, 0x0a, 0x05, 0x4f, 0x77,
	0x6e, 0x65, 0x72, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x4f, 0x77, 0x6e, 0x65, 0x72,
	0x12, 0x2a, 0x0a, 0x07, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x18, 0x0d, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x10, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2e, 0x53, 0x65, 0x72, 0x76,
	0x69, 0x63, 0x65, 0x52, 0x07, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x21, 0x0a, 0x05,
	0x53, 0x74, 0x61, 0x74, 0x65, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0b, 0x2e, 0x68, 0x6f,
	0x73, 0x74, 0x2e, 0x53, 0x74, 0x61, 0x74, 0x65, 0x52, 0x05, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12,
	0x32, 0x0a, 0x07, 0x53, 0x63, 0x72, 0x69, 0x70, 0x74, 0x73, 0x18, 0x0f, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x10, 0x2e, 0x73, 0x63, 0x61, 0x6e, 0x2e, 0x4e, 0x6d, 0x61, 0x70, 0x53, 0x63, 0x72, 0x69,
	0x70, 0x74, 0x42, 0x06, 0xba, 0xb9, 0x19, 0x02, 0x32, 0x00, 0x52, 0x07, 0x53, 0x63, 0x72, 0x69,
	0x70, 0x74, 0x73, 0x12, 0x14, 0x0a, 0x05, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x14, 0x20, 0x01,
	0x28, 0x05, 0x52, 0x05, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x2e, 0x0a, 0x07, 0x52, 0x65, 0x61,
	0x73, 0x6f, 0x6e, 0x73, 0x18, 0x15, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0c, 0x2e, 0x68, 0x6f, 0x73,
	0x74, 0x2e, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x42, 0x06, 0xba, 0xb9, 0x19, 0x02, 0x22, 0x00,
	0x52, 0x07, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x73, 0x3a, 0x06, 0xba, 0xb9, 0x19, 0x02, 0x08,
	0x01, 0x22, 0x3e, 0x0a, 0x06, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x12, 0x16, 0x0a, 0x06, 0x52,
	0x65, 0x61, 0x73, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x52, 0x65, 0x61,
	0x73, 0x6f, 0x6e, 0x12, 0x14, 0x0a, 0x05, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x05, 0x52, 0x05, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x3a, 0x06, 0xba, 0xb9, 0x19, 0x02, 0x08,
	0x01, 0x22, 0x9d, 0x02, 0x0a, 0x05, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x30, 0x0a, 0x02, 0x49,
	0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x67, 0x6f, 0x72, 0x6d, 0x2e, 0x74,
	0x79, 0x70, 0x65, 0x73, 0x2e, 0x55, 0x55, 0x49, 0x44, 0x42, 0x0e, 0xba, 0xb9, 0x19, 0x0a, 0x0a,
	0x08, 0x12, 0x04, 0x75, 0x75, 0x69, 0x64, 0x28, 0x01, 0x52, 0x02, 0x49, 0x64, 0x12, 0x38, 0x0a,
	0x09, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x43, 0x72,
	0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x12, 0x38, 0x0a, 0x09, 0x55, 0x70, 0x64, 0x61, 0x74,
	0x65, 0x64, 0x41, 0x74, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x41,
	0x74, 0x12, 0x14, 0x0a, 0x05, 0x53, 0x74, 0x61, 0x74, 0x65, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x05, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x52, 0x65, 0x61, 0x73, 0x6f,
	0x6e, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x12,
	0x1a, 0x0a, 0x08, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x49, 0x50, 0x18, 0x0c, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x08, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x49, 0x50, 0x12, 0x1c, 0x0a, 0x09, 0x52,
	0x65, 0x61, 0x73, 0x6f, 0x6e, 0x54, 0x54, 0x4c, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x02, 0x52, 0x09,
	0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x54, 0x54, 0x4c, 0x3a, 0x06, 0xba, 0xb9, 0x19, 0x02, 0x08,
	0x01, 0x42, 0x72, 0x0a, 0x08, 0x63, 0x6f, 0x6d, 0x2e, 0x68, 0x6f, 0x73, 0x74, 0x42, 0x09, 0x50,
	0x6f, 0x72, 0x74, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x2b, 0x67, 0x69, 0x74, 0x68,
	0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6d, 0x61, 0x78, 0x6c, 0x61, 0x6e, 0x64, 0x6f, 0x6e,
	0x2f, 0x61, 0x69, 0x6d, 0x73, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x65, 0x6e, 0x2f,
	0x67, 0x6f, 0x2f, 0x68, 0x6f, 0x73, 0x74, 0xa2, 0x02, 0x03, 0x48, 0x58, 0x58, 0xaa, 0x02, 0x04,
	0x48, 0x6f, 0x73, 0x74, 0xca, 0x02, 0x04, 0x48, 0x6f, 0x73, 0x74, 0xe2, 0x02, 0x10, 0x48, 0x6f,
	0x73, 0x74, 0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0xea, 0x02,
	0x04, 0x48, 0x6f, 0x73, 0x74, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_host_port_proto_rawDescOnce sync.Once
	file_host_port_proto_rawDescData = file_host_port_proto_rawDesc
)

func file_host_port_proto_rawDescGZIP() []byte {
	file_host_port_proto_rawDescOnce.Do(func() {
		file_host_port_proto_rawDescData = protoimpl.X.CompressGZIP(file_host_port_proto_rawDescData)
	})
	return file_host_port_proto_rawDescData
}

var file_host_port_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_host_port_proto_goTypes = []interface{}{
	(*Port)(nil),                  // 0: host.Port
	(*Reason)(nil),                // 1: host.Reason
	(*State)(nil),                 // 2: host.State
	(*types.UUID)(nil),            // 3: gorm.types.UUID
	(*timestamppb.Timestamp)(nil), // 4: google.protobuf.Timestamp
	(*network.Service)(nil),       // 5: network.Service
	(*scan.NmapScript)(nil),       // 6: scan.NmapScript
}
var file_host_port_proto_depIdxs = []int32{
	3,  // 0: host.Port.Id:type_name -> gorm.types.UUID
	4,  // 1: host.Port.CreatedAt:type_name -> google.protobuf.Timestamp
	4,  // 2: host.Port.UpdatedAt:type_name -> google.protobuf.Timestamp
	5,  // 3: host.Port.Service:type_name -> network.Service
	2,  // 4: host.Port.State:type_name -> host.State
	6,  // 5: host.Port.Scripts:type_name -> scan.NmapScript
	1,  // 6: host.Port.Reasons:type_name -> host.Reason
	3,  // 7: host.State.Id:type_name -> gorm.types.UUID
	4,  // 8: host.State.CreatedAt:type_name -> google.protobuf.Timestamp
	4,  // 9: host.State.UpdatedAt:type_name -> google.protobuf.Timestamp
	10, // [10:10] is the sub-list for method output_type
	10, // [10:10] is the sub-list for method input_type
	10, // [10:10] is the sub-list for extension type_name
	10, // [10:10] is the sub-list for extension extendee
	0,  // [0:10] is the sub-list for field type_name
}

func init() { file_host_port_proto_init() }
func file_host_port_proto_init() {
	if File_host_port_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_host_port_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Port); i {
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
		file_host_port_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Reason); i {
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
		file_host_port_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*State); i {
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
			RawDescriptor: file_host_port_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_host_port_proto_goTypes,
		DependencyIndexes: file_host_port_proto_depIdxs,
		MessageInfos:      file_host_port_proto_msgTypes,
	}.Build()
	File_host_port_proto = out.File
	file_host_port_proto_rawDesc = nil
	file_host_port_proto_goTypes = nil
	file_host_port_proto_depIdxs = nil
}
