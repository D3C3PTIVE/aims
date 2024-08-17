// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.33.0
// 	protoc        v3.18.1
// source: scan/pb/nmap/nmap.proto

package nmap

import (
	_ "github.com/infobloxopen/protoc-gen-gorm/options"
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

// Script - Represents a Nmap Scripting Engine Script.
// The inner elements can be an arbitrary collection of Tables and Elements. They can be empty
type Script struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// @gotags: display:"ID" readonly:"true" xml:"script_id"
	Id string `protobuf:"bytes,1,opt,name=Id,proto3" json:"Id,omitempty" display:"ID" readonly:"true" xml:"script_id"`
	// @gotags: display:"Created at" readonly:"true" xml:"-"
	CreatedAt *timestamppb.Timestamp `protobuf:"bytes,4,opt,name=CreatedAt,proto3" json:"CreatedAt,omitempty" display:"Created at" readonly:"true" xml:"-"`
	// @gotags: display:"Updated at" readonly:"true" xml:"-"
	UpdatedAt *timestamppb.Timestamp `protobuf:"bytes,5,opt,name=UpdatedAt,proto3" json:"UpdatedAt,omitempty" display:"Updated at" readonly:"true" xml:"-"`
	// @gotags: xml:"id,attr"
	Name string `protobuf:"bytes,10,opt,name=Name,proto3" json:"Name,omitempty" xml:"id,attr"`
	// @gotags: xml:"output,attr"
	Output string `protobuf:"bytes,11,opt,name=Output,proto3" json:"Output,omitempty" xml:"output,attr"`
	// @gotags: xml:"elem,omitempty"
	Elements []*Element `protobuf:"bytes,12,rep,name=Elements,proto3" json:"Elements,omitempty" xml:"elem,omitempty"`
	// @gotags: xml:"table,omitempty"
	Tables []*Table `protobuf:"bytes,13,rep,name=Tables,proto3" json:"Tables,omitempty" xml:"table,omitempty"`
}

func (x *Script) Reset() {
	*x = Script{}
	if protoimpl.UnsafeEnabled {
		mi := &file_scan_pb_nmap_nmap_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Script) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Script) ProtoMessage() {}

func (x *Script) ProtoReflect() protoreflect.Message {
	mi := &file_scan_pb_nmap_nmap_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Script.ProtoReflect.Descriptor instead.
func (*Script) Descriptor() ([]byte, []int) {
	return file_scan_pb_nmap_nmap_proto_rawDescGZIP(), []int{0}
}

func (x *Script) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Script) GetCreatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.CreatedAt
	}
	return nil
}

func (x *Script) GetUpdatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.UpdatedAt
	}
	return nil
}

func (x *Script) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Script) GetOutput() string {
	if x != nil {
		return x.Output
	}
	return ""
}

func (x *Script) GetElements() []*Element {
	if x != nil {
		return x.Elements
	}
	return nil
}

func (x *Script) GetTables() []*Table {
	if x != nil {
		return x.Tables
	}
	return nil
}

// elements - The smallest building block for scripts/tables. Key is optional
type Element struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// @gotags: display:"ID" readonly:"true"
	Id string `protobuf:"bytes,1,opt,name=Id,proto3" json:"Id,omitempty" display:"ID" readonly:"true"`
	// @gotags: xml:"key,attr,omitempty"
	Key string `protobuf:"bytes,10,opt,name=Key,proto3" json:"Key,omitempty" xml:"key,attr,omitempty"`
	// @gotags: xml:",innerxml"
	Value string `protobuf:"bytes,11,opt,name=Value,proto3" json:"Value,omitempty" xml:",innerxml"`
}

func (x *Element) Reset() {
	*x = Element{}
	if protoimpl.UnsafeEnabled {
		mi := &file_scan_pb_nmap_nmap_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Element) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Element) ProtoMessage() {}

func (x *Element) ProtoReflect() protoreflect.Message {
	mi := &file_scan_pb_nmap_nmap_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Element.ProtoReflect.Descriptor instead.
func (*Element) Descriptor() ([]byte, []int) {
	return file_scan_pb_nmap_nmap_proto_rawDescGZIP(), []int{1}
}

func (x *Element) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Element) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (x *Element) GetValue() string {
	if x != nil {
		return x.Value
	}
	return ""
}

// Table - An arbitrary collection of (sub-)Tables and Elements. Can be empty
type Table struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// @gotags: display:"ID" readonly:"true"
	Id string `protobuf:"bytes,1,opt,name=Id,proto3" json:"Id,omitempty" display:"ID" readonly:"true"`
	// @gotags: xml:"key,attr,omitempty"
	Key string `protobuf:"bytes,10,opt,name=Key,proto3" json:"Key,omitempty" xml:"key,attr,omitempty"`
	// @gotags: xml:"table,omitempty"
	Tables []*Table `protobuf:"bytes,11,rep,name=Tables,proto3" json:"Tables,omitempty" xml:"table,omitempty"`
	// @gotags: xml:"elem,omitempty"
	Elements []*Element `protobuf:"bytes,12,rep,name=Elements,proto3" json:"Elements,omitempty" xml:"elem,omitempty"`
}

func (x *Table) Reset() {
	*x = Table{}
	if protoimpl.UnsafeEnabled {
		mi := &file_scan_pb_nmap_nmap_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Table) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Table) ProtoMessage() {}

func (x *Table) ProtoReflect() protoreflect.Message {
	mi := &file_scan_pb_nmap_nmap_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Table.ProtoReflect.Descriptor instead.
func (*Table) Descriptor() ([]byte, []int) {
	return file_scan_pb_nmap_nmap_proto_rawDescGZIP(), []int{2}
}

func (x *Table) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Table) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (x *Table) GetTables() []*Table {
	if x != nil {
		return x.Tables
	}
	return nil
}

func (x *Table) GetElements() []*Element {
	if x != nil {
		return x.Elements
	}
	return nil
}

// Smurf - Contains responses from a smurf attack
type Smurf struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// @gotags: display:"ID" readonly:"true"
	Id string `protobuf:"bytes,1,opt,name=Id,proto3" json:"Id,omitempty" display:"ID" readonly:"true"`
	// @gotags: xml:"responses,attr"
	Responses string `protobuf:"bytes,10,opt,name=Responses,proto3" json:"Responses,omitempty" xml:"responses,attr"`
}

func (x *Smurf) Reset() {
	*x = Smurf{}
	if protoimpl.UnsafeEnabled {
		mi := &file_scan_pb_nmap_nmap_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Smurf) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Smurf) ProtoMessage() {}

func (x *Smurf) ProtoReflect() protoreflect.Message {
	mi := &file_scan_pb_nmap_nmap_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Smurf.ProtoReflect.Descriptor instead.
func (*Smurf) Descriptor() ([]byte, []int) {
	return file_scan_pb_nmap_nmap_proto_rawDescGZIP(), []int{3}
}

func (x *Smurf) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Smurf) GetResponses() string {
	if x != nil {
		return x.Responses
	}
	return ""
}

var File_scan_pb_nmap_nmap_proto protoreflect.FileDescriptor

var file_scan_pb_nmap_nmap_proto_rawDesc = []byte{
	0x0a, 0x17, 0x73, 0x63, 0x61, 0x6e, 0x2f, 0x70, 0x62, 0x2f, 0x6e, 0x6d, 0x61, 0x70, 0x2f, 0x6e,
	0x6d, 0x61, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x09, 0x73, 0x63, 0x61, 0x6e, 0x2e,
	0x6e, 0x6d, 0x61, 0x70, 0x1a, 0x12, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x67, 0x6f,
	0x72, 0x6d, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74,
	0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xaa, 0x02, 0x0a, 0x06, 0x53, 0x63,
	0x72, 0x69, 0x70, 0x74, 0x12, 0x1e, 0x0a, 0x02, 0x49, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x42, 0x0e, 0xba, 0xb9, 0x19, 0x0a, 0x0a, 0x08, 0x12, 0x04, 0x75, 0x75, 0x69, 0x64, 0x28, 0x01,
	0x52, 0x02, 0x49, 0x64, 0x12, 0x38, 0x0a, 0x09, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41,
	0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74,
	0x61, 0x6d, 0x70, 0x52, 0x09, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x12, 0x38,
	0x0a, 0x09, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x18, 0x05, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x55,
	0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x4e, 0x61, 0x6d, 0x65,
	0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x16, 0x0a, 0x06,
	0x4f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x4f, 0x75,
	0x74, 0x70, 0x75, 0x74, 0x12, 0x2e, 0x0a, 0x08, 0x45, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x73,
	0x18, 0x0c, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x73, 0x63, 0x61, 0x6e, 0x2e, 0x6e, 0x6d,
	0x61, 0x70, 0x2e, 0x45, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x52, 0x08, 0x45, 0x6c, 0x65, 0x6d,
	0x65, 0x6e, 0x74, 0x73, 0x12, 0x28, 0x0a, 0x06, 0x54, 0x61, 0x62, 0x6c, 0x65, 0x73, 0x18, 0x0d,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x73, 0x63, 0x61, 0x6e, 0x2e, 0x6e, 0x6d, 0x61, 0x70,
	0x2e, 0x54, 0x61, 0x62, 0x6c, 0x65, 0x52, 0x06, 0x54, 0x61, 0x62, 0x6c, 0x65, 0x73, 0x3a, 0x06,
	0xba, 0xb9, 0x19, 0x02, 0x08, 0x01, 0x22, 0x59, 0x0a, 0x07, 0x45, 0x6c, 0x65, 0x6d, 0x65, 0x6e,
	0x74, 0x12, 0x1e, 0x0a, 0x02, 0x49, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x0e, 0xba,
	0xb9, 0x19, 0x0a, 0x0a, 0x08, 0x12, 0x04, 0x75, 0x75, 0x69, 0x64, 0x28, 0x01, 0x52, 0x02, 0x49,
	0x64, 0x12, 0x10, 0x0a, 0x03, 0x4b, 0x65, 0x79, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03,
	0x4b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x0b, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x05, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x06, 0xba, 0xb9, 0x19, 0x02, 0x08,
	0x01, 0x22, 0x9b, 0x01, 0x0a, 0x05, 0x54, 0x61, 0x62, 0x6c, 0x65, 0x12, 0x1e, 0x0a, 0x02, 0x49,
	0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x0e, 0xba, 0xb9, 0x19, 0x0a, 0x0a, 0x08, 0x12,
	0x04, 0x75, 0x75, 0x69, 0x64, 0x28, 0x01, 0x52, 0x02, 0x49, 0x64, 0x12, 0x10, 0x0a, 0x03, 0x4b,
	0x65, 0x79, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x4b, 0x65, 0x79, 0x12, 0x28, 0x0a,
	0x06, 0x54, 0x61, 0x62, 0x6c, 0x65, 0x73, 0x18, 0x0b, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x10, 0x2e,
	0x73, 0x63, 0x61, 0x6e, 0x2e, 0x6e, 0x6d, 0x61, 0x70, 0x2e, 0x54, 0x61, 0x62, 0x6c, 0x65, 0x52,
	0x06, 0x54, 0x61, 0x62, 0x6c, 0x65, 0x73, 0x12, 0x2e, 0x0a, 0x08, 0x45, 0x6c, 0x65, 0x6d, 0x65,
	0x6e, 0x74, 0x73, 0x18, 0x0c, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x73, 0x63, 0x61, 0x6e,
	0x2e, 0x6e, 0x6d, 0x61, 0x70, 0x2e, 0x45, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x52, 0x08, 0x45,
	0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x3a, 0x06, 0xba, 0xb9, 0x19, 0x02, 0x08, 0x01, 0x22,
	0x4d, 0x0a, 0x05, 0x53, 0x6d, 0x75, 0x72, 0x66, 0x12, 0x1e, 0x0a, 0x02, 0x49, 0x64, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x42, 0x0e, 0xba, 0xb9, 0x19, 0x0a, 0x0a, 0x08, 0x12, 0x04, 0x75, 0x75,
	0x69, 0x64, 0x28, 0x01, 0x52, 0x02, 0x49, 0x64, 0x12, 0x1c, 0x0a, 0x09, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x73, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x73, 0x3a, 0x06, 0xba, 0xb9, 0x19, 0x02, 0x08, 0x01, 0x42, 0x87,
	0x01, 0x0a, 0x0d, 0x63, 0x6f, 0x6d, 0x2e, 0x73, 0x63, 0x61, 0x6e, 0x2e, 0x6e, 0x6d, 0x61, 0x70,
	0x42, 0x09, 0x4e, 0x6d, 0x61, 0x70, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x26, 0x67,
	0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x64, 0x33, 0x63, 0x33, 0x70, 0x74,
	0x69, 0x76, 0x65, 0x2f, 0x61, 0x69, 0x6d, 0x73, 0x2f, 0x73, 0x63, 0x61, 0x6e, 0x2f, 0x70, 0x62,
	0x2f, 0x6e, 0x6d, 0x61, 0x70, 0xa2, 0x02, 0x03, 0x53, 0x4e, 0x58, 0xaa, 0x02, 0x09, 0x53, 0x63,
	0x61, 0x6e, 0x2e, 0x4e, 0x6d, 0x61, 0x70, 0xca, 0x02, 0x09, 0x53, 0x63, 0x61, 0x6e, 0x5c, 0x4e,
	0x6d, 0x61, 0x70, 0xe2, 0x02, 0x15, 0x53, 0x63, 0x61, 0x6e, 0x5c, 0x4e, 0x6d, 0x61, 0x70, 0x5c,
	0x47, 0x50, 0x42, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0xea, 0x02, 0x0a, 0x53, 0x63,
	0x61, 0x6e, 0x3a, 0x3a, 0x4e, 0x6d, 0x61, 0x70, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_scan_pb_nmap_nmap_proto_rawDescOnce sync.Once
	file_scan_pb_nmap_nmap_proto_rawDescData = file_scan_pb_nmap_nmap_proto_rawDesc
)

func file_scan_pb_nmap_nmap_proto_rawDescGZIP() []byte {
	file_scan_pb_nmap_nmap_proto_rawDescOnce.Do(func() {
		file_scan_pb_nmap_nmap_proto_rawDescData = protoimpl.X.CompressGZIP(file_scan_pb_nmap_nmap_proto_rawDescData)
	})
	return file_scan_pb_nmap_nmap_proto_rawDescData
}

var file_scan_pb_nmap_nmap_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_scan_pb_nmap_nmap_proto_goTypes = []interface{}{
	(*Script)(nil),                // 0: scan.nmap.Script
	(*Element)(nil),               // 1: scan.nmap.Element
	(*Table)(nil),                 // 2: scan.nmap.Table
	(*Smurf)(nil),                 // 3: scan.nmap.Smurf
	(*timestamppb.Timestamp)(nil), // 4: google.protobuf.Timestamp
}
var file_scan_pb_nmap_nmap_proto_depIdxs = []int32{
	4, // 0: scan.nmap.Script.CreatedAt:type_name -> google.protobuf.Timestamp
	4, // 1: scan.nmap.Script.UpdatedAt:type_name -> google.protobuf.Timestamp
	1, // 2: scan.nmap.Script.Elements:type_name -> scan.nmap.Element
	2, // 3: scan.nmap.Script.Tables:type_name -> scan.nmap.Table
	2, // 4: scan.nmap.Table.Tables:type_name -> scan.nmap.Table
	1, // 5: scan.nmap.Table.Elements:type_name -> scan.nmap.Element
	6, // [6:6] is the sub-list for method output_type
	6, // [6:6] is the sub-list for method input_type
	6, // [6:6] is the sub-list for extension type_name
	6, // [6:6] is the sub-list for extension extendee
	0, // [0:6] is the sub-list for field type_name
}

func init() { file_scan_pb_nmap_nmap_proto_init() }
func file_scan_pb_nmap_nmap_proto_init() {
	if File_scan_pb_nmap_nmap_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_scan_pb_nmap_nmap_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Script); i {
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
		file_scan_pb_nmap_nmap_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Element); i {
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
		file_scan_pb_nmap_nmap_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Table); i {
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
		file_scan_pb_nmap_nmap_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Smurf); i {
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
			RawDescriptor: file_scan_pb_nmap_nmap_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_scan_pb_nmap_nmap_proto_goTypes,
		DependencyIndexes: file_scan_pb_nmap_nmap_proto_depIdxs,
		MessageInfos:      file_scan_pb_nmap_nmap_proto_msgTypes,
	}.Build()
	File_scan_pb_nmap_nmap_proto = out.File
	file_scan_pb_nmap_nmap_proto_rawDesc = nil
	file_scan_pb_nmap_nmap_proto_goTypes = nil
	file_scan_pb_nmap_nmap_proto_depIdxs = nil
}