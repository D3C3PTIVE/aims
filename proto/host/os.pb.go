// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v3.18.1
// source: host/os.proto

package host

import (
	_ "github.com/infobloxopen/protoc-gen-gorm/options"
	os "github.com/maxlandon/aims/proto/host/os"
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

// OS - An operating system identified by NMAP, with fingerprint information
type OS struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id string `protobuf:"bytes,1,opt,name=Id,proto3" json:"Id,omitempty"`
	// @inject_tag: xml:"portused"
	PortsUsed []*PortUsed `protobuf:"bytes,2,rep,name=PortsUsed,proto3" json:"PortsUsed,omitempty" xml:"portused"`
	// @inject_tag: xml:"osmatch"
	Matches []*OSMatch `protobuf:"bytes,3,rep,name=Matches,proto3" json:"Matches,omitempty" xml:"osmatch"`
	// @inject_tag: xml:"osfingerprint"
	Fingerprints []*OSFingerprint `protobuf:"bytes,4,rep,name=Fingerprints,proto3" json:"Fingerprints,omitempty" xml:"osfingerprint"`
}

func (x *OS) Reset() {
	*x = OS{}
	if protoimpl.UnsafeEnabled {
		mi := &file_host_os_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *OS) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*OS) ProtoMessage() {}

func (x *OS) ProtoReflect() protoreflect.Message {
	mi := &file_host_os_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use OS.ProtoReflect.Descriptor instead.
func (*OS) Descriptor() ([]byte, []int) {
	return file_host_os_proto_rawDescGZIP(), []int{0}
}

func (x *OS) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *OS) GetPortsUsed() []*PortUsed {
	if x != nil {
		return x.PortsUsed
	}
	return nil
}

func (x *OS) GetMatches() []*OSMatch {
	if x != nil {
		return x.Matches
	}
	return nil
}

func (x *OS) GetFingerprints() []*OSFingerprint {
	if x != nil {
		return x.Fingerprints
	}
	return nil
}

// OSMatch - Contains detailed information regarding an Operating System fingerprint
type OSMatch struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id string `protobuf:"bytes,100,opt,name=Id,proto3" json:"Id,omitempty"`
	// @inject_tag: xml:"name,attr"
	Name string `protobuf:"bytes,1,opt,name=Name,proto3" json:"Name,omitempty" xml:"name,attr"`
	// @inject_tag: xml:"accuracy,attr"
	Accuracy int32 `protobuf:"varint,2,opt,name=Accuracy,proto3" json:"Accuracy,omitempty" xml:"accuracy,attr"`
	// @inject_tag: xml:"line,attr"
	Line int32 `protobuf:"varint,3,opt,name=Line,proto3" json:"Line,omitempty" xml:"line,attr"`
	// @inject_tag: xml:"osclass,attr"
	Classes []*OSClass `protobuf:"bytes,4,rep,name=Classes,proto3" json:"Classes,omitempty" xml:"osclass,attr"`
}

func (x *OSMatch) Reset() {
	*x = OSMatch{}
	if protoimpl.UnsafeEnabled {
		mi := &file_host_os_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *OSMatch) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*OSMatch) ProtoMessage() {}

func (x *OSMatch) ProtoReflect() protoreflect.Message {
	mi := &file_host_os_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use OSMatch.ProtoReflect.Descriptor instead.
func (*OSMatch) Descriptor() ([]byte, []int) {
	return file_host_os_proto_rawDescGZIP(), []int{1}
}

func (x *OSMatch) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *OSMatch) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *OSMatch) GetAccuracy() int32 {
	if x != nil {
		return x.Accuracy
	}
	return 0
}

func (x *OSMatch) GetLine() int32 {
	if x != nil {
		return x.Line
	}
	return 0
}

func (x *OSMatch) GetClasses() []*OSClass {
	if x != nil {
		return x.Classes
	}
	return nil
}

// PortUsed - The port used to fingerprint the operating system
type PortUsed struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id string `protobuf:"bytes,100,opt,name=Id,proto3" json:"Id,omitempty"`
	// @inject_tag: xml:"portid,attr"
	Number uint32 `protobuf:"varint,2,opt,name=Number,proto3" json:"Number,omitempty" xml:"portid,attr"`
	// @inject_tag: xml:"state,attr"
	State string `protobuf:"bytes,3,opt,name=State,proto3" json:"State,omitempty" xml:"state,attr"`
	// @inject_tag: xml:"proto,attr"
	Protocol string `protobuf:"bytes,4,opt,name=Protocol,proto3" json:"Protocol,omitempty" xml:"proto,attr"`
}

func (x *PortUsed) Reset() {
	*x = PortUsed{}
	if protoimpl.UnsafeEnabled {
		mi := &file_host_os_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PortUsed) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PortUsed) ProtoMessage() {}

func (x *PortUsed) ProtoReflect() protoreflect.Message {
	mi := &file_host_os_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PortUsed.ProtoReflect.Descriptor instead.
func (*PortUsed) Descriptor() ([]byte, []int) {
	return file_host_os_proto_rawDescGZIP(), []int{2}
}

func (x *PortUsed) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *PortUsed) GetNumber() uint32 {
	if x != nil {
		return x.Number
	}
	return 0
}

func (x *PortUsed) GetState() string {
	if x != nil {
		return x.State
	}
	return ""
}

func (x *PortUsed) GetProtocol() string {
	if x != nil {
		return x.Protocol
	}
	return ""
}

// OSFingerprint - The actual fingerprint string of an operating system
type OSFingerprint struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id string `protobuf:"bytes,100,opt,name=Id,proto3" json:"Id,omitempty"`
	// @inject_tag: xml:"fingerprint,attr"
	Fingerprint string `protobuf:"bytes,1,opt,name=Fingerprint,proto3" json:"Fingerprint,omitempty" xml:"fingerprint,attr"`
}

func (x *OSFingerprint) Reset() {
	*x = OSFingerprint{}
	if protoimpl.UnsafeEnabled {
		mi := &file_host_os_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *OSFingerprint) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*OSFingerprint) ProtoMessage() {}

func (x *OSFingerprint) ProtoReflect() protoreflect.Message {
	mi := &file_host_os_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use OSFingerprint.ProtoReflect.Descriptor instead.
func (*OSFingerprint) Descriptor() ([]byte, []int) {
	return file_host_os_proto_rawDescGZIP(), []int{3}
}

func (x *OSFingerprint) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *OSFingerprint) GetFingerprint() string {
	if x != nil {
		return x.Fingerprint
	}
	return ""
}

// OSClass - Contains vendor information about an operating system
type OSClass struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id string `protobuf:"bytes,100,opt,name=Id,proto3" json:"Id,omitempty"`
	// @inject_tag: xml:"vendor,attr"
	Vendor string `protobuf:"bytes,1,opt,name=Vendor,proto3" json:"Vendor,omitempty" xml:"vendor,attr"`
	// @inject_tag: xml:"osgen,attr"
	OSGeneration string `protobuf:"bytes,2,opt,name=OSGeneration,proto3" json:"OSGeneration,omitempty" xml:"osgen,attr"`
	// @inject_tag: xml:"type,attr"
	Type string `protobuf:"bytes,3,opt,name=Type,proto3" json:"Type,omitempty" xml:"type,attr"`
	// @inject_tag: xml:"accurary,attr"
	Accuracy int32 `protobuf:"varint,4,opt,name=Accuracy,proto3" json:"Accuracy,omitempty" xml:"accurary,attr"`
	// @inject_tag: xml:"osfamily,attr"
	Family os.Family `protobuf:"varint,5,opt,name=Family,proto3,enum=os.Family" json:"Family,omitempty" xml:"osfamily,attr"`
	// @inject_tag: xml:"cpe"
	CPEs []string `protobuf:"bytes,6,rep,name=CPEs,proto3" json:"CPEs,omitempty" xml:"cpe"` // "Common Platform Enumeration" is standardized way to name software applications, OSs and Hardware platforms
}

func (x *OSClass) Reset() {
	*x = OSClass{}
	if protoimpl.UnsafeEnabled {
		mi := &file_host_os_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *OSClass) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*OSClass) ProtoMessage() {}

func (x *OSClass) ProtoReflect() protoreflect.Message {
	mi := &file_host_os_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use OSClass.ProtoReflect.Descriptor instead.
func (*OSClass) Descriptor() ([]byte, []int) {
	return file_host_os_proto_rawDescGZIP(), []int{4}
}

func (x *OSClass) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *OSClass) GetVendor() string {
	if x != nil {
		return x.Vendor
	}
	return ""
}

func (x *OSClass) GetOSGeneration() string {
	if x != nil {
		return x.OSGeneration
	}
	return ""
}

func (x *OSClass) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *OSClass) GetAccuracy() int32 {
	if x != nil {
		return x.Accuracy
	}
	return 0
}

func (x *OSClass) GetFamily() os.Family {
	if x != nil {
		return x.Family
	}
	return os.Family(0)
}

func (x *OSClass) GetCPEs() []string {
	if x != nil {
		return x.CPEs
	}
	return nil
}

var File_host_os_proto protoreflect.FileDescriptor

var file_host_os_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x68, 0x6f, 0x73, 0x74, 0x2f, 0x6f, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x04, 0x68, 0x6f, 0x73, 0x74, 0x1a, 0x16, 0x68, 0x6f, 0x73, 0x74, 0x2f, 0x6f, 0x73, 0x2f, 0x66,
	0x61, 0x6d, 0x69, 0x6c, 0x69, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x12, 0x6f,
	0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x67, 0x6f, 0x72, 0x6d, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x22, 0xbc, 0x01, 0x0a, 0x02, 0x4f, 0x53, 0x12, 0x1e, 0x0a, 0x02, 0x49, 0x64, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x42, 0x0e, 0xba, 0xb9, 0x19, 0x0a, 0x0a, 0x08, 0x12, 0x04, 0x75, 0x75,
	0x69, 0x64, 0x28, 0x01, 0x52, 0x02, 0x49, 0x64, 0x12, 0x2c, 0x0a, 0x09, 0x50, 0x6f, 0x72, 0x74,
	0x73, 0x55, 0x73, 0x65, 0x64, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0e, 0x2e, 0x68, 0x6f,
	0x73, 0x74, 0x2e, 0x50, 0x6f, 0x72, 0x74, 0x55, 0x73, 0x65, 0x64, 0x52, 0x09, 0x50, 0x6f, 0x72,
	0x74, 0x73, 0x55, 0x73, 0x65, 0x64, 0x12, 0x27, 0x0a, 0x07, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x65,
	0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0d, 0x2e, 0x68, 0x6f, 0x73, 0x74, 0x2e, 0x4f,
	0x53, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x52, 0x07, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x73, 0x12,
	0x37, 0x0a, 0x0c, 0x46, 0x69, 0x6e, 0x67, 0x65, 0x72, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x73, 0x18,
	0x04, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x13, 0x2e, 0x68, 0x6f, 0x73, 0x74, 0x2e, 0x4f, 0x53, 0x46,
	0x69, 0x6e, 0x67, 0x65, 0x72, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x52, 0x0c, 0x46, 0x69, 0x6e, 0x67,
	0x65, 0x72, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x73, 0x3a, 0x06, 0xba, 0xb9, 0x19, 0x02, 0x08, 0x01,
	0x22, 0x9e, 0x01, 0x0a, 0x07, 0x4f, 0x53, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x12, 0x1e, 0x0a, 0x02,
	0x49, 0x64, 0x18, 0x64, 0x20, 0x01, 0x28, 0x09, 0x42, 0x0e, 0xba, 0xb9, 0x19, 0x0a, 0x0a, 0x08,
	0x12, 0x04, 0x75, 0x75, 0x69, 0x64, 0x28, 0x01, 0x52, 0x02, 0x49, 0x64, 0x12, 0x12, 0x0a, 0x04,
	0x4e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x4e, 0x61, 0x6d, 0x65,
	0x12, 0x1a, 0x0a, 0x08, 0x41, 0x63, 0x63, 0x75, 0x72, 0x61, 0x63, 0x79, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x05, 0x52, 0x08, 0x41, 0x63, 0x63, 0x75, 0x72, 0x61, 0x63, 0x79, 0x12, 0x12, 0x0a, 0x04,
	0x4c, 0x69, 0x6e, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x05, 0x52, 0x04, 0x4c, 0x69, 0x6e, 0x65,
	0x12, 0x27, 0x0a, 0x07, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x65, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28,
	0x0b, 0x32, 0x0d, 0x2e, 0x68, 0x6f, 0x73, 0x74, 0x2e, 0x4f, 0x53, 0x43, 0x6c, 0x61, 0x73, 0x73,
	0x52, 0x07, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x65, 0x73, 0x3a, 0x06, 0xba, 0xb9, 0x19, 0x02, 0x08,
	0x01, 0x22, 0x7c, 0x0a, 0x08, 0x50, 0x6f, 0x72, 0x74, 0x55, 0x73, 0x65, 0x64, 0x12, 0x1e, 0x0a,
	0x02, 0x49, 0x64, 0x18, 0x64, 0x20, 0x01, 0x28, 0x09, 0x42, 0x0e, 0xba, 0xb9, 0x19, 0x0a, 0x0a,
	0x08, 0x12, 0x04, 0x75, 0x75, 0x69, 0x64, 0x28, 0x01, 0x52, 0x02, 0x49, 0x64, 0x12, 0x16, 0x0a,
	0x06, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x06, 0x4e,
	0x75, 0x6d, 0x62, 0x65, 0x72, 0x12, 0x14, 0x0a, 0x05, 0x53, 0x74, 0x61, 0x74, 0x65, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x50,
	0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x50,
	0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x3a, 0x06, 0xba, 0xb9, 0x19, 0x02, 0x08, 0x01, 0x22,
	0x59, 0x0a, 0x0d, 0x4f, 0x53, 0x46, 0x69, 0x6e, 0x67, 0x65, 0x72, 0x70, 0x72, 0x69, 0x6e, 0x74,
	0x12, 0x1e, 0x0a, 0x02, 0x49, 0x64, 0x18, 0x64, 0x20, 0x01, 0x28, 0x09, 0x42, 0x0e, 0xba, 0xb9,
	0x19, 0x0a, 0x0a, 0x08, 0x12, 0x04, 0x75, 0x75, 0x69, 0x64, 0x28, 0x01, 0x52, 0x02, 0x49, 0x64,
	0x12, 0x20, 0x0a, 0x0b, 0x46, 0x69, 0x6e, 0x67, 0x65, 0x72, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x46, 0x69, 0x6e, 0x67, 0x65, 0x72, 0x70, 0x72, 0x69,
	0x6e, 0x74, 0x3a, 0x06, 0xba, 0xb9, 0x19, 0x02, 0x08, 0x01, 0x22, 0xd5, 0x01, 0x0a, 0x07, 0x4f,
	0x53, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x12, 0x1e, 0x0a, 0x02, 0x49, 0x64, 0x18, 0x64, 0x20, 0x01,
	0x28, 0x09, 0x42, 0x0e, 0xba, 0xb9, 0x19, 0x0a, 0x0a, 0x08, 0x12, 0x04, 0x75, 0x75, 0x69, 0x64,
	0x28, 0x01, 0x52, 0x02, 0x49, 0x64, 0x12, 0x16, 0x0a, 0x06, 0x56, 0x65, 0x6e, 0x64, 0x6f, 0x72,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x56, 0x65, 0x6e, 0x64, 0x6f, 0x72, 0x12, 0x22,
	0x0a, 0x0c, 0x4f, 0x53, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x4f, 0x53, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x12, 0x12, 0x0a, 0x04, 0x54, 0x79, 0x70, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x04, 0x54, 0x79, 0x70, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x41, 0x63, 0x63, 0x75, 0x72, 0x61,
	0x63, 0x79, 0x18, 0x04, 0x20, 0x01, 0x28, 0x05, 0x52, 0x08, 0x41, 0x63, 0x63, 0x75, 0x72, 0x61,
	0x63, 0x79, 0x12, 0x22, 0x0a, 0x06, 0x46, 0x61, 0x6d, 0x69, 0x6c, 0x79, 0x18, 0x05, 0x20, 0x01,
	0x28, 0x0e, 0x32, 0x0a, 0x2e, 0x6f, 0x73, 0x2e, 0x46, 0x61, 0x6d, 0x69, 0x6c, 0x79, 0x52, 0x06,
	0x46, 0x61, 0x6d, 0x69, 0x6c, 0x79, 0x12, 0x12, 0x0a, 0x04, 0x43, 0x50, 0x45, 0x73, 0x18, 0x06,
	0x20, 0x03, 0x28, 0x09, 0x52, 0x04, 0x43, 0x50, 0x45, 0x73, 0x3a, 0x06, 0xba, 0xb9, 0x19, 0x02,
	0x08, 0x01, 0x42, 0x69, 0x0a, 0x08, 0x63, 0x6f, 0x6d, 0x2e, 0x68, 0x6f, 0x73, 0x74, 0x42, 0x07,
	0x4f, 0x73, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x24, 0x67, 0x69, 0x74, 0x68, 0x75,
	0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6d, 0x61, 0x78, 0x6c, 0x61, 0x6e, 0x64, 0x6f, 0x6e, 0x2f,
	0x61, 0x69, 0x6d, 0x73, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x68, 0x6f, 0x73, 0x74, 0xa2,
	0x02, 0x03, 0x48, 0x58, 0x58, 0xaa, 0x02, 0x04, 0x48, 0x6f, 0x73, 0x74, 0xca, 0x02, 0x04, 0x48,
	0x6f, 0x73, 0x74, 0xe2, 0x02, 0x10, 0x48, 0x6f, 0x73, 0x74, 0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65,
	0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0xea, 0x02, 0x04, 0x48, 0x6f, 0x73, 0x74, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_host_os_proto_rawDescOnce sync.Once
	file_host_os_proto_rawDescData = file_host_os_proto_rawDesc
)

func file_host_os_proto_rawDescGZIP() []byte {
	file_host_os_proto_rawDescOnce.Do(func() {
		file_host_os_proto_rawDescData = protoimpl.X.CompressGZIP(file_host_os_proto_rawDescData)
	})
	return file_host_os_proto_rawDescData
}

var file_host_os_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_host_os_proto_goTypes = []interface{}{
	(*OS)(nil),            // 0: host.OS
	(*OSMatch)(nil),       // 1: host.OSMatch
	(*PortUsed)(nil),      // 2: host.PortUsed
	(*OSFingerprint)(nil), // 3: host.OSFingerprint
	(*OSClass)(nil),       // 4: host.OSClass
	(os.Family)(0),        // 5: os.Family
}
var file_host_os_proto_depIdxs = []int32{
	2, // 0: host.OS.PortsUsed:type_name -> host.PortUsed
	1, // 1: host.OS.Matches:type_name -> host.OSMatch
	3, // 2: host.OS.Fingerprints:type_name -> host.OSFingerprint
	4, // 3: host.OSMatch.Classes:type_name -> host.OSClass
	5, // 4: host.OSClass.Family:type_name -> os.Family
	5, // [5:5] is the sub-list for method output_type
	5, // [5:5] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_host_os_proto_init() }
func file_host_os_proto_init() {
	if File_host_os_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_host_os_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*OS); i {
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
		file_host_os_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*OSMatch); i {
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
		file_host_os_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PortUsed); i {
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
		file_host_os_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*OSFingerprint); i {
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
		file_host_os_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*OSClass); i {
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
			RawDescriptor: file_host_os_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_host_os_proto_goTypes,
		DependencyIndexes: file_host_os_proto_depIdxs,
		MessageInfos:      file_host_os_proto_msgTypes,
	}.Build()
	File_host_os_proto = out.File
	file_host_os_proto_rawDesc = nil
	file_host_os_proto_goTypes = nil
	file_host_os_proto_depIdxs = nil
}
