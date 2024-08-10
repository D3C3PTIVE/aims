// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.33.0
// 	protoc        v3.18.1
// source: host/process.proto

package host

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

// Process - A basic process data type
type Process struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// @gotags: display:"ID" readonly:"true" strict:"yes"
	Id string `protobuf:"bytes,1,opt,name=Id,proto3" json:"Id,omitempty" display:"ID" readonly:"true" strict:"yes"`
	// @gotags: display:"Created at" readonly:"true" xml:"-"
	CreatedAt *timestamppb.Timestamp `protobuf:"bytes,4,opt,name=CreatedAt,proto3" json:"CreatedAt,omitempty" display:"Created at" readonly:"true" xml:"-"`
	// @gotags: display:"Updated at" readonly:"true" xml:"-"
	UpdatedAt *timestamppb.Timestamp `protobuf:"bytes,5,opt,name=UpdatedAt,proto3" json:"UpdatedAt,omitempty" display:"Updated at" readonly:"true" xml:"-"`
	// @gotags: display:"PID"
	Pid int32 `protobuf:"varint,10,opt,name=Pid,proto3" json:"Pid,omitempty" display:"PID"`
	// @gotags: display:"PPID"
	Ppid int32 `protobuf:"varint,11,opt,name=Ppid,proto3" json:"Ppid,omitempty" display:"PPID"`
	// @gotags: display:"Executable"
	Executable string `protobuf:"bytes,12,opt,name=Executable,proto3" json:"Executable,omitempty" display:"Executable"`
	// @gotags: display:"Owner"
	Owner *User `protobuf:"bytes,13,opt,name=Owner,proto3" json:"Owner,omitempty" display:"Owner"`
	// @gotags: display:"Arch"
	Architecture string `protobuf:"bytes,14,opt,name=Architecture,proto3" json:"Architecture,omitempty" display:"Arch"`
	// @gotags: display:"CmdLine"
	CmdLine []string `protobuf:"bytes,16,rep,name=CmdLine,proto3" json:"CmdLine,omitempty" display:"CmdLine"`
}

func (x *Process) Reset() {
	*x = Process{}
	if protoimpl.UnsafeEnabled {
		mi := &file_host_process_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Process) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Process) ProtoMessage() {}

func (x *Process) ProtoReflect() protoreflect.Message {
	mi := &file_host_process_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Process.ProtoReflect.Descriptor instead.
func (*Process) Descriptor() ([]byte, []int) {
	return file_host_process_proto_rawDescGZIP(), []int{0}
}

func (x *Process) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Process) GetCreatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.CreatedAt
	}
	return nil
}

func (x *Process) GetUpdatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.UpdatedAt
	}
	return nil
}

func (x *Process) GetPid() int32 {
	if x != nil {
		return x.Pid
	}
	return 0
}

func (x *Process) GetPpid() int32 {
	if x != nil {
		return x.Ppid
	}
	return 0
}

func (x *Process) GetExecutable() string {
	if x != nil {
		return x.Executable
	}
	return ""
}

func (x *Process) GetOwner() *User {
	if x != nil {
		return x.Owner
	}
	return nil
}

func (x *Process) GetArchitecture() string {
	if x != nil {
		return x.Architecture
	}
	return ""
}

func (x *Process) GetCmdLine() []string {
	if x != nil {
		return x.CmdLine
	}
	return nil
}

var File_host_process_proto protoreflect.FileDescriptor

var file_host_process_proto_rawDesc = []byte{
	0x0a, 0x12, 0x68, 0x6f, 0x73, 0x74, 0x2f, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65,
	0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x12, 0x6f, 0x70, 0x74,
	0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x67, 0x6f, 0x72, 0x6d, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x0f, 0x68, 0x6f, 0x73, 0x74, 0x2f, 0x75, 0x73, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x22, 0xcb, 0x02, 0x0a, 0x07, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x12, 0x1e, 0x0a, 0x02,
	0x49, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x0e, 0xba, 0xb9, 0x19, 0x0a, 0x0a, 0x08,
	0x12, 0x04, 0x75, 0x75, 0x69, 0x64, 0x28, 0x01, 0x52, 0x02, 0x49, 0x64, 0x12, 0x38, 0x0a, 0x09,
	0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x43, 0x72, 0x65,
	0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x12, 0x38, 0x0a, 0x09, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65,
	0x64, 0x41, 0x74, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65,
	0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74,
	0x12, 0x10, 0x0a, 0x03, 0x50, 0x69, 0x64, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x05, 0x52, 0x03, 0x50,
	0x69, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x50, 0x70, 0x69, 0x64, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x05,
	0x52, 0x04, 0x50, 0x70, 0x69, 0x64, 0x12, 0x1e, 0x0a, 0x0a, 0x45, 0x78, 0x65, 0x63, 0x75, 0x74,
	0x61, 0x62, 0x6c, 0x65, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x45, 0x78, 0x65, 0x63,
	0x75, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x12, 0x20, 0x0a, 0x05, 0x4f, 0x77, 0x6e, 0x65, 0x72, 0x18,
	0x0d, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0a, 0x2e, 0x68, 0x6f, 0x73, 0x74, 0x2e, 0x55, 0x73, 0x65,
	0x72, 0x52, 0x05, 0x4f, 0x77, 0x6e, 0x65, 0x72, 0x12, 0x22, 0x0a, 0x0c, 0x41, 0x72, 0x63, 0x68,
	0x69, 0x74, 0x65, 0x63, 0x74, 0x75, 0x72, 0x65, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c,
	0x41, 0x72, 0x63, 0x68, 0x69, 0x74, 0x65, 0x63, 0x74, 0x75, 0x72, 0x65, 0x12, 0x18, 0x0a, 0x07,
	0x43, 0x6d, 0x64, 0x4c, 0x69, 0x6e, 0x65, 0x18, 0x10, 0x20, 0x03, 0x28, 0x09, 0x52, 0x07, 0x43,
	0x6d, 0x64, 0x4c, 0x69, 0x6e, 0x65, 0x3a, 0x06, 0xba, 0xb9, 0x19, 0x02, 0x08, 0x01, 0x42, 0x6e,
	0x0a, 0x08, 0x63, 0x6f, 0x6d, 0x2e, 0x68, 0x6f, 0x73, 0x74, 0x42, 0x0c, 0x50, 0x72, 0x6f, 0x63,
	0x65, 0x73, 0x73, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x24, 0x67, 0x69, 0x74, 0x68,
	0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6d, 0x61, 0x78, 0x6c, 0x61, 0x6e, 0x64, 0x6f, 0x6e,
	0x2f, 0x61, 0x69, 0x6d, 0x73, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x68, 0x6f, 0x73, 0x74,
	0xa2, 0x02, 0x03, 0x48, 0x58, 0x58, 0xaa, 0x02, 0x04, 0x48, 0x6f, 0x73, 0x74, 0xca, 0x02, 0x04,
	0x48, 0x6f, 0x73, 0x74, 0xe2, 0x02, 0x10, 0x48, 0x6f, 0x73, 0x74, 0x5c, 0x47, 0x50, 0x42, 0x4d,
	0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0xea, 0x02, 0x04, 0x48, 0x6f, 0x73, 0x74, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_host_process_proto_rawDescOnce sync.Once
	file_host_process_proto_rawDescData = file_host_process_proto_rawDesc
)

func file_host_process_proto_rawDescGZIP() []byte {
	file_host_process_proto_rawDescOnce.Do(func() {
		file_host_process_proto_rawDescData = protoimpl.X.CompressGZIP(file_host_process_proto_rawDescData)
	})
	return file_host_process_proto_rawDescData
}

var file_host_process_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_host_process_proto_goTypes = []interface{}{
	(*Process)(nil),               // 0: host.Process
	(*timestamppb.Timestamp)(nil), // 1: google.protobuf.Timestamp
	(*User)(nil),                  // 2: host.User
}
var file_host_process_proto_depIdxs = []int32{
	1, // 0: host.Process.CreatedAt:type_name -> google.protobuf.Timestamp
	1, // 1: host.Process.UpdatedAt:type_name -> google.protobuf.Timestamp
	2, // 2: host.Process.Owner:type_name -> host.User
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_host_process_proto_init() }
func file_host_process_proto_init() {
	if File_host_process_proto != nil {
		return
	}
	file_host_user_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_host_process_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Process); i {
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
			RawDescriptor: file_host_process_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_host_process_proto_goTypes,
		DependencyIndexes: file_host_process_proto_depIdxs,
		MessageInfos:      file_host_process_proto_msgTypes,
	}.Build()
	File_host_process_proto = out.File
	file_host_process_proto_rawDesc = nil
	file_host_process_proto_goTypes = nil
	file_host_process_proto_depIdxs = nil
}
