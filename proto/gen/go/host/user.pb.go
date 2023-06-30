// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v3.18.1
// source: host/user.proto

package host

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

// User - An operating-system user.
type User struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// @gotags: display:"ID" readonly:"true" strict:"yes"
	Id *types.UUID `protobuf:"bytes,1,opt,name=Id,proto3" json:"Id,omitempty" display:"ID" readonly:"true" strict:"yes"`
	// @gotags: display:"Created at" readonly:"true" xml:"-"
	CreatedAt *timestamppb.Timestamp `protobuf:"bytes,4,opt,name=CreatedAt,proto3" json:"CreatedAt,omitempty" display:"Created at" readonly:"true" xml:"-"`
	// @gotags: display:"Updated at" readonly:"true" xml:"-"
	UpdatedAt *timestamppb.Timestamp `protobuf:"bytes,5,opt,name=UpdatedAt,proto3" json:"UpdatedAt,omitempty" display:"Updated at" readonly:"true" xml:"-"` // -------------------------------------
	// @gotags: display:"Name"
	Name string `protobuf:"bytes,10,opt,name=Name,proto3" json:"Name,omitempty" display:"Name"`
	// @gotags: display:"UID"
	UID    int32    `protobuf:"varint,11,opt,name=UID,proto3" json:"UID,omitempty" display:"UID"`
	Groups []*Group `protobuf:"bytes,12,rep,name=Groups,proto3" json:"Groups,omitempty"`
}

func (x *User) Reset() {
	*x = User{}
	if protoimpl.UnsafeEnabled {
		mi := &file_host_user_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *User) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*User) ProtoMessage() {}

func (x *User) ProtoReflect() protoreflect.Message {
	mi := &file_host_user_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use User.ProtoReflect.Descriptor instead.
func (*User) Descriptor() ([]byte, []int) {
	return file_host_user_proto_rawDescGZIP(), []int{0}
}

func (x *User) GetId() *types.UUID {
	if x != nil {
		return x.Id
	}
	return nil
}

func (x *User) GetCreatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.CreatedAt
	}
	return nil
}

func (x *User) GetUpdatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.UpdatedAt
	}
	return nil
}

func (x *User) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *User) GetUID() int32 {
	if x != nil {
		return x.UID
	}
	return 0
}

func (x *User) GetGroups() []*Group {
	if x != nil {
		return x.Groups
	}
	return nil
}

// Group - An operating-system group of users
type Group struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// @gotags: display:"ID" hidden:"true" strict:"yes"
	Id *types.UUID `protobuf:"bytes,1,opt,name=Id,proto3" json:"Id,omitempty" display:"ID" hidden:"true" strict:"yes"`
	// @gotags: display:"Created at" readonly:"true" xml:"-"
	CreatedAt *timestamppb.Timestamp `protobuf:"bytes,4,opt,name=CreatedAt,proto3" json:"CreatedAt,omitempty" display:"Created at" readonly:"true" xml:"-"`
	// @gotags: display:"Updated at" readonly:"true" xml:"-"
	UpdatedAt *timestamppb.Timestamp `protobuf:"bytes,5,opt,name=UpdatedAt,proto3" json:"UpdatedAt,omitempty" display:"Updated at" readonly:"true" xml:"-"`
	// @gotags: display:"Name"
	Name string `protobuf:"bytes,10,opt,name=Name,proto3" json:"Name,omitempty" display:"Name"`
	// @gotags: display:"Group ID"
	GID     int32   `protobuf:"varint,11,opt,name=GID,proto3" json:"GID,omitempty" display:"Group ID"`
	Members []*User `protobuf:"bytes,12,rep,name=Members,proto3" json:"Members,omitempty"`
}

func (x *Group) Reset() {
	*x = Group{}
	if protoimpl.UnsafeEnabled {
		mi := &file_host_user_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Group) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Group) ProtoMessage() {}

func (x *Group) ProtoReflect() protoreflect.Message {
	mi := &file_host_user_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Group.ProtoReflect.Descriptor instead.
func (*Group) Descriptor() ([]byte, []int) {
	return file_host_user_proto_rawDescGZIP(), []int{1}
}

func (x *Group) GetId() *types.UUID {
	if x != nil {
		return x.Id
	}
	return nil
}

func (x *Group) GetCreatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.CreatedAt
	}
	return nil
}

func (x *Group) GetUpdatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.UpdatedAt
	}
	return nil
}

func (x *Group) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Group) GetGID() int32 {
	if x != nil {
		return x.GID
	}
	return 0
}

func (x *Group) GetMembers() []*User {
	if x != nil {
		return x.Members
	}
	return nil
}

var File_host_user_proto protoreflect.FileDescriptor

var file_host_user_proto_rawDesc = []byte{
	0x0a, 0x0f, 0x68, 0x6f, 0x73, 0x74, 0x2f, 0x75, 0x73, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61,
	0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x12, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x2f, 0x67, 0x6f, 0x72, 0x6d, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x11, 0x74, 0x79,
	0x70, 0x65, 0x73, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0x87, 0x02, 0x0a, 0x04, 0x55, 0x73, 0x65, 0x72, 0x12, 0x30, 0x0a, 0x02, 0x49, 0x64, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x67, 0x6f, 0x72, 0x6d, 0x2e, 0x74, 0x79, 0x70, 0x65,
	0x73, 0x2e, 0x55, 0x55, 0x49, 0x44, 0x42, 0x0e, 0xba, 0xb9, 0x19, 0x0a, 0x0a, 0x08, 0x12, 0x04,
	0x75, 0x75, 0x69, 0x64, 0x28, 0x01, 0x52, 0x02, 0x49, 0x64, 0x12, 0x38, 0x0a, 0x09, 0x43, 0x72,
	0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x43, 0x72, 0x65, 0x61, 0x74,
	0x65, 0x64, 0x41, 0x74, 0x12, 0x38, 0x0a, 0x09, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x41,
	0x74, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74,
	0x61, 0x6d, 0x70, 0x52, 0x09, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x12, 0x12,
	0x0a, 0x04, 0x4e, 0x61, 0x6d, 0x65, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x4e, 0x61,
	0x6d, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x55, 0x49, 0x44, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x05, 0x52,
	0x03, 0x55, 0x49, 0x44, 0x12, 0x2b, 0x0a, 0x06, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x73, 0x18, 0x0c,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x0b, 0x2e, 0x68, 0x6f, 0x73, 0x74, 0x2e, 0x47, 0x72, 0x6f, 0x75,
	0x70, 0x42, 0x06, 0xba, 0xb9, 0x19, 0x02, 0x32, 0x00, 0x52, 0x06, 0x47, 0x72, 0x6f, 0x75, 0x70,
	0x73, 0x3a, 0x06, 0xba, 0xb9, 0x19, 0x02, 0x08, 0x01, 0x22, 0x89, 0x02, 0x0a, 0x05, 0x47, 0x72,
	0x6f, 0x75, 0x70, 0x12, 0x30, 0x0a, 0x02, 0x49, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x10, 0x2e, 0x67, 0x6f, 0x72, 0x6d, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x55, 0x55, 0x49,
	0x44, 0x42, 0x0e, 0xba, 0xb9, 0x19, 0x0a, 0x0a, 0x08, 0x12, 0x04, 0x75, 0x75, 0x69, 0x64, 0x28,
	0x01, 0x52, 0x02, 0x49, 0x64, 0x12, 0x38, 0x0a, 0x09, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64,
	0x41, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73,
	0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x12,
	0x38, 0x0a, 0x09, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x18, 0x05, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09,
	0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x4e, 0x61, 0x6d,
	0x65, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x10, 0x0a,
	0x03, 0x47, 0x49, 0x44, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x05, 0x52, 0x03, 0x47, 0x49, 0x44, 0x12,
	0x2c, 0x0a, 0x07, 0x4d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x73, 0x18, 0x0c, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x0a, 0x2e, 0x68, 0x6f, 0x73, 0x74, 0x2e, 0x55, 0x73, 0x65, 0x72, 0x42, 0x06, 0xba, 0xb9,
	0x19, 0x02, 0x32, 0x00, 0x52, 0x07, 0x4d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x73, 0x3a, 0x06, 0xba,
	0xb9, 0x19, 0x02, 0x08, 0x01, 0x42, 0x72, 0x0a, 0x08, 0x63, 0x6f, 0x6d, 0x2e, 0x68, 0x6f, 0x73,
	0x74, 0x42, 0x09, 0x55, 0x73, 0x65, 0x72, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x2b,
	0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6d, 0x61, 0x78, 0x6c, 0x61,
	0x6e, 0x64, 0x6f, 0x6e, 0x2f, 0x61, 0x69, 0x6d, 0x73, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f,
	0x67, 0x65, 0x6e, 0x2f, 0x67, 0x6f, 0x2f, 0x68, 0x6f, 0x73, 0x74, 0xa2, 0x02, 0x03, 0x48, 0x58,
	0x58, 0xaa, 0x02, 0x04, 0x48, 0x6f, 0x73, 0x74, 0xca, 0x02, 0x04, 0x48, 0x6f, 0x73, 0x74, 0xe2,
	0x02, 0x10, 0x48, 0x6f, 0x73, 0x74, 0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61,
	0x74, 0x61, 0xea, 0x02, 0x04, 0x48, 0x6f, 0x73, 0x74, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_host_user_proto_rawDescOnce sync.Once
	file_host_user_proto_rawDescData = file_host_user_proto_rawDesc
)

func file_host_user_proto_rawDescGZIP() []byte {
	file_host_user_proto_rawDescOnce.Do(func() {
		file_host_user_proto_rawDescData = protoimpl.X.CompressGZIP(file_host_user_proto_rawDescData)
	})
	return file_host_user_proto_rawDescData
}

var file_host_user_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_host_user_proto_goTypes = []interface{}{
	(*User)(nil),                  // 0: host.User
	(*Group)(nil),                 // 1: host.Group
	(*types.UUID)(nil),            // 2: gorm.types.UUID
	(*timestamppb.Timestamp)(nil), // 3: google.protobuf.Timestamp
}
var file_host_user_proto_depIdxs = []int32{
	2, // 0: host.User.Id:type_name -> gorm.types.UUID
	3, // 1: host.User.CreatedAt:type_name -> google.protobuf.Timestamp
	3, // 2: host.User.UpdatedAt:type_name -> google.protobuf.Timestamp
	1, // 3: host.User.Groups:type_name -> host.Group
	2, // 4: host.Group.Id:type_name -> gorm.types.UUID
	3, // 5: host.Group.CreatedAt:type_name -> google.protobuf.Timestamp
	3, // 6: host.Group.UpdatedAt:type_name -> google.protobuf.Timestamp
	0, // 7: host.Group.Members:type_name -> host.User
	8, // [8:8] is the sub-list for method output_type
	8, // [8:8] is the sub-list for method input_type
	8, // [8:8] is the sub-list for extension type_name
	8, // [8:8] is the sub-list for extension extendee
	0, // [0:8] is the sub-list for field type_name
}

func init() { file_host_user_proto_init() }
func file_host_user_proto_init() {
	if File_host_user_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_host_user_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*User); i {
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
		file_host_user_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Group); i {
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
			RawDescriptor: file_host_user_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_host_user_proto_goTypes,
		DependencyIndexes: file_host_user_proto_depIdxs,
		MessageInfos:      file_host_user_proto_msgTypes,
	}.Build()
	File_host_user_proto = out.File
	file_host_user_proto_rawDesc = nil
	file_host_user_proto_goTypes = nil
	file_host_user_proto_depIdxs = nil
}
