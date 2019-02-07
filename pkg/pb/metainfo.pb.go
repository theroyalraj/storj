// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: metainfo.proto

package pb

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/gogo/protobuf/gogoproto"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion2 // please upgrade the proto package

type ObjectHealthRequest struct {
	EncryptedPath        []byte   `protobuf:"bytes,1,opt,name=encrypted_path,json=encryptedPath,proto3" json:"encrypted_path,omitempty"`
	Bucket               []byte   `protobuf:"bytes,2,opt,name=bucket,proto3" json:"bucket,omitempty"`
	UplinkId             NodeID   `protobuf:"bytes,3,opt,name=uplink_id,json=uplinkId,proto3,customtype=NodeID" json:"uplink_id"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ObjectHealthRequest) Reset()         { *m = ObjectHealthRequest{} }
func (m *ObjectHealthRequest) String() string { return proto.CompactTextString(m) }
func (*ObjectHealthRequest) ProtoMessage()    {}
func (*ObjectHealthRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_metainfo_f4b31718600d778a, []int{0}
}
func (m *ObjectHealthRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ObjectHealthRequest.Unmarshal(m, b)
}
func (m *ObjectHealthRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ObjectHealthRequest.Marshal(b, m, deterministic)
}
func (dst *ObjectHealthRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ObjectHealthRequest.Merge(dst, src)
}
func (m *ObjectHealthRequest) XXX_Size() int {
	return xxx_messageInfo_ObjectHealthRequest.Size(m)
}
func (m *ObjectHealthRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_ObjectHealthRequest.DiscardUnknown(m)
}

var xxx_messageInfo_ObjectHealthRequest proto.InternalMessageInfo

func (m *ObjectHealthRequest) GetEncryptedPath() []byte {
	if m != nil {
		return m.EncryptedPath
	}
	return nil
}

func (m *ObjectHealthRequest) GetBucket() []byte {
	if m != nil {
		return m.Bucket
	}
	return nil
}

type ObjectHealthResponse struct {
	Segments             []*ObjectHealthResponse_SegmentInfo `protobuf:"bytes,1,rep,name=segments,proto3" json:"segments,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                            `json:"-"`
	XXX_unrecognized     []byte                              `json:"-"`
	XXX_sizecache        int32                               `json:"-"`
}

func (m *ObjectHealthResponse) Reset()         { *m = ObjectHealthResponse{} }
func (m *ObjectHealthResponse) String() string { return proto.CompactTextString(m) }
func (*ObjectHealthResponse) ProtoMessage()    {}
func (*ObjectHealthResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_metainfo_f4b31718600d778a, []int{1}
}
func (m *ObjectHealthResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ObjectHealthResponse.Unmarshal(m, b)
}
func (m *ObjectHealthResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ObjectHealthResponse.Marshal(b, m, deterministic)
}
func (dst *ObjectHealthResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ObjectHealthResponse.Merge(dst, src)
}
func (m *ObjectHealthResponse) XXX_Size() int {
	return xxx_messageInfo_ObjectHealthResponse.Size(m)
}
func (m *ObjectHealthResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_ObjectHealthResponse.DiscardUnknown(m)
}

var xxx_messageInfo_ObjectHealthResponse proto.InternalMessageInfo

func (m *ObjectHealthResponse) GetSegments() []*ObjectHealthResponse_SegmentInfo {
	if m != nil {
		return m.Segments
	}
	return nil
}

type ObjectHealthResponse_SegmentInfo struct {
	GoodNodes            int64    `protobuf:"varint,1,opt,name=good_nodes,json=goodNodes,proto3" json:"good_nodes,omitempty"`
	BadNodes             int64    `protobuf:"varint,2,opt,name=bad_nodes,json=badNodes,proto3" json:"bad_nodes,omitempty"`
	OfflineNodes         int64    `protobuf:"varint,3,opt,name=offline_nodes,json=offlineNodes,proto3" json:"offline_nodes,omitempty"`
	BelowRecover         int64    `protobuf:"varint,4,opt,name=below_recover,json=belowRecover,proto3" json:"below_recover,omitempty"`
	BelowRepair          int64    `protobuf:"varint,5,opt,name=below_repair,json=belowRepair,proto3" json:"below_repair,omitempty"`
	BelowSuccess         int64    `protobuf:"varint,6,opt,name=below_success,json=belowSuccess,proto3" json:"below_success,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ObjectHealthResponse_SegmentInfo) Reset()         { *m = ObjectHealthResponse_SegmentInfo{} }
func (m *ObjectHealthResponse_SegmentInfo) String() string { return proto.CompactTextString(m) }
func (*ObjectHealthResponse_SegmentInfo) ProtoMessage()    {}
func (*ObjectHealthResponse_SegmentInfo) Descriptor() ([]byte, []int) {
	return fileDescriptor_metainfo_f4b31718600d778a, []int{1, 0}
}
func (m *ObjectHealthResponse_SegmentInfo) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ObjectHealthResponse_SegmentInfo.Unmarshal(m, b)
}
func (m *ObjectHealthResponse_SegmentInfo) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ObjectHealthResponse_SegmentInfo.Marshal(b, m, deterministic)
}
func (dst *ObjectHealthResponse_SegmentInfo) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ObjectHealthResponse_SegmentInfo.Merge(dst, src)
}
func (m *ObjectHealthResponse_SegmentInfo) XXX_Size() int {
	return xxx_messageInfo_ObjectHealthResponse_SegmentInfo.Size(m)
}
func (m *ObjectHealthResponse_SegmentInfo) XXX_DiscardUnknown() {
	xxx_messageInfo_ObjectHealthResponse_SegmentInfo.DiscardUnknown(m)
}

var xxx_messageInfo_ObjectHealthResponse_SegmentInfo proto.InternalMessageInfo

func (m *ObjectHealthResponse_SegmentInfo) GetGoodNodes() int64 {
	if m != nil {
		return m.GoodNodes
	}
	return 0
}

func (m *ObjectHealthResponse_SegmentInfo) GetBadNodes() int64 {
	if m != nil {
		return m.BadNodes
	}
	return 0
}

func (m *ObjectHealthResponse_SegmentInfo) GetOfflineNodes() int64 {
	if m != nil {
		return m.OfflineNodes
	}
	return 0
}

func (m *ObjectHealthResponse_SegmentInfo) GetBelowRecover() int64 {
	if m != nil {
		return m.BelowRecover
	}
	return 0
}

func (m *ObjectHealthResponse_SegmentInfo) GetBelowRepair() int64 {
	if m != nil {
		return m.BelowRepair
	}
	return 0
}

func (m *ObjectHealthResponse_SegmentInfo) GetBelowSuccess() int64 {
	if m != nil {
		return m.BelowSuccess
	}
	return 0
}

func init() {
	proto.RegisterType((*ObjectHealthRequest)(nil), "metainfo.ObjectHealthRequest")
	proto.RegisterType((*ObjectHealthResponse)(nil), "metainfo.ObjectHealthResponse")
	proto.RegisterType((*ObjectHealthResponse_SegmentInfo)(nil), "metainfo.ObjectHealthResponse.SegmentInfo")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// MetainfoClient is the client API for Metainfo service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type MetainfoClient interface {
	Health(ctx context.Context, in *ObjectHealthRequest, opts ...grpc.CallOption) (*ObjectHealthResponse, error)
}

type metainfoClient struct {
	cc *grpc.ClientConn
}

func NewMetainfoClient(cc *grpc.ClientConn) MetainfoClient {
	return &metainfoClient{cc}
}

func (c *metainfoClient) Health(ctx context.Context, in *ObjectHealthRequest, opts ...grpc.CallOption) (*ObjectHealthResponse, error) {
	out := new(ObjectHealthResponse)
	err := c.cc.Invoke(ctx, "/metainfo.Metainfo/Health", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// MetainfoServer is the server API for Metainfo service.
type MetainfoServer interface {
	Health(context.Context, *ObjectHealthRequest) (*ObjectHealthResponse, error)
}

func RegisterMetainfoServer(s *grpc.Server, srv MetainfoServer) {
	s.RegisterService(&_Metainfo_serviceDesc, srv)
}

func _Metainfo_Health_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ObjectHealthRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MetainfoServer).Health(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/metainfo.Metainfo/Health",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MetainfoServer).Health(ctx, req.(*ObjectHealthRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Metainfo_serviceDesc = grpc.ServiceDesc{
	ServiceName: "metainfo.Metainfo",
	HandlerType: (*MetainfoServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Health",
			Handler:    _Metainfo_Health_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "metainfo.proto",
}

func init() { proto.RegisterFile("metainfo.proto", fileDescriptor_metainfo_f4b31718600d778a) }

var fileDescriptor_metainfo_f4b31718600d778a = []byte{
	// 361 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x92, 0xcd, 0x4a, 0xeb, 0x40,
	0x14, 0xc7, 0x9b, 0xa4, 0x37, 0xa4, 0xa7, 0x1f, 0x8b, 0xb9, 0x97, 0x4b, 0xe8, 0xa5, 0xb7, 0xb5,
	0x22, 0x14, 0x85, 0x2e, 0xea, 0x1b, 0x14, 0x11, 0xb3, 0xf0, 0x83, 0x14, 0x37, 0x6e, 0x42, 0x3e,
	0x4e, 0xd2, 0xd8, 0x74, 0x26, 0x66, 0x26, 0x8a, 0x4b, 0xdf, 0xcb, 0x07, 0xf0, 0x19, 0x14, 0xfa,
	0x2c, 0x92, 0x49, 0x1a, 0x2b, 0xa8, 0xcb, 0xf9, 0xfd, 0x7f, 0x33, 0x9c, 0xf3, 0x4f, 0xa0, 0xb7,
	0x46, 0xe1, 0xc6, 0x34, 0x64, 0xd3, 0x34, 0x63, 0x82, 0x11, 0x63, 0x7b, 0xee, 0x43, 0xc4, 0xa2,
	0x8a, 0x8e, 0x9f, 0x14, 0xf8, 0x7d, 0xe9, 0xdd, 0xa2, 0x2f, 0xce, 0xd0, 0x4d, 0xc4, 0xd2, 0xc6,
	0xbb, 0x1c, 0xb9, 0x20, 0x07, 0xd0, 0x43, 0xea, 0x67, 0x8f, 0xa9, 0xc0, 0xc0, 0x49, 0x5d, 0xb1,
	0x34, 0x95, 0x91, 0x32, 0xe9, 0xd8, 0xdd, 0x9a, 0x5e, 0xb9, 0x62, 0x49, 0xfe, 0x82, 0xee, 0xe5,
	0xfe, 0x0a, 0x85, 0xa9, 0xca, 0xb8, 0x3a, 0x91, 0x23, 0x68, 0xe5, 0x69, 0x12, 0xd3, 0x95, 0x13,
	0x07, 0xa6, 0x56, 0x44, 0xf3, 0xde, 0xcb, 0x66, 0xd8, 0x78, 0xdd, 0x0c, 0xf5, 0x0b, 0x16, 0xa0,
	0x75, 0x62, 0x1b, 0xa5, 0x60, 0x05, 0xe3, 0x67, 0x15, 0xfe, 0x7c, 0x9e, 0x81, 0xa7, 0x8c, 0x72,
	0x24, 0xa7, 0x60, 0x70, 0x8c, 0xd6, 0x48, 0x05, 0x37, 0x95, 0x91, 0x36, 0x69, 0xcf, 0x0e, 0xa7,
	0xf5, 0x56, 0x5f, 0xdd, 0x98, 0x2e, 0x4a, 0xdd, 0xa2, 0x21, 0xb3, 0xeb, 0xbb, 0xfd, 0x37, 0x05,
	0xda, 0x3b, 0x09, 0x19, 0x00, 0x44, 0x8c, 0x05, 0x0e, 0x65, 0x01, 0x72, 0xb9, 0x98, 0x66, 0xb7,
	0x0a, 0x52, 0x8c, 0xc6, 0xc9, 0x3f, 0x68, 0x79, 0xee, 0x36, 0x55, 0x65, 0x6a, 0x78, 0x6e, 0x15,
	0xee, 0x43, 0x97, 0x85, 0x61, 0x12, 0x53, 0xac, 0x04, 0x4d, 0x0a, 0x9d, 0x0a, 0xd6, 0x92, 0x87,
	0x09, 0x7b, 0x70, 0x32, 0xf4, 0xd9, 0x3d, 0x66, 0x66, 0xb3, 0x94, 0x24, 0xb4, 0x4b, 0x46, 0xf6,
	0xa0, 0xb3, 0x95, 0x52, 0x37, 0xce, 0xcc, 0x5f, 0xd2, 0x69, 0x57, 0x4e, 0x81, 0x3e, 0xde, 0xe1,
	0xb9, 0xef, 0x23, 0xe7, 0xa6, 0xbe, 0xf3, 0xce, 0xa2, 0x64, 0xb3, 0x6b, 0x30, 0xce, 0xab, 0x52,
	0x88, 0x05, 0x7a, 0xd9, 0x08, 0x19, 0x7c, 0xd7, 0x94, 0xfc, 0xbe, 0xfd, 0xff, 0x3f, 0x17, 0x39,
	0x6e, 0xcc, 0x9b, 0x37, 0x6a, 0xea, 0x79, 0xba, 0xfc, 0x4d, 0x8e, 0xdf, 0x03, 0x00, 0x00, 0xff,
	0xff, 0xce, 0x6f, 0x4d, 0x27, 0x4e, 0x02, 0x00, 0x00,
}
