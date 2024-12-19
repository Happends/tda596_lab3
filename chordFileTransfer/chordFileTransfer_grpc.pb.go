// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v3.19.6
// source: chordFileTransfer.proto

package ctfp

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	ChordFileTransfer_FindSuccessor_FullMethodName  = "/ChordFileTransfer/FindSuccessor"
	ChordFileTransfer_Notify_FullMethodName         = "/ChordFileTransfer/Notify"
	ChordFileTransfer_GetSuccessors_FullMethodName  = "/ChordFileTransfer/GetSuccessors"
	ChordFileTransfer_GetPredecessor_FullMethodName = "/ChordFileTransfer/GetPredecessor"
	ChordFileTransfer_Get_FullMethodName            = "/ChordFileTransfer/Get"
	ChordFileTransfer_Put_FullMethodName            = "/ChordFileTransfer/Put"
	ChordFileTransfer_Delete_FullMethodName         = "/ChordFileTransfer/Delete"
	ChordFileTransfer_GetAESKey_FullMethodName      = "/ChordFileTransfer/GetAESKey"
	ChordFileTransfer_PrintState_FullMethodName     = "/ChordFileTransfer/PrintState"
)

// ChordFileTransferClient is the client API for ChordFileTransfer service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ChordFileTransferClient interface {
	FindSuccessor(ctx context.Context, in *FindSuccessorArgs, opts ...grpc.CallOption) (*FindSuccessorReply, error)
	Notify(ctx context.Context, in *NotifyArgs, opts ...grpc.CallOption) (*NotifyReply, error)
	GetSuccessors(ctx context.Context, in *GetSuccessorsArgs, opts ...grpc.CallOption) (*GetSuccessorsReply, error)
	GetPredecessor(ctx context.Context, in *GetPredecessorArgs, opts ...grpc.CallOption) (*GetPredecessorReply, error)
	Get(ctx context.Context, in *GetArgs, opts ...grpc.CallOption) (*GetReply, error)
	Put(ctx context.Context, in *PutArgs, opts ...grpc.CallOption) (*PutReply, error)
	Delete(ctx context.Context, in *DeleteArgs, opts ...grpc.CallOption) (*DeleteReply, error)
	GetAESKey(ctx context.Context, in *GetAESKeyArgs, opts ...grpc.CallOption) (*GetAESKeyReply, error)
	PrintState(ctx context.Context, in *EmptyArgs, opts ...grpc.CallOption) (*EmptyReply, error)
}

type chordFileTransferClient struct {
	cc grpc.ClientConnInterface
}

func NewChordFileTransferClient(cc grpc.ClientConnInterface) ChordFileTransferClient {
	return &chordFileTransferClient{cc}
}

func (c *chordFileTransferClient) FindSuccessor(ctx context.Context, in *FindSuccessorArgs, opts ...grpc.CallOption) (*FindSuccessorReply, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(FindSuccessorReply)
	err := c.cc.Invoke(ctx, ChordFileTransfer_FindSuccessor_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *chordFileTransferClient) Notify(ctx context.Context, in *NotifyArgs, opts ...grpc.CallOption) (*NotifyReply, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(NotifyReply)
	err := c.cc.Invoke(ctx, ChordFileTransfer_Notify_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *chordFileTransferClient) GetSuccessors(ctx context.Context, in *GetSuccessorsArgs, opts ...grpc.CallOption) (*GetSuccessorsReply, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(GetSuccessorsReply)
	err := c.cc.Invoke(ctx, ChordFileTransfer_GetSuccessors_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *chordFileTransferClient) GetPredecessor(ctx context.Context, in *GetPredecessorArgs, opts ...grpc.CallOption) (*GetPredecessorReply, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(GetPredecessorReply)
	err := c.cc.Invoke(ctx, ChordFileTransfer_GetPredecessor_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *chordFileTransferClient) Get(ctx context.Context, in *GetArgs, opts ...grpc.CallOption) (*GetReply, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(GetReply)
	err := c.cc.Invoke(ctx, ChordFileTransfer_Get_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *chordFileTransferClient) Put(ctx context.Context, in *PutArgs, opts ...grpc.CallOption) (*PutReply, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(PutReply)
	err := c.cc.Invoke(ctx, ChordFileTransfer_Put_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *chordFileTransferClient) Delete(ctx context.Context, in *DeleteArgs, opts ...grpc.CallOption) (*DeleteReply, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(DeleteReply)
	err := c.cc.Invoke(ctx, ChordFileTransfer_Delete_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *chordFileTransferClient) GetAESKey(ctx context.Context, in *GetAESKeyArgs, opts ...grpc.CallOption) (*GetAESKeyReply, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(GetAESKeyReply)
	err := c.cc.Invoke(ctx, ChordFileTransfer_GetAESKey_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *chordFileTransferClient) PrintState(ctx context.Context, in *EmptyArgs, opts ...grpc.CallOption) (*EmptyReply, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(EmptyReply)
	err := c.cc.Invoke(ctx, ChordFileTransfer_PrintState_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ChordFileTransferServer is the server API for ChordFileTransfer service.
// All implementations must embed UnimplementedChordFileTransferServer
// for forward compatibility.
type ChordFileTransferServer interface {
	FindSuccessor(context.Context, *FindSuccessorArgs) (*FindSuccessorReply, error)
	Notify(context.Context, *NotifyArgs) (*NotifyReply, error)
	GetSuccessors(context.Context, *GetSuccessorsArgs) (*GetSuccessorsReply, error)
	GetPredecessor(context.Context, *GetPredecessorArgs) (*GetPredecessorReply, error)
	Get(context.Context, *GetArgs) (*GetReply, error)
	Put(context.Context, *PutArgs) (*PutReply, error)
	Delete(context.Context, *DeleteArgs) (*DeleteReply, error)
	GetAESKey(context.Context, *GetAESKeyArgs) (*GetAESKeyReply, error)
	PrintState(context.Context, *EmptyArgs) (*EmptyReply, error)
	mustEmbedUnimplementedChordFileTransferServer()
}

// UnimplementedChordFileTransferServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedChordFileTransferServer struct{}

func (UnimplementedChordFileTransferServer) FindSuccessor(context.Context, *FindSuccessorArgs) (*FindSuccessorReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method FindSuccessor not implemented")
}
func (UnimplementedChordFileTransferServer) Notify(context.Context, *NotifyArgs) (*NotifyReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Notify not implemented")
}
func (UnimplementedChordFileTransferServer) GetSuccessors(context.Context, *GetSuccessorsArgs) (*GetSuccessorsReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetSuccessors not implemented")
}
func (UnimplementedChordFileTransferServer) GetPredecessor(context.Context, *GetPredecessorArgs) (*GetPredecessorReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetPredecessor not implemented")
}
func (UnimplementedChordFileTransferServer) Get(context.Context, *GetArgs) (*GetReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Get not implemented")
}
func (UnimplementedChordFileTransferServer) Put(context.Context, *PutArgs) (*PutReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Put not implemented")
}
func (UnimplementedChordFileTransferServer) Delete(context.Context, *DeleteArgs) (*DeleteReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Delete not implemented")
}
func (UnimplementedChordFileTransferServer) GetAESKey(context.Context, *GetAESKeyArgs) (*GetAESKeyReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetAESKey not implemented")
}
func (UnimplementedChordFileTransferServer) PrintState(context.Context, *EmptyArgs) (*EmptyReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PrintState not implemented")
}
func (UnimplementedChordFileTransferServer) mustEmbedUnimplementedChordFileTransferServer() {}
func (UnimplementedChordFileTransferServer) testEmbeddedByValue()                           {}

// UnsafeChordFileTransferServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ChordFileTransferServer will
// result in compilation errors.
type UnsafeChordFileTransferServer interface {
	mustEmbedUnimplementedChordFileTransferServer()
}

func RegisterChordFileTransferServer(s grpc.ServiceRegistrar, srv ChordFileTransferServer) {
	// If the following call pancis, it indicates UnimplementedChordFileTransferServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&ChordFileTransfer_ServiceDesc, srv)
}

func _ChordFileTransfer_FindSuccessor_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(FindSuccessorArgs)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ChordFileTransferServer).FindSuccessor(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ChordFileTransfer_FindSuccessor_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ChordFileTransferServer).FindSuccessor(ctx, req.(*FindSuccessorArgs))
	}
	return interceptor(ctx, in, info, handler)
}

func _ChordFileTransfer_Notify_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(NotifyArgs)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ChordFileTransferServer).Notify(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ChordFileTransfer_Notify_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ChordFileTransferServer).Notify(ctx, req.(*NotifyArgs))
	}
	return interceptor(ctx, in, info, handler)
}

func _ChordFileTransfer_GetSuccessors_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetSuccessorsArgs)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ChordFileTransferServer).GetSuccessors(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ChordFileTransfer_GetSuccessors_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ChordFileTransferServer).GetSuccessors(ctx, req.(*GetSuccessorsArgs))
	}
	return interceptor(ctx, in, info, handler)
}

func _ChordFileTransfer_GetPredecessor_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetPredecessorArgs)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ChordFileTransferServer).GetPredecessor(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ChordFileTransfer_GetPredecessor_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ChordFileTransferServer).GetPredecessor(ctx, req.(*GetPredecessorArgs))
	}
	return interceptor(ctx, in, info, handler)
}

func _ChordFileTransfer_Get_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetArgs)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ChordFileTransferServer).Get(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ChordFileTransfer_Get_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ChordFileTransferServer).Get(ctx, req.(*GetArgs))
	}
	return interceptor(ctx, in, info, handler)
}

func _ChordFileTransfer_Put_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PutArgs)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ChordFileTransferServer).Put(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ChordFileTransfer_Put_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ChordFileTransferServer).Put(ctx, req.(*PutArgs))
	}
	return interceptor(ctx, in, info, handler)
}

func _ChordFileTransfer_Delete_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteArgs)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ChordFileTransferServer).Delete(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ChordFileTransfer_Delete_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ChordFileTransferServer).Delete(ctx, req.(*DeleteArgs))
	}
	return interceptor(ctx, in, info, handler)
}

func _ChordFileTransfer_GetAESKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetAESKeyArgs)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ChordFileTransferServer).GetAESKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ChordFileTransfer_GetAESKey_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ChordFileTransferServer).GetAESKey(ctx, req.(*GetAESKeyArgs))
	}
	return interceptor(ctx, in, info, handler)
}

func _ChordFileTransfer_PrintState_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(EmptyArgs)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ChordFileTransferServer).PrintState(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ChordFileTransfer_PrintState_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ChordFileTransferServer).PrintState(ctx, req.(*EmptyArgs))
	}
	return interceptor(ctx, in, info, handler)
}

// ChordFileTransfer_ServiceDesc is the grpc.ServiceDesc for ChordFileTransfer service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var ChordFileTransfer_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "ChordFileTransfer",
	HandlerType: (*ChordFileTransferServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "FindSuccessor",
			Handler:    _ChordFileTransfer_FindSuccessor_Handler,
		},
		{
			MethodName: "Notify",
			Handler:    _ChordFileTransfer_Notify_Handler,
		},
		{
			MethodName: "GetSuccessors",
			Handler:    _ChordFileTransfer_GetSuccessors_Handler,
		},
		{
			MethodName: "GetPredecessor",
			Handler:    _ChordFileTransfer_GetPredecessor_Handler,
		},
		{
			MethodName: "Get",
			Handler:    _ChordFileTransfer_Get_Handler,
		},
		{
			MethodName: "Put",
			Handler:    _ChordFileTransfer_Put_Handler,
		},
		{
			MethodName: "Delete",
			Handler:    _ChordFileTransfer_Delete_Handler,
		},
		{
			MethodName: "GetAESKey",
			Handler:    _ChordFileTransfer_GetAESKey_Handler,
		},
		{
			MethodName: "PrintState",
			Handler:    _ChordFileTransfer_PrintState_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "chordFileTransfer.proto",
}
