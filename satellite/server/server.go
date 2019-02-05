// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package satellite_server

import (
	"context"

	"github.com/zeebo/errs"
	"go.uber.org/zap"
	monkit "gopkg.in/spacemonkeygo/monkit.v2"

	"storj.io/storj/pkg/pb"
)

var (
	mon          = monkit.Package()
	segmentError = errs.Class("satellite_server error")
)

// Server implements the network state RPC service
type Server struct {
	logger *zap.Logger
	config Config
}

// NewServer creates instance of Server
func NewServer(logger *zap.Logger, config Config) *Server {
	return &Server{
		logger: logger,
		config: config,
	}
}

// Close closes resources
func (s *Server) Close() error { return nil }

// Put formats and hands off a key/value (path/pointer) to be saved to boltdb
func (s *Server) Health(ctx context.Context, req *pb.FileFealthRequest) (resp *pb.FileHealthResponse, err error) {
	defer mon.Task()(&ctx)(&err)

	return &pb.FileHealthResponse{}, nil
}