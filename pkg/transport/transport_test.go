// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package transport_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"storj.io/storj/internal/testcontext"
	"storj.io/storj/internal/testplanet"
	"storj.io/storj/pkg/pb"
	"storj.io/storj/pkg/peertls/tlsopts"
	"storj.io/storj/pkg/storj"
)

func TestDialNode(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	planet, err := testplanet.New(t, 0, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Check(planet.Shutdown)

	whitelistPath, err := planet.WriteWhitelist()
	require.NoError(t, err)

	planet.Start(ctx)

	client := planet.StorageNodes[0].Transport

	unsignedIdent, err := testplanet.PregeneratedIdentity(0)
	require.NoError(t, err)

	signedIdent, err := testplanet.PregeneratedSignedIdentity(0)
	require.NoError(t, err)

	opts, err := tlsopts.NewOptions(signedIdent, tlsopts.Config{
		UsePeerCAWhitelist:  true,
		PeerCAWhitelistPath: whitelistPath,
	})
	require.NoError(t, err)

	unsignedClientOpts, err := tlsopts.NewOptions(unsignedIdent, tlsopts.Config{})
	require.NoError(t, err)

	t.Run("DialNode with invalid targets", func(t *testing.T) {
		targets := []*pb.Node{
			{
				Id:      storj.NodeID{},
				Address: nil,
				Type:    pb.NodeType_STORAGE,
			},
			{
				Id: storj.NodeID{},
				Address: &pb.NodeAddress{
					Transport: pb.NodeTransport_TCP_TLS_GRPC,
				},
				Type: pb.NodeType_STORAGE,
			},
			{
				Id: storj.NodeID{123},
				Address: &pb.NodeAddress{
					Transport: pb.NodeTransport_TCP_TLS_GRPC,
					Address:   "127.0.0.1:100",
				},
				Type: pb.NodeType_STORAGE,
			},
		}

		for _, target := range targets {
			tag := fmt.Sprintf("%+v", target)

			timedCtx, cancel := context.WithTimeout(ctx, time.Second)
			conn, err := client.DialNode(timedCtx, target)
			cancel()
			assert.Error(t, err, tag)
			assert.Nil(t, conn, tag)
		}
	})

	t.Run("DialNode with valid target", func(t *testing.T) {
		target := &pb.Node{
			Id: planet.StorageNodes[1].ID(),
			Address: &pb.NodeAddress{
				Transport: pb.NodeTransport_TCP_TLS_GRPC,
				Address:   planet.StorageNodes[1].Addr(),
			},
			Type: pb.NodeType_STORAGE,
		}

		timedCtx, cancel := context.WithTimeout(ctx, time.Second)
		dialOption := opts.DialOption(storj.NodeID{})
		conn, err := client.DialNode(timedCtx, target, dialOption)
		cancel()

		assert.NoError(t, err)
		require.NotNil(t, conn)

		assert.NoError(t, conn.Close())
	})

	t.Run("DialNode with bad client certificate", func(t *testing.T) {
		target := &pb.Node{
			Id: planet.StorageNodes[1].ID(),
			Address: &pb.NodeAddress{
				Transport: pb.NodeTransport_TCP_TLS_GRPC,
				Address:   planet.StorageNodes[1].Addr(),
			},
			Type: pb.NodeType_STORAGE,
		}

		timedCtx, cancel := context.WithTimeout(ctx, time.Second)
		dialOption := unsignedClientOpts.DialOption(storj.NodeID{})
		conn, err := client.DialNode(
			timedCtx, target, dialOption,
		)
		cancel()

		tag := fmt.Sprintf("%+v", target)
		assert.Nil(t, conn, tag)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "bad certificate")
	})

	t.Run("DialAddress with bad client certificate", func(t *testing.T) {
		timedCtx, cancel := context.WithTimeout(ctx, time.Second)
		dialOption := unsignedClientOpts.DialOption(storj.NodeID{})
		conn, err := client.DialAddress(
			timedCtx, planet.StorageNodes[1].Addr(), dialOption,
		)
		cancel()

		assert.Nil(t, conn)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "bad certificate")
	})

	t.Run("DialAddress with valid address", func(t *testing.T) {
		timedCtx, cancel := context.WithTimeout(ctx, time.Second)
		conn, err := client.DialAddress(timedCtx, planet.StorageNodes[1].Addr())
		cancel()

		assert.NoError(t, err)
		require.NotNil(t, conn)
		assert.NoError(t, conn.Close())
	})
}

func TestDialNode_BadServerCertificate(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	planet, err := testplanet.NewCustom(
		zap.L(),
		testplanet.Config{
			SatelliteCount:   0,
			StorageNodeCount: 2,
			UplinkCount:      0,
			Reconfigure:      testplanet.DisablePeerCAWhitelist,
			Identities:       testplanet.NewPregeneratedIdentities(),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Check(planet.Shutdown)

	whitelistPath, err := planet.WriteWhitelist()
	require.NoError(t, err)

	planet.Start(ctx)

	client := planet.StorageNodes[0].Transport
	ident, err := testplanet.PregeneratedSignedIdentity(0)
	require.NoError(t, err)

	opts, err := tlsopts.NewOptions(ident, tlsopts.Config{
		UsePeerCAWhitelist:  true,
		PeerCAWhitelistPath: whitelistPath,
	})
	require.NoError(t, err)

	t.Run("DialNode with bad server certificate", func(t *testing.T) {
		target := &pb.Node{
			Id: planet.StorageNodes[1].ID(),
			Address: &pb.NodeAddress{
				Transport: pb.NodeTransport_TCP_TLS_GRPC,
				Address:   planet.StorageNodes[1].Addr(),
			},
			Type: pb.NodeType_STORAGE,
		}

		timedCtx, cancel := context.WithTimeout(ctx, time.Second)
		dialOption := opts.DialOption(storj.NodeID{})
		conn, err := client.DialNode(timedCtx, target, dialOption)
		cancel()

		tag := fmt.Sprintf("%+v", target)
		assert.Nil(t, conn, tag)
		require.Error(t, err, tag)
		assert.Contains(t, err.Error(), "not signed by any CA in the whitelist")
	})

	t.Run("DialAddress with bad server certificate", func(t *testing.T) {
		timedCtx, cancel := context.WithTimeout(ctx, time.Second)
		dialOption := opts.DialOption(storj.NodeID{})
		conn, err := client.DialAddress(timedCtx, planet.StorageNodes[1].Addr(), dialOption)
		cancel()

		assert.Nil(t, conn)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not signed by any CA in the whitelist")
	})
}
