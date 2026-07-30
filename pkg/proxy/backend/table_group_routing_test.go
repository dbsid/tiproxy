// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/pingcap/tiproxy/pkg/balance/router"
	pnet "github.com/pingcap/tiproxy/pkg/proxy/net"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestParseTableGroupRoutingValue(t *testing.T) {
	tests := []struct {
		query string
		value uint64
		ok    bool
	}{
		{"SET SESSION tidb_table_group_routing_value = 0", 0, true},
		{" set  session TIDB_TABLE_GROUP_ROUTING_VALUE=18446744073709551615; ", ^uint64(0), true},
		{"SET tidb_table_group_routing_value = 1", 0, false},
		{"SET GLOBAL tidb_table_group_routing_value = 1", 0, false},
		{"SET SESSION tidb_table_group_routing_value = -1", 0, false},
		{"SET SESSION tidb_table_group_routing_value = 01", 0, false},
		{"SET SESSION tidb_table_group_routing_value = 18446744073709551616", 0, false},
		{"SET SESSION tidb_table_group_routing_value = 1; SELECT 1", 0, false},
	}
	for _, test := range tests {
		value, ok := parseTableGroupRoutingValue([]byte(test.query))
		require.Equal(t, test.ok, ok, test.query)
		require.Equal(t, test.value, value, test.query)
	}
}

func TestTableGroupRoutingKeepsSameBackend(t *testing.T) {
	backend := router.NewStaticBackend("store-2:4000")
	mgr := &BackendConnManager{
		logger:                zap.NewNop(),
		config:                &BCConfig{},
		curBackend:            backend,
		cmdProcessor:          NewCmdProcessor(zap.NewNop()),
		authenticator:         &Authenticator{emptyPassword: true},
		tableGroupRerouteSafe: true,
	}
	mgr.config.TableGroupRouteResolver = func(context.Context, string, uint64) (TableGroupRouteTarget, error) {
		return TableGroupRouteTarget{
			Address: "store-2:4000", FragmentID: 1, LeaderStoreID: 2, RegionID: 3,
			MetadataVersion: 4, StatusVersion: 5,
		}, nil
	}
	request := append([]byte{pnet.ComQuery.Byte()}, []byte("SET SESSION tidb_table_group_routing_value = 1")...)

	matched, err := mgr.routeTableGroupStatement(context.Background(), request)
	require.NoError(t, err)
	require.True(t, matched)
}

func TestTableGroupRoutingRejectsUnsafeReroute(t *testing.T) {
	mgr := &BackendConnManager{
		logger:                zap.NewNop(),
		config:                &BCConfig{},
		curBackend:            router.NewStaticBackend("store-1:4000"),
		cmdProcessor:          NewCmdProcessor(zap.NewNop()),
		authenticator:         &Authenticator{emptyPassword: true},
		tableGroupRerouteSafe: false,
	}
	mgr.config.TableGroupRouteResolver = func(context.Context, string, uint64) (TableGroupRouteTarget, error) {
		return TableGroupRouteTarget{
			Address: "store-2:4000", FragmentID: 1, LeaderStoreID: 2, RegionID: 3,
			MetadataVersion: 4, StatusVersion: 5,
		}, nil
	}
	request := append([]byte{pnet.ComQuery.Byte()}, []byte("SET SESSION tidb_table_group_routing_value = 1")...)

	matched, err := mgr.routeTableGroupStatement(context.Background(), request)
	require.True(t, matched)
	require.ErrorIs(t, err, ErrTableGroupRerouteUnsafe)
}

func TestTableGroupRoutingRejectsPendingRedirect(t *testing.T) {
	mgr := &BackendConnManager{
		logger:                zap.NewNop(),
		config:                &BCConfig{},
		curBackend:            router.NewStaticBackend("store-1:4000"),
		cmdProcessor:          NewCmdProcessor(zap.NewNop()),
		authenticator:         &Authenticator{emptyPassword: true},
		tableGroupRerouteSafe: true,
	}
	mgr.config.TableGroupRouteResolver = func(context.Context, string, uint64) (TableGroupRouteTarget, error) {
		return TableGroupRouteTarget{
			Address: "store-2:4000", FragmentID: 1, LeaderStoreID: 2, RegionID: 3,
			MetadataVersion: 4, StatusVersion: 5,
		}, nil
	}
	pendingBackend := router.BackendInst(router.NewStaticBackend("store-3:4000"))
	mgr.redirectInfo.Store(&pendingBackend)
	request := append([]byte{pnet.ComQuery.Byte()}, []byte("SET SESSION tidb_table_group_routing_value = 1")...)

	matched, err := mgr.routeTableGroupStatement(context.Background(), request)
	require.True(t, matched)
	require.ErrorIs(t, err, ErrTableGroupRerouteUnsafe)
}

func TestTableGroupRoutingReroutesPristineSession(t *testing.T) {
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = targetListener.Close() })
	targetAddress := targetListener.Addr().String()

	var dialedCluster string
	ts := newBackendMgrTester(t, func(cfg *testConfig) {
		cfg.clientConfig.authData = nil
		cfg.clientConfig.authPlugin = pnet.AuthNativePassword
		cfg.backendConfig.authPlugin = pnet.AuthNativePassword
		cfg.proxyConfig.bcConfig.DialTimeout = time.Second
		cfg.proxyConfig.bcConfig.ConnectTimeout = time.Second
		cfg.proxyConfig.bcConfig.TableGroupRouteResolver = func(context.Context, string, uint64) (TableGroupRouteTarget, error) {
			return TableGroupRouteTarget{
				ClusterName: "cluster-a", Address: targetAddress, FragmentID: 1,
				LeaderStoreID: 2, RegionID: 3, MetadataVersion: 4, StatusVersion: 5,
			}, nil
		}
		cfg.proxyConfig.bcConfig.DialContext = func(ctx context.Context, backend router.BackendInst, address string) (net.Conn, error) {
			if address == targetAddress {
				dialedCluster = backend.ClusterName()
			}
			var dialer net.Dialer
			return dialer.DialContext(ctx, "tcp", address)
		}
	})

	ts.runAndCheck(t, nil, ts.mc.authenticate, ts.handshake4Backend, ts.firstHandshake4Proxy)
	require.True(t, ts.mp.tableGroupRerouteSafe)

	targetBackend := newMockBackend(newBackendConfig())
	targetBackend.authPlugin = pnet.AuthNativePassword
	targetBackend.tlsConfig = ts.tc.backendTLSConfig
	targetDone := make(chan error, 1)
	go func() {
		conn, acceptErr := targetListener.Accept()
		if acceptErr != nil {
			targetDone <- acceptErr
			return
		}
		packetIO := pnet.NewPacketIO(conn, zap.NewNop(), pnet.DefaultConnBufferSize)
		defer func() { _ = packetIO.Close() }()
		if authErr := targetBackend.authenticate(packetIO); authErr != nil {
			targetDone <- authErr
			return
		}
		targetBackend.respondType = responseTypeOK
		targetBackend.status = 0
		if respondErr := targetBackend.respondOnce(packetIO); respondErr != nil {
			targetDone <- respondErr
			return
		}
		targetBackend.status = mysql.SERVER_STATUS_IN_TRANS
		targetDone <- targetBackend.respondOnce(packetIO)
	}()

	ts.mc.sql = "SET SESSION tidb_table_group_routing_value = 1"
	ts.runAndCheck(t, func(t *testing.T, ts *testSuite) {
		require.NoError(t, ts.mc.err)
		require.NoError(t, ts.mb.err)
		require.NoError(t, ts.mp.err)
	}, ts.mc.request, func(packetIO pnet.PacketIO) error {
		_, readErr := packetIO.ReadPacket()
		if pnet.IsDisconnectError(readErr) {
			return nil
		}
		return readErr
	}, func(clientIO, _ pnet.PacketIO) error {
		clientIO.ResetSequence()
		_, executeErr := ts.mp.ExecuteCmd(context.Background())
		return executeErr
	})

	require.Equal(t, targetAddress, ts.mp.curBackend.Addr())
	require.Equal(t, "cluster-a", ts.mp.curBackend.ClusterName())
	require.Equal(t, "cluster-a", dialedCluster)
	require.Empty(t, targetBackend.authData)
	require.Nil(t, ts.mp.getEventReceiver())
	require.True(t, ts.mp.tableGroupRerouteSafe)

	ts.mc.sql = "BEGIN"
	ts.runAndCheck(t, func(t *testing.T, ts *testSuite) {
		require.NoError(t, ts.mc.err)
		require.NoError(t, ts.mp.err)
	}, ts.mc.request, nil, func(clientIO, _ pnet.PacketIO) error {
		clientIO.ResetSequence()
		_, executeErr := ts.mp.ExecuteCmd(context.Background())
		return executeErr
	})
	require.NoError(t, <-targetDone)
	require.False(t, ts.mp.tableGroupRerouteSafe)
	require.False(t, ts.mp.cmdProcessor.finishedTxn())
}

func TestCmdProcessorTracksPreparedStatements(t *testing.T) {
	cp := NewCmdProcessor(zap.NewNop())
	cp.addPreparedStatement(7)
	require.True(t, cp.hasPreparedStatements())

	request := make([]byte, 5)
	request[0] = pnet.ComStmtClose.Byte()
	binary.LittleEndian.PutUint32(request[1:], 7)
	cp.updatePrepStmtStatus(request, 0)
	require.False(t, cp.hasPreparedStatements())
}
