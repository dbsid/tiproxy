// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"context"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/pingcap/tiproxy/lib/util/errors"
	"github.com/pingcap/tiproxy/pkg/balance/router"
	"github.com/pingcap/tiproxy/pkg/metrics"
	pnet "github.com/pingcap/tiproxy/pkg/proxy/net"
	"go.uber.org/zap"
)

const maxTableGroupRoutingStatementBytes = 160

var (
	tableGroupRoutingStatement = regexp.MustCompile(
		`(?i)^\s*SET\s+SESSION\s+tidb_table_group_routing_value\s*=\s*(0|[1-9][0-9]*)\s*;?\s*$`,
	)
	ErrTableGroupRouteUnavailable = errors.New("table group route is unavailable")
	ErrTableGroupRerouteUnsafe    = errors.New("table group session cannot be rerouted")
)

// TableGroupRouteTarget is the exact backend selected from one validated PD
// route snapshot.
type TableGroupRouteTarget struct {
	ClusterName     string
	Address         string
	FragmentID      uint32
	LeaderStoreID   uint64
	RegionID        uint64
	MetadataVersion uint64
	StatusVersion   uint64
}

// TableGroupRouteResolver resolves a routing value against cluster-scoped PD
// metadata. A nil resolver leaves legacy TiProxy behavior unchanged.
type TableGroupRouteResolver func(context.Context, string, uint64) (TableGroupRouteTarget, error)

func parseTableGroupRoutingValue(query []byte) (uint64, bool) {
	if len(query) == 0 || len(query) > maxTableGroupRoutingStatementBytes {
		return 0, false
	}
	match := tableGroupRoutingStatement.FindSubmatch(query)
	if len(match) != 2 {
		return 0, false
	}
	value, err := strconv.ParseUint(string(match[1]), 10, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

// routeTableGroupStatement moves an otherwise pristine empty-password session
// before the routing statement reaches a backend. It returns true only for the
// frozen routing statement, including the same-target case.
func (mgr *BackendConnManager) routeTableGroupStatement(ctx context.Context, request []byte) (bool, error) {
	if len(request) < 2 || pnet.Command(request[0]) != pnet.ComQuery {
		return false, nil
	}
	routingValue, matched := parseTableGroupRoutingValue(request[1:])
	if !matched {
		return false, nil
	}
	if mgr.config.TableGroupRouteResolver == nil {
		return true, nil
	}

	clusterName := ""
	if mgr.curBackend != nil {
		clusterName = mgr.curBackend.ClusterName()
	}
	target, err := mgr.config.TableGroupRouteResolver(ctx, clusterName, routingValue)
	if err != nil {
		metrics.TableGroupRerouteCounter.WithLabelValues("route_error").Inc()
		return true, errors.Wrap(err, ErrTableGroupRouteUnavailable)
	}
	if err := validateTableGroupRouteTarget(target); err != nil {
		metrics.TableGroupRerouteCounter.WithLabelValues("invalid_target").Inc()
		return true, err
	}
	if mgr.curBackend != nil && sameBackendAddress(mgr.curBackend.Addr(), target.Address) {
		metrics.TableGroupRerouteCounter.WithLabelValues("same_backend").Inc()
		mgr.logger.Debug("Table Group route remains on current backend",
			zap.Uint32("fragment_id", target.FragmentID),
			zap.Uint64("leader_store_id", target.LeaderStoreID),
			zap.Uint64("metadata_version", target.MetadataVersion),
			zap.Uint64("status_version", target.StatusVersion))
		return true, nil
	}
	if mgr.redirectInfo.Load() != nil || !mgr.tableGroupRerouteSafe || !mgr.cmdProcessor.finishedTxn() ||
		mgr.cmdProcessor.hasPreparedStatements() ||
		!mgr.authenticator.canPristineReroute() {
		metrics.TableGroupRerouteCounter.WithLabelValues("unsafe").Inc()
		return true, ErrTableGroupRerouteUnsafe
	}
	if err := mgr.reroutePristineSession(ctx, target); err != nil {
		metrics.TableGroupRerouteCounter.WithLabelValues("reroute_error").Inc()
		return true, err
	}
	metrics.TableGroupRerouteCounter.WithLabelValues("rerouted").Inc()
	return true, nil
}

func validateTableGroupRouteTarget(target TableGroupRouteTarget) error {
	if target.Address == "" || target.LeaderStoreID == 0 || target.RegionID == 0 ||
		target.MetadataVersion == 0 || target.StatusVersion == 0 {
		return errors.Wrapf(ErrTableGroupRouteUnavailable, "route target is incomplete")
	}
	host, port, err := net.SplitHostPort(target.Address)
	if err != nil || strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
		return errors.Wrapf(ErrTableGroupRouteUnavailable, "route target address is malformed")
	}
	return nil
}

func sameBackendAddress(left, right string) bool {
	return strings.EqualFold(strings.TrimSpace(left), strings.TrimSpace(right))
}

func (mgr *BackendConnManager) reroutePristineSession(ctx context.Context, target TableGroupRouteTarget) error {
	backend := router.NewStaticBackend(target.Address)
	backend.SetClusterName(target.ClusterName)

	dialCtx, cancel := context.WithTimeout(ctx, mgr.config.DialTimeout)
	conn, err := mgr.dialBackend(dialCtx, backend, target.Address)
	cancel()
	if err != nil {
		return errors.Wrap(err, ErrBackendHandshake)
	}
	newBackendIO := pnet.PacketIO(pnet.NewPacketIO(
		conn,
		mgr.logger,
		mgr.config.ConnBufferSize,
		pnet.WithRemoteAddr(target.Address, conn.RemoteAddr()),
		pnet.WithWrapError(ErrBackendConn),
	))
	if err := mgr.authenticator.handshakePristineEmptyPassword(
		mgr.logger.Named("table-group-authenticator"),
		mgr.clientIO,
		newBackendIO,
		mgr.backendTLS,
	); err != nil {
		if closeErr := newBackendIO.Close(); closeErr != nil && !pnet.IsDisconnectError(closeErr) {
			mgr.logger.Warn("close failed Table Group backend connection", zap.Error(closeErr))
		}
		return err
	}

	oldBackendIO := *mgr.backendIO.Load()
	mgr.updateTraffic(oldBackendIO)
	mgr.inBytes, mgr.inPackets, mgr.outBytes, mgr.outPackets = 0, 0, 0, 0
	mgr.abandonRoutedBackend()
	if err := oldBackendIO.Close(); err != nil && !pnet.IsDisconnectError(err) {
		mgr.logger.Warn("close previous Table Group backend connection", zap.Error(err))
	}
	mgr.backendIO.Store(&newBackendIO)
	mgr.curBackend = backend
	mgr.updateTraffic(newBackendIO)
	mgr.setKeepAlive()
	mgr.handshakeHandler.OnHandshake(mgr, target.Address, nil, SrcNone)
	mgr.logger.Info("routed pristine session to Table Group leader",
		zap.Uint32("fragment_id", target.FragmentID),
		zap.Uint64("leader_store_id", target.LeaderStoreID),
		zap.Uint64("region_id", target.RegionID),
		zap.Uint64("metadata_version", target.MetadataVersion),
		zap.Uint64("status_version", target.StatusVersion))
	return nil
}

func (mgr *BackendConnManager) writeTableGroupRoutingError(err error) error {
	mgr.logger.Warn("Table Group routing rejected", zap.Error(err))
	clientErr := mysql.NewError(mysql.ER_UNKNOWN_ERROR, "table group routing is unavailable")
	if writeErr := mgr.clientIO.WritePacket(pnet.MakeErrPacket(clientErr), true); writeErr != nil {
		return writeErr
	}
	return clientErr
}
