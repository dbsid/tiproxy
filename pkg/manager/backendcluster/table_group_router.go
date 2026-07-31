// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package backendcluster

import (
	"context"
	"encoding/binary"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/pingcap/kvproto/pkg/table_grouppb"
	"github.com/pingcap/tiproxy/lib/util/errors"
	"github.com/pingcap/tiproxy/pkg/metrics"
	clientv3 "go.etcd.io/etcd/client/v3"
	"golang.org/x/sync/singleflight"
	"google.golang.org/grpc"
)

const (
	clusterIDKey                = "/pd/cluster_id"
	tableGroupRouteCacheTTL     = time.Second
	tableGroupRouteFetchTimeout = 2 * time.Second
	maxTableGroupFragments      = 1024
)

var (
	ErrTableGroupRoutingDisabled = errors.New("table group routing is disabled")
	ErrInvalidTableGroupRoute    = errors.New("invalid table group route")
	ErrStaleTableGroupRoute      = errors.New("stale table group route")
)

// TableGroupRouteTarget is one immutable SQL endpoint selected from a validated
// PD Table Group route snapshot.
type TableGroupRouteTarget struct {
	ClusterName     string
	Address         string
	FragmentID      uint32
	LeaderStoreID   uint64
	RegionID        uint64
	MetadataVersion uint64
	StatusVersion   uint64
}

type tableGroupServiceClient interface {
	GetTableGroupRoute(context.Context, *table_grouppb.GetTableGroupRouteRequest, ...grpc.CallOption) (*table_grouppb.GetTableGroupRouteResponse, error)
}

type cachedTableGroupRoute struct {
	route       *table_grouppb.TableGroupRoute
	refreshedAt time.Time
}

type tableGroupRouter struct {
	clusterName string
	clusterID   uint64
	identity    table_grouppb.TableGroupIdentity
	client      tableGroupServiceClient
	cacheTTL    time.Duration
	now         func() time.Time
	refresh     singleflight.Group

	mu struct {
		sync.RWMutex
		cached *cachedTableGroupRoute
	}
}

func newTableGroupRouter(
	ctx context.Context,
	clusterName string,
	keyspaceID uint32,
	tableGroupID uint64,
	etcdCli *clientv3.Client,
) (*tableGroupRouter, error) {
	if tableGroupID == 0 {
		return nil, ErrTableGroupRoutingDisabled
	}
	clusterID, err := loadClusterID(ctx, etcdCli)
	if err != nil {
		return nil, errors.Wrapf(err, "load PD cluster ID for Table Group routing")
	}
	conn := etcdCli.ActiveConnection()
	if conn == nil {
		return nil, errors.Wrapf(ErrInvalidTableGroupRoute, "PD connection is unavailable")
	}
	return &tableGroupRouter{
		clusterName: clusterName,
		clusterID:   clusterID,
		identity: table_grouppb.TableGroupIdentity{
			KeyspaceId:   keyspaceID,
			TableGroupId: tableGroupID,
		},
		client:   table_grouppb.NewTableGroupServiceClient(conn),
		cacheTTL: tableGroupRouteCacheTTL,
		now:      time.Now,
	}, nil
}

func loadClusterID(ctx context.Context, etcdCli *clientv3.Client) (uint64, error) {
	fetchCtx, cancel := context.WithTimeout(ctx, tableGroupRouteFetchTimeout)
	defer cancel()
	response, err := etcdCli.Get(fetchCtx, clusterIDKey, clientv3.WithLimit(1))
	if err != nil {
		return 0, err
	}
	if len(response.Kvs) != 1 || len(response.Kvs[0].Value) != 8 {
		return 0, errors.Wrapf(ErrInvalidTableGroupRoute, "PD cluster ID is missing or malformed")
	}
	clusterID := binary.BigEndian.Uint64(response.Kvs[0].Value)
	if clusterID == 0 {
		return 0, errors.Wrapf(ErrInvalidTableGroupRoute, "PD cluster ID is zero")
	}
	return clusterID, nil
}

func (r *tableGroupRouter) resolve(ctx context.Context, routingValue uint64) (TableGroupRouteTarget, error) {
	route, err := r.route(ctx)
	if err != nil {
		return TableGroupRouteTarget{}, err
	}

	partitionCount := route.GetPartitioning().GetPartitionCount()
	fragmentID := uint32(routingValue % uint64(partitionCount))
	return r.target(route, fragmentID), nil
}

func (r *tableGroupRouter) targets(ctx context.Context) ([]TableGroupRouteTarget, error) {
	route, err := r.route(ctx)
	if err != nil {
		return nil, err
	}
	targets := make([]TableGroupRouteTarget, 0, len(route.GetFragmentRoutes()))
	for fragmentID := range route.GetFragmentRoutes() {
		targets = append(targets, r.target(route, uint32(fragmentID)))
	}
	return targets, nil
}

func (r *tableGroupRouter) route(ctx context.Context) (*table_grouppb.TableGroupRoute, error) {
	if route := r.cachedRoute(); route != nil {
		metrics.TableGroupRouteCounter.WithLabelValues("cache_hit").Inc()
		return route, nil
	}
	route, err := r.refreshRoute(ctx)
	if err != nil {
		metrics.TableGroupRouteCounter.WithLabelValues("refresh_error").Inc()
		return nil, err
	}
	metrics.TableGroupRouteCounter.WithLabelValues("refresh").Inc()
	return route, nil
}

func (r *tableGroupRouter) target(route *table_grouppb.TableGroupRoute, fragmentID uint32) TableGroupRouteTarget {
	fragment := route.GetFragmentRoutes()[fragmentID]
	return TableGroupRouteTarget{
		ClusterName:     r.clusterName,
		Address:         fragment.GetLeaderSqlAddress(),
		FragmentID:      fragmentID,
		LeaderStoreID:   fragment.GetLeaderStoreId(),
		RegionID:        fragment.GetRegionBinding().GetRegionId(),
		MetadataVersion: route.GetMetadataVersion(),
		StatusVersion:   route.GetStatusVersion(),
	}
}

func (r *tableGroupRouter) cachedRoute() *table_grouppb.TableGroupRoute {
	r.mu.RLock()
	cached := r.mu.cached
	r.mu.RUnlock()
	if cached == nil {
		return nil
	}
	age := r.now().Sub(cached.refreshedAt)
	if age < 0 || age >= r.cacheTTL {
		return nil
	}
	return cached.route
}

func (r *tableGroupRouter) refreshRoute(ctx context.Context) (*table_grouppb.TableGroupRoute, error) {
	result, err, _ := r.refresh.Do("route", func() (any, error) {
		if route := r.cachedRoute(); route != nil {
			return route, nil
		}
		fetchCtx, cancel := context.WithTimeout(ctx, tableGroupRouteFetchTimeout)
		defer cancel()
		response, err := r.client.GetTableGroupRoute(fetchCtx, &table_grouppb.GetTableGroupRouteRequest{
			Header: &table_grouppb.RequestHeader{
				ClusterId:       r.clusterID,
				CallerId:        r.clusterName,
				CallerComponent: "tiproxy-table-group-router",
			},
			Identity: &r.identity,
		})
		if err != nil {
			return nil, errors.Wrapf(err, "fetch Table Group route from PD")
		}
		if err := r.validateResponse(response); err != nil {
			return nil, err
		}
		route := response.GetRoute()

		r.mu.Lock()
		defer r.mu.Unlock()
		if r.mu.cached != nil && tableGroupRouteRegressed(route, r.mu.cached.route) {
			return nil, ErrStaleTableGroupRoute
		}
		r.mu.cached = &cachedTableGroupRoute{route: route, refreshedAt: r.now()}
		return route, nil
	})
	if err != nil {
		return nil, err
	}
	return result.(*table_grouppb.TableGroupRoute), nil
}

func (r *tableGroupRouter) validateResponse(response *table_grouppb.GetTableGroupRouteResponse) error {
	if response == nil || response.GetHeader() == nil {
		return errors.Wrapf(ErrInvalidTableGroupRoute, "PD response header is missing")
	}
	if response.GetHeader().GetClusterId() != r.clusterID {
		return errors.Wrapf(ErrInvalidTableGroupRoute, "PD response cluster ID does not match")
	}
	if detail := response.GetHeader().GetError(); detail != nil &&
		detail.GetCode() != table_grouppb.TableGroupErrorCode_TABLE_GROUP_ERROR_CODE_OK {
		if detail.GetMessage() != "" {
			return errors.Wrapf(ErrInvalidTableGroupRoute, "PD returned Table Group error code %s: %s",
				detail.GetCode(), detail.GetMessage())
		}
		return errors.Wrapf(ErrInvalidTableGroupRoute, "PD returned Table Group error code %s", detail.GetCode())
	}
	return validateTableGroupRoute(response.GetRoute(), &r.identity)
}

func validateTableGroupRoute(route *table_grouppb.TableGroupRoute, identity *table_grouppb.TableGroupIdentity) error {
	if route == nil || route.GetIdentity() == nil || route.GetPartitioning() == nil {
		return errors.Wrapf(ErrInvalidTableGroupRoute, "required route fields are missing")
	}
	if route.GetIdentity().GetKeyspaceId() != identity.GetKeyspaceId() ||
		route.GetIdentity().GetTableGroupId() != identity.GetTableGroupId() {
		return errors.Wrapf(ErrInvalidTableGroupRoute, "route identity does not match")
	}
	if route.GetMetadataVersion() == 0 || route.GetStatusVersion() == 0 || route.GetActiveMembershipVersion() == 0 {
		return errors.Wrapf(ErrInvalidTableGroupRoute, "route versions must be non-zero")
	}

	partitioning := route.GetPartitioning()
	partitionCount := partitioning.GetPartitionCount()
	if partitionCount == 0 || partitionCount > maxTableGroupFragments {
		return errors.Wrapf(ErrInvalidTableGroupRoute, "partition count is outside the supported range")
	}
	switch partitioning.GetMethod() {
	case table_grouppb.TableGroupPartitionMethod_TABLE_GROUP_PARTITION_METHOD_SINGLE:
		if partitionCount != 1 || partitioning.GetHashAlgorithm() !=
			table_grouppb.TableGroupHashAlgorithm_TABLE_GROUP_HASH_ALGORITHM_UNSPECIFIED {
			return errors.Wrapf(ErrInvalidTableGroupRoute, "single-fragment partitioning is malformed")
		}
	case table_grouppb.TableGroupPartitionMethod_TABLE_GROUP_PARTITION_METHOD_HASH:
		if partitioning.GetHashAlgorithm() !=
			table_grouppb.TableGroupHashAlgorithm_TABLE_GROUP_HASH_ALGORITHM_MODULO_U64_V1 {
			return errors.Wrapf(ErrInvalidTableGroupRoute, "hash algorithm is unsupported")
		}
	default:
		return errors.Wrapf(ErrInvalidTableGroupRoute, "partition method is unsupported")
	}

	fragments := route.GetFragmentRoutes()
	if len(fragments) != int(partitionCount) {
		return errors.Wrapf(ErrInvalidTableGroupRoute, "fragment route count does not match partition count")
	}
	regionIDs := make(map[uint64]struct{}, len(fragments))
	shardIDs := make(map[uint64]struct{}, len(fragments))
	for i, fragment := range fragments {
		if fragment == nil || fragment.GetFragmentId() != uint32(i) || fragment.GetRegionBinding() == nil {
			return errors.Wrapf(ErrInvalidTableGroupRoute, "fragment routes are incomplete or out of order")
		}
		binding := fragment.GetRegionBinding()
		epoch := binding.GetRegionEpoch()
		if binding.GetRegionId() == 0 || binding.GetShardId() == 0 ||
			binding.GetAppliedMetadataVersion() != route.GetMetadataVersion() || epoch == nil ||
			epoch.GetConfVer() == 0 || epoch.GetVersion() == 0 || fragment.GetLeaderStoreId() == 0 {
			return errors.Wrapf(ErrInvalidTableGroupRoute, "fragment binding or leader is not route-ready")
		}
		if _, exists := regionIDs[binding.GetRegionId()]; exists {
			return errors.Wrapf(ErrInvalidTableGroupRoute, "fragment Region IDs are not unique")
		}
		regionIDs[binding.GetRegionId()] = struct{}{}
		if _, exists := shardIDs[binding.GetShardId()]; exists {
			return errors.Wrapf(ErrInvalidTableGroupRoute, "fragment Shard IDs are not unique")
		}
		shardIDs[binding.GetShardId()] = struct{}{}
		if err := validateSQLAddress(fragment.GetLeaderSqlAddress()); err != nil {
			return err
		}
	}
	return nil
}

func validateSQLAddress(address string) error {
	host, portText, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return errors.Wrapf(ErrInvalidTableGroupRoute, "leader SQL address is malformed")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return errors.Wrapf(ErrInvalidTableGroupRoute, "leader SQL port is malformed")
	}
	return nil
}

func tableGroupRouteRegressed(next, current *table_grouppb.TableGroupRoute) bool {
	if next.GetMetadataVersion() < current.GetMetadataVersion() ||
		next.GetStatusVersion() < current.GetStatusVersion() ||
		next.GetActiveMembershipVersion() < current.GetActiveMembershipVersion() {
		return true
	}
	currentFragments := current.GetFragmentRoutes()
	for i, fragment := range next.GetFragmentRoutes() {
		if i >= len(currentFragments) {
			break
		}
		oldBinding := currentFragments[i].GetRegionBinding()
		newBinding := fragment.GetRegionBinding()
		if oldBinding.GetRegionId() != newBinding.GetRegionId() {
			continue
		}
		oldEpoch := oldBinding.GetRegionEpoch()
		newEpoch := newBinding.GetRegionEpoch()
		if newEpoch.GetVersion() < oldEpoch.GetVersion() || newEpoch.GetConfVer() < oldEpoch.GetConfVer() {
			return true
		}
	}
	return false
}
