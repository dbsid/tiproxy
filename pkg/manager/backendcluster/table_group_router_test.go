// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package backendcluster

import (
	"context"
	"testing"
	"time"

	"github.com/pingcap/kvproto/pkg/metapb"
	"github.com/pingcap/kvproto/pkg/table_grouppb"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

type fakeTableGroupServiceClient struct {
	responses []*table_grouppb.GetTableGroupRouteResponse
	calls     int
}

func (c *fakeTableGroupServiceClient) GetTableGroupRoute(
	context.Context,
	*table_grouppb.GetTableGroupRouteRequest,
	...grpc.CallOption,
) (*table_grouppb.GetTableGroupRouteResponse, error) {
	response := c.responses[c.calls]
	c.calls++
	return response, nil
}

func testTableGroupRoute(clusterID, metadataVersion, statusVersion uint64, addresses ...string) *table_grouppb.GetTableGroupRouteResponse {
	fragments := make([]*table_grouppb.TableGroupFragmentRoute, 0, len(addresses))
	for i, address := range addresses {
		fragments = append(fragments, &table_grouppb.TableGroupFragmentRoute{
			FragmentId: uint32(i),
			RegionBinding: &table_grouppb.TableGroupRegionBinding{
				RegionId:               uint64(100 + i),
				RegionEpoch:            &metapb.RegionEpoch{ConfVer: 1, Version: metadataVersion},
				ShardId:                uint64(200 + i),
				AppliedMetadataVersion: metadataVersion,
			},
			LeaderStoreId:    uint64(300 + i),
			LeaderSqlAddress: address,
		})
	}
	return &table_grouppb.GetTableGroupRouteResponse{
		Header: &table_grouppb.ResponseHeader{ClusterId: clusterID},
		Route: &table_grouppb.TableGroupRoute{
			Identity:                &table_grouppb.TableGroupIdentity{KeyspaceId: 42, TableGroupId: 101},
			MetadataVersion:         metadataVersion,
			StatusVersion:           statusVersion,
			ActiveMembershipVersion: 1,
			Partitioning: &table_grouppb.TableGroupPartitioning{
				Method:         table_grouppb.TableGroupPartitionMethod_TABLE_GROUP_PARTITION_METHOD_HASH,
				PartitionCount: uint32(len(addresses)),
				HashAlgorithm:  table_grouppb.TableGroupHashAlgorithm_TABLE_GROUP_HASH_ALGORITHM_MODULO_U64_V1,
			},
			FragmentRoutes: fragments,
		},
	}
}

func newTestTableGroupRouter(client tableGroupServiceClient, now *time.Time) *tableGroupRouter {
	return &tableGroupRouter{
		clusterName: "cluster-a",
		clusterID:   9,
		identity:    table_grouppb.TableGroupIdentity{KeyspaceId: 42, TableGroupId: 101},
		client:      client,
		cacheTTL:    time.Second,
		now:         func() time.Time { return *now },
	}
}

func TestTableGroupRouterCachesAndRoutesByModulo(t *testing.T) {
	now := time.Unix(100, 0)
	client := &fakeTableGroupServiceClient{responses: []*table_grouppb.GetTableGroupRouteResponse{
		testTableGroupRoute(9, 3, 5, "store-1:4000", "store-2:4000", "store-3:4000"),
	}}
	router := newTestTableGroupRouter(client, &now)

	target, err := router.resolve(context.Background(), 8)
	require.NoError(t, err)
	require.Equal(t, uint32(2), target.FragmentID)
	require.Equal(t, "store-3:4000", target.Address)
	require.Equal(t, uint64(302), target.LeaderStoreID)

	target, err = router.resolve(context.Background(), 1)
	require.NoError(t, err)
	require.Equal(t, "store-2:4000", target.Address)
	require.Equal(t, 1, client.calls)

	targets, err := router.targets(context.Background())
	require.NoError(t, err)
	require.Equal(t, []string{"store-1:4000", "store-2:4000", "store-3:4000"}, []string{
		targets[0].Address,
		targets[1].Address,
		targets[2].Address,
	})
	require.Equal(t, 1, client.calls)
}

func TestClusterUsesTableGroupRouteAsInitialTopology(t *testing.T) {
	now := time.Unix(100, 0)
	client := &fakeTableGroupServiceClient{responses: []*table_grouppb.GetTableGroupRouteResponse{
		testTableGroupRoute(9, 3, 5, "store-1:4000", "store-2:4000", "store-1:4000"),
	}}
	cluster := &Cluster{tableGroupRouter: newTestTableGroupRouter(client, &now)}

	topology, err := cluster.GetTiDBTopology(context.Background())
	require.NoError(t, err)
	require.Len(t, topology, 2)
	require.Equal(t, "store-1:4000", topology["store-1:4000"].Addr)
	require.Equal(t, "store-2:4000", topology["store-2:4000"].Addr)
	require.Equal(t, 1, client.calls)
}

func TestTableGroupRouterRefreshesLeaderAndRejectsRegression(t *testing.T) {
	now := time.Unix(100, 0)
	client := &fakeTableGroupServiceClient{responses: []*table_grouppb.GetTableGroupRouteResponse{
		testTableGroupRoute(9, 3, 5, "store-1:4000"),
		testTableGroupRoute(9, 3, 5, "store-2:4000"),
		testTableGroupRoute(9, 2, 6, "store-3:4000"),
	}}
	router := newTestTableGroupRouter(client, &now)

	target, err := router.resolve(context.Background(), 0)
	require.NoError(t, err)
	require.Equal(t, "store-1:4000", target.Address)

	now = now.Add(2 * time.Second)
	target, err = router.resolve(context.Background(), 0)
	require.NoError(t, err)
	require.Equal(t, "store-2:4000", target.Address)

	now = now.Add(2 * time.Second)
	_, err = router.resolve(context.Background(), 0)
	require.ErrorIs(t, err, ErrStaleTableGroupRoute)
}

func TestTableGroupRouterRejectsMissingSQLEndpoint(t *testing.T) {
	now := time.Unix(100, 0)
	client := &fakeTableGroupServiceClient{responses: []*table_grouppb.GetTableGroupRouteResponse{
		testTableGroupRoute(9, 3, 5, ""),
	}}
	router := newTestTableGroupRouter(client, &now)

	_, err := router.resolve(context.Background(), 0)
	require.ErrorIs(t, err, ErrInvalidTableGroupRoute)
}

func TestTableGroupRouterIncludesPDErrorMessage(t *testing.T) {
	now := time.Unix(100, 0)
	router := newTestTableGroupRouter(nil, &now)
	response := &table_grouppb.GetTableGroupRouteResponse{
		Header: &table_grouppb.ResponseHeader{
			ClusterId: 9,
			Error: &table_grouppb.TableGroupError{
				Code:    table_grouppb.TableGroupErrorCode_TABLE_GROUP_ERROR_CODE_REGION_MISMATCH,
				Message: "fragment 8 is not route-ready",
			},
		},
	}

	err := router.validateResponse(response)
	require.ErrorIs(t, err, ErrInvalidTableGroupRoute)
	require.ErrorContains(t, err, "fragment 8 is not route-ready")
}

func TestValidateTableGroupRouteRejectsInvalidSnapshots(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*table_grouppb.TableGroupRoute)
	}{
		{
			name: "identity mismatch",
			mutate: func(route *table_grouppb.TableGroupRoute) {
				route.Identity.TableGroupId++
			},
		},
		{
			name: "zero status version",
			mutate: func(route *table_grouppb.TableGroupRoute) {
				route.StatusVersion = 0
			},
		},
		{
			name: "zero membership version",
			mutate: func(route *table_grouppb.TableGroupRoute) {
				route.ActiveMembershipVersion = 0
			},
		},
		{
			name: "partition count mismatch",
			mutate: func(route *table_grouppb.TableGroupRoute) {
				route.Partitioning.PartitionCount++
			},
		},
		{
			name: "unsupported hash algorithm",
			mutate: func(route *table_grouppb.TableGroupRoute) {
				route.Partitioning.HashAlgorithm = table_grouppb.TableGroupHashAlgorithm_TABLE_GROUP_HASH_ALGORITHM_UNSPECIFIED
			},
		},
		{
			name: "non-contiguous fragments",
			mutate: func(route *table_grouppb.TableGroupRoute) {
				route.FragmentRoutes[1].FragmentId = 9
			},
		},
		{
			name: "stale applied version",
			mutate: func(route *table_grouppb.TableGroupRoute) {
				route.FragmentRoutes[0].RegionBinding.AppliedMetadataVersion--
			},
		},
		{
			name: "zero Region epoch",
			mutate: func(route *table_grouppb.TableGroupRoute) {
				route.FragmentRoutes[0].RegionBinding.RegionEpoch.Version = 0
			},
		},
		{
			name: "duplicate Region",
			mutate: func(route *table_grouppb.TableGroupRoute) {
				route.FragmentRoutes[1].RegionBinding.RegionId = route.FragmentRoutes[0].RegionBinding.RegionId
			},
		},
		{
			name: "duplicate Shard",
			mutate: func(route *table_grouppb.TableGroupRoute) {
				route.FragmentRoutes[1].RegionBinding.ShardId = route.FragmentRoutes[0].RegionBinding.ShardId
			},
		},
		{
			name: "zero leader",
			mutate: func(route *table_grouppb.TableGroupRoute) {
				route.FragmentRoutes[0].LeaderStoreId = 0
			},
		},
		{
			name: "malformed SQL endpoint",
			mutate: func(route *table_grouppb.TableGroupRoute) {
				route.FragmentRoutes[0].LeaderSqlAddress = "store-1"
			},
		},
	}

	identity := &table_grouppb.TableGroupIdentity{KeyspaceId: 42, TableGroupId: 101}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			route := testTableGroupRoute(9, 3, 5, "store-1:4000", "store-2:4000").GetRoute()
			test.mutate(route)
			require.ErrorIs(t, validateTableGroupRoute(route, identity), ErrInvalidTableGroupRoute)
		})
	}
}

func TestTableGroupRouteRegression(t *testing.T) {
	current := testTableGroupRoute(9, 3, 5, "store-1:4000").GetRoute()
	tests := []struct {
		name   string
		mutate func(*table_grouppb.TableGroupRoute)
	}{
		{
			name: "metadata version",
			mutate: func(route *table_grouppb.TableGroupRoute) {
				route.MetadataVersion--
			},
		},
		{
			name: "status version",
			mutate: func(route *table_grouppb.TableGroupRoute) {
				route.StatusVersion--
			},
		},
		{
			name: "membership version",
			mutate: func(route *table_grouppb.TableGroupRoute) {
				route.ActiveMembershipVersion--
			},
		},
		{
			name: "Region epoch",
			mutate: func(route *table_grouppb.TableGroupRoute) {
				route.FragmentRoutes[0].RegionBinding.RegionEpoch.Version--
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			next := testTableGroupRoute(9, 3, 5, "store-1:4000").GetRoute()
			test.mutate(next)
			require.True(t, tableGroupRouteRegressed(next, current))
		})
	}
}
