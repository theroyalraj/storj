// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package psdb_test

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/storj/internal/teststorj"
	"storj.io/storj/pkg/pb"
	"storj.io/storj/pkg/piecestore/psserver/psdb"
	"storj.io/storj/pkg/storj"
)

const concurrency = 10

func newDB(t testing.TB, id string) (*psdb.DB, func()) {
	tmpdir, err := ioutil.TempDir("", "storj-psdb-"+id)
	require.NoError(t, err)

	dbpath := filepath.Join(tmpdir, "psdb.db")

	db, err := psdb.Open(dbpath)
	require.NoError(t, err)

	err = db.Migration().Run(zaptest.NewLogger(t), db)
	require.NoError(t, err)

	return db, func() {
		err := db.Close()
		require.NoError(t, err)
		err = os.RemoveAll(tmpdir)
		require.NoError(t, err)
	}
}

func TestNewInmemory(t *testing.T) {
	db, err := psdb.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestHappyPath(t *testing.T) {
	db, cleanup := newDB(t, "1")
	defer cleanup()

	type TTL struct {
		ID         string
		Expiration int64
	}

	tests := []TTL{
		{ID: "", Expiration: 0},
		{ID: "\x00", Expiration: ^int64(0)},
		{ID: "test", Expiration: 666},
	}

	bandwidthAllocation := func(serialnum, signature string, satelliteID storj.NodeID, total int64) *pb.Order {
		return &pb.Order{
			PayerAllocation: pb.OrderLimit{SatelliteId: satelliteID, SerialNumber: serialnum},
			Total:           total,
			Signature:       []byte(signature),
		}
	}

	//TODO: use better data
	nodeIDAB := teststorj.NodeIDFromString("AB")
	allocationTests := []*pb.Order{
		bandwidthAllocation("serialnum_1", "signed by test", nodeIDAB, 0),
		bandwidthAllocation("serialnum_2", "signed by sigma", nodeIDAB, 10),
		bandwidthAllocation("serialnum_3", "signed by sigma", nodeIDAB, 98),
		bandwidthAllocation("serialnum_4", "signed by test", nodeIDAB, 3),
	}

	type bwUsage struct {
		size    int64
		timenow time.Time
	}

	bwtests := []bwUsage{
		// size is total size stored
		{size: 1110, timenow: time.Now()},
	}

	t.Run("Empty", func(t *testing.T) {
		t.Run("Bandwidth Allocation", func(t *testing.T) {
			for _, test := range allocationTests {
				agreements, err := db.GetBandwidthAllocationBySignature(test.Signature)
				require.Len(t, agreements, 0)
				require.NoError(t, err)
			}
		})

		t.Run("Get all Bandwidth Allocations", func(t *testing.T) {
			agreementGroups, err := db.GetBandwidthAllocations()
			require.Len(t, agreementGroups, 0)
			require.NoError(t, err)
		})

		t.Run("GetBandwidthUsedByDay", func(t *testing.T) {
			for _, bw := range bwtests {
				size, err := db.GetBandwidthUsedByDay(bw.timenow)
				require.NoError(t, err)
				require.Equal(t, int64(0), size)
			}
		})

		t.Run("GetTotalBandwidthBetween", func(t *testing.T) {
			for _, bw := range bwtests {
				size, err := db.GetTotalBandwidthBetween(bw.timenow, bw.timenow)
				require.NoError(t, err)
				require.Equal(t, int64(0), size)
			}
		})

	})

	t.Run("Create", func(t *testing.T) {
		for P := 0; P < concurrency; P++ {
			t.Run("#"+strconv.Itoa(P), func(t *testing.T) {
				t.Parallel()
				for _, ttl := range tests {
					err := db.AddTTL(ttl.ID, ttl.Expiration, 0)
					if err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	})

	t.Run("Get", func(t *testing.T) {
		for P := 0; P < concurrency; P++ {
			t.Run("#"+strconv.Itoa(P), func(t *testing.T) {
				t.Parallel()
				for _, ttl := range tests {
					expiration, err := db.GetTTLByID(ttl.ID)
					if err != nil {
						t.Fatal(err)
					}

					if ttl.Expiration != expiration {
						t.Fatalf("expected %d got %d", ttl.Expiration, expiration)
					}
				}
			})
		}
	})

	t.Run("Delete", func(t *testing.T) {
		for P := 0; P < concurrency; P++ {
			t.Run("Delete", func(t *testing.T) {
				t.Parallel()
				for _, ttl := range tests {
					err := db.DeleteTTLByID(ttl.ID)
					if err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	})

	t.Run("Get Deleted", func(t *testing.T) {
		for P := 0; P < concurrency; P++ {
			t.Run("#"+strconv.Itoa(P), func(t *testing.T) {
				t.Parallel()
				for _, ttl := range tests {
					expiration, err := db.GetTTLByID(ttl.ID)
					if err == nil {
						t.Fatal(err)
					}
					if expiration != 0 {
						t.Fatalf("expected expiration 0 got %d", expiration)
					}
				}
			})
		}
	})

	t.Run("Bandwidth Allocation", func(t *testing.T) {
		for P := 0; P < concurrency; P++ {
			t.Run("#"+strconv.Itoa(P), func(t *testing.T) {
				t.Parallel()
				for _, test := range allocationTests {
					err := db.WriteBandwidthAllocToDB(test)
					if err != nil {
						t.Fatal(err)
					}

					agreements, err := db.GetBandwidthAllocationBySignature(test.Signature)
					if err != nil {
						t.Fatal(err)
					}

					found := false
					for _, agreement := range agreements {
						if pb.Equal(agreement, test) {
							found = true
							break
						}
					}

					if !found {
						t.Fatal("did not find added bandwidth allocation")
					}
				}
			})
		}
	})

	t.Run("Get all Bandwidth Allocations", func(t *testing.T) {
		for P := 0; P < concurrency; P++ {
			t.Run("#"+strconv.Itoa(P), func(t *testing.T) {
				t.Parallel()

				agreementGroups, err := db.GetBandwidthAllocations()
				if err != nil {
					t.Fatal(err)
				}

				found := false
				for _, agreements := range agreementGroups {
					for _, agreement := range agreements {
						for _, test := range allocationTests {
							if pb.Equal(&agreement.Agreement, test) {
								found = true
								break
							}
						}
					}
				}

				if !found {
					t.Fatal("did not find added bandwidth allocation")
				}
			})
		}
	})

	t.Run("GetBandwidthUsedByDay", func(t *testing.T) {
		for P := 0; P < concurrency; P++ {
			t.Run("#"+strconv.Itoa(P), func(t *testing.T) {
				t.Parallel()
				for _, bw := range bwtests {
					size, err := db.GetBandwidthUsedByDay(bw.timenow)
					if err != nil {
						t.Fatal(err)
					}
					if bw.size != size {
						t.Fatalf("expected %d got %d", bw.size, size)
					}
				}
			})
		}
	})

	t.Run("GetTotalBandwidthBetween", func(t *testing.T) {
		for P := 0; P < concurrency; P++ {
			t.Run("#"+strconv.Itoa(P), func(t *testing.T) {
				t.Parallel()
				for _, bw := range bwtests {
					size, err := db.GetTotalBandwidthBetween(bw.timenow, bw.timenow)
					if err != nil {
						t.Fatal(err)
					}
					if bw.size != size {
						t.Fatalf("expected %d got %d", bw.size, size)
					}
				}
			})
		}
	})

	type bwaUsage struct {
		serialnum string
		setStatus psdb.BwaStatus
		expStatus psdb.BwaStatus
	}

	bwatests := []bwaUsage{
		// size is total size stored
		{serialnum: "serialnum_1", setStatus: psdb.BwaStatusUNSENT, expStatus: psdb.BwaStatusUNSENT},
		{serialnum: "serialnum_2", setStatus: psdb.BwaStatusREJECT, expStatus: psdb.BwaStatusREJECT},
		{serialnum: "serialnum_3", setStatus: psdb.BwaStatusSENT, expStatus: psdb.BwaStatusSENT},
	}
	t.Run("UpdateBandwidthAllocationStatus", func(t *testing.T) {
		for P := 0; P < concurrency; P++ {
			t.Run("#"+strconv.Itoa(P), func(t *testing.T) {
				t.Parallel()
				for _, bw := range bwatests {
					err := db.UpdateBandwidthAllocationStatus(bw.serialnum, bw.setStatus)
					require.NoError(t, err)
					status, err := db.GetBwaStatusBySerialNum(bw.serialnum)
					require.NoError(t, err)
					assert.Equal(t, bw.expStatus, status)
				}
			})
		}
	})

}

func BenchmarkWriteBandwidthAllocation(b *testing.B) {
	db, cleanup := newDB(b, "3")
	defer cleanup()
	const WritesPerLoop = 10
	b.RunParallel(func(b *testing.PB) {
		for b.Next() {
			for i := 0; i < WritesPerLoop; i++ {
				_ = db.WriteBandwidthAllocToDB(&pb.Order{
					PayerAllocation: pb.OrderLimit{},
					Total:           156,
					Signature:       []byte("signed by test"),
				})
			}
		}
	})
}
