// Copyright 2026 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package object

import (
	"context"
	"sync"
	"time"

	"github.com/beego/beego/v2/core/logs"
	"github.com/casdoor/casdoor/conf"
	"github.com/casdoor/casdoor/util"
	"github.com/redis/go-redis/v9"
)

// dpopReplayStore tracks DPoP proof jti values that have already been accepted within their
// freshness window, so a captured (access token, DPoP proof) pair cannot be replayed to repeat
// a request (RFC 9449 §4.2, §11.1). The default implementation is in-memory; when redisEndpoint
// is configured, a Redis-backed implementation is used so replay detection is correct across
// multiple Casdoor replicas — an in-memory store only sees the replicas it lands on.
type dpopReplayStore interface {
	// CheckAndStore reports whether key has already been recorded (a replay) and, if not,
	// atomically records it with the given TTL so subsequent calls with the same key report
	// a replay until it expires.
	CheckAndStore(key string, ttl time.Duration) (alreadySeen bool)
}

const dpopReplayRedisPrefix = "casdoor:dpop_jti:"

// DPoPReplayStore stores DPoP proof jti values already accepted, keyed by "<jkt>:<jti>" so
// replay detection is scoped per bound key. It defaults to an in-memory store; call
// InitDPoPReplayStore() at startup to switch to Redis when redisEndpoint is configured.
var DPoPReplayStore dpopReplayStore = &memoryDPoPReplayStore{}

// InitDPoPReplayStore switches DPoPReplayStore to a Redis-backed store when redisEndpoint is
// configured. It must be called after configuration is loaded and before serving requests.
// On failure it logs a warning and keeps the default in-memory store.
func InitDPoPReplayStore() {
	endpoint := conf.GetConfigString("redisEndpoint")
	if endpoint == "" {
		return
	}

	client, err := newRedisClient(endpoint)
	if err != nil {
		logs.Warn("dpop_replay_store: failed to connect to Redis (%s), falling back to in-memory store: %v", endpoint, err)
		return
	}

	DPoPReplayStore = &redisDPoPReplayStore{client: client}
	logs.Info("dpop_replay_store: using Redis backend at %s", endpoint)
}

// ── in-memory implementation (default) ──────────────────────────────────────

type memoryDPoPReplayEntry struct {
	expiresAt time.Time
}

type memoryDPoPReplayStore struct {
	m sync.Map
}

func (s *memoryDPoPReplayStore) CheckAndStore(key string, ttl time.Duration) bool {
	now := time.Now()
	entry := memoryDPoPReplayEntry{expiresAt: now.Add(ttl)}

	actual, loaded := s.m.LoadOrStore(key, entry)
	if !loaded {
		return false
	}

	existing, ok := actual.(memoryDPoPReplayEntry)
	if !ok || !existing.expiresAt.After(now) {
		// Not a valid entry, or it already expired: treat as unseen and refresh it.
		s.m.Store(key, entry)
		return false
	}

	return true
}

// cleanupExpired removes entries past their TTL so the in-memory map stays bounded. It is
// invoked periodically by InitCleanupDPoPReplayStore.
func (s *memoryDPoPReplayStore) cleanupExpired() {
	now := time.Now()
	s.m.Range(func(key, value any) bool {
		entry, ok := value.(memoryDPoPReplayEntry)
		if !ok || !entry.expiresAt.After(now) {
			s.m.Delete(key)
		}
		return true
	})
}

// ── Redis implementation ─────────────────────────────────────────────────────

type redisDPoPReplayStore struct {
	client *redis.Client
}

func (s *redisDPoPReplayStore) CheckAndStore(key string, ttl time.Duration) bool {
	rk := dpopReplayRedisPrefix + key

	// SetNX is atomic: it sets the key only if it does not already exist, so concurrent
	// requests replaying the same jti cannot both "win" a check-then-set race.
	wasSet, err := s.client.SetNX(context.Background(), rk, "1", ttl).Result()
	if err != nil {
		// Fail open, matching the rest of this store's Redis error handling (see
		// device_auth_store.go): an unreachable Redis degrades DPoP back to
		// presence-only jti validation rather than blocking all DPoP-bound traffic.
		// See the PR's Residual risk section for this tradeoff.
		logs.Warn("dpop_replay_store: Redis SETNX failed for key %s: %v", rk, err)
		return false
	}

	return !wasSet
}

// InitCleanupDPoPReplayStore switches DPoPReplayStore to Redis when configured, and starts a
// periodic sweep of the in-memory store so it does not grow unbounded (the Redis-backed store
// relies on native key TTLs instead, so the sweep is a no-op there).
func InitCleanupDPoPReplayStore() {
	InitDPoPReplayStore()

	memStore, ok := DPoPReplayStore.(*memoryDPoPReplayStore)
	if !ok {
		return
	}

	util.SafeGoroutine(func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			memStore.cleanupExpired()
		}
	})
}
