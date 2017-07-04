// Copyright (C) 2017, Beijing Bochen Technology Co.,Ltd.  All rights reserved.
//
// This file is part of L0
//
// The L0 is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The L0 is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package state_hash

import (
	"bytes"
	"hash/fnv"
	"math"
	"sort"
	"sync"

	"time"

	"github.com/bocheninc/L0/components/crypto"
	"github.com/bocheninc/L0/components/db"
	"github.com/bocheninc/L0/components/log"
)

var (
	cacheBranchNumber = 5
	cacheLevelNumber  = 10
)

var (
	once          sync.Once
	cacheRootNode *stateCacheNode
	cacheLeafs    map[int]*stateCacheNode
)

// stateCacheUnit
type stateCacheUnit struct {
	key    []byte
	value  []byte
	sum    crypto.Hash
	latest bool
}

func newStateCacheUnit(key, value []byte) *stateCacheUnit {
	return &stateCacheUnit{
		key:   key,
		value: value,
	}
}

func unitKeyEigen(key []byte) int {
	fnvHash := fnv.New32a()
	fnvHash.Write(key)
	sum := int(fnvHash.Sum32())
	return sum % int(math.Pow(float64(cacheBranchNumber), float64(cacheLevelNumber-1)))
}

func unitLevelIndex(keyEigen int, level int) (int, int) {
	n := cacheLevelNumber - level - 1
	if n > 0 {
		factor := int(math.Pow(float64(cacheBranchNumber), float64(n)))
		return keyEigen / factor, keyEigen % factor
	}
	return 0, 0
}

func (u *stateCacheUnit) set(value []byte) {
	if !bytes.Equal(value, u.value) {
		u.value = value
		u.latest = false
	}
}

func (u *stateCacheUnit) hash() []byte {
	if u.latest {
		return u.sum[:]
	}

	var data []byte
	data = append(data, u.key...)
	data = append(data, u.value...)
	u.sum = crypto.Sha256(data)
	u.latest = true
	return u.sum[:]
}

// stateCacheUnits
type stateCacheUnits struct {
	units  []*stateCacheUnit
	sum    crypto.Hash
	latest bool
}

func newStateCacheUnits() *stateCacheUnits {
	return &stateCacheUnits{}
}

func (us *stateCacheUnits) set(unit *stateCacheUnit) {
	if unit == nil {
		return
	}

	for _, u := range us.units {
		if bytes.Equal(u.key, unit.key) {
			u.set(unit.value)
			us.latest = false
			return
		}
	}
	us.units = append(us.units, unit)
	us.latest = false
}

func (us *stateCacheUnits) remove(key []byte) {
	if len(key) == 0 {
		return
	}

	for i, u := range us.units {
		if bytes.Compare(u.key, key) == 0 {
			us.units = append(us.units[:i], us.units[i+1:]...)
			us.latest = false
			return
		}
	}
}

func (us *stateCacheUnits) len() int {
	return len(us.units)
}

func (us *stateCacheUnits) hash() []byte {
	if us.latest {
		return us.sum[:]
	}

	if len(us.units) == 0 {
		return nil
	}

	if len(us.units) == 1 {
		copy(us.sum[:], us.units[0].hash())
		us.latest = true
		return us.sum[:]
	}

	us.sort()
	var data []byte
	for _, u := range us.units {
		data = append(data, u.hash()...)
	}
	us.sum = crypto.Sha256(data)
	us.latest = true
	return us.sum[:]
}

func (us *stateCacheUnits) sort() {
	sort.Slice(us.units, func(i, j int) bool {
		return bytes.Compare(us.units[i].key, us.units[j].key) < 0
	})
}

// stateCacheNode
type stateCacheNode struct {
	children []*stateCacheNode
	level    byte
	sum      crypto.Hash
	latest   bool
	units    *stateCacheUnits
}

func newStateCacheNode(level byte) *stateCacheNode {
	return &stateCacheNode{
		children: make([]*stateCacheNode, cacheBranchNumber),
		level:    level,
	}
}

func (n *stateCacheNode) valid() bool {
	if n == nil {
		return false
	}

	if !n.isLeaf() {
		for _, c := range n.children {
			if c.valid() {
				return true
			}
		}
		return false
	}
	return (n.units != nil) && (n.units.len() > 0)
}

func (n *stateCacheNode) set(unit *stateCacheUnit, keyEigen int) {
	if unit == nil {
		return
	}

	if !n.isLeaf() {
		index, keyEigen := unitLevelIndex(keyEigen, int(n.level))
		if index >= cacheBranchNumber {
			log.Errorf("ledger/state/hash, stateCacheNode.set, invalid index: %d, branch number: %d", index, cacheBranchNumber)
			return
		}

		c := n.children[index]
		if c == nil {
			c = newStateCacheNode(n.level + 1)
			n.children[index] = c
		}
		c.set(unit, keyEigen)
		n.latest = false
	} else {
		if n.units == nil {
			n.units = newStateCacheUnits()
		}
		n.units.set(unit)
		n.latest = false
	}
}

func (n *stateCacheNode) remove(key []byte, keyEigen int) {
	if len(key) == 0 {
		return
	}

	if !n.isLeaf() {
		index, keyEigen := unitLevelIndex(keyEigen, int(n.level))
		c := n.children[index]
		if c != nil {
			c.remove(key, keyEigen)
			if !c.valid() {
				n.children[index] = nil
			}
			n.latest = false
		}
	} else {
		if n.units != nil {
			n.units.remove(key)
			n.latest = false
		}
	}
}

func (n *stateCacheNode) hash() crypto.Hash {
	if n.latest {
		return n.sum
	}

	var data []byte
	for _, c := range n.children {
		if c.valid() {
			data = append(data, c.hash().Bytes()...)
		}
	}
	n.sum = crypto.Sha256(data)
	n.latest = true
	return n.sum
}

func (n *stateCacheNode) isLeaf() bool {
	return int(n.level) >= cacheLevelNumber
}

func (n *stateCacheNode) childrenNumber() int {
	if !n.isLeaf() {
		count := 0
		for _, c := range n.children {
			if c.valid() {
				count++
			}
		}
		return count
	}

	if n.units != nil {
		return n.units.len()
	}
	return 0
}

// ForeacherHandler handle iterating.
type ForeacherHandler func([]byte, []byte)

// Foreacher iterates.
type Foreacher func(ForeacherHandler)

// InitHash returns stateRootHash
func InitHash(foreacher Foreacher) crypto.Hash {
	if cacheRootNode == nil {
		initStateCache(foreacher)
	}
	t := time.Now()
	hash := cacheRootNode.hash()
	delay := time.Since(t)

	log.Debugln("rootNode delay", delay)
	return hash
}

// UpdateHash updates state cache and returns the new stateRootHash.
func UpdateHash(writeBatchs []*db.WriteBatch) crypto.Hash {
	if cacheRootNode == nil {
		panic("must init first!")
	}

	for _, writeBatch := range writeBatchs {
		switch writeBatch.Operation {
		case db.OperationPut:
			cacheRootNode.set(
				newStateCacheUnit(writeBatch.Key, writeBatch.Value),
				unitKeyEigen(writeBatch.Key))
		case db.OperationDelete:
			cacheRootNode.remove(writeBatch.Key, unitKeyEigen(writeBatch.Key))
		}
	}
	return cacheRootNode.hash()
}

func initStateCache(foreacher Foreacher) {
	if foreacher == nil {
		panic("invalid foreacher.")
	}

	once.Do(func() {
		cacheRootNode = newStateCacheNode(1)

		k := 0
		foreacher(func(key, value []byte) {
			cacheRootNode.set(&stateCacheUnit{
				key:   key,
				value: value,
			}, unitKeyEigen(key))
			k++
		})
		log.Infoln("state hash init, count:", k)
	})
}
