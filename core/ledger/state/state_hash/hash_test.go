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
	"testing"

	"github.com/bocheninc/L0/components/db"
)

func TestInitHash(t *testing.T) {
	type kv struct {
		key   []byte
		value []byte
	}
	hash := InitHash(func(handler ForeacherHandler) {
		datas := []kv{
			kv{[]byte{1, 2, 3}, []byte{2, 1, 4}},
			kv{[]byte{2, 2, 3}, []byte{2, 1, 3}},
		}
		for _, d := range datas {
			handler(d.key, d.value)
		}
	})
	t.Logf("TestInitHash, hash: %s", hash)
}

func TestUpdateHash(t *testing.T) {
	writeBatch := []*db.WriteBatch{
		db.NewWriteBatch("", db.OperationPut, []byte{1, 2, 3}, []byte{2, 1, 3}),
		db.NewWriteBatch("", db.OperationDelete, []byte{2, 2, 3}, []byte{}),
	}
	hash := UpdateHash(writeBatch)
	t.Logf("TestUpdateHash, hash: %s", hash)
}
