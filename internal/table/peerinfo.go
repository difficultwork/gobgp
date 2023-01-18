// Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package table

import (
	"bytes"
	"fmt"
	"net"

	"github.com/osrg/gobgp/v3/internal/pkg/config"
)

type PeerInfo struct {
	AS           uint32
	ID           net.IP
	LocalAS      uint32
	LocalID      net.IP
	Address      net.IP
	LocalAddress net.IP
	MultihopTtl  uint8
}

func (lhs *PeerInfo) Equal(rhs *PeerInfo) bool {
	if lhs == rhs {
		return true
	}

	if rhs == nil {
		return false
	}

	if (lhs.AS == rhs.AS) && lhs.ID.Equal(rhs.ID) && lhs.LocalID.Equal(rhs.LocalID) && lhs.Address.Equal(rhs.Address) {
		return true
	}
	return false
}

func (i *PeerInfo) String() string {
	if i.Address == nil {
		return "local"
	}
	s := bytes.NewBuffer(make([]byte, 0, 64))
	s.WriteString(fmt.Sprintf("{ %s | ", i.Address))
	s.WriteString(fmt.Sprintf("as: %d", i.AS))
	s.WriteString(fmt.Sprintf(", id: %s", i.ID))
	s.WriteString(" }")
	return s.String()
}

func NewPeerInfo(g *config.Global, p *config.Neighbor) *PeerInfo {
	// exclude zone info
	naddr, _ := net.ResolveIPAddr("ip", p.State.NeighborAddress)
	return &PeerInfo{
		AS:          p.Config.PeerAs,
		LocalAS:     g.Config.As,
		LocalID:     net.ParseIP(g.Config.RouterId).To4(),
		Address:     naddr.IP,
		MultihopTtl: p.EbgpMultihop.Config.MultihopTtl,
	}
}
