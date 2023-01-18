// Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
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

package config

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	tspb "google.golang.org/protobuf/types/known/timestamppb"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

// yaml is decoded as []interface{}
// but toml is decoded as []map[string]interface{}.
// currently, viper can't hide this difference.
// handle the difference here.
func extractArray(intf interface{}) ([]interface{}, error) {
	if intf != nil {
		list, ok := intf.([]interface{})
		if ok {
			return list, nil
		}
		l, ok := intf.([]map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid configuration: neither []interface{} nor []map[string]interface{}")
		}
		list = make([]interface{}, 0, len(l))
		for _, m := range l {
			list = append(list, m)
		}
		return list, nil
	}
	return nil, nil
}

func getIPv6LinkLocalAddress(ifname string) (string, error) {
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return "", err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		ip := addr.(*net.IPNet).IP
		if ip.To4() == nil && ip.IsLinkLocalUnicast() {
			return fmt.Sprintf("%s%%%s", ip.String(), ifname), nil
		}
	}
	return "", fmt.Errorf("no ipv6 link local address for %s", ifname)
}

func (n *Peer) IsEBGPPeer(g *Global) bool {
	return n.Config.PeerAs != n.Config.LocalAs
}

func (n *Peer) CreateRfMap() map[bgp.RouteFamily]bgp.BGPAddPathMode {
	rfMap := make(map[bgp.RouteFamily]bgp.BGPAddPathMode)
	for _, af := range n.AfiSafis {
		mode := bgp.BGP_ADD_PATH_NONE
		if af.AddPaths.State.Receive {
			mode |= bgp.BGP_ADD_PATH_RECEIVE
		}
		if af.AddPaths.State.SendMax > 0 {
			mode |= bgp.BGP_ADD_PATH_SEND
		}
		rfMap[af.State.Family] = mode
	}
	return rfMap
}

func (n *Peer) GetAfiSafi(family bgp.RouteFamily) *AfiSafi {
	for _, a := range n.AfiSafis {
		if string(a.Config.AfiSafiName) == family.String() {
			return &a
		}
	}
	return nil
}

func (n *Peer) ExtractNeighborAddress() (string, error) {
	addr := n.State.PeerAddress
	if addr == "" {
		addr = n.Config.PeerAddress
		if addr == "" {
			return "", fmt.Errorf("PeerAddress is not configured")
		}
	}
	return addr, nil
}

func (n *Peer) IsAddPathReceiveEnabled(family bgp.RouteFamily) bool {
	for _, af := range n.AfiSafis {
		if af.State.Family == family {
			return af.AddPaths.State.Receive
		}
	}
	return false
}

type AfiSafis []AfiSafi

func (c AfiSafis) ToRfList() ([]bgp.RouteFamily, error) {
	rfs := make([]bgp.RouteFamily, 0, len(c))
	for _, af := range c {
		rfs = append(rfs, af.State.Family)
	}
	return rfs, nil
}

func inSlice(n Peer, b []Peer) int {
	for i, nb := range b {
		if nb.State.PeerAddress == n.State.PeerAddress {
			return i
		}
	}
	return -1
}

func isAfiSafiChanged(x, y []AfiSafi) bool {
	if len(x) != len(y) {
		return true
	}
	m := make(map[string]AfiSafi)
	for i, e := range x {
		m[string(e.Config.AfiSafiName)] = x[i]
	}
	for _, e := range y {
		if v, ok := m[string(e.Config.AfiSafiName)]; !ok || !v.Config.Equal(&e.Config) || !v.AddPaths.Config.Equal(&e.AddPaths.Config) || !v.MpGracefulRestart.Config.Equal(&e.MpGracefulRestart.Config) {
			return true
		}
	}
	return false
}

func (n *Peer) NeedsResendOpenMessage(new *Peer) bool {
	return !n.Config.Equal(&new.Config) ||
		!n.Transport.Config.Equal(&new.Transport.Config) ||
		!n.AddPaths.Config.Equal(&new.AddPaths.Config) ||
		!n.AsPathOptions.Config.Equal(&new.AsPathOptions.Config) ||
		isAfiSafiChanged(n.AfiSafis, new.AfiSafis)
}

// TODO: these regexp are duplicated in api
var _regexpPrefixMaskLengthRange = regexp.MustCompile(`(\d+)\.\.(\d+)`)

func ParseMaskLength(prefix, mask string) (int, int, error) {
	_, ipNet, err := net.ParseCIDR(prefix)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid prefix: %s", prefix)
	}
	if mask == "" {
		l, _ := ipNet.Mask.Size()
		return l, l, nil
	}
	elems := _regexpPrefixMaskLengthRange.FindStringSubmatch(mask)
	if len(elems) != 3 {
		return 0, 0, fmt.Errorf("invalid mask length range: %s", mask)
	}
	// we've already checked the range is sane by regexp
	min, _ := strconv.ParseUint(elems[1], 10, 8)
	max, _ := strconv.ParseUint(elems[2], 10, 8)
	if min > max {
		return 0, 0, fmt.Errorf("invalid mask length range: %s", mask)
	}
	if ipv4 := ipNet.IP.To4(); ipv4 != nil {
		f := func(i uint64) bool {
			return i <= 32
		}
		if !f(min) || !f(max) {
			return 0, 0, fmt.Errorf("ipv4 mask length range outside scope :%s", mask)
		}
	} else {
		f := func(i uint64) bool {
			return i <= 128
		}
		if !f(min) || !f(max) {
			return 0, 0, fmt.Errorf("ipv6 mask length range outside scope :%s", mask)
		}
	}
	return int(min), int(max), nil
}

func extractFamilyFromConfigAfiSafi(c *AfiSafi) uint32 {
	if c == nil {
		return 0
	}
	// If address family value is already stored in AfiSafiState structure,
	// we prefer to use this value.
	if c.State.Family != 0 {
		return uint32(c.State.Family)
	}
	// In case that Neighbor structure came from CLI or gRPC, address family
	// value in AfiSafiState structure can be omitted.
	// Here extracts value from AfiSafiName field in AfiSafiConfig structure.
	if rf, err := bgp.GetRouteFamily(string(c.Config.AfiSafiName)); err == nil {
		return uint32(rf)
	}
	// Ignores invalid address family name
	return 0
}

func newAfiSafiConfigFromConfigStruct(c *AfiSafi) *api.AfiSafiConfig {
	rf := extractFamilyFromConfigAfiSafi(c)
	afi, safi := bgp.RouteFamilyToAfiSafi(bgp.RouteFamily(rf))
	return &api.AfiSafiConfig{
		Family:  &api.Family{Afi: api.Family_Afi(afi), Safi: api.Family_Safi(safi)},
		Enabled: c.Config.Enabled,
	}
}

func newRouteTargetMembershipFromConfigStruct(c *RouteTargetMembership) *api.RouteTargetMembership {
	return &api.RouteTargetMembership{
		Config: &api.RouteTargetMembershipConfig{
			DeferralTime: uint32(c.Config.DeferralTime),
		},
	}
}

func newAddPathsFromConfigStruct(c *AddPaths) *api.AddPaths {
	return &api.AddPaths{
		Config: &api.AddPathsConfig{
			Receive: c.Config.Receive,
			SendMax: uint32(c.Config.SendMax),
		},
	}
}

func newUseMultiplePathsFromConfigStruct(c *UseMultiplePaths) *api.UseMultiplePaths {
	return &api.UseMultiplePaths{
		Config: &api.UseMultiplePathsConfig{
			Enabled: c.Config.Enabled,
		},
		Ebgp: &api.Ebgp{
			Config: &api.EbgpConfig{
				AllowMultipleAsn: c.Ebgp.Config.AllowMultipleAs,
				MaximumPaths:     c.Ebgp.Config.MaximumPaths,
			},
		},
		Ibgp: &api.Ibgp{
			Config: &api.IbgpConfig{
				MaximumPaths: c.Ibgp.Config.MaximumPaths,
			},
		},
	}
}

func newAfiSafiFromConfigStruct(c *AfiSafi) *api.AfiSafi {
	return &api.AfiSafi{
		Config:                newAfiSafiConfigFromConfigStruct(c),
		UseMultiplePaths:      newUseMultiplePathsFromConfigStruct(&c.UseMultiplePaths),
		RouteTargetMembership: newRouteTargetMembershipFromConfigStruct(&c.RouteTargetMembership),
		AddPaths:              newAddPathsFromConfigStruct(&c.AddPaths),
	}
}

func ProtoTimestamp(secs int64) *tspb.Timestamp {
	if secs == 0 {
		return nil
	}
	return tspb.New(time.Unix(secs, 0))
}

func NewPeerFromConfigStruct(pconf *Peer) *api.Peer {
	afiSafis := make([]*api.AfiSafi, 0, len(pconf.AfiSafis))
	for _, f := range pconf.AfiSafis {
		if afiSafi := newAfiSafiFromConfigStruct(&f); afiSafi != nil {
			afiSafis = append(afiSafis, afiSafi)
		}
	}

	timer := pconf.Timers
	s := pconf.State
	localAddress := pconf.Transport.Config.LocalAddress
	if pconf.Transport.State.LocalAddress != "" {
		localAddress = pconf.Transport.State.LocalAddress
	}
	remoteCap, err := apiutil.MarshalCapabilities(pconf.State.RemoteCapabilityList)
	if err != nil {
		return nil
	}
	localCap, err := apiutil.MarshalCapabilities(pconf.State.LocalCapabilityList)
	if err != nil {
		return nil
	}
	var removePrivate api.RemovePrivate
	switch pconf.Config.RemovePrivateAs {
	case REMOVE_PRIVATE_AS_OPTION_ALL:
		removePrivate = api.RemovePrivate_REMOVE_ALL
	case REMOVE_PRIVATE_AS_OPTION_REPLACE:
		removePrivate = api.RemovePrivate_REPLACE
	}
	return &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress:   pconf.Config.PeerAddress,
			PeerAsn:           pconf.Config.PeerAs,
			LocalAsn:          pconf.Config.LocalAs,
			Type:              api.PeerType(pconf.Config.PeerType.ToInt()),
			AuthPassword:      pconf.Config.AuthPassword,
			RouteFlapDamping:  pconf.Config.RouteFlapDamping,
			Description:       pconf.Config.Description,
			NeighborInterface: pconf.Config.PeerInterface,
			Vrf:               pconf.Config.Vrf,
			AllowOwnAsn:       uint32(pconf.AsPathOptions.Config.AllowOwnAs),
			RemovePrivate:     removePrivate,
			ReplacePeerAsn:    pconf.AsPathOptions.Config.ReplacePeerAs,
		},
		State: &api.PeerState{
			SessionState: api.PeerState_SessionState(api.PeerState_SessionState_value[strings.ToUpper(string(s.SessionState))]),
			AdminState:   api.PeerState_UP,
			Messages: &api.Messages{
				Received: &api.Message{
					Notification:   s.Messages.Received.Notification,
					Update:         s.Messages.Received.Update,
					Open:           s.Messages.Received.Open,
					Keepalive:      s.Messages.Received.Keepalive,
					Refresh:        s.Messages.Received.Refresh,
					Discarded:      s.Messages.Received.Discarded,
					Total:          s.Messages.Received.Total,
					WithdrawUpdate: uint64(s.Messages.Received.WithdrawUpdate),
					WithdrawPrefix: uint64(s.Messages.Received.WithdrawPrefix),
				},
				Sent: &api.Message{
					Notification: s.Messages.Sent.Notification,
					Update:       s.Messages.Sent.Update,
					Open:         s.Messages.Sent.Open,
					Keepalive:    s.Messages.Sent.Keepalive,
					Refresh:      s.Messages.Sent.Refresh,
					Discarded:    s.Messages.Sent.Discarded,
					Total:        s.Messages.Sent.Total,
				},
			},
			PeerAsn:         s.PeerAs,
			Type:            api.PeerType(s.PeerType.ToInt()),
			NeighborAddress: pconf.State.PeerAddress,
			Queues:          &api.Queues{},
			RemoteCap:       remoteCap,
			LocalCap:        localCap,
			RouterId:        s.RemoteRouterId,
		},
		EbgpMultihop: &api.EbgpMultihop{
			Enabled:     pconf.EbgpMultihop.Config.Enabled,
			MultihopTtl: uint32(pconf.EbgpMultihop.Config.MultihopTtl),
		},
		TtlSecurity: &api.TtlSecurity{
			Enabled: pconf.TtlSecurity.Config.Enabled,
			TtlMin:  uint32(pconf.TtlSecurity.Config.TtlMin),
		},
		Timers: &api.Timers{
			Config: &api.TimersConfig{
				ConnectRetry:           uint64(timer.Config.ConnectRetry),
				HoldTime:               uint64(timer.Config.HoldTime),
				KeepaliveInterval:      uint64(timer.Config.KeepaliveInterval),
				IdleHoldTimeAfterReset: uint64(timer.Config.IdleHoldTimeAfterReset),
			},
			State: &api.TimersState{
				KeepaliveInterval:  uint64(timer.State.KeepaliveInterval),
				NegotiatedHoldTime: uint64(timer.State.NegotiatedHoldTime),
				Uptime:             ProtoTimestamp(timer.State.Uptime),
				Downtime:           ProtoTimestamp(timer.State.Downtime),
			},
		},
		Transport: &api.Transport{
			RemotePort:    uint32(pconf.Transport.Config.RemotePort),
			LocalPort:     uint32(pconf.Transport.Config.LocalPort),
			LocalAddress:  localAddress,
			PassiveMode:   pconf.Transport.Config.PassiveMode,
			BindInterface: pconf.Transport.Config.BindInterface,
		},
		AfiSafis: afiSafis,
	}
}
