package config

import (
	"fmt"
	"net"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/spf13/viper"
)

const (
	DEFAULT_HOLDTIME                  = 90
	DEFAULT_IDLE_HOLDTIME_AFTER_RESET = 30
	DEFAULT_CONNECT_RETRY             = 120
)

var forcedOverwrittenConfig = []string{
	"peer.config.peer-as",
	"peer.timers.config.minimum-advertisement-interval",
}

var configuredFields map[string]interface{}

func RegisterConfiguredFields(addr string, n interface{}) {
	if configuredFields == nil {
		configuredFields = make(map[string]interface{})
	}
	configuredFields[addr] = n
}

func defaultAfiSafi(typ AfiSafiType, enable bool) AfiSafi {
	return AfiSafi{
		Config: AfiSafiConfig{
			AfiSafiName: typ,
			Enabled:     enable,
		},
		State: AfiSafiState{
			AfiSafiName: typ,
			Family:      bgp.AddressFamilyValueMap[string(typ)],
		},
	}
}

func SetDefaultPeerConfigValues(n *Peer, g *Global) error {
	// Determines this function is called against the same Neighbor struct,
	// and if already called, returns immediately.
	if n.State.LocalAs != 0 {
		return nil
	}

	return setDefaultPeerConfigValuesWithViper(nil, n, g)
}

func setDefaultPeerConfigValuesWithViper(v *viper.Viper, n *Peer, g *Global) error {
	if n == nil {
		return fmt.Errorf("neighbor config is nil")
	}
	if g == nil {
		return fmt.Errorf("global config is nil")
	}

	if v == nil {
		v = viper.New()
	}

	if n.Config.LocalAs == 0 {
		n.Config.LocalAs = g.Config.As
	}
	n.State.LocalAs = n.Config.LocalAs

	if n.Config.PeerAs != n.Config.LocalAs {
		n.Config.PeerType = PEER_TYPE_EXTERNAL
		n.State.PeerType = PEER_TYPE_EXTERNAL
		n.State.RemovePrivateAs = n.Config.RemovePrivateAs
		n.AsPathOptions.State.ReplacePeerAs = n.AsPathOptions.Config.ReplacePeerAs
	} else {
		n.Config.PeerType = PEER_TYPE_INTERNAL
		n.State.PeerType = PEER_TYPE_INTERNAL
		if string(n.Config.RemovePrivateAs) != "" {
			return fmt.Errorf("can't set remove-private-as for iBGP peer")
		}
		if n.AsPathOptions.Config.ReplacePeerAs {
			return fmt.Errorf("can't set replace-peer-as for iBGP peer")
		}
	}

	if n.State.PeerAddress == "" {
		n.State.PeerAddress = n.Config.PeerAddress
	}

	n.State.PeerAs = n.Config.PeerAs
	n.AsPathOptions.State.AllowOwnAs = n.AsPathOptions.Config.AllowOwnAs

	if !v.IsSet("peer.error-handling.config.treat-as-withdraw") {
		n.ErrorHandling.Config.TreatAsWithdraw = true
	}

	if !v.IsSet("peer.timers.config.connect-retry") && n.Timers.Config.ConnectRetry == 0 {
		n.Timers.Config.ConnectRetry = float64(DEFAULT_CONNECT_RETRY)
	}
	if !v.IsSet("peer.timers.config.hold-time") && n.Timers.Config.HoldTime == 0 {
		n.Timers.Config.HoldTime = float64(DEFAULT_HOLDTIME)
	}
	if !v.IsSet("peer.timers.config.keepalive-interval") && n.Timers.Config.KeepaliveInterval == 0 {
		n.Timers.Config.KeepaliveInterval = n.Timers.Config.HoldTime / 3
	}
	if !v.IsSet("peer.timers.config.idle-hold-time-after-reset") && n.Timers.Config.IdleHoldTimeAfterReset == 0 {
		n.Timers.Config.IdleHoldTimeAfterReset = float64(DEFAULT_IDLE_HOLDTIME_AFTER_RESET)
	}

	if n.Config.PeerInterface != "" {
		addr, err := GetIPv6LinkLocalNeighborAddress(n.Config.PeerInterface)
		if err != nil {
			return err
		}
		n.State.PeerAddress = addr
	}

	if n.Transport.Config.LocalAddress == "" {
		if n.State.PeerAddress == "" {
			return fmt.Errorf("no peer address/interface specified")
		}
		ipAddr, err := net.ResolveIPAddr("ip", n.State.PeerAddress)
		if err != nil {
			return err
		}
		localAddress := "0.0.0.0"
		if ipAddr.IP.To4() == nil {
			localAddress = "::"
			if ipAddr.Zone != "" {
				localAddress, err = getIPv6LinkLocalAddress(ipAddr.Zone)
				if err != nil {
					return err
				}
			}
		}
		n.Transport.Config.LocalAddress = localAddress
	}

	if len(n.AfiSafis) == 0 {
		if n.Config.PeerInterface != "" {
			n.AfiSafis = []AfiSafi{
				defaultAfiSafi(AFI_SAFI_TYPE_IPV4_UNICAST, true),
				defaultAfiSafi(AFI_SAFI_TYPE_IPV6_UNICAST, true),
			}
		} else if ipAddr, err := net.ResolveIPAddr("ip", n.State.PeerAddress); err != nil {
			return fmt.Errorf("invalid peer address: %s", n.State.PeerAddress)
		} else if ipAddr.IP.To4() != nil {
			n.AfiSafis = []AfiSafi{defaultAfiSafi(AFI_SAFI_TYPE_IPV4_UNICAST, true)}
		} else {
			n.AfiSafis = []AfiSafi{defaultAfiSafi(AFI_SAFI_TYPE_IPV6_UNICAST, true)}
		}
		for i := range n.AfiSafis {
			n.AfiSafis[i].AddPaths.Config.Receive = n.AddPaths.Config.Receive
			n.AfiSafis[i].AddPaths.State.Receive = n.AddPaths.Config.Receive
			n.AfiSafis[i].AddPaths.Config.SendMax = n.AddPaths.Config.SendMax
			n.AfiSafis[i].AddPaths.State.SendMax = n.AddPaths.Config.SendMax
		}
	} else {
		afs, err := extractArray(v.Get("peer.afi-safis"))
		if err != nil {
			return err
		}
		for i := range n.AfiSafis {
			vv := viper.New()
			if len(afs) > i {
				vv.Set("afi-safi", afs[i])
			}
			rf, err := bgp.GetRouteFamily(string(n.AfiSafis[i].Config.AfiSafiName))
			if err != nil {
				return err
			}
			n.AfiSafis[i].State.Family = rf
			n.AfiSafis[i].State.AfiSafiName = n.AfiSafis[i].Config.AfiSafiName
			if !vv.IsSet("afi-safi.config.enabled") {
				n.AfiSafis[i].Config.Enabled = true
			}
			if !vv.IsSet("afi-safi.add-paths.config.receive") {
				if n.AddPaths.Config.Receive {
					n.AfiSafis[i].AddPaths.Config.Receive = n.AddPaths.Config.Receive
				}
			}
			n.AfiSafis[i].AddPaths.State.Receive = n.AfiSafis[i].AddPaths.Config.Receive
			if !vv.IsSet("afi-safi.add-paths.config.send-max") {
				if n.AddPaths.Config.SendMax != 0 {
					n.AfiSafis[i].AddPaths.Config.SendMax = n.AddPaths.Config.SendMax
				}
			}
			n.AfiSafis[i].AddPaths.State.SendMax = n.AfiSafis[i].AddPaths.Config.SendMax
		}
	}

	n.State.Description = n.Config.Description

	if n.EbgpMultihop.Config.Enabled {
		if n.TtlSecurity.Config.Enabled {
			return fmt.Errorf("ebgp-multihop and ttl-security are mututally exclusive")
		}
		if n.EbgpMultihop.Config.MultihopTtl == 0 {
			n.EbgpMultihop.Config.MultihopTtl = 255
		}
	} else if n.TtlSecurity.Config.Enabled {
		if n.TtlSecurity.Config.TtlMin == 0 {
			n.TtlSecurity.Config.TtlMin = 255
		}
	}

	return nil
}

func SetDefaultGlobalConfigValues(g *Global) error {
	if len(g.AfiSafis) == 0 {
		g.AfiSafis = []AfiSafi{}
		for k := range AfiSafiTypeToIntMap {
			g.AfiSafis = append(g.AfiSafis, defaultAfiSafi(k, true))
		}
	}

	if g.Config.Port == 0 {
		g.Config.Port = bgp.BGP_PORT
	}

	if len(g.Config.LocalAddressList) == 0 {
		g.Config.LocalAddressList = []string{"0.0.0.0", "::"}
	}
	return nil
}

func SetDefaultConfigValues(b *BgpConfigSet) error {
	return setDefaultConfigValuesWithViper(nil, b)
}

func setDefaultConfigValuesWithViper(v *viper.Viper, b *BgpConfigSet) error {
	if v == nil {
		v = viper.New()
	}

	if err := SetDefaultGlobalConfigValues(&b.Global); err != nil {
		return err
	}

	list, err := extractArray(v.Get("peers"))
	if err != nil {
		return err
	}

	for idx, n := range b.Peers {
		vv := viper.New()
		if len(list) > idx {
			vv.Set("peer", list[idx])
		}

		if err := setDefaultPeerConfigValuesWithViper(vv, &n, &b.Global); err != nil {
			return err
		}
		b.Peers[idx] = n
	}

	return nil
}
