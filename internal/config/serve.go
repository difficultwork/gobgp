package config

import (
	"github.com/spf13/viper"

	"github.com/osrg/gobgp/v3/pkg/log"
)

type BgpConfigSet struct {
	Global Global `mapstructure:"global"`
	Peers  []Peer `mapstructure:"peers"`
}

func ReadConfigfile(path string) (*BgpConfigSet, error) {
	config := &BgpConfigSet{}
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")
	var err error
	if err = v.ReadInConfig(); err != nil {
		return nil, err
	}
	if err = v.UnmarshalExact(config); err != nil {
		return nil, err
	}
	if err = setDefaultConfigValuesWithViper(v, config); err != nil {
		return nil, err
	}
	return config, nil
}

func ConfigSetToRoutingPolicy(c *BgpConfigSet) *RoutingPolicy {
	return &RoutingPolicy{
		DefinedSets:       c.DefinedSets,
		PolicyDefinitions: c.PolicyDefinitions,
	}
}

func UpdatePeerConfig(logger log.Logger, curC, newC *BgpConfigSet) ([]Peer, []Peer, []Peer) {
	added := []Peer{}
	deleted := []Peer{}
	updated := []Peer{}

	for _, n := range newC.Peers {
		if idx := inSlice(n, curC.Peers); idx < 0 {
			added = append(added, n)
		} else if !n.Equal(&curC.Peers[idx]) {
			logger.Debug("Current peer config",
				log.Fields{
					"Topic": "Config",
					"Key":   curC.Peers[idx]})
			logger.Debug("New peer config",
				log.Fields{
					"Topic": "Config",
					"Key":   n})
			updated = append(updated, n)
		}
	}

	for _, n := range curC.Peers {
		if inSlice(n, newC.Peers) < 0 {
			deleted = append(deleted, n)
		}
	}
	return added, deleted, updated
}
