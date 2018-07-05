// Copyright 2015 The go-ethereum Authors
// Copyright 2018 The go-etherzero Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package masternode

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/etherzero/go-etherzero/common"
	"github.com/etherzero/go-etherzero/rlp"
	"github.com/etherzero/go-etherzero/crypto/sha3"
	"github.com/etherzero/go-etherzero/contracts/masternode/contract"
	"github.com/etherzero/go-etherzero/log"
	"github.com/etherzero/go-etherzero/p2p/discover"
	"github.com/etherzero/go-etherzero/core/types"
)

const (
	MasternodeInit         = iota
	MasternodeDisconnected
	MasternodeExpired
	MasternodeEnable
)

const (
	MASTERNODE_CHECK_INTERVAL = 30 * time.Second
	MASTERNODE_PING_TIMEOUT   = 180 * time.Second
	MASTERNODE_PING_INTERVAL  = 60 * time.Second
	MASTERNODE_ONLINE_ENABLE  = 60 * time.Second
)

var (
	errClosed            = errors.New("masternode set is closed")
	errAlreadyRegistered = errors.New("masternode is already registered")
	errNotRegistered     = errors.New("masternode is not registered")
)

type PingMsg struct {
	Time uint64
	Sig  []byte
}


func rlpHash(x interface{}) (h common.Hash) {
	hw := sha3.NewKeccak256()
	rlp.Encode(hw, x)
	hw.Sum(h[:0])
	return h
}



type Masternode struct {
	ID              string
	Node            *discover.Node
	Account         common.Address
	OriginBlock     uint64
	Height          *big.Int
	State           int
	ProtocolVersion uint
	LastPingTime    uint64
	UpdateTime      time.Time
	AccOnlineTime   time.Duration

	CollateralMinConfBlockHash common.Hash
}


func newMasternode(nodeId discover.NodeID, ip net.IP, port uint16, account common.Address, block uint64) *Masternode {

	id := GetMasternodeID(nodeId)
	n := discover.NewNode(nodeId, ip, 0, port)
	return &Masternode{
		ID:                         id,
		Node:                       n,
		Account:                    account,
		OriginBlock:                block,
		State:                      MasternodeInit,
		Height:                     big.NewInt(0),
		ProtocolVersion:            64,
		CollateralMinConfBlockHash: common.Hash{},
	}
}

func (n *Masternode) String() string {
	return fmt.Sprintf("Account: %s\nNode: %s\n", n.Account.String(), n.Node)
}

func (n *Masternode) CalculateScore(block *types.Block) int64 {
	blockHash := rlpHash([]interface{}{
		block.Hash(),
		n.ID,
		n.Node,
		block.Number(),
		n.Account,
		n.CollateralMinConfBlockHash,
	})
	return blockHash.Big().Int64()
}

type MasternodeSet struct {
	nodes    map[string]*Masternode
	lock     sync.RWMutex
	closed   bool
	contract *contract.Contract
}

func NewMasternodeSet(contract *contract.Contract) (*MasternodeSet, error) {
	ms := &MasternodeSet{
		nodes: make(map[string]*Masternode),
	}
	var (
		lastId [8]byte
		ctx    *MasternodeContext
	)
	lastId, err := contract.LastId(nil)
	if err != nil {
		return ms, err
	}
	for lastId != ([8]byte{}) {
		ctx, err = GetMasternodeContext(contract, lastId)
		if err != nil {
			log.Error("Init NodeSet", "error", err)
			break
		}
		ms.nodes[ctx.Node.ID] = ctx.Node

		lastId = ctx.pre
	}
	ms.contract = contract

	return ms, nil
}

// Register injects a new node into the working set, or returns an error if the
// node is already known.
func (ns *MasternodeSet) Register(n *Masternode) error {
	ns.lock.Lock()
	defer ns.lock.Unlock()

	if ns.closed {
		return errClosed
	}
	if _, ok := ns.nodes[n.ID]; ok {
		return errAlreadyRegistered
	}
	ns.nodes[n.ID] = n
	return nil
}

// Unregister removes a remote peer from the active set, disabling any further
// actions to/from that particular entity.
func (ns *MasternodeSet) Unregister(id string) error {
	ns.lock.Lock()
	defer ns.lock.Unlock()

	if _, ok := ns.nodes[id]; !ok {
		return errNotRegistered
	}
	delete(ns.nodes, id)
	return nil
}

func (ns *MasternodeSet) CheckNodeID(nodeId discover.NodeID) bool {
	id := GetMasternodeID(nodeId)
	return ns.Node(id) != nil
}

// Peer retrieves the registered peer with the given id.
func (ns *MasternodeSet) Node(id string) *Masternode {
	ns.lock.RLock()
	defer ns.lock.RUnlock()
	return ns.nodes[id]
}

func (ns *MasternodeSet) RecvPingMsg(id string, t uint64) {
	ns.lock.RLock()
	defer ns.lock.RUnlock()

	n := ns.nodes[id]
	if n == nil {
		return
	}

	if !n.UpdateTime.IsZero() {
		since := time.Since(n.UpdateTime)
		if since < MASTERNODE_PING_TIMEOUT {
			n.AccOnlineTime += time.Since(n.UpdateTime)
		} else {
			n.AccOnlineTime = time.Since(n.UpdateTime)
		}
	}

	n.UpdateTime = time.Now()
	n.LastPingTime = t
}



func (ns *MasternodeSet) SetState(id string, state int) bool {
	ns.lock.RLock()
	defer ns.lock.RUnlock()

	n := ns.nodes[id]
	if n == nil {
		return false
	}
	n.State = state
	return true
}

// Close disconnects all nodes.
// No new nodes can be registered after Close has returned.
func (ns *MasternodeSet) Close() {
	ns.lock.Lock()
	defer ns.lock.Unlock()

	//for _, p := range ns.nodes {
	//	p.Disconnect(p2p.DiscQuitting)
	//}
	ns.closed = true
}

func (ns *MasternodeSet) NodeJoin(id [8]byte) (*Masternode, error) {
	fmt.Println("")
	ctx, err := GetMasternodeContext(ns.contract, id)
	if err != nil {
		return &Masternode{}, err
	}
	err = ns.Register(ctx.Node)
	if err != nil {
		return &Masternode{}, err
	}
	return ctx.Node, nil
}

func (ns *MasternodeSet) NodeQuit(id [8]byte) {
	ns.Unregister(fmt.Sprintf("%x", id[:8]))
}

func (ns *MasternodeSet) Show() {
	for _, n := range ns.nodes {
		fmt.Println(n.String())
	}
}

func (ns *MasternodeSet) AllNodes() map[string]*Masternode {
	ns.lock.Lock()
	defer ns.lock.Unlock()
	return ns.nodes
}

func (ns *MasternodeSet) EnableNodes() map[string]*Masternode {
	ns.lock.Lock()
	defer ns.lock.Unlock()
	//enableNodes := make(map[string]*Masternode)
	//for id, n := range ns.nodes {
	//	if n.State == MasternodeEnable {
	//		enableNodes[id] = n
	//	}
	//}
	//return enableNodes
	return ns.nodes

}

func (ns *MasternodeSet) Len() int {

	if ns.nodes != nil {
		return len(ns.nodes)
	}
	return 0
}

func (ns *MasternodeSet) Check() {
	ns.lock.Lock()
	defer ns.lock.Unlock()
	for _, n := range ns.nodes {
		if !n.UpdateTime.IsZero() {
			since := time.Since(n.UpdateTime)
			if since > MASTERNODE_PING_TIMEOUT {
				n.State = MasternodeExpired
				n.AccOnlineTime = 0
			} else if n.State != MasternodeEnable && n.AccOnlineTime >= MASTERNODE_ONLINE_ENABLE {
				n.State = MasternodeEnable
			}
		}
	}
}

func GetMasternodeID(ID discover.NodeID) string {
	return fmt.Sprintf("%x", ID[:8])
}

type MasternodeContext struct {
	Node *Masternode
	pre  [8]byte
	next [8]byte
}

func GetMasternodeContext(contract *contract.Contract, id [8]byte) (*MasternodeContext, error) {
	data, err := contract.ContractCaller.GetInfo(nil, id)
	if err != nil {
	return &MasternodeContext{}, err
	}
	// version := int(data.Misc[0])
	var ip net.IP = data.Misc[1:17]
	port := binary.BigEndian.Uint16(data.Misc[17:19])
	nodeId, _ := discover.BytesID(append(data.Id1[:], data.Id2[:]...))
	node := newMasternode(nodeId, ip, port, data.Account, data.BlockNumber.Uint64())

	return &MasternodeContext{
	Node: node,
	pre:  data.PreId,
	next: data.NextId,
	}, nil
}
