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

package eth

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/ethzero/go-ethzero/common"
	"github.com/ethzero/go-ethzero/consensus"
	"github.com/ethzero/go-ethzero/contracts/masternode/contract"
	"github.com/ethzero/go-ethzero/core"
	"github.com/ethzero/go-ethzero/core/types"
	"github.com/ethzero/go-ethzero/core/types/masternode"
	"github.com/ethzero/go-ethzero/crypto"
	"github.com/ethzero/go-ethzero/crypto/secp256k1"
	"github.com/ethzero/go-ethzero/eth/downloader"
	"github.com/ethzero/go-ethzero/eth/fetcher"
	"github.com/ethzero/go-ethzero/ethdb"
	"github.com/ethzero/go-ethzero/event"
	"github.com/ethzero/go-ethzero/log"
	"github.com/ethzero/go-ethzero/p2p"
	"github.com/ethzero/go-ethzero/params"
)

const (
	SignaturesTotal = 10
)

// Backend wraps all methods required for mining.
type Backend interface {
	TxPool() *core.TxPool
	BlockChain() *core.BlockChain
}

type MasternodeManager struct {
	networkId uint64

	fastSync  uint32 // Flag whether fast sync is enabled (gets disabled if we already have blocks)
	acceptTxs uint32 // Flag whether we're considered synchronised (enables transaction processing)

	eth      Backend
	blockchain  *core.BlockChain
	chainconfig *params.ChainConfig
	maxPeers    int

	fetcher *fetcher.Fetcher
	peers   *peerSet

	masternodes *masternode.MasternodeSet
	enableds    map[string]*masternode.Masternode //id -> masternode
	is          *InstantSend
	winner      *MasternodePayments
	active      *masternode.ActiveMasternode
	scope       event.SubscriptionScope
	voteFeed    event.Feed
	winnerFeed  event.Feed

	SubProtocols []p2p.Protocol

	eventMux      *event.TypeMux
	txCh          chan core.TxPreEvent
	txSub         event.Subscription
	minedBlockSub *event.TypeMuxSubscription

	minBlocksToStore *big.Int
	storageCoeff     *big.Int //masternode count times nStorageCoeff payments blocks should be stored ...

	// channels for fetcher, syncer, txsyncLoop
	newPeerCh   chan *peer
	txsyncCh    chan *txsync
	quitSync    chan struct{}
	noMorePeers chan struct{}

	// wait group is used for graceful shutdowns during downloading
	// and processing
	wg sync.WaitGroup
	mu sync.Mutex

	log log.Logger

	contract *contract.Contract
	srvr     *p2p.Server
}

// NewProtocolManager returns a new Masternode sub protocol manager. The Masternode sub protocol manages peers capable
// with the ETZ-Masternode network.
func NewMasternodeManager(config *params.ChainConfig, mode downloader.SyncMode, networkId uint64, mux *event.TypeMux, eth Backend, engine consensus.Engine, blockchain *core.BlockChain, chaindb ethdb.Database) (*MasternodeManager, error) {
	// Create the protocol manager with the base fields
	manager := &MasternodeManager{
		networkId:   networkId,
		eventMux:    mux,
		eth:      eth,
		txCh:           make(chan core.TxPreEvent, txChanSize),
		blockchain:  blockchain,
		chainconfig: config,
		newPeerCh:   make(chan *peer),
		noMorePeers: make(chan struct{}),
		txsyncCh:    make(chan *txsync),
		quitSync:    make(chan struct{}),
		masternodes: &masternode.MasternodeSet{},
		is:NewInstantx(config,eth),
	}

	ranksFn := func(height *big.Int) map[int64]*masternode.Masternode {
		return manager.GetMasternodeRanks(height)
	}
	manager.txSub=eth.TxPool().SubscribeTxPreEvent(manager.txCh)
	manager.winner = NewMasternodePayments( blockchain.CurrentBlock().Number(), ranksFn)
	return manager, nil
}

func (mm *MasternodeManager) removePeer(id string) {
	mm.masternodes.SetState(id, masternode.MasternodeDisconnected)
}

func (mm *MasternodeManager) Start(srvr *p2p.Server, contract *contract.Contract, peers *peerSet) {
	mm.contract = contract
	mm.srvr = srvr
	mm.peers = peers
	log.Trace("MasternodeManqager start ")
	mns, err := masternode.NewMasternodeSet(contract)
	if err != nil {
		log.Error("masternode.NewMasternodeSet", "error", err)
	}
	mm.masternodes = mns
	mm.active = masternode.NewActiveMasternode(srvr, mns)
	mm.is.Active = mm.active
	mm.winner.active = mm.active

	go mm.is.Start()
	go mm.masternodeLoop()
}

func (mm *MasternodeManager) Stop() {
	mm.is.Stop()
	mm.is.CheckAndRemove()
	mm.winner.CheckAndRemove(big.NewInt(0))
}

// SubscribeTxPreEvent registers a subscription of VoteEvent and
// starts sending event to the given channel.
func (self *MasternodeManager) SubscribeVoteEvent(ch chan<- core.VoteEvent) event.Subscription {
	return self.is.SubscribeVoteEvent(ch)
}

// SubscribeWinnerVoteEvent registers a subscription of PaymentVoteEvent and
// starts sending event to the given channel.
func (self *MasternodeManager) SubscribeWinnerVoteEvent(ch chan<- core.PaymentVoteEvent) event.Subscription {
	return self.winner.SubscribeWinnerVoteEvent(ch)
}

func (mm *MasternodeManager) newPeer(p *peer) {
	p.SetMasternode(true)
	mm.masternodes.SetState(p.id, masternode.MasternodeEnable)
}

// Deterministically select the oldest/best masternode to pay on the network
// Pass in the hash value of the block that participates in the calculation.
// Dash is the Hash passed to the first 100 blocks.
// If use the current block Hash, there is a risk that the current block will be discarded.
func (mm *MasternodeManager) BestMasternode(block *types.Block) (common.Address, error) {

	if account, ok := mm.winner.BlockWinner(block.Number()); ok {
		return account, nil
	}
	// masternodes is nil
	if mm.masternodes == nil {
		return common.Address{}, errors.New("no masternode detected")
	}

	var (
		enableMasternodeNodes = mm.masternodes.EnableNodes()
		paids                 []int
		tenthNetWork          = len(enableMasternodeNodes) / 10 // TODO: when len < 10
		countTenth            = 0
		highest               int64
		best                  common.Address
	)

	sortMap := make(map[int]*masternode.Masternode)
	if enableMasternodeNodes == nil {
		return common.Address{}, errors.New("no masternode detected")
	}
	log.Trace(" The number of local cached masternode ", "EnablesMasternodes", len(enableMasternodeNodes))
	if len(enableMasternodeNodes) < 1 {
		return common.Address{}, fmt.Errorf("The number of local masternodes is too less to obtain the best Masternode")
	}

	for _, node := range enableMasternodeNodes {
		i := int(node.Height.Int64())
		paids = append(paids, i)
		sortMap[i] = node
	}
	// Sort them low to high
	sort.Sort(sort.IntSlice(paids))

	for _, i := range paids {
		//fmt.Printf("CalculateScore result index: %d \t  Score :%d \n", i, sortMap[i].CalculateScore(block))
		score := sortMap[i].CalculateScore(block.Hash())
		if score > highest {
			highest = score
			best = sortMap[i].Account
		}
		countTenth++
		if countTenth >= tenthNetWork {
			break
		}
	}
	return best, nil
}

func (mm *MasternodeManager) ProcessPaymentVotes(votes []*masternode.MasternodePaymentVote) bool {

	for i, vote := range votes {
		if ok, err := mm.IsValidPaymentVote(vote, mm.blockchain.CurrentBlock().Number()); !ok {
			log.Error("CheckPaymentVote valid error:", err)
			return false
		}
		if !mm.winner.Vote(vote, mm.StorageLimit()) {
			log.Info("Payment Winner vote :: Block Payment winner vote failed ", "vote hash:", vote.Hash().String(), "i:%s", i)
			return false
		}
	}
	return true
}

func (mm *MasternodeManager) GetMasternodeRank(id string) int {

	var rank int = 0
	mm.syncer()
	block := mm.blockchain.CurrentBlock()
	if block == nil {
		log.Error("ERROR: GetBlockHash() failed at BlockHeight:%d ", block.Number())
		return rank
	}
	masternodeScores := mm.GetMasternodeScores(block.Hash(), 1)

	tRank := 0
	for _, masternode := range masternodeScores {
		//info := MasternodeInfo()
		tRank++
		if id == masternode.ID {
			rank = tRank
			break
		}
	}
	return rank
}

func (self *MasternodeManager) GetMasternodeRanks(height *big.Int) map[int64]*masternode.Masternode {

	block := self.blockchain.GetBlockByNumber(height.Uint64())
	hash := block.Hash()
	self.mu.Lock()
	defer self.mu.Unlock()

	scores := self.GetMasternodeScores(hash, 0)
	var rank int64 = 0
	ranks := make(map[int64]*masternode.Masternode)

	for _, node := range scores {
		rank++
		ranks[rank] = node
	}
	return scores
}

func (mm *MasternodeManager) GetMasternodeScores(blockHash common.Hash, minProtocol int) map[int64]*masternode.Masternode {

	masternodeScores := make(map[int64]*masternode.Masternode)
	for _, m := range mm.masternodes.EnableNodes() {
		masternodeScores[m.CalculateScore(blockHash)] = m
	}
	return masternodeScores
}

func (mm *MasternodeManager) StorageLimit() *big.Int {

	if mm.masternodes != nil {
		count := mm.masternodes.Len()
		size := big.NewInt(1).Mul(mm.storageCoeff, big.NewInt(int64(count)))

		if size.Cmp(mm.minBlocksToStore) > 0 {
			return size
		}
	}
	return mm.minBlocksToStore
}

func (mm *MasternodeManager) ProcessTxLockVotes(votes []*masternode.TxLockVote) bool {

	rank := mm.GetMasternodeRank(mm.active.ID)
	if rank != 0 {
		log.Info("InstantSend::Vote -- Can't calculate rank for masternode ", mm.active.ID, " rank: ", rank)
		return false
	} else if rank > SignaturesTotal {
		log.Info("InstantSend::Vote -- Masternode not in the top ", SignaturesTotal, " (", rank, ")")
		return false
	}
	log.Info("InstantSend::Vote -- In the top ", SignaturesTotal, " (", rank, ")")

	for i := range votes {
		if ok, err := mm.IsValidTxVote(votes[i]); !ok {
			log.Error("processTxLockVotes vote veified failed ,vote Hash:", votes[i].Hash().String(), "error:", err.Error())
			continue
		}
		if !mm.is.ProcessTxLockVote(votes[i]) {
			log.Info("processTxLockVotes vote failed vote Hash:", votes[i].Hash().String())
			continue
		} else {
			//Vote valid, let us forward it
			mm.winner.winnerFeed.Send(core.VoteEvent{votes[i]})
		}
	}

	return mm.is.ProcessTxLockVotes(votes)
}

//TODO:Need to improve the judgment of vote validity in MasternodePayments and increase the validity of the voting masternode
//height is CachedHeight
func (self *MasternodeManager) IsValidPaymentVote(vote *masternode.MasternodePaymentVote, height *big.Int) (bool, error) {

	var masternodeId = vote.MasternodeId

	masternode := self.masternodes.Node(masternodeId)
	if masternode.ProtocolVersion < etz64 {
		err := fmt.Errorf("Masternode protocol is too old: ProtocolVersion=%d, MinRequiredProtocol=%d", masternode.ProtocolVersion, etz64)
		return false, err
	}

	// Only masternodes should try to check masternode rank for old votes - they need to pick the right winner for future blocks.
	// Regular clients (miners included) need to verify masternode rank for future block votes only.
	if self.active.State() != 4 && vote.Number.Cmp(height) <= 0 {
		return true, nil
	}
	rank := self.GetMasternodeRank(masternodeId)
	if rank < 1 {
		err := fmt.Errorf("MasternodeManager::IsValidPaymentVote -- Can't calculate rank for masternode,MasternodeId: %s", masternodeId)
		return false, err
	}
	if rank > MNPaymentsSignaturesTotal {
		// It's common to have masternodes mistakenly think they are in the top 10
		// We don't want to print all of these messages in normal mode, debug mode should print though
		fmt.Printf("Masternode is not in the top %d (%d)", MNPaymentsSignaturesTotal, rank)
		// Only ban for new mnw which is out of bounds, for old mnw MN list itself might be way too much off
		if rank > MNPaymentsSignaturesTotal*2 && vote.Number.Cmp(height) > 0 {
			fmt.Printf("Masternode is not in the top %d (%d)", MNPaymentsSignaturesTotal, rank)
		}
		// Still invalid however
		return false, fmt.Errorf("MasternodeManager::IsValid --Error: Masternode is not in the top %d (%d)", MNPaymentsSignaturesTotal, rank)
	}

	if !self.CheckPaymentVoteSignature(vote) {
		return false, fmt.Errorf("MasternodeManager  CheckPaymentVote signature Failed ")
	}
	return true, nil
}

func (self *MasternodeManager) IsValidTxVote(vote *masternode.TxLockVote) (bool, error) {

	masternodeId := vote.MasternodeId()
	if self.masternodes.Node(masternodeId) == nil {
		return false, fmt.Errorf("MasternodeManager IsValidTxVote --Unknow masternode %s \n", masternodeId)
	}
	rank := self.GetMasternodeRank(masternodeId)
	// can be caused by past versions trying to vote with an invalid protocol
	if rank < 1 {
		return false, fmt.Errorf("MasternodeManager IsValidTxVote -- Can't calculate rank for masternode %s \n", masternodeId)
	}
	log.Info("MasternodeManager IsValidTxVote -- masternode ", masternodeId, " Rank:", rank)

	if rank > SignaturesTotal {
		return false, fmt.Errorf("MasternodeManager IsValidTxVote -- Masternode %s is not in the top %d(%d) ,vote hash=%s", masternodeId, SignaturesTotal, rank, vote.Hash())
	}

	if self.CheckTxVoteSignature(vote) {
		log.Info("MasternodeManager CheckTxVoteSignature Failed")
		return false, fmt.Errorf("MasternodeManager IsValidTxVote -- CheckSignature Failed")
	}

	return true, nil
}

// ProcessTxVote process the vote procedure
func (self *MasternodeManager) CheckTxVoteSignature(vote *masternode.TxLockVote) bool {
	masternode := self.masternodes.Node(vote.MasternodeId())

	if masternode == nil {
		log.Info("check tx vote signature Failed ,masternode not found ", "masternodeId:", vote.MasternodeId())
		return false
	}
	pubkey, err := masternode.Node.ID.Pubkey()
	if err != nil {
		log.Info("check tx vote signature Failed , pubkey not fund")
		return false
	}
	return vote.Verify(pubkey)
}

func (self *MasternodeManager) CheckPaymentVoteSignature(vote *masternode.MasternodePaymentVote) bool {

	masternode := self.masternodes.Node(vote.MasternodeId)
	if masternode == nil {
		log.Info("check payment vote signature fial,masternode not found ", "masternodeId:", vote.MasternodeId)
		return false
	}
	pubkey, err := masternode.Node.ID.Pubkey()
	if err != nil {
		log.Info("check Payment vote signature Failed,pubkey not found")
		return false
	}
	return vote.Verify(vote.Hash().Bytes(), vote.Sig, pubkey)
}

// If server is masternode, connect one masternode at least
func (mm *MasternodeManager) checkPeers() {
	if mm.active.State() != masternode.ACTIVE_MASTERNODE_STARTED {
		return
	}
	for _, p := range mm.peers.peers {
		if p.isMasternode {
			return
		}
	}

	nodes := make(map[int]*masternode.Masternode)
	var i int = 0
	for _, p := range mm.masternodes.EnableNodes() {
		if p.State == masternode.MasternodeEnable && p.ID != mm.active.ID {
			nodes[i] = p
			i++
		}
	}
	if i <= 0 {
		return
	}
	key := rand.Intn(i - 1)
	mm.srvr.AddPeer(nodes[key].Node)
}

func (mm *MasternodeManager) updateActiveMasternode() {
	var state int

	n := mm.masternodes.Node(mm.active.ID)
	if n == nil {
		state = masternode.ACTIVE_MASTERNODE_NOT_CAPABLE
	} else if int(n.Node.TCP) != mm.active.Addr.Port {
		log.Error("updateActiveMasternode", "Port", n.Node.TCP, "active.Port", mm.active.Addr.Port)
		state = masternode.ACTIVE_MASTERNODE_NOT_CAPABLE
	} else if !n.Node.IP.Equal(mm.active.Addr.IP) {
		log.Error("updateActiveMasternode", "IP", n.Node.IP, "active.IP", mm.active.Addr.IP)
		state = masternode.ACTIVE_MASTERNODE_NOT_CAPABLE
	} else {
		state = masternode.ACTIVE_MASTERNODE_STARTED
	}

	mm.active.SetState(state)
}

func (mm *MasternodeManager) masternodeLoop() {
	mm.updateActiveMasternode()
	if mm.active.State() == masternode.ACTIVE_MASTERNODE_STARTED {
		fmt.Println("masternodeCheck true")
		mm.checkPeers()
	} else if !mm.srvr.MasternodeAddr.IP.Equal(net.IP{}) {

		var misc [32]byte
		misc[0] = 1
		copy(misc[1:17], mm.srvr.Config.MasternodeAddr.IP)
		binary.BigEndian.PutUint16(misc[17:19], uint16(mm.srvr.Config.MasternodeAddr.Port))

		var buf bytes.Buffer
		buf.Write(mm.srvr.Self().ID[:])
		buf.Write(misc[:])
		d := "0x4da274fd" + common.Bytes2Hex(buf.Bytes())
		fmt.Println("Masternode transaction data:", d)
	}

	mm.masternodes.Show()

	joinCh := make(chan *contract.ContractJoin, 32)
	quitCh := make(chan *contract.ContractQuit, 32)
	joinSub, err1 := mm.contract.WatchJoin(nil, joinCh)
	if err1 != nil {
		// TODO: exit
		return
	}
	quitSub, err2 := mm.contract.WatchQuit(nil, quitCh)
	if err2 != nil {
		// TODO: exit
		return
	}

	ping := time.NewTimer(masternode.MASTERNODE_PING_INTERVAL)
	check := time.NewTimer(masternode.MASTERNODE_CHECK_INTERVAL)

	for {
		select {
		case join := <-joinCh:
			fmt.Println("join", common.Bytes2Hex(join.Id[:]))
			node, err := mm.masternodes.NodeJoin(join.Id)
			if err == nil {
				if bytes.Equal(join.Id[:], mm.srvr.Self().ID[0:8]) {
					mm.updateActiveMasternode()
					mm.active.Account = node.Account
				} else {
					mm.srvr.AddPeer(node.Node)
				}
				mm.masternodes.Show()
			}

		case quit := <-quitCh:
			fmt.Println("quit", common.Bytes2Hex(quit.Id[:]))
			mm.masternodes.NodeQuit(quit.Id)
			if bytes.Equal(quit.Id[:], mm.srvr.Self().ID[0:8]) {
				mm.updateActiveMasternode()
			}
			mm.masternodes.Show()

		case err := <-joinSub.Err():
			joinSub.Unsubscribe()
			fmt.Println("eventJoin err", err.Error())
		case err := <-quitSub.Err():
			quitSub.Unsubscribe()
			fmt.Println("eventQuit err", err.Error())

		case <-ping.C:
			if mm.active.State() != masternode.ACTIVE_MASTERNODE_STARTED {
				continue
			}
			msg, err := mm.active.NewPingMsg()
			if err != nil {
				log.Error("NewPingMsg", "error", err)
				continue
			}
			peers := mm.peers.peers
			for _, peer := range peers {
				log.Debug("sending ping msg", "peer", peer.id)
				if err := peer.SendMasternodePing(msg); err != nil {
					log.Error("SendMasternodePing", "error", err)
				}
			}
			ping.Reset(masternode.MASTERNODE_PING_INTERVAL)

		case <-check.C:
			mm.masternodes.Check()
			check.Reset(masternode.MASTERNODE_CHECK_INTERVAL)
		}
	}
}

func (mm *MasternodeManager) DealPingMsg(pm *masternode.PingMsg) error {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], pm.Time)
	key, err := secp256k1.RecoverPubkey(crypto.Keccak256(b[:]), pm.Sig)
	if err != nil || len(key) != 65 {
		return err
	}
	id := fmt.Sprintf("%x", key[1:9])
	node := mm.masternodes.Node(id)
	if node == nil {
		return fmt.Errorf("error id %s", id)
	}
	if node.LastPingTime > pm.Time {
		return fmt.Errorf("error ping time: %d > %d", node.LastPingTime, pm.Time)
	}
	mm.masternodes.RecvPingMsg(id, pm.Time)
	return nil
}

