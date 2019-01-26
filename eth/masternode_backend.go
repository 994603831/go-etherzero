// Copyright 2018 The go-etherzero Authors
// This file is part of the go-etherzero library.
//
// The go-etherzero library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-etherzero library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-etherzero library. If not, see <http://www.gnu.org/licenses/>.

package eth

import (
	"fmt"
	"math/big"
	"sync"
	"time"
	"errors"

	"github.com/etherzero/go-etherzero/common"
	"github.com/etherzero/go-etherzero/contracts/masternode/contract"
	"github.com/etherzero/go-etherzero/core"
	"github.com/etherzero/go-etherzero/core/types"
	"github.com/etherzero/go-etherzero/core/types/masternode"
	"github.com/etherzero/go-etherzero/event"
	"github.com/etherzero/go-etherzero/log"
	"github.com/etherzero/go-etherzero/p2p"
	"github.com/etherzero/go-etherzero/params"
	"github.com/etherzero/go-etherzero/p2p/discover"
	"crypto/ecdsa"
	"github.com/etherzero/go-etherzero/crypto"
	"github.com/etherzero/go-etherzero/common/math"
	"github.com/etherzero/go-etherzero/eth/downloader"
	"sync/atomic"
)


var (
	statsReportInterval  = 10 * time.Second // Time interval to report vote pool stats
	ErrUnknownMasternode = errors.New("unknown masternode")
)

type x8 [8]byte

type MasternodeAccount struct {
	id       string
	address  common.Address
	isActive bool
}

type MasternodeManager struct {
	mux *event.TypeMux

	mu sync.Mutex
	rw sync.RWMutex

	srvr         *p2p.Server
	contract     *contract.Contract
	blockchain   *core.BlockChain

	txPool *core.TxPool

	masternodeKeys     map[string]*ecdsa.PrivateKey
	masternodeAccounts map[x8]*MasternodeAccount

	syncing int32
}

func NewMasternodeManager(blockchain *core.BlockChain, contract *contract.Contract, txPool *core.TxPool) *MasternodeManager {

	// Create the masternode manager with its initial settings
	manager := &MasternodeManager{
		blockchain:         blockchain,
		contract:           contract,
		txPool:             txPool,
		masternodeKeys:     make(map[string]*ecdsa.PrivateKey, params.MasternodeKeyCount),
		masternodeAccounts: make(map[x8]*MasternodeAccount, params.MasternodeKeyCount),
		syncing: 0,
	}
	return manager
}

func (self *MasternodeManager) Start(srvr *p2p.Server, mux *event.TypeMux) {
	self.mux = mux
	log.Info("MasternodeManqager start ")
	for _, key := range srvr.Config.MasternodeKeys {
		addr := crypto.PubkeyToAddress(key.PublicKey)
		id8 := self.X8(key)
		id := fmt.Sprintf("%x", id8[:])
		self.masternodeKeys[id] = key
		active, err := self.contract.Has(nil, id8)
		if err != nil {
			log.Error("contract.Has", "id", id, "error", err)
		}
		account := &MasternodeAccount{
			id:       id,
			address:  addr,
			isActive: active,
		}
		self.masternodeAccounts[id8] = account
	}
	self.srvr = srvr
	go self.masternodeLoop()
	go self.checkSyncing()
}

func (self *MasternodeManager) checkSyncing() {
	events := self.mux.Subscribe(downloader.StartEvent{}, downloader.DoneEvent{}, downloader.FailedEvent{})
	for ev := range events.Chan() {
		switch ev.Data.(type) {
		case downloader.StartEvent:
			atomic.StoreInt32(&self.syncing, 1)
		case downloader.DoneEvent, downloader.FailedEvent:
			atomic.StoreInt32(&self.syncing, 0)
		}
	}
}

// SignHash calculates a ECDSA signature for the given hash. The produced
// signature is in the [R || S || V] format where V is 0 or 1.
func (self *MasternodeManager) SignHash(id string, hash []byte) ([]byte, error) {
	// Look up the key to sign with and abort if it cannot be found
	self.rw.RLock()
	defer self.rw.RUnlock()

	if key, ok := self.masternodeKeys[id]; ok {
		// Sign the hash using plain ECDSA operations
		return crypto.Sign(hash, key)
	}

	return nil, ErrUnknownMasternode
}

func (self *MasternodeManager) GetWitnesses() (ids []string) {
	for id, _ := range self.masternodeKeys {
		ids = append(ids, id)
	}
	return ids
}

// X8 returns 8 bytes of ecdsa.PublicKey.X
func (self *MasternodeManager) X8(key *ecdsa.PrivateKey) (id x8) {
	buf := make([]byte, 32)
	math.ReadBits(key.PublicKey.X, buf)
	copy(id[:], buf[:8])
	return id
}

func (self *MasternodeManager) XY(key *ecdsa.PrivateKey) (xy [64]byte) {
	pubkey := key.PublicKey
	math.ReadBits(pubkey.X, xy[:32])
	math.ReadBits(pubkey.Y, xy[32:])
	return xy
}

func (self *MasternodeManager) Stop() {

}

func (mm *MasternodeManager) masternodeLoop() {
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
	defer ping.Stop()
	ntp := time.NewTimer(time.Second)
	defer ntp.Stop()
	minPower := big.NewInt(20e+14)

	report := time.NewTicker(statsReportInterval)
	defer report.Stop()

	for {
		select {
		case join := <-joinCh:
			if account, ok := mm.masternodeAccounts[join.Id]; ok {
				fmt.Printf("### [%x] Become masternode! \n", join.Id)
				account.isActive = true
			}
		case quit := <-quitCh:
			if account, ok := mm.masternodeAccounts[quit.Id]; ok {
				fmt.Printf("### [%x] Remove masternode! \n", quit.Id)
				account.isActive = false
			}
		case err := <-joinSub.Err():
			joinSub.Unsubscribe()
			fmt.Println("eventJoin err", err.Error())
		case err := <-quitSub.Err():
			quitSub.Unsubscribe()
			fmt.Println("eventQuit err", err.Error())
		case <-ntp.C:
			ntp.Reset(10 * time.Minute)
			go discover.CheckClockDrift()
		case <-ping.C:
			logTime := time.Now().Format("2006-01-02 15:04:05")
			ping.Reset(masternode.MASTERNODE_PING_INTERVAL)
			if atomic.LoadInt32(&mm.syncing) == 1 {
				fmt.Println(logTime, " syncing...")
				break
			}
			stateDB, _ := mm.blockchain.State()
			for _, account := range mm.masternodeAccounts {
				address := account.address
				if stateDB.GetBalance(address).Cmp(big.NewInt(1e+16)) < 0 {
					fmt.Println(logTime, "Expect to deposit 0.01 etz to ", address.String())
					continue
				}
				if stateDB.GetPower(address, mm.blockchain.CurrentBlock().Number()).Cmp(minPower) < 0 {
					fmt.Println(logTime, "Insufficient power for ping transaction.", address.Hex(), mm.blockchain.CurrentBlock().Number().String(), stateDB.GetPower(address, mm.blockchain.CurrentBlock().Number()).String())
					continue
				}
				tx := types.NewTransaction(
					mm.txPool.State().GetNonce(address),
					params.MasterndeContractAddress,
					big.NewInt(0),
					90000,
					big.NewInt(20e+9),
					nil,
				)
				signed, err := types.SignTx(tx, types.NewEIP155Signer(mm.blockchain.Config().ChainID), mm.masternodeKeys[account.id])
				if err != nil {
					fmt.Println(logTime, "SignTx error:", err)
					continue
				}
				if err := mm.txPool.AddLocal(signed); err != nil {
					fmt.Println(logTime, "send ping to txpool error:", err)
					continue
				}
				fmt.Println(logTime, "Send ping message!", address.String())

			}
			fmt.Println(logTime, "Send ping message!")
		}
	}
}

func (self *MasternodeManager) MasternodeList(number *big.Int) ([]string, error) {
	return masternode.GetIdsByBlockNumber(self.contract, number)
}

func (self *MasternodeManager) GetGovernanceContractAddress(number *big.Int) (common.Address, error) {
	return masternode.GetGovernanceAddress(self.contract, number)
}
