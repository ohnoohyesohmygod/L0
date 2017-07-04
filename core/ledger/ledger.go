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

package ledger

import (
	"fmt"
	"math/big"

	"bytes"

	"time"

	"github.com/bocheninc/L0/components/crypto"
	"github.com/bocheninc/L0/components/db"
	"github.com/bocheninc/L0/components/log"
	"github.com/bocheninc/L0/components/utils"
	"github.com/bocheninc/L0/core/accounts"
	"github.com/bocheninc/L0/core/coordinate"
	"github.com/bocheninc/L0/core/ledger/block_storage"
	"github.com/bocheninc/L0/core/ledger/contract"
	"github.com/bocheninc/L0/core/ledger/merge"
	"github.com/bocheninc/L0/core/ledger/state"
	"github.com/bocheninc/L0/core/ledger/state/state_hash"
	"github.com/bocheninc/L0/core/params"
	"github.com/bocheninc/L0/core/types"
	"github.com/bocheninc/L0/vm"
)

var (
	ledgerInstance *Ledger
)

// Ledger represents the ledger in blockchain
type Ledger struct {
	block    *block_storage.Blockchain
	state    *state.State
	storage  *merge.Storage
	contract *contract.SmartConstract
}

// NewLedger returns the ledger instance
func NewLedger(db *db.BlockchainDB) *Ledger {
	if ledgerInstance == nil {
		ledgerInstance = &Ledger{
			block:   block_storage.NewBlockchain(db),
			state:   state.NewState(db),
			storage: merge.NewStorage(db),
		}
		_, err := ledgerInstance.Height()
		if err != nil {
			ledgerInstance.init()
		}
	}

	ledgerInstance.contract = contract.NewSmartConstract(db, ledgerInstance)
	return ledgerInstance
}

// VerifyChain verifys the blockchain data
func (ledger *Ledger) VerifyChain() {
	height, err := ledger.Height()
	if err != nil {
		panic(err)
	}
	currentBlockHeader, err := ledger.block.GetBlockByNumber(height)
	for i := height; i >= 1; i-- {
		previousBlockHeader, err := ledger.block.GetBlockByNumber(i - 1) // storage
		if previousBlockHeader != nil && err != nil {

			log.Debug("get block err")
			panic(err)
		}
		// verify previous block
		if !previousBlockHeader.Hash().Equal(currentBlockHeader.PreviousHash) {
			panic(fmt.Errorf("block [%d], veifychain breaks", i))
		}
		currentBlockHeader = previousBlockHeader
	}
}

// GetGenesisBlock returns the genesis block of the ledger
func (ledger *Ledger) GetGenesisBlock() *types.BlockHeader {

	genesisBlockHeader, err := ledger.GetBlockByNumber(0)
	if err != nil {
		panic(err)
	}
	return genesisBlockHeader
}

// AppendBlock appends a new block to the ledger,flag = true pack up block ,flag = false sync block
func (ledger *Ledger) AppendBlock(block *types.Block, flag bool) error {
	var (
		err           error
		txWriteBatchs []*db.WriteBatch
	)

	txWriteBatchs, block.Transactions, err = ledger.executeTransaction(block.Transactions)
	if err != nil {
		return err
	}

	block.Header.TxsMerkleHash = merkleRootHash(block.Transactions)
	t := time.Now()
	block.Header.StateHash = state_hash.UpdateHash(txWriteBatchs)
	delay := time.Since(t)

	writeBatchs := ledger.block.AppendBlock(block)

	writeBatchs = append(writeBatchs, txWriteBatchs...)

	if err := ledger.state.AtomicWrite(writeBatchs); err != nil {
		return nil
	}

	if flag {
		var txs types.Transactions
		for _, tx := range block.Transactions {
			if (tx.GetType() == types.TypeMerged && !ledger.checkCoordinate(tx)) || tx.GetType() == types.TypeAcrossChain {
				txs = append(txs, tx)
			}
		}
		if err := ledger.storage.ClassifiedTransaction(txs); err != nil {
			return err
		}
		log.Infoln("blockHeight: ", block.Height(), "need merge Txs len : ", len(txs), "all Txs len: ", len(block.Transactions), " state delay ", delay)
	}

	return nil
}

// GetBlockByNumber gets the block by the given number
func (ledger *Ledger) GetBlockByNumber(number uint32) (*types.BlockHeader, error) {
	return ledger.block.GetBlockByNumber(number)
}

// GetBlockByHash returns the block detail by hash
func (ledger *Ledger) GetBlockByHash(blockHashBytes []byte) (*types.BlockHeader, error) {
	return ledger.block.GetBlockByHash(blockHashBytes)
}

//GetTransactionHashList returns transactions hash list by block number
func (ledger *Ledger) GetTransactionHashList(number uint32) ([]crypto.Hash, error) {

	txHashsBytes, err := ledger.block.GetTransactionHashList(number)
	if err != nil {
		return nil, err
	}

	txHashs := []crypto.Hash{}

	utils.Deserialize(txHashsBytes, &txHashs)

	return txHashs, nil
}

// Height returns height of ledger
func (ledger *Ledger) Height() (uint32, error) {
	return ledger.block.GetBlockchainHeight()
}

//GetLastBlockHash returns last block hash
func (ledger *Ledger) GetLastBlockHash() (crypto.Hash, error) {
	height, err := ledger.block.GetBlockchainHeight()
	if err != nil {
		return crypto.Hash{}, err
	}
	lastBlock, err := ledger.block.GetBlockByNumber(height)
	if err != nil {
		return crypto.Hash{}, err
	}
	return lastBlock.Hash(), nil
}

//GetBlockHashByNumber returns block hash by block number
func (ledger *Ledger) GetBlockHashByNumber(blockNum uint32) (crypto.Hash, error) {

	hashBytes, err := ledger.block.GetBlockHashByNumber(blockNum)
	if err != nil {
		return crypto.Hash{}, err
	}

	blockHash := new(crypto.Hash)

	blockHash.SetBytes(hashBytes)

	return *blockHash, err
}

// GetTxsByBlockHash returns transactions  by block hash and transactionType
func (ledger *Ledger) GetTxsByBlockHash(blockHashBytes []byte, transactionType uint32) (types.Transactions, error) {
	return ledger.block.GetTransactionsByHash(blockHashBytes, transactionType)
}

//GetTxsByBlockNumber returns transactions by blcokNumber and transactionType
func (ledger *Ledger) GetTxsByBlockNumber(blockNumber uint32, transactionType uint32) (types.Transactions, error) {
	return ledger.block.GetTransactionsByNumber(blockNumber, transactionType)
}

//GetTxByTxHash returns transaction by tx hash []byte
func (ledger *Ledger) GetTxByTxHash(txHashBytes []byte) (*types.Transaction, error) {
	return ledger.block.GetTransactionByTxHash(txHashBytes)
}

// GetBalance returns balance by account
func (ledger *Ledger) GetBalance(addr accounts.Address) (*big.Int, uint32, error) {
	return ledger.state.GetBalance(addr)
}

//GetMergedTransaction returns merged transaction within a specified period of time
func (ledger *Ledger) GetMergedTransaction(duration uint32) (types.Transactions, error) {

	txs, err := ledger.storage.GetMergedTransaction(duration)
	if err != nil {
		return nil, err
	}
	return txs, nil
}

//PutTxsHashByMergeTxHash put transactions hashs by merge transaction hash
func (ledger *Ledger) PutTxsHashByMergeTxHash(mergeTxHash crypto.Hash, txsHashs []crypto.Hash) error {
	return ledger.storage.PutTxsHashByMergeTxHash(mergeTxHash, txsHashs)
}

//GetTxsByMergeTxHash gets transactions
func (ledger *Ledger) GetTxsByMergeTxHash(mergeTxHash crypto.Hash) (types.Transactions, error) {
	txsHashs, err := ledger.storage.GetTxsByMergeTxHash(mergeTxHash)
	if err != nil {
		return nil, err
	}

	txs := types.Transactions{}
	for _, v := range txsHashs {
		tx, err := ledger.GetTxByTxHash(v.Bytes())
		if err != nil {
			return nil, err
		}
		txs = append(txs, tx)
	}
	return txs, nil
}

//QueryContract processes new contract query transaction
func (ledger *Ledger) QueryContract(tx *types.Transaction) ([]byte, error) {
	contractSpec := new(types.ContractSpec)
	utils.Deserialize(tx.Payload, contractSpec)
	ledger.contract.ExecTransaction(tx, string(contractSpec.ContractAddr))
	ctx := vm.NewCTX(tx, contractSpec, ledger.contract)
	result, err := vm.RealExecute(ctx)
	if err != nil {
		log.Error("contract query execute failed  ", err)
		return nil, fmt.Errorf("contract query execute failed : %v ", err)
	}
	return result, nil
}

// init generates the genesis block
func (ledger *Ledger) init() error {
	blockHeader := new(types.BlockHeader)
	blockHeader.Nonce = uint32(100)
	blockHeader.Height = 0
	blockHeader.TimeStamp = uint32(0)

	genesisBlock := new(types.Block)
	genesisBlock.Header = blockHeader
	writeBatchs := ledger.block.AppendBlock(genesisBlock)

	return ledger.state.AtomicWrite(writeBatchs)
}

func (ledger *Ledger) executeTransaction(Txs types.Transactions) ([]*db.WriteBatch, types.Transactions, error) {
	var (
		err                                               error
		tmpAtomicWriteBatchs, tmpWriteBatchs, writeBatchs []*db.WriteBatch
		effectiveTxs                                      types.Transactions
	)

	bh, _ := ledger.Height()
	log.Debugln("tx-len start ", len(Txs), "bh ", bh)
	ledger.contract.StartConstract(bh)

	for _, tx := range Txs {
		switch tx.GetType() {
		case types.TypeIssue:
			if writeBatchs, err = ledger.executeIssueTx(writeBatchs, tx); err != nil {
				return nil, nil, err
			}
		case types.TypeAtomic:
			if writeBatchs, err = ledger.executeAtomicTx(writeBatchs, tx); err != nil {
				return nil, nil, err
			}
		case types.TypeAcrossChain:
			if writeBatchs, err = ledger.executeACrossChainTx(writeBatchs, tx); err != nil {
				return nil, nil, err
			}
		case types.TypeMerged:
			if writeBatchs, err = ledger.executeMergedTx(writeBatchs, tx); err != nil {
				return nil, nil, err
			}
		case types.TypeBackfront:
			if writeBatchs, err = ledger.executeBackfrontTx(writeBatchs, tx); err != nil {
				return nil, nil, err
			}
		case types.TypeDistribut:
			if writeBatchs, err = ledger.executeDistriTx(writeBatchs, tx); err != nil {
				return nil, nil, err
			}
		case types.TypeContractInit:
			fallthrough
		case types.TypeContractInvoke:
			tmpAtomicWriteBatchs, err = ledger.executeAtomicTx(tmpWriteBatchs, tx)
			if err != nil {
				return nil, nil, err
			}

			txs, err := ledger.executeSmartContractTx(tx)
			if err != nil {
				log.Errorf("execute Contract Tx hash: %s ,err: %v", tx.Hash(), err)
				continue
			}

			writeBatchs = append(writeBatchs, tmpAtomicWriteBatchs...)

			if len(txs) != 0 {
				contractTxWriteBatchs, contractTxs, err := ledger.executeTransaction(txs)
				if err != nil {
					return nil, nil, err
				}

				writeBatchs = append(writeBatchs, contractTxWriteBatchs...)
				Txs = append(Txs, contractTxs...)
			}
		}

		effectiveTxs = append(effectiveTxs, tx)
	}

	writeBatchs, err = ledger.contract.AddChangesForPersistence(writeBatchs)
	if err != nil {
		return nil, nil, err
	}

	ledger.contract.StopContract(bh)
	log.Debugln("tx-len stop", len(Txs), "bh ", bh)
	return writeBatchs, effectiveTxs, nil
}

func (ledger *Ledger) executeIssueTx(writeBatchs []*db.WriteBatch, tx *types.Transaction) ([]*db.WriteBatch, error) {
	sender := tx.Sender()
	atomicTxWriteBatchs, err := ledger.state.Transfer(sender, tx.Recipient(), tx.Fee(), state.NewBalance(tx.Amount(), tx.Nonce()), types.TypeIssue)
	if err != nil {
		return writeBatchs, err
	}
	writeBatchs = append(writeBatchs, atomicTxWriteBatchs...)

	return writeBatchs, nil
}

func (ledger *Ledger) executeAtomicTx(writeBatchs []*db.WriteBatch, tx *types.Transaction) ([]*db.WriteBatch, error) {
	sender := tx.Sender()
	atomicTxWriteBatchs, err := ledger.state.Transfer(sender, tx.Recipient(), tx.Fee(), state.NewBalance(tx.Amount(), tx.Nonce()), types.TypeAtomic)
	if err != nil {
		if err == state.ErrNegativeBalance {
			log.Errorf("execute atomic transaction: %s, err:%s\n", tx.Hash().String(), err)
			return writeBatchs, nil
		}
		return writeBatchs, err
	}
	writeBatchs = append(writeBatchs, atomicTxWriteBatchs...)

	return writeBatchs, nil
}

func (ledger *Ledger) executeACrossChainTx(writeBatchs []*db.WriteBatch, tx *types.Transaction) ([]*db.WriteBatch, error) {
	chainID := coordinate.HexToChainCoordinate(tx.FromChain()).Bytes()
	if bytes.Equal(chainID, params.ChainID) {
		sender := tx.Sender()
		TxWriteBatch, err := ledger.state.UpdateBalance(sender, state.NewBalance(tx.Amount(), tx.Nonce()), tx.Fee(), state.OperationSub)
		if err != nil {
			if err == state.ErrNegativeBalance {
				log.Errorf("execute acrosschain transaction: %s, err:%s\n", tx.Hash().String(), err)
				return writeBatchs, nil
			}
			return writeBatchs, err
		}
		writeBatchs = append(writeBatchs, TxWriteBatch...)
	} else {
		mergedTxWriteBatchs, err := ledger.state.UpdateBalance(tx.Recipient(), state.NewBalance(tx.Amount(), tx.Nonce()), tx.Fee(), state.OperationPlus)
		if err != nil {
			if err == state.ErrNegativeBalance {
				log.Errorf("execute acrosschain transaction: %s, err:%s\n", tx.Hash().String(), err)
				return writeBatchs, nil
			}
			return writeBatchs, err
		}

		writeBatchs = append(writeBatchs, mergedTxWriteBatchs...)
	}
	return writeBatchs, nil
}

func (ledger *Ledger) executeMergedTx(writeBatchs []*db.WriteBatch, tx *types.Transaction) ([]*db.WriteBatch, error) {
	//mergeTx not continue merge
	if tx.GetType() == types.TypeMerged && ledger.checkCoordinate(tx) {
		sender := tx.Data.Signature.Bytes()
		senderAddress := accounts.NewAddress(sender)
		TxWriteBatchs, err := ledger.state.Transfer(senderAddress, tx.Recipient(), tx.Fee(), state.NewBalance(tx.Amount(), tx.Nonce()), tx.GetType())
		if err != nil {
			if err == state.ErrNegativeBalance {
				log.Errorf("execute merged transaction: %s, err:%s\n", tx.Hash().String(), err)
				return writeBatchs, nil
			}
			return writeBatchs, err
		}
		writeBatchs = append(writeBatchs, TxWriteBatchs...)
		return writeBatchs, nil
	}

	return ledger.executeACrossChainTx(writeBatchs, tx)
}

func (ledger *Ledger) executeDistriTx(writeBatchs []*db.WriteBatch, tx *types.Transaction) ([]*db.WriteBatch, error) {
	chainID := coordinate.HexToChainCoordinate(tx.FromChain()).Bytes()
	if bytes.Equal(chainID, params.ChainID) {
		chainAddress := accounts.ChainCoordinateToAddress(coordinate.HexToChainCoordinate(tx.ToChain()))
		TxWriteBatch, err := ledger.state.UpdateBalance(chainAddress, state.NewBalance(tx.Amount(), uint32(0)), big.NewInt(0), state.OperationPlus)
		if err != nil {
			if err == state.ErrNegativeBalance {
				log.Errorf("execute distri transaction: %s, err:%s\n", tx.Hash().String(), err)
				return writeBatchs, nil
			}
			return writeBatchs, err
		}
		writeBatchs = append(writeBatchs, TxWriteBatch...)
	}
	return ledger.executeACrossChainTx(writeBatchs, tx)
}

func (ledger *Ledger) executeBackfrontTx(writeBatchs []*db.WriteBatch, tx *types.Transaction) ([]*db.WriteBatch, error) {
	//Backfront transaction
	chainID := coordinate.HexToChainCoordinate(tx.ToChain()).Bytes()
	if bytes.Equal(chainID, params.ChainID) {
		chainAddress := accounts.ChainCoordinateToAddress(coordinate.HexToChainCoordinate(tx.ToChain()))
		TxWriteBatch, err := ledger.state.UpdateBalance(chainAddress, state.NewBalance(tx.Amount(), uint32(0)), big.NewInt(0), state.OperationSub)
		if err != nil {
			if err == state.ErrNegativeBalance {
				log.Errorf("execute backfront transaction: %s, err:%s\n", tx.Hash().String(), err)
				return writeBatchs, nil
			}
			return writeBatchs, err
		}
		writeBatchs = append(writeBatchs, TxWriteBatch...)
	}
	return ledger.executeACrossChainTx(writeBatchs, tx)
}

func (ledger *Ledger) executeSmartContractTx(tx *types.Transaction) (types.Transactions, error) {
	contractSpec := new(types.ContractSpec)
	utils.Deserialize(tx.Payload, contractSpec)
	ledger.contract.ExecTransaction(tx, string(contractSpec.ContractAddr))
	ctx := vm.NewCTX(tx, contractSpec, ledger.contract)
	_, err := vm.RealExecute(ctx)
	if err != nil {
		log.Error("contract execute failed : ", err)
		return nil, fmt.Errorf("contract execute failed : %v ", err)
	}

	smartContractTxs, err := ledger.contract.FinishContractTransaction()
	if err != nil {
		log.Error("FinishContractTransaction: ", err)
		return nil, err
	}

	return smartContractTxs, nil
}

func (ledger *Ledger) checkCoordinate(tx *types.Transaction) bool {
	fromChainID := coordinate.HexToChainCoordinate(tx.FromChain()).Bytes()
	toChainID := coordinate.HexToChainCoordinate(tx.ToChain()).Bytes()
	if bytes.Equal(fromChainID, toChainID) {
		return true
	}
	return false
}

//GetTmpBalance get balance
func (ledger *Ledger) GetTmpBalance(addr accounts.Address) (*big.Int, error) {
	balance, err := ledger.state.GetTmpBalance(addr)
	if err != nil {
		log.Error("can't get balance from db")
	}

	return balance.Amount, err
}

func (ledger *Ledger) LoadSateHash() crypto.Hash {
	return state_hash.InitHash(func(handler state_hash.ForeacherHandler) {
		ledger.state.GetStateDelta(handler)
		ledger.contract.GetStateDelta(handler)
	})
}

func merkleRootHash(txs []*types.Transaction) crypto.Hash {
	if len(txs) > 0 {
		hashs := make([]crypto.Hash, 0)
		for _, tx := range txs {
			hashs = append(hashs, tx.Hash())
		}
		return crypto.ComputeMerkleHash(hashs)[0]
	}
	return crypto.Hash{}
}
