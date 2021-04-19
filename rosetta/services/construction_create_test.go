package services

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	common2 "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/harmony-one/harmony/crypto/bls"
	"github.com/harmony-one/harmony/internal/common"
	"github.com/harmony-one/harmony/numeric"

	"github.com/coinbase/rosetta-sdk-go/types"
	"github.com/ethereum/go-ethereum/crypto"

	hmytypes "github.com/harmony-one/harmony/core/types"
	stakingTypes "github.com/harmony-one/harmony/staking/types"
	"github.com/harmony-one/harmony/test/helpers"
)

func TestUnpackWrappedTransactionFromString(t *testing.T) {
	refKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	refAddr := crypto.PubkeyToAddress(refKey.PublicKey)
	refAddrID, rosettaError := newAccountIdentifier(refAddr)
	if rosettaError != nil {
		t.Fatal(rosettaError)
	}
	refEstGasUsed := big.NewInt(100000)
	signer := hmytypes.NewEIP155Signer(big.NewInt(0))

	// Test plain transactions
	tx, err := helpers.CreateTestTransaction(
		signer, 0, 1, 2, refEstGasUsed.Uint64(), gasPrice, big.NewInt(1e10), []byte{0x01, 0x02},
	)
	if err != nil {
		t.Fatal(err)
	}
	buf := &bytes.Buffer{}
	if err := tx.EncodeRLP(buf); err != nil {
		t.Fatal(err)
	}
	wrappedTransaction := WrappedTransaction{
		RLPBytes:  buf.Bytes(),
		From:      refAddrID,
		IsStaking: false,
	}
	marshalledBytes, err := json.Marshal(wrappedTransaction)
	if err != nil {
		t.Fatal(err)
	}
	testWrappedTx, testTx, rosettaError := unpackWrappedTransactionFromString(string(marshalledBytes))
	if rosettaError != nil {
		t.Fatal(rosettaError)
	}
	if types.Hash(tx) != types.Hash(testTx) {
		t.Error("unwrapped tx does not match reference tx")
	}
	if types.Hash(testWrappedTx) != types.Hash(wrappedTransaction) {
		t.Error("unwrapped tx struct does not matched reference tx struct")
	}

	// Test staking transactions
	receiverKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf(err.Error())
	}
	stx, err := helpers.CreateTestStakingTransaction(func() (stakingTypes.Directive, interface{}) {
		return stakingTypes.DirectiveDelegate, stakingTypes.Delegate{
			DelegatorAddress: refAddr,
			ValidatorAddress: crypto.PubkeyToAddress(receiverKey.PublicKey),
			Amount:           tenOnes,
		}
	}, refKey, 10, refEstGasUsed.Uint64(), gasPrice)
	if err != nil {
		t.Fatal(err)
	}
	buf = &bytes.Buffer{}
	if err := stx.EncodeRLP(buf); err != nil {
		t.Fatal(err)
	}
	wrappedTransaction.RLPBytes = buf.Bytes()
	wrappedTransaction.IsStaking = true
	marshalledBytes, err = json.Marshal(wrappedTransaction)
	if err != nil {
		t.Fatal(err)
	}
	testWrappedTx, testStx, rosettaError := unpackWrappedTransactionFromString(string(marshalledBytes))
	if rosettaError != nil {
		t.Fatal(rosettaError)
	}
	if types.Hash(testStx) != types.Hash(stx) {
		t.Error("unwrapped tx does not match reference tx")
	}
	if types.Hash(testWrappedTx) != types.Hash(wrappedTransaction) {
		t.Error("unwrapped tx struct does not matched reference tx struct")
	}

	// Test invalid marshall
	marshalledBytesFail := marshalledBytes[:]
	marshalledBytesFail[0] = 0x0
	_, _, rosettaError = unpackWrappedTransactionFromString(string(marshalledBytesFail))
	if rosettaError == nil {
		t.Fatal("expected error")
	}

	// test invalid RLP encoding for staking
	wrappedTransaction.RLPBytes = []byte{0x0}
	marshalledBytesFail, err = json.Marshal(wrappedTransaction)
	if err != nil {
		t.Fatal(err)
	}
	_, _, rosettaError = unpackWrappedTransactionFromString(string(marshalledBytesFail))
	if rosettaError == nil {
		t.Fatal("expected error")
	}

	// test invalid RLP encoding for plain
	wrappedTransaction.IsStaking = false
	marshalledBytesFail, err = json.Marshal(wrappedTransaction)
	if err != nil {
		t.Fatal(err)
	}
	_, _, rosettaError = unpackWrappedTransactionFromString(string(marshalledBytesFail))
	if rosettaError == nil {
		t.Fatal("expected error")
	}

	// test invalid nil RLP
	wrappedTransaction.RLPBytes = nil
	marshalledBytesFail, err = json.Marshal(wrappedTransaction)
	if err != nil {
		t.Fatal(err)
	}
	_, _, rosettaError = unpackWrappedTransactionFromString(string(marshalledBytesFail))
	if rosettaError == nil {
		t.Fatal("expected error")
	}

	// test invalid from address
	wrappedTransaction.RLPBytes = buf.Bytes()
	wrappedTransaction.From = nil
	marshalledBytesFail, err = json.Marshal(wrappedTransaction)
	if err != nil {
		t.Fatal(err)
	}
	_, _, rosettaError = unpackWrappedTransactionFromString(string(marshalledBytesFail))
	if rosettaError == nil {
		t.Fatal("expected error")
	}
}

func TestRecoverSenderAddressFromString(t *testing.T) {
	key, err := crypto.HexToECDSA("4edef2c24995d15b0e25cbd152fb0e2c05d3b79b9c2afd134e6f59f91bf99e48")
	if err != nil {
		t.Fatal(err.Error())
	}
	stakingTransaction, expectedPayload, err := stakingCreateValidatorTransaction(key)
	if err != nil {
		t.Fatal(err.Error())
	}

	address, err := stakingTransaction.SenderAddress()
	if err != nil {
		t.Fatal(err.Error())
	}

	if strings.ToLower(hexutil.Encode(address[:])) != "0xebcd16e8c1d8f493ba04e99a56474122d81a9c58" {
		t.Fatal("address error")
	}

	_, tx, rosettaError := unpackWrappedTransactionFromString("{\"rlp_bytes\":\"+LWA+KWU680W6MHY9JO6BOmaVkdBItganFj4OIVBbGljZYVhbGljZZFhbGljZS5oYXJtb255Lm9uZYNCb2KVRG9uJ3QgbWVzcyB3aXRoIG1lISEh3cmIAWNFeF2KAADJiAx9cTtJ2gAAyIexorwuxQAACoILuPGwuUhhZ6uQh6uBjcTOAm7bW/IWhjNkwy5C3yrwPFztGtGB59EvDm3VMHpztiJHYIYRwGSAhHc1lACDUN8ggICA\",\"is_staking\":true,\"contract_code\":\"0x\",\"from\":{\"address\":\"one1a0x3d6xpmr6f8wsyaxd9v36pytvp48zckswvv9\",\"metadata\":{\"hex_address\":\"0xeBCD16e8c1D8f493bA04E99a56474122D81A9c58\"}}}")
	if rosettaError != nil {
		t.Fatal(rosettaError)
	}

	signer := stakingTypes.NewEIP155Signer(new(big.Int).SetUint64(1))
	stakingTx, ok := tx.(*stakingTypes.StakingTransaction)
	if !ok {
		t.Fatal()
	}
	sig, err := hexutil.Decode("0x548b71f68f424794cf9ccd283d13288944e93bc44579d2919e23d057f14ea0b87074bfead1a4d88d7d78e6eaed729517ac2e84f6d1ed8bd23618d532038a451700")
	if err != nil {
		t.Fatal(err)
	}
	stakingTx, err = stakingTx.WithSignature(signer, sig)
	if err != nil {
		t.Fatal(err)
	}
	v, r, s := stakingTransaction.RawSignatureValues()
	v1, r1, s1 := stakingTx.RawSignatureValues()
	if v.String() != v1.String() || r.String() != r1.String() || s.String() != s1.String() {
		t.Log(stakingTransaction.RawSignatureValues())
		t.Log(stakingTx.RawSignatureValues())
		t.Fatal("signature error")
	}

	if expectedPayload != signer.Hash(stakingTx) {
		t.Error("payload error")
	}

	address, err = stakingTx.SenderAddress()
	if err != nil {
		t.Fatal(err.Error())
	}

	if strings.ToLower(hexutil.Encode(address[:])) != "0xebcd16e8c1d8f493ba04e99a56474122d81a9c58" {
		t.Fatal("address error")
	}
}

func stakingCreateValidatorTransaction(key *ecdsa.PrivateKey) (*stakingTypes.StakingTransaction, common2.Hash, error) {
	var pub bls.SerializedPublicKey
	pubb, err := hexutil.Decode("0xb9486167ab9087ab818dc4ce026edb5bf216863364c32e42df2af03c5ced1ad181e7d12f0e6dd5307a73b62247608611")
	if err != nil {
		return nil, common2.Hash{}, err
	}
	copy(pub[:], pubb)
	validator, _ := common.Bech32ToAddress("one1a0x3d6xpmr6f8wsyaxd9v36pytvp48zckswvv9")
	stakePayloadMaker := func() (stakingTypes.Directive, interface{}) {
		return stakingTypes.DirectiveCreateValidator, stakingTypes.CreateValidator{
			Description: stakingTypes.Description{
				Name:            "Alice",
				Identity:        "alice",
				Website:         "alice.harmony.one",
				SecurityContact: "Bob",
				Details:         "Don't mess with me!!!",
			},
			CommissionRates: stakingTypes.CommissionRates{
				Rate:          numeric.Dec{new(big.Int).SetUint64(100000000000000000)},
				MaxRate:       numeric.Dec{new(big.Int).SetUint64(900000000000000000)},
				MaxChangeRate: numeric.Dec{new(big.Int).SetUint64(50000000000000000)},
			},
			MinSelfDelegation:  new(big.Int).SetInt64(10),
			MaxTotalDelegation: new(big.Int).SetUint64(3000),
			ValidatorAddress:   validator,
			SlotPubKeys:        []bls.SerializedPublicKey{pub},
			Amount:             new(big.Int).SetUint64(100),
		}
	}

	gasPrice := big.NewInt(2000000000)
	tx, _ := stakingTypes.NewStakingTransaction(0, 5300000, gasPrice, stakePayloadMaker)

	signer := stakingTypes.NewEIP155Signer(new(big.Int).SetUint64(1))
	signingPayload := signer.Hash(tx)

	stakingTransaction, err := stakingTypes.Sign(tx, signer, key)
	if err != nil {
		return nil, common2.Hash{}, err
	}

	return stakingTransaction, signingPayload, nil
}
