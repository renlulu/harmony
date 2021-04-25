package services

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
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
	testWrappedTx, testTx, rosettaError := unpackWrappedTransactionFromString(string(marshalledBytes), true)
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
	testWrappedTx, testStx, rosettaError := unpackWrappedTransactionFromString(string(marshalledBytes), true)
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
	_, _, rosettaError = unpackWrappedTransactionFromString(string(marshalledBytesFail), true)
	if rosettaError == nil {
		t.Fatal("expected error")
	}

	// test invalid RLP encoding for staking
	wrappedTransaction.RLPBytes = []byte{0x0}
	marshalledBytesFail, err = json.Marshal(wrappedTransaction)
	if err != nil {
		t.Fatal(err)
	}
	_, _, rosettaError = unpackWrappedTransactionFromString(string(marshalledBytesFail), true)
	if rosettaError == nil {
		t.Fatal("expected error")
	}

	// test invalid RLP encoding for plain
	wrappedTransaction.IsStaking = false
	marshalledBytesFail, err = json.Marshal(wrappedTransaction)
	if err != nil {
		t.Fatal(err)
	}
	_, _, rosettaError = unpackWrappedTransactionFromString(string(marshalledBytesFail), true)
	if rosettaError == nil {
		t.Fatal("expected error")
	}

	// test invalid nil RLP
	wrappedTransaction.RLPBytes = nil
	marshalledBytesFail, err = json.Marshal(wrappedTransaction)
	if err != nil {
		t.Fatal(err)
	}
	_, _, rosettaError = unpackWrappedTransactionFromString(string(marshalledBytesFail), true)
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
	_, _, rosettaError = unpackWrappedTransactionFromString(string(marshalledBytesFail), true)
	if rosettaError == nil {
		t.Fatal("expected error")
	}
}

func TestRecoverSenderAddressFromCreateValidatorString(t *testing.T) {
	key, err := crypto.HexToECDSA("4edef2c24995d15b0e25cbd152fb0e2c05d3b79b9c2afd134e6f59f91bf99e48")
	if err != nil {
		t.Fatal(err.Error())
	}
	stakingTransaction, expectedPayload, err := stakingCreateValidatorTransaction(key)
	if err != nil {
		t.Fatal(err.Error())
	}

	fmt.Println(hexutil.Encode(expectedPayload[:]))

	address, err := stakingTransaction.SenderAddress()
	if err != nil {
		t.Fatal(err.Error())
	}

	if strings.ToLower(hexutil.Encode(address[:])) != "0xebcd16e8c1d8f493ba04e99a56474122d81a9c58" {
		t.Fatal("address error")
	}

	_, tx, rosettaError := unpackWrappedTransactionFromString("{\"rlp_bytes\":\"+QEZgPkBCJQLWF+NrvvGijEfvUyyDZF0rRdAFvg4hUFsaWNlhWFsaWNlkWFsaWNlLmhhcm1vbnkub25lg0JvYpVEb24ndCBtZXNzIHdpdGggbWUhISHdyYgBY0V4XYoAAMmIDH1xO0naAADIh7GivC7FAAAKggu48bAwssOLExbakeBorDvYdRwJAe9sAqHVi8cSEEkYMCxu0D1YlGcdDIFtrStNMDMg8gL4YrhgaPgAtq32V7Z0kD4EcIBgkSuJO3x7UAeIgIJHVQqz4YblakTr88pIj47RpC9s7zoEvV0rK361p2eEjTE1s2LmaM5rukLHudVmbY46g75we1cI5yLFiTn+mwfBcPO3BiQUZICEdzWUAIOhvkCAgIA=\",\"is_staking\":true,\"contract_code\":\"0x\",\"from\":{\"address\":\"one1a0x3d6xpmr6f8wsyaxd9v36pytvp48zckswvv9\",\"metadata\":{\"hex_address\":\"0xeBCD16e8c1D8f493bA04E99a56474122D81A9c58\"}}}", false)
	if rosettaError != nil {
		t.Fatal(rosettaError)
	}

	signer := stakingTypes.NewEIP155Signer(new(big.Int).SetUint64(1))
	stakingTx, ok := tx.(*stakingTypes.StakingTransaction)
	if !ok {
		t.Fatal()
	}
	sig, err := hexutil.Decode("0x3073694c4775727c84e6a395c3e16228fbc0d5e4d201b27bdec70d24f332c419679d81e6b4f9f0d7c2c2eb1eb4d4d82e8472622bdf6ab28f2f5ea6b27497662900")
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

func TestRecoverSenderAddressFromEditValidatorString(t *testing.T) {
	key, err := crypto.HexToECDSA("4edef2c24995d15b0e25cbd152fb0e2c05d3b79b9c2afd134e6f59f91bf99e48")
	if err != nil {
		t.Fatal(err.Error())
	}
	stakingTransaction, expectedPayload, err := stakingEditValidatorTransaction(key)
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

	_, tx, rosettaError := unpackWrappedTransactionFromString("{\"rlp_bytes\":\"+NAB+MGU680W6MHY9JO6BOmaVkdBItganFj4OIVBbGljZYVhbGljZZFhbGljZS5oYXJtb255Lm9uZYNCb2KVRG9uJ3QgbWVzcyB3aXRoIG1lISEhyYgBY0V4XYoAAAqCC7iwuUhhZ6uQh6uBjcTOAm7bW/IWhjNkwy5C3yrwPFztGtGB59EvDm3VMHpztiJHYIYRsLlIYWerkIergY3EzgJu21vyFoYzZMMuQt8q8Dxc7RrRgefRLw5t1TB6c7YiR2CGEYCAgIR3NZQAgqQQgICA\",\"is_staking\":true,\"contract_code\":\"0x\",\"from\":{\"address\":\"one1a0x3d6xpmr6f8wsyaxd9v36pytvp48zckswvv9\",\"metadata\":{\"hex_address\":\"0xeBCD16e8c1D8f493bA04E99a56474122D81A9c58\"}}}", false)
	if rosettaError != nil {
		t.Fatal(rosettaError)
	}
	signer := stakingTypes.NewEIP155Signer(new(big.Int).SetUint64(1))
	stakingTx, ok := tx.(*stakingTypes.StakingTransaction)
	if !ok {
		t.Fatal()
	}
	sig, err := hexutil.Decode("0xf18c7a68e64f2f9f94ae0ed8975c161c3c4b1ca469dc6635ab05911fc749f60f26fc899ff8eaab60d8e924b565367f294861868ca0709d935ca74ddda91103a701")
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

func TestRecoverSenderAddressFromDelegateString(t *testing.T) {
	key, err := crypto.HexToECDSA("4edef2c24995d15b0e25cbd152fb0e2c05d3b79b9c2afd134e6f59f91bf99e48")
	if err != nil {
		t.Fatal(err.Error())
	}
	stakingTransaction, expectedPayload, err := stakingDelegateTransaction(key)
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

	_, tx, rosettaError := unpackWrappedTransactionFromString("{\"rlp_bytes\":\"+DkC65Su++69nA0xde5diT8aa65lIsefgpTrzRbowdj0k7oE6ZpWR0Ei2BqcWAqAhHc1lACCpBCAgIA=\",\"is_staking\":true,\"contract_code\":\"0x\",\"from\":{\"address\":\"one1a0x3d6xpmr6f8wsyaxd9v36pytvp48zckswvv9\",\"metadata\":{\"hex_address\":\"0xeBCD16e8c1D8f493bA04E99a56474122D81A9c58\"}}}", false)
	if rosettaError != nil {
		t.Fatal(rosettaError)
	}
	signer := stakingTypes.NewEIP155Signer(new(big.Int).SetUint64(1))
	stakingTx, ok := tx.(*stakingTypes.StakingTransaction)
	if !ok {
		t.Fatal()
	}
	sig, err := hexutil.Decode("0x2e99c4d18a43a263d078d1b60423b26f83ff65714b81ceb6de362737b0960ee32309267b6cd1eb6912da4fa98ab297bec9c3f8e1ed67e8fc91614a81d33300d200")
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

func TestRecoverSenderAddressFromUndelegateString(t *testing.T) {
	key, err := crypto.HexToECDSA("4edef2c24995d15b0e25cbd152fb0e2c05d3b79b9c2afd134e6f59f91bf99e48")
	if err != nil {
		t.Fatal(err.Error())
	}
	stakingTransaction, expectedPayload, err := stakingUndelegateTransaction(key)
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

	_, tx, rosettaError := unpackWrappedTransactionFromString("{\"rlp_bytes\":\"+DkD65TrzRbowdj0k7oE6ZpWR0Ei2BqcWJTrzRbowdj0k7oE6ZpWR0Ei2BqcWAqAhHc1lACCUgiAgIA=\",\"is_staking\":true,\"contract_code\":\"0x\",\"from\":{\"address\":\"one13lx3exmpfc446vsguc5d0mtgha2ff7h5uz85pk\",\"metadata\":{\"hex_address\":\"0x8fCD1C9B614E2b5D3208E628d7eD68bF5494faF4\"}}}", false)
	if rosettaError != nil {
		t.Fatal(rosettaError)
	}
	signer := stakingTypes.NewEIP155Signer(new(big.Int).SetUint64(1))
	stakingTx, ok := tx.(*stakingTypes.StakingTransaction)
	if !ok {
		t.Fatal()
	}
	sig, err := hexutil.Decode("0x68485d11cd1db90fef8605d26b0415a900d5b9e6d87f8fd9529e7a483d30d7565631035fdd88816950ad1f591534ad437314fabc2c1d8bcfc4a164e3361fbfaa01")
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

func TestRecoverSenderAddressFromCollectRewardsString(t *testing.T) {
	key, err := crypto.HexToECDSA("4edef2c24995d15b0e25cbd152fb0e2c05d3b79b9c2afd134e6f59f91bf99e48")
	if err != nil {
		t.Fatal(err.Error())
	}
	stakingTransaction, expectedPayload, err := stakingCollectRewardsTransaction(key)
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

	_, tx, rosettaError := unpackWrappedTransactionFromString("{\"rlp_bytes\":\"4wTVlOvNFujB2PSTugTpmlZHQSLYGpxYgIR3NZQAglIIgICA\",\"is_staking\":true,\"contract_code\":\"0x\",\"from\":{\"address\":\"one13lx3exmpfc446vsguc5d0mtgha2ff7h5uz85pk\",\"metadata\":{\"hex_address\":\"0x8fCD1C9B614E2b5D3208E628d7eD68bF5494faF4\"}}}", false)
	if rosettaError != nil {
		a, _ := json.Marshal(rosettaError)
		fmt.Println(string(a))
		t.Fatal(rosettaError)
	}
	signer := stakingTypes.NewEIP155Signer(new(big.Int).SetUint64(1))
	stakingTx, ok := tx.(*stakingTypes.StakingTransaction)
	if !ok {
		t.Fatal()
	}
	sig, err := hexutil.Decode("0x13f25e40cf5cadf9ae68a318b216de52dc97ec423f581a36defccbdd31870cc26c66872f9f543246d0da7ee6b48d7e11e5034227795e80a5c1e95ac68a2a024500")
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
	pubb, err := hexutil.Decode("0x30b2c38b1316da91e068ac3bd8751c0901ef6c02a1d58bc712104918302c6ed03d5894671d0c816dad2b4d303320f202")
	if err != nil {
		return nil, common2.Hash{}, err
	}
	copy(pub[:], pubb)

	var sig bls.SerializedSignature
	sigg, err := hexutil.Decode("0x68f800b6adf657b674903e04708060912b893b7c7b500788808247550ab3e186e56a44ebf3ca488f8ed1a42f6cef3a04bd5d2b2b7eb5a767848d3135b362e668ce6bba42c7b9d5666d8e3a83be707b5708e722c58939fe9b07c170f3b7062414")
	if err != nil {
		return nil, common2.Hash{}, err
	}
	copy(sig[:], sigg)
	validator, _ := common.Bech32ToAddress("one1pdv9lrdwl0rg5vglh4xtyrv3wjk3wsqket7zxy")
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
			SlotKeySigs:        []bls.SerializedSignature{sig},
			Amount:             new(big.Int).SetUint64(100),
		}
	}

	gasPrice := big.NewInt(2000000000)
	tx, _ := stakingTypes.NewStakingTransaction(0, 10600000, gasPrice, stakePayloadMaker)

	signer := stakingTypes.NewEIP155Signer(new(big.Int).SetUint64(1))
	signingPayload := signer.Hash(tx)

	stakingTransaction, err := stakingTypes.Sign(tx, signer, key)
	if err != nil {
		return nil, common2.Hash{}, err
	}

	return stakingTransaction, signingPayload, nil
}

func stakingEditValidatorTransaction(key *ecdsa.PrivateKey) (*stakingTypes.StakingTransaction, common2.Hash, error) {
	stakePayloadMaker := func() (stakingTypes.Directive, interface{}) {
		var slotKeyToRemove bls.SerializedPublicKey
		removeBytes, _ := hexutil.Decode("0xb9486167ab9087ab818dc4ce026edb5bf216863364c32e42df2af03c5ced1ad181e7d12f0e6dd5307a73b62247608611")
		copy(slotKeyToRemove[:], removeBytes)

		var slotKeyToAdd bls.SerializedPublicKey
		addBytes, _ := hexutil.Decode("0xb9486167ab9087ab818dc4ce026edb5bf216863364c32e42df2af03c5ced1ad181e7d12f0e6dd5307a73b62247608611")
		copy(slotKeyToAdd[:], addBytes)

		validator, _ := common.Bech32ToAddress("one1a0x3d6xpmr6f8wsyaxd9v36pytvp48zckswvv9")

		return stakingTypes.DirectiveEditValidator, stakingTypes.EditValidator{
			Description: stakingTypes.Description{
				Name:            "Alice",
				Identity:        "alice",
				Website:         "alice.harmony.one",
				SecurityContact: "Bob",
				Details:         "Don't mess with me!!!",
			},
			CommissionRate:     &numeric.Dec{new(big.Int).SetUint64(100000000000000000)},
			MinSelfDelegation:  new(big.Int).SetInt64(10),
			MaxTotalDelegation: new(big.Int).SetUint64(3000),
			SlotKeyToRemove:    &slotKeyToRemove,
			SlotKeyToAdd:       &slotKeyToAdd,
			ValidatorAddress:   validator,
		}
	}

	gasPrice := big.NewInt(2000000000)
	tx, _ := stakingTypes.NewStakingTransaction(0, 42000, gasPrice, stakePayloadMaker)

	signer := stakingTypes.NewEIP155Signer(new(big.Int).SetUint64(1))
	signingPayload := signer.Hash(tx)

	stakingTransaction, err := stakingTypes.Sign(tx, signer, key)
	if err != nil {
		return nil, common2.Hash{}, err
	}

	return stakingTransaction, signingPayload, nil
}

func stakingDelegateTransaction(key *ecdsa.PrivateKey) (*stakingTypes.StakingTransaction, common2.Hash, error) {
	stakePayloadMaker := func() (stakingTypes.Directive, interface{}) {

		validator, _ := common.Bech32ToAddress("one1a0x3d6xpmr6f8wsyaxd9v36pytvp48zckswvv9")
		delegator, _ := common.Bech32ToAddress("one14ma7a0vup5chtmja3yl356awv53v08uzln8ehm")
		return stakingTypes.DirectiveDelegate, stakingTypes.Delegate{
			ValidatorAddress: validator,
			DelegatorAddress: delegator,
			Amount:           new(big.Int).SetUint64(10),
		}
	}

	gasPrice := big.NewInt(2000000000)
	tx, _ := stakingTypes.NewStakingTransaction(0, 42000, gasPrice, stakePayloadMaker)

	signer := stakingTypes.NewEIP155Signer(new(big.Int).SetUint64(1))
	signingPayload := signer.Hash(tx)

	stakingTransaction, err := stakingTypes.Sign(tx, signer, key)
	if err != nil {
		return nil, common2.Hash{}, err
	}
	return stakingTransaction, signingPayload, nil
}

func stakingUndelegateTransaction(key *ecdsa.PrivateKey) (*stakingTypes.StakingTransaction, common2.Hash, error) {
	stakePayloadMaker := func() (stakingTypes.Directive, interface{}) {

		validator, _ := common.Bech32ToAddress("one1a0x3d6xpmr6f8wsyaxd9v36pytvp48zckswvv9")
		delegator, _ := common.Bech32ToAddress("one1a0x3d6xpmr6f8wsyaxd9v36pytvp48zckswvv9")
		return stakingTypes.DirectiveUndelegate, stakingTypes.Undelegate{
			ValidatorAddress: validator,
			DelegatorAddress: delegator,
			Amount:           new(big.Int).SetUint64(10),
		}
	}

	gasPrice := big.NewInt(2000000000)
	tx, _ := stakingTypes.NewStakingTransaction(0, 21000, gasPrice, stakePayloadMaker)

	signer := stakingTypes.NewEIP155Signer(new(big.Int).SetUint64(1))
	signingPayload := signer.Hash(tx)

	stakingTransaction, err := stakingTypes.Sign(tx, signer, key)
	if err != nil {
		return nil, common2.Hash{}, err
	}
	return stakingTransaction, signingPayload, nil
}

func stakingCollectRewardsTransaction(key *ecdsa.PrivateKey) (*stakingTypes.StakingTransaction, common2.Hash, error) {
	stakePayloadMaker := func() (stakingTypes.Directive, interface{}) {

		delegator, _ := common.Bech32ToAddress("one1a0x3d6xpmr6f8wsyaxd9v36pytvp48zckswvv9")
		return stakingTypes.DirectiveCollectRewards, stakingTypes.CollectRewards{
			DelegatorAddress: delegator,
		}
	}

	gasPrice := big.NewInt(2000000000)
	tx, _ := stakingTypes.NewStakingTransaction(0, 21000, gasPrice, stakePayloadMaker)

	signer := stakingTypes.NewEIP155Signer(new(big.Int).SetUint64(1))
	signingPayload := signer.Hash(tx)

	stakingTransaction, err := stakingTypes.Sign(tx, signer, key)
	if err != nil {
		return nil, common2.Hash{}, err
	}
	return stakingTransaction, signingPayload, nil
}
