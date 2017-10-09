// Copyright 2014 The go-ethereum Authors
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

package vm

import (
	"encoding/binary"
	"encoding/hex"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/logger"
	"github.com/ethereum/go-ethereum/logger/glog"
	"github.com/ethereum/go-ethereum/params"

	// ZSL START
	sha256compress "github.com/jpmorganchase/zsl-q/zsl-golang/zsl/sha256"
	"github.com/jpmorganchase/zsl-q/zsl-golang/zsl/snark"
	// ZSL END
)

// ZSL START
const ZSL_PROOF_SIZE uint64 = 584

// ZSL END

// PrecompiledAccount represents a native ethereum contract
type PrecompiledAccount struct {
	Gas func(l int) *big.Int
	fn  func(in []byte) []byte
}

// Call calls the native function
func (self PrecompiledAccount) Call(in []byte) []byte {
	return self.fn(in)
}

// Precompiled contains the default set of ethereum contracts
var Precompiled = PrecompiledContracts()

// PrecompiledContracts returns the default set of precompiled ethereum
// contracts defined by the ethereum yellow paper.
func PrecompiledContracts() map[string]*PrecompiledAccount {
	return map[string]*PrecompiledAccount{
		// ECRECOVER
		string(common.LeftPadBytes([]byte{1}, 20)): &PrecompiledAccount{func(l int) *big.Int {
			return params.EcrecoverGas
		}, ecrecoverFunc},

		// SHA256
		string(common.LeftPadBytes([]byte{2}, 20)): &PrecompiledAccount{func(l int) *big.Int {
			n := big.NewInt(int64(l+31) / 32)
			n.Mul(n, params.Sha256WordGas)
			return n.Add(n, params.Sha256Gas)
		}, sha256Func},

		// RIPEMD160
		string(common.LeftPadBytes([]byte{3}, 20)): &PrecompiledAccount{func(l int) *big.Int {
			n := big.NewInt(int64(l+31) / 32)
			n.Mul(n, params.Ripemd160WordGas)
			return n.Add(n, params.Ripemd160Gas)
		}, ripemd160Func},

		string(common.LeftPadBytes([]byte{4}, 20)): &PrecompiledAccount{func(l int) *big.Int {
			n := big.NewInt(int64(l+31) / 32)
			n.Mul(n, params.IdentityWordGas)

			return n.Add(n, params.IdentityGas)
		}, memCpy},

		// ZSL START

		// Sha256Compress
		string(common.LeftPadBytes([]byte{0x88, 0x01}, 20)): &PrecompiledAccount{func(l int) *big.Int {
			n := big.NewInt(int64(l+31) / 32)
			n.Mul(n, params.Sha256CompressWordGas)
			return n.Add(n, params.Sha256CompressGas)
		}, sha256CompressFunc},

		// Verify Shielded Transfer
		string(common.LeftPadBytes([]byte{0x88, 0x02}, 20)): &PrecompiledAccount{func(l int) *big.Int {
			n := big.NewInt(int64(l+31) / 32)
			n.Mul(n, params.VerifyZKProofWordGas)
			return n.Add(n, params.VerifyZKProofGas)
		}, verifyShieldedTransferFunc},

		// Verify Shielding
		string(common.LeftPadBytes([]byte{0x88, 0x03}, 20)): &PrecompiledAccount{func(l int) *big.Int {
			n := big.NewInt(int64(l+31) / 32)
			n.Mul(n, params.VerifyZKProofWordGas)
			return n.Add(n, params.VerifyZKProofGas)
		}, verifyShieldingFunc},

		// Verify Unshielding
		string(common.LeftPadBytes([]byte{0x88, 0x04}, 20)): &PrecompiledAccount{func(l int) *big.Int {
			n := big.NewInt(int64(l+31) / 32)
			n.Mul(n, params.VerifyZKProofWordGas)
			return n.Add(n, params.VerifyZKProofGas)
		}, verifyUnshieldingFunc},

		// ZSL END
	}
}

func sha256Func(in []byte) []byte {
	return crypto.Sha256(in)
}

func ripemd160Func(in []byte) []byte {
	return common.LeftPadBytes(crypto.Ripemd160(in), 32)
}

const ecRecoverInputLength = 128

func ecrecoverFunc(in []byte) []byte {
	in = common.RightPadBytes(in, 128)
	// "in" is (hash, v, r, s), each 32 bytes
	// but for ecrecover we want (r, s, v)

	r := common.BytesToBig(in[64:96])
	s := common.BytesToBig(in[96:128])
	// Treat V as a 256bit integer
	vbig := common.Bytes2Big(in[32:64])
	v := byte(vbig.Uint64())

	// tighter sig s values in homestead only apply to tx sigs
	if !crypto.ValidateSignatureValues(v, r, s, false) {
		glog.V(logger.Detail).Infof("ECRECOVER error: v, r or s value invalid")
		return nil
	}

	// v needs to be at the end and normalized for libsecp256k1
	vbignormal := new(big.Int).Sub(vbig, big.NewInt(27))
	vnormal := byte(vbignormal.Uint64())
	rsv := append(in[64:128], vnormal)
	pubKey, err := crypto.Ecrecover(in[:32], rsv)
	// make sure the public key is a valid one
	if err != nil {
		glog.V(logger.Detail).Infoln("ECRECOVER error: ", err)
		return nil
	}

	// the first byte of pubkey is bitcoin heritage
	return common.LeftPadBytes(crypto.Keccak256(pubKey[1:])[12:], 32)
}

func memCpy(in []byte) []byte {
	return in
}

// ZSL START

/*
	Input bytes when the precompile is called with string "hello":
	0000000000000000000000000000000000000000000000000000000000000020
	0000000000000000000000000000000000000000000000000000000000000005
	68656c6c6f000000000000000000000000000000000000000000000000000000
*/
func sha256CompressFunc(in []byte) []byte {
	// ignore keccac
	in = in[4:]

	// ignore next 32 bytes
	in = in[32:]

	// check payload size
	n := binary.BigEndian.Uint64(in[24:32])
	if n != 64 {
		glog.Errorln("ZSL input must have size of 64 bytes (512 bits)")
		return nil
	}

	// skip payload size
	in = in[32:]

	c := sha256compress.NewCompress()
	c.Write(in[0:n])
	return c.Compress()
}

/**
In geth:
zslprecompile.VerifyShielding("0x001122", "0x08dbb5c1357d05e5178c9f8b88b590e0728d36f1a2e04ae93e963d5174fc4d35", "0xff2c9bdc59089c8d3aa313e9394a19ea17dbfa6f8b2520c7165734b6da615dc4", 12345)

Data passed into function:
4e320263000000000000000000000000000000000000000000000000000000000000000808dbb5c1357d05e5178c9f8b88b590e0728d36f1a2e04ae93e963d5174fc4d35ff2c9bdc59089c8d3aa313e9394a19ea17dbfa6f8b2520c7165734b6da615dc400000000000000000000000000000000000000000000000000000000000030390000000000000000000000000000000000000000000000000000000000000003001122
*/
func verifyShieldingFunc(in []byte) []byte {
	snark.Init()

	// ignore keccac
	in = in[4:]

	// ignore next 32 bytes
	in = in[32:]

	var send_nf [32]byte
	var cm [32]byte
	copy(send_nf[:], in[:32])
	copy(cm[:], in[32:64])
	noteValue := binary.BigEndian.Uint64(in[88:96])
	proofSize := binary.BigEndian.Uint64(in[120:128]) // should be 584

	if proofSize != ZSL_PROOF_SIZE {
		glog.Errorf("ZSL error, proof must have size of %d bytes, not %d.\n", ZSL_PROOF_SIZE, proofSize)
		return nil
	}

	var proof [ZSL_PROOF_SIZE]byte
	copy(proof[:], in[128:])

	result := snark.VerifyShielding(proof, send_nf, cm, noteValue)
	var b byte
	if result {
		b = 1
	}

	glog.Errorln("verifyShieldingFunc: ", hex.EncodeToString(in))
	glog.Errorln("send_nf: ", hex.EncodeToString(send_nf[:]))
	glog.Errorln("     cm: ", hex.EncodeToString(cm[:]))
	glog.Errorln("  value: ", noteValue)
	glog.Errorln("   size: ", proofSize)
	glog.Errorln("  proof: ", hex.EncodeToString(in[128:]))
	glog.Errorln(" result: ", result)

	return []byte{b}
}

func verifyUnshieldingFunc(in []byte) []byte {
	snark.Init()

	// ignore keccac
	in = in[4:]

	// ignore next 32 bytes
	in = in[32:]

	var spend_nf [32]byte
	var rt [32]byte
	copy(spend_nf[:], in[:32])
	copy(rt[:], in[32:64])
	noteValue := binary.BigEndian.Uint64(in[88:96])
	proofSize := binary.BigEndian.Uint64(in[120:128]) // should be 584

	if proofSize != ZSL_PROOF_SIZE {
		glog.Errorf("ZSL error, proof must have size of %d bytes, not %d.\n", ZSL_PROOF_SIZE, proofSize)
		return nil
	}

	var proof [ZSL_PROOF_SIZE]byte
	copy(proof[:], in[128:])

	result := snark.VerifyUnshielding(proof, spend_nf, rt, noteValue)
	var b byte
	if result {
		b = 1
	}

	glog.Errorln("verifyUnshieldingFunc: ", hex.EncodeToString(in))
	glog.Errorln("spend_nf: ", hex.EncodeToString(spend_nf[:]))
	glog.Errorln("      rt: ", hex.EncodeToString(rt[:]))
	glog.Errorln("   value: ", noteValue)
	glog.Errorln("    size: ", proofSize)
	glog.Errorln("   proof: ", hex.EncodeToString(in[128:]))
	glog.Errorln("  result: ", result)

	return []byte{b}
}

func verifyShieldedTransferFunc(in []byte) []byte {

	// ignore keccac
	in = in[4:]

	// ignore next 32 bytes
	in = in[32:]

	var anchor [32]byte
	var spend_nf_1 [32]byte
	var spend_nf_2 [32]byte
	var send_nf_1 [32]byte
	var send_nf_2 [32]byte
	var cm_1 [32]byte
	var cm_2 [32]byte
	copy(anchor[:], in[:32])
	copy(spend_nf_1[:], in[32:64])
	copy(spend_nf_2[:], in[64:96])
	copy(send_nf_1[:], in[96:128])
	copy(send_nf_2[:], in[128:160])
	copy(cm_1[:], in[160:192])
	copy(cm_2[:], in[192:224])
	proofSize := binary.BigEndian.Uint64(in[248:256]) // should be 584

	if proofSize != ZSL_PROOF_SIZE {
		glog.Errorf("ZSL error, proof must have size of %d bytes, not %d.\n", ZSL_PROOF_SIZE, proofSize)
		return nil
	}

	var proof [ZSL_PROOF_SIZE]byte
	copy(proof[:], in[256:])

	snark.Init()
	result := snark.VerifyTransfer(proof, anchor, spend_nf_1, spend_nf_2, send_nf_1, send_nf_2, cm_1, cm_2)
	var b byte
	if result {
		b = 1
	}

	glog.Errorln("verifyShieldedTransferFunc: ", hex.EncodeToString(in))
	glog.Errorln("spend_nf_1: ", hex.EncodeToString(spend_nf_1[:]))
	glog.Errorln("spend_nf_2: ", hex.EncodeToString(spend_nf_2[:]))
	glog.Errorln(" send_nf_1: ", hex.EncodeToString(send_nf_1[:]))
	glog.Errorln(" send_nf_2: ", hex.EncodeToString(send_nf_2[:]))
	glog.Errorln("      cm_1: ", hex.EncodeToString(cm_1[:]))
	glog.Errorln("      cm_2: ", hex.EncodeToString(cm_2[:]))
	glog.Errorln("    anchor: ", hex.EncodeToString(anchor[:]))
	glog.Errorln("      size: ", proofSize)
	glog.Errorln("     proof: ", hex.EncodeToString(proof[:]))
	glog.Errorln("    result: ", result)

	return []byte{b}
}

// ZSL END
