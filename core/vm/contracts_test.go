// Copyright 2017 The go-ethereum Authors
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
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

// precompiledTest defines the input/output pairs for precompiled contract tests.
type precompiledTest struct {
	Input, Expected string
	Gas             uint64
	Name            string
	NoBenchmark     bool // Benchmark primarily the worst-cases
}

// precompiledFailureTest defines the input/error pairs for precompiled
// contract failure tests.
type precompiledFailureTest struct {
	Input         string
	ExpectedError string
	Name          string
}

// allPrecompiles does not map to the actual set of precompiles, as it also contains
// repriced versions of precompiles at certain slots
var allPrecompiles = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{1}):    &ecrecover{},
	common.BytesToAddress([]byte{2}):    &sha256hash{},
	common.BytesToAddress([]byte{3}):    &ripemd160hash{},
	common.BytesToAddress([]byte{4}):    &dataCopy{},
	common.BytesToAddress([]byte{5}):    &bigModExp{eip2565: false},
	common.BytesToAddress([]byte{0xf5}): &bigModExp{eip2565: true},
	common.BytesToAddress([]byte{6}):    &bn256AddIstanbul{},
	common.BytesToAddress([]byte{7}):    &bn256ScalarMulIstanbul{},
	common.BytesToAddress([]byte{8}):    &bn256PairingIstanbul{},
	common.BytesToAddress([]byte{9}):    &blake2F{},
	common.BytesToAddress([]byte{0x0a}): &kzgPointEvaluation{},

	common.BytesToAddress([]byte{0x0f, 0x0a}): &bls12381G1Add{},
	common.BytesToAddress([]byte{0x0f, 0x0b}): &bls12381G1Mul{},
	common.BytesToAddress([]byte{0x0f, 0x0c}): &bls12381G1MultiExp{},
	common.BytesToAddress([]byte{0x0f, 0x0d}): &bls12381G2Add{},
	common.BytesToAddress([]byte{0x0f, 0x0e}): &bls12381G2Mul{},
	common.BytesToAddress([]byte{0x0f, 0x0f}): &bls12381G2MultiExp{},
	common.BytesToAddress([]byte{0x0f, 0x10}): &bls12381Pairing{},
	common.BytesToAddress([]byte{0x0f, 0x11}): &bls12381MapG1{},
	common.BytesToAddress([]byte{0x0f, 0x12}): &bls12381MapG2{},
}

// EIP-152 test vectors
var blake2FMalformedInputTests = []precompiledFailureTest{
	{
		Input:         "",
		ExpectedError: errBlake2FInvalidInputLength.Error(),
		Name:          "vector 0: empty input",
	},
	{
		Input:         "00000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001",
		ExpectedError: errBlake2FInvalidInputLength.Error(),
		Name:          "vector 1: less than 213 bytes input",
	},
	{
		Input:         "000000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001",
		ExpectedError: errBlake2FInvalidInputLength.Error(),
		Name:          "vector 2: more than 213 bytes input",
	},
	{
		Input:         "0000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000002",
		ExpectedError: errBlake2FInvalidFinalFlag.Error(),
		Name:          "vector 3: malformed final block indicator flag",
	},
}

func testPrecompiled(addr string, test precompiledTest, t *testing.T) {
	p := allPrecompiles[common.HexToAddress(addr)]
	in := common.Hex2Bytes(test.Input)
	gas := p.RequiredGas(in)
	t.Run(fmt.Sprintf("%s-Gas=%d", test.Name, gas), func(t *testing.T) {
		if res, _, err := RunPrecompiledContract(p, nil, common.Address{}, common.Address{}, in, gas); err != nil {
			t.Error(err)
		} else if common.Bytes2Hex(res) != test.Expected {
			t.Errorf("Expected %v, got %v", test.Expected, common.Bytes2Hex(res))
		}
		if expGas := test.Gas; expGas != gas {
			t.Errorf("%v: gas wrong, expected %d, got %d", test.Name, expGas, gas)
		}
		// Verify that the precompile did not touch the input buffer
		exp := common.Hex2Bytes(test.Input)
		if !bytes.Equal(in, exp) {
			t.Errorf("Precompiled %v modified input data", addr)
		}
	})
}

func testPrecompiledOOG(addr string, test precompiledTest, t *testing.T) {
	p := allPrecompiles[common.HexToAddress(addr)]
	in := common.Hex2Bytes(test.Input)
	gas := p.RequiredGas(in) - 1

	t.Run(fmt.Sprintf("%s-Gas=%d", test.Name, gas), func(t *testing.T) {
		_, _, err := RunPrecompiledContract(p, nil, common.Address{}, common.Address{}, in, gas)
		if err.Error() != "out of gas" {
			t.Errorf("Expected error [out of gas], got [%v]", err)
		}
		// Verify that the precompile did not touch the input buffer
		exp := common.Hex2Bytes(test.Input)
		if !bytes.Equal(in, exp) {
			t.Errorf("Precompiled %v modified input data", addr)
		}
	})
}

func testPrecompiledFailure(addr string, test precompiledFailureTest, t *testing.T) {
	p := allPrecompiles[common.HexToAddress(addr)]
	in := common.Hex2Bytes(test.Input)
	gas := p.RequiredGas(in)
	t.Run(test.Name, func(t *testing.T) {
		_, _, err := RunPrecompiledContract(p, nil, common.Address{}, common.Address{}, in, gas)
		if err.Error() != test.ExpectedError {
			t.Errorf("Expected error [%v], got [%v]", test.ExpectedError, err)
		}
		// Verify that the precompile did not touch the input buffer
		exp := common.Hex2Bytes(test.Input)
		if !bytes.Equal(in, exp) {
			t.Errorf("Precompiled %v modified input data", addr)
		}
	})
}

func benchmarkPrecompiled(addr string, test precompiledTest, bench *testing.B) {
	if test.NoBenchmark {
		return
	}
	p := allPrecompiles[common.HexToAddress(addr)]
	in := common.Hex2Bytes(test.Input)
	reqGas := p.RequiredGas(in)

	var (
		res  []byte
		err  error
		data = make([]byte, len(in))
	)

	bench.Run(fmt.Sprintf("%s-Gas=%d", test.Name, reqGas), func(bench *testing.B) {
		bench.ReportAllocs()
		start := time.Now()
		bench.ResetTimer()
		for i := 0; i < bench.N; i++ {
			copy(data, in)
			res, _, err = RunPrecompiledContract(p, nil, common.Address{}, common.Address{}, in, reqGas)
		}
		bench.StopTimer()
		elapsed := uint64(time.Since(start))
		if elapsed < 1 {
			elapsed = 1
		}
		gasUsed := reqGas * uint64(bench.N)
		bench.ReportMetric(float64(reqGas), "gas/op")
		// Keep it as uint64, multiply 100 to get two digit float later
		mgasps := (100 * 1000 * gasUsed) / elapsed
		bench.ReportMetric(float64(mgasps)/100, "mgas/s")
		//Check if it is correct
		if err != nil {
			bench.Error(err)
			return
		}
		if common.Bytes2Hex(res) != test.Expected {
			bench.Errorf("Expected %v, got %v", test.Expected, common.Bytes2Hex(res))
			return
		}
	})
}

// Benchmarks the sample inputs from the ECRECOVER precompile.
func BenchmarkPrecompiledEcrecover(bench *testing.B) {
	t := precompiledTest{
		Input:    "38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e000000000000000000000000000000000000000000000000000000000000001b38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e789d1dd423d25f0772d2748d60f7e4b81bb14d086eba8e8e8efb6dcff8a4ae02",
		Expected: "000000000000000000000000ceaccac640adf55b2028469bd36ba501f28b699d",
		Name:     "",
	}
	benchmarkPrecompiled("01", t, bench)
}

// Benchmarks the sample inputs from the SHA256 precompile.
func BenchmarkPrecompiledSha256(bench *testing.B) {
	t := precompiledTest{
		Input:    "38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e000000000000000000000000000000000000000000000000000000000000001b38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e789d1dd423d25f0772d2748d60f7e4b81bb14d086eba8e8e8efb6dcff8a4ae02",
		Expected: "811c7003375852fabd0d362e40e68607a12bdabae61a7d068fe5fdd1dbbf2a5d",
		Name:     "128",
	}
	benchmarkPrecompiled("02", t, bench)
}

// Benchmarks the sample inputs from the RIPEMD precompile.
func BenchmarkPrecompiledRipeMD(bench *testing.B) {
	t := precompiledTest{
		Input:    "38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e000000000000000000000000000000000000000000000000000000000000001b38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e789d1dd423d25f0772d2748d60f7e4b81bb14d086eba8e8e8efb6dcff8a4ae02",
		Expected: "0000000000000000000000009215b8d9882ff46f0dfde6684d78e831467f65e6",
		Name:     "128",
	}
	benchmarkPrecompiled("03", t, bench)
}

// Benchmarks the sample inputs from the identiy precompile.
func BenchmarkPrecompiledIdentity(bench *testing.B) {
	t := precompiledTest{
		Input:    "38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e000000000000000000000000000000000000000000000000000000000000001b38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e789d1dd423d25f0772d2748d60f7e4b81bb14d086eba8e8e8efb6dcff8a4ae02",
		Expected: "38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e000000000000000000000000000000000000000000000000000000000000001b38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e789d1dd423d25f0772d2748d60f7e4b81bb14d086eba8e8e8efb6dcff8a4ae02",
		Name:     "128",
	}
	benchmarkPrecompiled("04", t, bench)
}

// Tests the sample inputs from the ModExp EIP 198.
func TestPrecompiledModExp(t *testing.T)      { testJson("modexp", "05", t) }
func BenchmarkPrecompiledModExp(b *testing.B) { benchJson("modexp", "05", b) }

func TestPrecompiledModExpEip2565(t *testing.T)      { testJson("modexp_eip2565", "f5", t) }
func BenchmarkPrecompiledModExpEip2565(b *testing.B) { benchJson("modexp_eip2565", "f5", b) }

// Tests the sample inputs from the elliptic curve addition EIP 213.
func TestPrecompiledBn256Add(t *testing.T)      { testJson("bn256Add", "06", t) }
func BenchmarkPrecompiledBn256Add(b *testing.B) { benchJson("bn256Add", "06", b) }

// Tests OOG
func TestPrecompiledModExpOOG(t *testing.T) {
	modexpTests, err := loadJson("modexp")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range modexpTests {
		testPrecompiledOOG("05", test, t)
	}
}

// Tests the sample inputs from the elliptic curve scalar multiplication EIP 213.
func TestPrecompiledBn256ScalarMul(t *testing.T)      { testJson("bn256ScalarMul", "07", t) }
func BenchmarkPrecompiledBn256ScalarMul(b *testing.B) { benchJson("bn256ScalarMul", "07", b) }

// Tests the sample inputs from the elliptic curve pairing check EIP 197.
func TestPrecompiledBn256Pairing(t *testing.T)      { testJson("bn256Pairing", "08", t) }
func BenchmarkPrecompiledBn256Pairing(b *testing.B) { benchJson("bn256Pairing", "08", b) }

func TestPrecompiledBlake2F(t *testing.T)      { testJson("blake2F", "09", t) }
func BenchmarkPrecompiledBlake2F(b *testing.B) { benchJson("blake2F", "09", b) }

func TestPrecompileBlake2FMalformedInput(t *testing.T) {
	for _, test := range blake2FMalformedInputTests {
		testPrecompiledFailure("09", test, t)
	}
}

func TestPrecompiledEcrecover(t *testing.T) { testJson("ecRecover", "01", t) }

func testJson(name, addr string, t *testing.T) {
	tests, err := loadJson(name)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		testPrecompiled(addr, test, t)
	}
}

func testJsonFail(name, addr string, t *testing.T) {
	tests, err := loadJsonFail(name)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		testPrecompiledFailure(addr, test, t)
	}
}

func benchJson(name, addr string, b *testing.B) {
	tests, err := loadJson(name)
	if err != nil {
		b.Fatal(err)
	}
	for _, test := range tests {
		benchmarkPrecompiled(addr, test, b)
	}
}

func TestPrecompiledBLS12381G1Add(t *testing.T)      { testJson("blsG1Add", "f0a", t) }
func TestPrecompiledBLS12381G1Mul(t *testing.T)      { testJson("blsG1Mul", "f0b", t) }
func TestPrecompiledBLS12381G1MultiExp(t *testing.T) { testJson("blsG1MultiExp", "f0c", t) }
func TestPrecompiledBLS12381G2Add(t *testing.T)      { testJson("blsG2Add", "f0d", t) }
func TestPrecompiledBLS12381G2Mul(t *testing.T)      { testJson("blsG2Mul", "f0e", t) }
func TestPrecompiledBLS12381G2MultiExp(t *testing.T) { testJson("blsG2MultiExp", "f0f", t) }
func TestPrecompiledBLS12381Pairing(t *testing.T)    { testJson("blsPairing", "f10", t) }
func TestPrecompiledBLS12381MapG1(t *testing.T)      { testJson("blsMapG1", "f11", t) }
func TestPrecompiledBLS12381MapG2(t *testing.T)      { testJson("blsMapG2", "f12", t) }

func TestPrecompiledPointEvaluation(t *testing.T) { testJson("pointEvaluation", "0a", t) }

func BenchmarkPrecompiledBLS12381G1Add(b *testing.B)      { benchJson("blsG1Add", "f0a", b) }
func BenchmarkPrecompiledBLS12381G1Mul(b *testing.B)      { benchJson("blsG1Mul", "f0b", b) }
func BenchmarkPrecompiledBLS12381G1MultiExp(b *testing.B) { benchJson("blsG1MultiExp", "f0c", b) }
func BenchmarkPrecompiledBLS12381G2Add(b *testing.B)      { benchJson("blsG2Add", "f0d", b) }
func BenchmarkPrecompiledBLS12381G2Mul(b *testing.B)      { benchJson("blsG2Mul", "f0e", b) }
func BenchmarkPrecompiledBLS12381G2MultiExp(b *testing.B) { benchJson("blsG2MultiExp", "f0f", b) }
func BenchmarkPrecompiledBLS12381Pairing(b *testing.B)    { benchJson("blsPairing", "f10", b) }
func BenchmarkPrecompiledBLS12381MapG1(b *testing.B)      { benchJson("blsMapG1", "f11", b) }
func BenchmarkPrecompiledBLS12381MapG2(b *testing.B)      { benchJson("blsMapG2", "f12", b) }

// Failure tests
func TestPrecompiledBLS12381G1AddFail(t *testing.T)      { testJsonFail("blsG1Add", "f0a", t) }
func TestPrecompiledBLS12381G1MulFail(t *testing.T)      { testJsonFail("blsG1Mul", "f0b", t) }
func TestPrecompiledBLS12381G1MultiExpFail(t *testing.T) { testJsonFail("blsG1MultiExp", "f0c", t) }
func TestPrecompiledBLS12381G2AddFail(t *testing.T)      { testJsonFail("blsG2Add", "f0d", t) }
func TestPrecompiledBLS12381G2MulFail(t *testing.T)      { testJsonFail("blsG2Mul", "f0e", t) }
func TestPrecompiledBLS12381G2MultiExpFail(t *testing.T) { testJsonFail("blsG2MultiExp", "f0f", t) }
func TestPrecompiledBLS12381PairingFail(t *testing.T)    { testJsonFail("blsPairing", "f10", t) }
func TestPrecompiledBLS12381MapG1Fail(t *testing.T)      { testJsonFail("blsMapG1", "f11", t) }
func TestPrecompiledBLS12381MapG2Fail(t *testing.T)      { testJsonFail("blsMapG2", "f12", t) }

func loadJson(name string) ([]precompiledTest, error) {
	data, err := os.ReadFile(fmt.Sprintf("testdata/precompiles/%v.json", name))
	if err != nil {
		return nil, err
	}
	var testcases []precompiledTest
	err = json.Unmarshal(data, &testcases)
	return testcases, err
}

func loadJsonFail(name string) ([]precompiledFailureTest, error) {
	data, err := os.ReadFile(fmt.Sprintf("testdata/precompiles/fail-%v.json", name))
	if err != nil {
		return nil, err
	}
	var testcases []precompiledFailureTest
	err = json.Unmarshal(data, &testcases)
	return testcases, err
}

// BenchmarkPrecompiledBLS12381G1MultiExpWorstCase benchmarks the worst case we could find that still fits a gaslimit of 10MGas.
func BenchmarkPrecompiledBLS12381G1MultiExpWorstCase(b *testing.B) {
	task := "0000000000000000000000000000000008d8c4a16fb9d8800cce987c0eadbb6b3b005c213d44ecb5adeed713bae79d606041406df26169c35df63cf972c94be1" +
		"0000000000000000000000000000000011bc8afe71676e6730702a46ef817060249cd06cd82e6981085012ff6d013aa4470ba3a2c71e13ef653e1e223d1ccfe9" +
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
	input := task
	for i := 0; i < 4787; i++ {
		input = input + task
	}
	testcase := precompiledTest{
		Input:       input,
		Expected:    "0000000000000000000000000000000005a6310ea6f2a598023ae48819afc292b4dfcb40aabad24a0c2cb6c19769465691859eeb2a764342a810c5038d700f18000000000000000000000000000000001268ac944437d15923dc0aec00daa9250252e43e4b35ec7a19d01f0d6cd27f6e139d80dae16ba1c79cc7f57055a93ff5",
		Name:        "WorstCaseG1",
		NoBenchmark: false,
	}
	benchmarkPrecompiled("0c", testcase, b)
}

// BenchmarkPrecompiledBLS12381G2MultiExpWorstCase benchmarks the worst case we could find that still fits a gaslimit of 10MGas.
func BenchmarkPrecompiledBLS12381G2MultiExpWorstCase(b *testing.B) {
	task := "000000000000000000000000000000000d4f09acd5f362e0a516d4c13c5e2f504d9bd49fdfb6d8b7a7ab35a02c391c8112b03270d5d9eefe9b659dd27601d18f" +
		"000000000000000000000000000000000fd489cb75945f3b5ebb1c0e326d59602934c8f78fe9294a8877e7aeb95de5addde0cb7ab53674df8b2cfbb036b30b99" +
		"00000000000000000000000000000000055dbc4eca768714e098bbe9c71cf54b40f51c26e95808ee79225a87fb6fa1415178db47f02d856fea56a752d185f86b" +
		"000000000000000000000000000000001239b7640f416eb6e921fe47f7501d504fadc190d9cf4e89ae2b717276739a2f4ee9f637c35e23c480df029fd8d247c7" +
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
	input := task
	for i := 0; i < 1040; i++ {
		input = input + task
	}

	testcase := precompiledTest{
		Input:       input,
		Expected:    "0000000000000000000000000000000018f5ea0c8b086095cfe23f6bb1d90d45de929292006dba8cdedd6d3203af3c6bbfd592e93ecb2b2c81004961fdcbb46c00000000000000000000000000000000076873199175664f1b6493a43c02234f49dc66f077d3007823e0343ad92e30bd7dc209013435ca9f197aca44d88e9dac000000000000000000000000000000000e6f07f4b23b511eac1e2682a0fc224c15d80e122a3e222d00a41fab15eba645a700b9ae84f331ae4ed873678e2e6c9b000000000000000000000000000000000bcb4849e460612aaed79617255fd30c03f51cf03d2ed4163ca810c13e1954b1e8663157b957a601829bb272a4e6c7b8",
		Name:        "WorstCaseG2",
		NoBenchmark: false,
	}
	benchmarkPrecompiled("0f", testcase, b)
}

// ================== Tests for mpc extended precompiles ==================

func TestPrecompiledMPCRunBinaryOperation(t *testing.T) {
	// Arrange
	// Create an instance of mpcContract
	mpc := &mpcContract{}

	// Define multiple test cases for different operations
	testCases := []struct {
		input1         *big.Int
		input2         *big.Int
		expectedOutput *big.Int
		signature      uint32 // The signature of the operation being tested
		bits           byte   // The number of bits for the inputs
		args           byte   // The type of the argumants for the operation - 0 = BOTH_SECRET, 1 = LHS_PUBLIC, 2 = RHS_PUBLIC
	}{
		// Test case 1: Addition
		{
			input1:         big.NewInt(10),
			input2:         big.NewInt(5),
			expectedOutput: big.NewInt(15),
			signature:      signatureAdd,
			bits:           SUINT8_T,
			args:           BOTH_SECRET,
		},
		// Test case 2: Subtraction
		{
			input1:         big.NewInt(20),
			input2:         big.NewInt(8),
			expectedOutput: big.NewInt(12),
			signature:      signatureSub,
			bits:           SUINT8_T,
			args:           BOTH_SECRET,
		},
		// Test case 3: Multiplication
		{
			input1:         big.NewInt(7),
			input2:         big.NewInt(3),
			expectedOutput: big.NewInt(21),
			signature:      signatureMul,
			bits:           SUINT8_T,
			args:           BOTH_SECRET,
		},
		// Test case 4: Less than or equal
		{
			input1:         big.NewInt(5),
			input2:         big.NewInt(10),
			expectedOutput: big.NewInt(1),
			signature:      signatureLe,
			bits:           SUINT8_T,
			args:           BOTH_SECRET,
		},
		// Test case 5: Less than
		{
			input1:         big.NewInt(15),
			input2:         big.NewInt(20),
			expectedOutput: big.NewInt(1),
			signature:      signatureLt,
			bits:           SUINT8_T,
			args:           BOTH_SECRET,
		},
		// Test case 6: Equal
		{
			input1:         big.NewInt(25),
			input2:         big.NewInt(25),
			expectedOutput: big.NewInt(1),
			signature:      signatureEq,
			bits:           SUINT8_T,
			args:           BOTH_SECRET,
		},
		// Test case 7: Greater than or equal
		{
			input1:         big.NewInt(30),
			input2:         big.NewInt(25),
			expectedOutput: big.NewInt(1),
			signature:      signatureGe,
			bits:           SUINT8_T,
			args:           BOTH_SECRET,
		},
		// Test case 8: Greater than
		{
			input1:         big.NewInt(18),
			input2:         big.NewInt(15),
			expectedOutput: big.NewInt(1),
			signature:      signatureGt,
			bits:           SUINT8_T,
			args:           BOTH_SECRET,
		},
		// Test case 9: Not equal
		{
			input1:         big.NewInt(10),
			input2:         big.NewInt(5),
			expectedOutput: big.NewInt(1),
			signature:      signatureNe,
			bits:           SUINT8_T,
			args:           BOTH_SECRET,
		},
		// Test case 10: Min
		{
			input1:         big.NewInt(8),
			input2:         big.NewInt(12),
			expectedOutput: big.NewInt(8),
			signature:      signatureMin,
			bits:           SUINT8_T,
			args:           BOTH_SECRET,
		},
		// Test case 11: Max
		{
			input1:         big.NewInt(15),
			input2:         big.NewInt(10),
			expectedOutput: big.NewInt(15),
			signature:      signatureMax,
			bits:           SUINT8_T,
			args:           BOTH_SECRET,
		},
		// Test case 12: Division
		{
			input1:         big.NewInt(30),
			input2:         big.NewInt(5),
			expectedOutput: big.NewInt(6),
			signature:      signatureDiv,
			bits:           SUINT8_T,
			args:           BOTH_SECRET,
		},
		// Test case 13: Remainder
		{
			input1:         big.NewInt(28),
			input2:         big.NewInt(6),
			expectedOutput: big.NewInt(4),
			signature:      signatureRem,
			bits:           SUINT8_T,
			args:           BOTH_SECRET,
		},
		// Test case 14: Bitwise AND
		{
			input1:         big.NewInt(15),
			input2:         big.NewInt(10),
			expectedOutput: big.NewInt(10),
			signature:      signatureBitAnd,
			bits:           SUINT8_T,
			args:           BOTH_SECRET,
		},
		// Test case 15: Bitwise OR
		{
			input1:         big.NewInt(15),
			input2:         big.NewInt(10),
			expectedOutput: big.NewInt(15),
			signature:      signatureBitOr,
			bits:           SUINT8_T,
			args:           BOTH_SECRET,
		},
		// Test case 16: Bitwise XOR
		{
			input1:         big.NewInt(15),
			input2:         big.NewInt(10),
			expectedOutput: big.NewInt(5),
			signature:      signatureBitXor,
			bits:           SUINT8_T,
			args:           BOTH_SECRET,
		},
		// Test case 17: Shift Left
		{
			input1:         big.NewInt(5),
			input2:         big.NewInt(2),
			expectedOutput: big.NewInt(20),
			signature:      signatureShl,
			bits:           SUINT8_T,
			args:           BOTH_SECRET,
		},
		// Test case 18: Shift Right
		{
			input1:         big.NewInt(20),
			input2:         big.NewInt(2),
			expectedOutput: big.NewInt(5),
			signature:      signatureShr,
			bits:           SUINT8_T,
			args:           BOTH_SECRET,
		},

		// Test case 19: Addition with lhs as constant
		{
			input1:         big.NewInt(10),
			input2:         big.NewInt(5),
			expectedOutput: big.NewInt(15),
			signature:      signatureAdd,
			bits:           SUINT8_T,
			args:           LHS_PUBLIC,
		},

		// Test case 19: Addition with rhs as constant
		{
			input1:         big.NewInt(10),
			input2:         big.NewInt(5),
			expectedOutput: big.NewInt(15),
			signature:      signatureAdd,
			bits:           SUINT8_T,
			args:           RHS_PUBLIC,
		},

		// Test case 20: Large Addition
		{
			input1:         new(big.Int).SetUint64(4294967310),
			input2:         new(big.Int).SetUint64(4294967285),
			expectedOutput: new(big.Int).SetUint64(8589934595),
			signature:      signatureAdd,
			bits:           SUINT64_T,
			args:           BOTH_SECRET,
		},

		// Test case 21: Large Subtraction
		{
			input1:         new(big.Int).SetUint64(8589934595),
			input2:         new(big.Int).SetUint64(4294967285),
			expectedOutput: new(big.Int).SetUint64(4294967310),
			signature:      signatureSub,
			bits:           SUINT64_T,
			args:           BOTH_SECRET,
		},

		// Test case 22: Large Multiplication (64-bit result)
		{
			input1:         new(big.Int).SetUint64(487730528894985869),
			input2:         new(big.Int).SetUint64(2),
			expectedOutput: new(big.Int).SetUint64(975461057789971738),
			signature:      signatureMul,
			bits:           SUINT64_T,
			args:           BOTH_SECRET,
		},

		// Test case 23: Large Division (64-bit input)
		{
			input1:         new(big.Int).SetUint64(987654321098765),
			input2:         new(big.Int).SetUint64(123456789012345),
			expectedOutput: new(big.Int).SetUint64(8),
			signature:      signatureDiv,
			bits:           SUINT64_T,
			args:           BOTH_SECRET,
		},
	}

	// Act and Assert
	for _, testCase := range testCases {
		t.Run("", func(t *testing.T) {
			var input1, input2 []byte
			// Prepare first input
			if testCase.args == 0 || testCase.args == 2 { // lhs is a secret
				input1 = prepareInput(t, testCase.input1, testCase.bits, false, mpc)
			} else { // lhs is a constant
				input1 = prepareInput(t, testCase.input1, testCase.bits, true, mpc)
			}

			// Prepare second input
			if testCase.args == 0 || testCase.args == 1 { // rhs is a secret
				input2 = prepareInput(t, testCase.input2, testCase.bits, false, mpc)
			} else { // lhs is a constant
				input2 = prepareInput(t, testCase.input2, testCase.bits, true, mpc)
			}

			// Run the binary operation
			output, err := runBinaryOperationInput(testCase.signature, input1, input2, testCase.bits, testCase.args, mpc)
			if err != nil {
				require.NoError(t, err, "Expected no error")
			}

			// Run decrypt on the output
			mpcOutput, err := runDecrypt(output, testCase.bits, mpc)
			if err != nil {
				require.NoError(t, err, "Expected no error")
			}

			// Convert the output byte slice to a big.Int
			actualOutput := new(big.Int).SetBytes(mpcOutput)

			// Check if the output matches the expected output
			if actualOutput.Cmp(testCase.expectedOutput) != 0 {
				assert.Equal(t, testCase.expectedOutput, actualOutput, "Expected output does not match actual output")
			}
		})
	}
}

func prepareInput(t *testing.T, value *big.Int, bits byte, isConstant bool, mpc *mpcContract) []byte {
	if isConstant { // The value is a constant
		return prepareConstant(value)
	} else { // The value is a secret
		// Set the public input 1
		input, err := runSetPublic(value, bits, mpc)
		if err != nil {
			require.NoError(t, err, "Expected no error")
		}
		return input
	}
}

func runSetPublic(value *big.Int, bits byte, mpc *mpcContract) ([]byte, error) {
	input := make([]byte, FUNC_SIG_SIZE)
	binary.BigEndian.PutUint32(input[:FUNC_SIG_SIZE], signatureSetPublic)

	input = append(input, bits)                                         // Append the metadata
	input = append(input, make([]byte, METADATA_SIZE-UNIRY_MD_SIZE)...) // Append the metadata to 32 bytes

	valueBytes := value.Bytes()
	if len(valueBytes) < 32 {
		paddedBytes := make([]byte, 32-len(valueBytes))
		valueBytes = append(paddedBytes, valueBytes...)
	}

	input = append(input, valueBytes...)

	input1, err := mpc.Run(input)
	if err != nil {
		return nil, err
	}

	return input1, nil
}

func TestPrecompiledMPCRandoms(t *testing.T) {

	// Create an instance of mpcContract
	mpc := &mpcContract{}

	testCases := []struct {
		bits             byte // The number of bits for the inputs
		numRandomNumbers int
		upperBoundBits   int // The number of bits for the upper bound
		forBounded       bool
	}{
		// Test case 1:
		{
			bits:             SUINT8_T,
			numRandomNumbers: 4,
			upperBoundBits:   7,
			forBounded:       true,
		},

		{
			bits:             SUINT8_T,
			numRandomNumbers: 4,
			upperBoundBits:   0,
			forBounded:       false,
		},

		// Test case 2: large input
		{
			bits:             SUINT16_T,
			numRandomNumbers: 5,
			upperBoundBits:   10,
			forBounded:       true,
		},
		{
			bits:             SUINT16_T,
			numRandomNumbers: 3,
			upperBoundBits:   0,
			forBounded:       false,
		},
		// Test case 3:
		{
			bits:             SUINT32_T,
			numRandomNumbers: 2,
			upperBoundBits:   0,
			forBounded:       false,
		},

		{
			bits:             SUINT32_T,
			numRandomNumbers: 2,
			upperBoundBits:   30,
			forBounded:       true,
		},

		// Test case 4: large input
		{
			bits:             SUINT64_T,
			numRandomNumbers: 2,
			upperBoundBits:   0,
			forBounded:       false,
		},

		// Test case 5: large input
		{
			bits:             SBOOL_T,
			numRandomNumbers: 30,
			upperBoundBits:   0,
			forBounded:       false,
		},
	}
	// Act and Assert
	for _, testCase := range testCases {
		t.Run("", func(t *testing.T) {

			input := make([]byte, FUNC_SIG_SIZE)
			if !testCase.forBounded {
				binary.BigEndian.PutUint32(input[:FUNC_SIG_SIZE], signatureRand)
				input = append(input, testCase.bits) // Append the metadata
			} else {
				binary.BigEndian.PutUint32(input[:FUNC_SIG_SIZE], signatureRandBoundedBits)
				input = append(input, testCase.bits) // Append the metadata

				input = append(input, make([]byte, METADATA_SIZE-UNIRY_MD_SIZE)...) // Append the metadata to 32 bytes

				valueBytes := big.NewInt(int64(testCase.upperBoundBits)).Bytes()
				if len(valueBytes) < 32 {
					paddedBytes := make([]byte, 32-len(valueBytes))
					valueBytes = append(paddedBytes, valueBytes...)
				}

				input = append(input, valueBytes...)

			}

			// Create a slice to store the generated random numbers
			generatedRandomNumbers := make([]*big.Int, testCase.numRandomNumbers)

			// Generate random numbers
			for i := 0; i < testCase.numRandomNumbers; i++ {

				randGt, err := mpc.Run(input)
				require.NoError(t, err, "Expected no error")

				// Run decrypt on the result
				output, err := runDecrypt(randGt, testCase.bits, mpc)
				require.NoError(t, err, "Expected no error")

				generatedRandomNumbers[i] = new(big.Int).SetBytes(output)
			}

			if testCase.forBounded {
				// Check that all generated random numbers are within the specified number of bits
				for i := 0; i < testCase.numRandomNumbers; i++ {
					require.True(t, getSize(testCase.bits) >= testCase.upperBoundBits, "Random number exceeds the specified number of bits")
				}
			}

			// Check that all generated random numbers are not the same
			firstRandomNumber := generatedRandomNumbers[0]
			counter := 1
			for i := 1; i < testCase.numRandomNumbers; i++ {
				if generatedRandomNumbers[i].Cmp(firstRandomNumber) == 0 {
					counter++
				}
			}

			require.NotEqual(t, testCase.numRandomNumbers, counter)
		})
	}
}

func runBinaryOperationInput(signature uint32, input1, input2 []byte, bits, args byte, mpc *mpcContract) ([]byte, error) {
	input := make([]byte, FUNC_SIG_SIZE)
	binary.BigEndian.PutUint32(input[:FUNC_SIG_SIZE], signature)

	input = append(input, bits, bits, args)                              // Append the metadata
	input = append(input, make([]byte, METADATA_SIZE-BINARY_MD_SIZE)...) // Append the metadata to 32 bytes

	input = append(input, input1...)
	input = append(input, input2...)

	output, err := mpc.Run(input)
	if err != nil {
		return nil, err
	}

	return output, nil
}

func runDecrypt(value []byte, bits byte, mpc *mpcContract) ([]byte, error) {
	input := make([]byte, FUNC_SIG_SIZE)
	binary.BigEndian.PutUint32(input[:FUNC_SIG_SIZE], signatureDecrypt)

	input = append(input, bits)                                         // Append the metadata
	input = append(input, make([]byte, METADATA_SIZE-UNIRY_MD_SIZE)...) // Append the metadata to 32 bytes

	input = append(input, value...)

	output, err := mpc.Run(input)
	if err != nil {
		return nil, err
	}

	return output, nil
}

func prepareConstant(value *big.Int) []byte {
	valueBytes := value.Bytes()
	if len(valueBytes) < 32 {
		paddedBytes := make([]byte, 32-len(valueBytes))
		valueBytes = append(paddedBytes, valueBytes...)
	}

	return valueBytes
}

func TestPrecompiledMPCOffboardOnboard(t *testing.T) {
	// Arrange

	// Generate a new EVM for the on\off board functions
	evm := NewEVM(BlockContext{}, TxContext{}, nil, params.TestChainConfig, Config{})
	// Create an instance of mpcContract
	mpc := &mpcContract{}

	mpc.SetParams(evm, common.Address{}, common.Address{})

	// Define multiple test cases for different operations
	testCases := []struct {
		value *big.Int
		bits  byte // The number of bits for the inputs
	}{
		// Test case 1:
		{
			value: big.NewInt(10),
			bits:  SUINT8_T,
		},

		// Test case 2: large input
		{
			value: big.NewInt(987654321098765),
			bits:  SUINT8_T,
		},
	}

	// Act and Assert
	for _, testCase := range testCases {
		t.Run("", func(t *testing.T) {
			err := generateKeyForTesting()
			if err != nil {
				require.NoError(t, err, "Expected no error")
			}

			// Prepare input
			value, err := runSetPublic(testCase.value, testCase.bits, mpc)
			if err != nil {
				require.NoError(t, err, "Expected no error")
			}

			// Run offboard
			offboardInput := make([]byte, FUNC_SIG_SIZE)
			binary.BigEndian.PutUint32(offboardInput[:FUNC_SIG_SIZE], signatureOffboard)
			offboardInput = append(offboardInput, testCase.bits)                                // Append the metadata
			offboardInput = append(offboardInput, make([]byte, METADATA_SIZE-UNIRY_MD_SIZE)...) // Append the metadata to 32 bytes
			offboardInput = append(offboardInput, value...)

			cipher, err := mpc.Run(offboardInput)
			if err != nil {
				require.NoError(t, err, "Expected no error")
			}

			// Run onboard
			onboardInput := make([]byte, FUNC_SIG_SIZE)
			binary.BigEndian.PutUint32(onboardInput[:FUNC_SIG_SIZE], signatureOnboard)
			onboardInput = append(onboardInput, testCase.bits)                                // Append the metadata
			onboardInput = append(onboardInput, make([]byte, METADATA_SIZE-UNIRY_MD_SIZE)...) // Append the metadata to 32 bytes
			onboardInput = append(onboardInput, cipher...)

			val, err := mpc.Run(onboardInput)
			if err != nil {
				require.NoError(t, err, "Expected no error")
			}

			// Run decrypt on the output
			mpcOutput, err := runDecrypt(val, testCase.bits, mpc)
			if err != nil {
				require.NoError(t, err, "Expected no error")
			}

			// Convert the output byte slice to a big.Int
			actualOutput := new(big.Int).SetBytes(mpcOutput)

			// Check if the output matches the expected output
			if actualOutput.Cmp(testCase.value) != 0 {
				assert.Equal(t, testCase.value, actualOutput, "Expected output does not match actual output")
			}

			err = deleteTestingKey()
			if err != nil {
				require.NoError(t, err, "Expected no error")
			}
		})
	}
}

func generateKeyForTesting() error {
	key, err := generateAESKey()
	if err != nil {
		return err
	}

	// Write the key to the file
	err = writeAESKey(key, "key.txt")
	if err != nil {
		return err
	}

	return nil
}

func deleteTestingKey() error {

	// Remove the file
	err := deleteAESKey("key.txt")
	if err != nil {
		return err
	}

	return nil
}

func TestPrecompiledMPCTransfer(t *testing.T) {
	// Arrange
	// Create an instance of mpcContract
	mpc := &mpcContract{}

	// Define multiple test cases for different operations
	testCases := []struct {
		balance1         *big.Int
		balance2         *big.Int
		transferAmount   *big.Int
		expectedBalance1 *big.Int
		expectedBalance2 *big.Int
		bits             byte // The number of bits for the inputs
		args             byte // The type of the argumants for the operation - 0 = BOTH_SECRET, 1 = LHS_PUBLIC, 2 = RHS_PUBLIC
		err              string
	}{
		// Test case 1:
		{
			balance1:         big.NewInt(10),
			balance2:         big.NewInt(10),
			transferAmount:   big.NewInt(5),
			expectedBalance1: big.NewInt(5),
			expectedBalance2: big.NewInt(15),
			bits:             SUINT8_T,
			args:             BOTH_SECRET,
		},

		// Test case 2:
		{
			balance1:         big.NewInt(10),
			balance2:         big.NewInt(10),
			transferAmount:   big.NewInt(10),
			expectedBalance1: big.NewInt(0),
			expectedBalance2: big.NewInt(20),
			bits:             SUINT8_T,
			args:             BOTH_SECRET,
		},

		// Test case 3:
		{
			balance1:         big.NewInt(10),
			balance2:         big.NewInt(10),
			transferAmount:   big.NewInt(15),
			expectedBalance1: big.NewInt(10),
			expectedBalance2: big.NewInt(10),
			bits:             SUINT8_T,
			args:             BOTH_SECRET,
			err:              "not enough balance.",
		},

		// Test case 4:
		{
			balance1:         big.NewInt(10),
			balance2:         big.NewInt(10),
			transferAmount:   big.NewInt(5),
			expectedBalance1: big.NewInt(5),
			expectedBalance2: big.NewInt(15),
			bits:             SUINT8_T,
			// In the context of a transfer, scalar balances are irrelevant;
			// The only possibility for a scalar value is within the "amount" parameter.
			// Therefore, in this scenario, LHS_PUBLIC signifies a scalar amount, not balance1.
			args: LHS_PUBLIC,
		},
	}

	// Act and Assert
	for _, testCase := range testCases {
		t.Run("", func(t *testing.T) {
			// Prepare first input
			balance1, err := runSetPublic(testCase.balance1, testCase.bits, mpc)
			if err != nil {
				require.NoError(t, err, "Expected no error")
			}

			// Prepare second input
			balance2, err := runSetPublic(testCase.balance2, testCase.bits, mpc)
			if err != nil {
				require.NoError(t, err, "Expected no error")
			}

			// Prepare amount
			// In the context of a transfer, scalar balances are irrelevant;
			// The only possibility for a scalar value is within the "amount" parameter.
			// Therefore, in this scenario, BOTH_SECRET signifies a secret amount while LHS_PUBLIC signifies a scalar amount.
			var amount []byte
			if testCase.args == 0 { // amount is a secret
				amount = prepareInput(t, testCase.transferAmount, testCase.bits, false, mpc)
			} else { // amount is a constant
				amount = prepareInput(t, testCase.transferAmount, testCase.bits, true, mpc)
			}

			// Run transfer
			input := make([]byte, FUNC_SIG_SIZE)
			binary.BigEndian.PutUint32(input[:FUNC_SIG_SIZE], signatureTransfer)
			input = append(input, testCase.bits, testCase.bits, testCase.bits, testCase.args) // Append the metadata
			input = append(input, make([]byte, METADATA_SIZE-TRANSFER_MD_SIZE)...)            // Append the metadata to 32 bytes

			input = append(input, balance1...)
			input = append(input, balance2...)
			input = append(input, amount...)

			output, err := mpc.Run(input)
			if err != nil {
				if testCase.err != "" {
					assert.EqualError(t, err, testCase.err, "Expected error does not match actual error")
				} else {
					require.NoError(t, err, "Expected no error")
				}
			}

			new_balance1, new_balance2, res, err := splitIntoThreeSlices(output)
			if err != nil {
				require.NoError(t, err, "Expected no error")
			}

			// Run decrypt on the result
			result, err := runDecrypt(res, testCase.bits, mpc)
			if err != nil {
				require.NoError(t, err, "Expected no error")
			}

			// Convert the output byte slice to a big.Int
			actualOutput := new(big.Int).SetBytes(result)

			// Check if the output matches the expected output
			if testCase.err != "" {
				assert.NotEqual(t, big.NewInt(1), actualOutput, "Expected result does not match actual result")
			} else {
				assert.Equal(t, big.NewInt(1), actualOutput, "Expected result does not match actual result")
			}

			// Run decrypt on the new_balance1
			mpcOutput, err := runDecrypt(new_balance1, testCase.bits, mpc)
			if err != nil {
				require.NoError(t, err, "Expected no error")
			}

			// Convert the output byte slice to a big.Int
			actualOutput = new(big.Int).SetBytes(mpcOutput)

			// Check if the output matches the expected output
			assert.Equal(t, 0, actualOutput.Cmp(testCase.expectedBalance1), "Expected output does not match actual output")

			// Run decrypt on the new_balance2
			mpcOutput, err = runDecrypt(new_balance2, testCase.bits, mpc)
			if err != nil {
				require.NoError(t, err, "Expected no error")
			}

			// Convert the output byte slice to a big.Int
			actualOutput = new(big.Int).SetBytes(mpcOutput)

			// Check if the output matches the expected output
			assert.Equal(t, 0, actualOutput.Cmp(testCase.expectedBalance2), "Expected output does not match actual output")

		})
	}
}

func TestPrecompiledMPCTransferWithAllowance(t *testing.T) {
	// Arrange
	// Create an instance of mpcContract
	mpc := &mpcContract{}

	// Define multiple test cases for different operations
	testCases := []struct {
		balance1          *big.Int
		balance2          *big.Int
		transferAmount    *big.Int
		allowance         *big.Int
		expectedBalance1  *big.Int
		expectedBalance2  *big.Int
		expectedAllowance *big.Int
		bits              byte // The number of bits for the inputs
		args              byte // The type of the argumants for the operation - 0 = BOTH_SECRET, 1 = LHS_PUBLIC, 2 = RHS_PUBLIC
		err               string
	}{
		// Test case 1:
		{
			balance1:          big.NewInt(10),
			balance2:          big.NewInt(10),
			transferAmount:    big.NewInt(5),
			allowance:         big.NewInt(10),
			expectedBalance1:  big.NewInt(5),
			expectedBalance2:  big.NewInt(15),
			expectedAllowance: big.NewInt(5),
			bits:              SUINT8_T,
			args:              BOTH_SECRET,
		},

		// Test case 2:
		{
			balance1:          big.NewInt(10),
			balance2:          big.NewInt(10),
			transferAmount:    big.NewInt(5),
			allowance:         big.NewInt(5),
			expectedBalance1:  big.NewInt(5),
			expectedBalance2:  big.NewInt(15),
			expectedAllowance: big.NewInt(0),
			bits:              SUINT8_T,
			args:              BOTH_SECRET,
		},

		// Test case 3:
		{
			balance1:          big.NewInt(10),
			balance2:          big.NewInt(10),
			transferAmount:    big.NewInt(5),
			allowance:         big.NewInt(4),
			expectedBalance1:  big.NewInt(10),
			expectedBalance2:  big.NewInt(10),
			expectedAllowance: big.NewInt(4),
			bits:              SUINT8_T,
			args:              BOTH_SECRET,
			err:               "not allowed.",
		},

		// Test case 4:
		{
			balance1:          big.NewInt(10),
			balance2:          big.NewInt(10),
			transferAmount:    big.NewInt(5),
			allowance:         big.NewInt(5),
			expectedBalance1:  big.NewInt(5),
			expectedBalance2:  big.NewInt(15),
			expectedAllowance: big.NewInt(0),
			bits:              SUINT8_T,
			// In the context of a transfer, scalar balances are irrelevant;
			// The only possibility for a scalar value is within the "amount" parameter.
			// Therefore, in this scenario, LHS_PUBLIC signifies a scalar amount, not balance1.
			args: LHS_PUBLIC,
		},
	}

	// Act and Assert
	for _, testCase := range testCases {
		t.Run("", func(t *testing.T) {
			// Prepare first input
			balance1, err := runSetPublic(testCase.balance1, testCase.bits, mpc)
			if err != nil {
				require.NoError(t, err, "Expected no error")
			}

			// Prepare second input
			balance2, err := runSetPublic(testCase.balance2, testCase.bits, mpc)
			if err != nil {
				require.NoError(t, err, "Expected no error")
			}

			// Prepare allowance
			allowance, err := runSetPublic(testCase.allowance, testCase.bits, mpc)
			if err != nil {
				require.NoError(t, err, "Expected no error")
			}

			// Prepare amount
			// In the context of a transfer, scalar balances are irrelevant;
			// The only possibility for a scalar value is within the "amount" parameter.
			// Therefore, in this scenario, BOTH_SECRET signifies a secret amount while LHS_PUBLIC signifies a scalar amount.
			var amount []byte
			if testCase.args == 0 { // amount is a secret
				amount = prepareInput(t, testCase.transferAmount, testCase.bits, false, mpc)
			} else { // amount is a constant
				amount = prepareInput(t, testCase.transferAmount, testCase.bits, true, mpc)
			}

			// Run transfer
			input := make([]byte, FUNC_SIG_SIZE)
			binary.BigEndian.PutUint32(input[:FUNC_SIG_SIZE], signatureTransferWithAllowance)
			input = append(input, testCase.bits, testCase.bits, testCase.bits, testCase.bits, testCase.args) // Append the metadata
			input = append(input, make([]byte, METADATA_SIZE-TRANSFERALLOWANCE_MD_SIZE)...)                  // Append the metadata to 32 bytes

			input = append(input, balance1...)
			input = append(input, balance2...)
			input = append(input, amount...)
			input = append(input, allowance...)

			output, err := mpc.Run(input)
			if err != nil {
				if testCase.err != "" {
					assert.EqualError(t, err, testCase.err, "Expected error does not match actual error")
				} else {
					require.NoError(t, err, "Expected no error")
				}
			}

			newBalance1, newBalance2, res, newAllowance, err := splitIntoFourSlices(output)
			if err != nil {
				require.NoError(t, err, "Expected no error")
			}

			// Run decrypt on the result
			result, err := runDecrypt(res, testCase.bits, mpc)
			if err != nil {
				require.NoError(t, err, "Expected no error")
			}

			// Convert the output byte slice to a big.Int
			actualOutput := new(big.Int).SetBytes(result)

			// Check if the output matches the expected output
			if testCase.err != "" {
				assert.NotEqual(t, big.NewInt(1), actualOutput, "Expected result does not match actual result")
			} else {
				assert.Equal(t, big.NewInt(1), actualOutput, "Expected result does not match actual result")
			}

			// Run decrypt on the new_balance1
			mpcOutput, err := runDecrypt(newBalance1, testCase.bits, mpc)
			if err != nil {
				require.NoError(t, err, "Expected no error")
			}

			// Convert the output byte slice to a big.Int
			actualOutput = new(big.Int).SetBytes(mpcOutput)

			// Check if the output matches the expected output
			assert.Equal(t, 0, actualOutput.Cmp(testCase.expectedBalance1), "Expected output does not match actual output")

			// Run decrypt on the new_balance2
			mpcOutput, err = runDecrypt(newBalance2, testCase.bits, mpc)
			if err != nil {
				require.NoError(t, err, "Expected no error")
			}

			// Convert the output byte slice to a big.Int
			actualOutput = new(big.Int).SetBytes(mpcOutput)

			// Check if the output matches the expected output
			assert.Equal(t, 0, actualOutput.Cmp(testCase.expectedBalance2), "Expected output does not match actual output")

			// Run decrypt on the new_balance2
			mpcOutput, err = runDecrypt(newAllowance, testCase.bits, mpc)
			if err != nil {
				require.NoError(t, err, "Expected no error")
			}

			// Convert the output byte slice to a big.Int
			actualOutput = new(big.Int).SetBytes(mpcOutput)

			// Check if the output matches the expected output
			assert.Equal(t, 0, actualOutput.Cmp(testCase.expectedAllowance), "Expected output does not match actual output")

		})
	}
}

func TestPrecompiledMPCMux(t *testing.T) {
	// Arrange
	// Create an instance of mpcContract
	mpc := &mpcContract{}

	// Define multiple test cases for different operations
	testCases := []struct {
		input1         *big.Int
		input2         *big.Int
		selectionBit   *big.Int
		expectedOutput *big.Int
		bits           byte // The number of bits for the inputs
		args           byte // The type of the argumants for the operation - 0 = BOTH_SECRET, 1 = LHS_PUBLIC, 2 = RHS_PUBLIC
	}{
		// Test case 1:
		{
			input1:         big.NewInt(10),
			input2:         big.NewInt(5),
			selectionBit:   big.NewInt(1),
			expectedOutput: big.NewInt(5),
			bits:           SUINT8_T,
			args:           BOTH_SECRET,
		},

		// Test case 2:
		{
			input1:         big.NewInt(10),
			input2:         big.NewInt(5),
			selectionBit:   big.NewInt(0),
			expectedOutput: big.NewInt(10),
			bits:           SUINT8_T,
			args:           BOTH_SECRET,
		},
	}

	// Act and Assert
	for _, testCase := range testCases {
		t.Run("", func(t *testing.T) {
			var input1, input2 []byte
			// Prepare first input
			if testCase.args == 0 || testCase.args == 2 { // lhs is a secret
				input1 = prepareInput(t, testCase.input1, testCase.bits, false, mpc)
			} else { // lhs is a constant
				input1 = prepareInput(t, testCase.input1, testCase.bits, true, mpc)
			}

			// Prepare second input
			if testCase.args == 0 || testCase.args == 1 { // rhs is a secret
				input2 = prepareInput(t, testCase.input2, testCase.bits, false, mpc)
			} else { // lhs is a constant
				input2 = prepareInput(t, testCase.input2, testCase.bits, true, mpc)
			}

			// Prepare the selection bit
			bit, err := runSetPublic(testCase.selectionBit, testCase.bits, mpc)
			if err != nil {
				require.NoError(t, err, "Expected no error")
			}

			// Run Mux
			input := make([]byte, FUNC_SIG_SIZE)
			binary.BigEndian.PutUint32(input[:FUNC_SIG_SIZE], signatureMux)
			input = append(input, testCase.bits, testCase.bits, testCase.args)   // Append the metadata
			input = append(input, make([]byte, METADATA_SIZE-BINARY_MD_SIZE)...) // Append the metadata to 32 bytes
			input = append(input, bit...)
			input = append(input, input1...)
			input = append(input, input2...)

			mpcOutput, err := mpc.Run(input)
			if err != nil {
				require.NoError(t, err, "Expected no error")
			}

			// Run decrypt on the result
			output, err := runDecrypt(mpcOutput, testCase.bits, mpc)
			if err != nil {
				require.NoError(t, err, "Expected no error")
			}

			// Convert the output byte slice to a big.Int
			actualOutput := new(big.Int).SetBytes(output)

			// Check if the output matches the expected output
			if actualOutput.Cmp(testCase.expectedOutput) != 0 {
				assert.Equal(t, testCase.expectedOutput, actualOutput, "Expected output does not match actual output")
			}
		})
	}
}

func TestPrecompiledMPCNot(t *testing.T) {
	// Arrange
	// Create an instance of mpcContract
	mpc := &mpcContract{}

	// Define multiple test cases for different operations
	testCases := []struct {
		input *big.Int
	}{
		// Test case 1:
		{
			input: big.NewInt(0),
		},

		// Test case 2:
		{
			input: big.NewInt(1),
		},
	}

	// Act and Assert
	for _, testCase := range testCases {
		t.Run("", func(t *testing.T) {
			// Prepare the input
			val, err := runSetPublic(testCase.input, byte(1), mpc)
			if err != nil {
				require.NoError(t, err, "Expected no error")
			}

			// Run Not
			input := make([]byte, FUNC_SIG_SIZE)
			binary.BigEndian.PutUint32(input[:FUNC_SIG_SIZE], signatureNot)
			input = append(input, byte(SBOOL_T))                                // Append the metadata
			input = append(input, make([]byte, METADATA_SIZE-UNIRY_MD_SIZE)...) // Append the metadata to 32 bytes
			input = append(input, val...)

			mpcOutput, err := mpc.Run(input)
			if err != nil {
				require.NoError(t, err, "Expected no error")
			}

			// Run decrypt on the result
			output, err := runDecrypt(mpcOutput, byte(SBOOL_T), mpc)
			if err != nil {
				require.NoError(t, err, "Expected no error")
			}

			// Convert the output byte slice to a big.Int
			actualOutput := new(big.Int).SetBytes(output)
			expectedOutput := new(big.Int).Sub(big.NewInt(1), testCase.input)

			// Check if the output matches the expected output
			if actualOutput.Cmp(expectedOutput) != 0 {
				assert.Equal(t, expectedOutput, actualOutput, "Expected output does not match actual output")
			}
		})
	}
}

func TestPrecompiledMPCValidateInput(t *testing.T) {
	testCases := []struct {
		input           *big.Int
		contractAddress common.Address
		funcSig         [4]byte
		userPrivKey     string
		bits            int
	}{
		// Test case 1:
		{
			input:           big.NewInt(1000),
			contractAddress: common.Address{1},
			funcSig:         [4]byte{1, 32, 0, 0},
			userPrivKey:     "2e0834786285daccd064ca17f1654f67b4aef298acbb82cef9ec422fb4975622",
			bits:            SUINT64_T,
		},

		// Test case 2:
		{
			input:           big.NewInt(100),
			contractAddress: common.Address{10},
			funcSig:         [4]byte{88, 2, 0, 4},
			userPrivKey:     "3eca17786285d6ccd064ca17f1654f67b4aef298acbb82cef6ec422fb4975623",
			bits:            SUINT32_T,
		},
		// Test case 3:
		{
			input:           big.NewInt(500),
			contractAddress: common.Address{5},
			funcSig:         [4]byte{10, 20, 30, 40},
			userPrivKey:     "3eca17786285d6ccd064ca17f1654f67b4aef298acbb82cef6ec422fb4975623",
			bits:            SUINT16_T,
		},

		// Test case 4:
		{
			input:           big.NewInt(123),
			contractAddress: common.Address{15},
			funcSig:         [4]byte{100, 200, 150, 50},
			userPrivKey:     "3eca17786285d6ccd064ca17f1654f67b4aef298acbb82cef6ec422fb4975623",
			bits:            SUINT8_T,
		},
	}
	for _, testCase := range testCases {
		t.Run("", func(t *testing.T) {
			// Arrange and Assert
			evm := NewEVM(BlockContext{}, TxContext{}, nil, params.TestChainConfig, Config{})

			// Create an instance of mpcContract
			mpc := &mpcContract{}
			mpc.SetParams(evm, testCase.contractAddress, common.Address{})

			// Set the function signature
			mpc.evm.funcSig = testCase.funcSig
			mpc.evm.depth = 1 // Only works on depth 1

			// Pick some key
			privateKeyForSign, err := hex.DecodeString(testCase.userPrivKey)
			assert.NoError(t, err)

			// Get the related private key
			privateKey, err := crypto.ToECDSA(privateKeyForSign)
			assert.NoError(t, err)

			// Derive the address
			userAddr := crypto.PubkeyToAddress(privateKey.PublicKey)
			commonAddr := common.BytesToAddress(userAddr.Bytes())

			// Generate and save the user key
			key, err := genUserKeyFromSeed(userAddr.Bytes())

			assert.NoError(t, err)
			pt := testCase.input.FillBytes(make([]byte, 16))

			//Generate the ciphertext
			ct, err := encrypt(key, pt)
			assert.NoError(t, err)

			// Act and Assert
			validateInputTextInput := make([]byte, FUNC_SIG_SIZE)
			binary.BigEndian.PutUint32(validateInputTextInput[:FUNC_SIG_SIZE], signatureValidateCiphertext)
			validateInputTextInput = append(validateInputTextInput, SUINT16_T)                                    // Set the number of bits
			validateInputTextInput = append(validateInputTextInput, make([]byte, METADATA_SIZE-UNIRY_MD_SIZE)...) // Append the metadata to 32 bytes

			validateInputTextInput = append(validateInputTextInput, ct...) // Append the metadata

			// Set the user address
			evm.Origin = commonAddr

			// Generate signature for the user input
			signature, err := SignIT(evm.Origin[:], mpc.caller[:], testCase.funcSig[:], ct, privateKeyForSign)
			assert.NoError(t, err)

			// Expected format of signature
			signature = append(make([]byte, 64), signature...)

			validateInputTextInput = append(validateInputTextInput, signature...)

			// Run the validateCiphertext contract with EVM format of inputs
			valit, err := mpc.Run(validateInputTextInput)
			if err != nil {
				require.NoError(t, err, "Expected no error")
			}

			// Run decrypt on the output
			mpcOutput, err := runDecrypt(valit, SUINT16_T, mpc)
			if err != nil {
				require.NoError(t, err, "Expected no error")
			}
			actualOutput := new(big.Int).SetBytes(mpcOutput)

			// Check if the output matches the expected output
			if actualOutput.Cmp(testCase.input) != 0 {
				assert.Equal(t, testCase.input, actualOutput, "Expected output does not match actual output")
			}
		})
	}
}

func TestPrecompiledMPCUserKey(t *testing.T) {
	// Arrange

	// Define multiple test cases for different checks:
	// 1. check that for a given address and signature (including the RSA public key and the signature on it), a valid user key is generated
	// 2. check that for the same address and different RSA keys, the same user key is returned
	// 3. check that for different addresses, different user key is returned
	testCases := []struct {
		privateKey string   // The RSA private key
		signature  []byte   // The signature is a concatenation of the RSA public key and the signature on it
		user       []byte   // The user address in a EVM format (add bytes that includes the size, padding, etc.)
		address    []byte   // The address in bytes
		value      *big.Int // The value to be checked
		bits       byte     // The number of bits for the inputs
	}{
		// Test case 1:
		{
			privateKey: "308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100b560c4977c053ee98dc7b0119c698b3cd7d684b2128e4c5f3f556bf8389f04088d8aebbe8aa7e533afa093c79b55b3a3d6d014d08c0a04c98ae97545bd42abd52664abc36ea189b73693ee43d8f630b3ecfdb39a38d37e009075448bb052fd3d2ca6dab9c7d4ddc036c3cafcecd421b969d3a04b9e6eb5470e9709992e20257ef4a1d677733f2f176f6ceff9f7197f32a4b7d6ed3809b44d1090fc1b522a3e77c91a82c6d89cb4d65844b051580d549859e226a4966be8655bb579c127767dfdb7d23e8bbaefb4b512df51785acd6140cf759fc7f412b6055dc408ec9b4f7049302737438cda15fc20df691672dd551c1c89b53a26be9aeb50c8333644cfd6fb020301000102820100030c9f3b1724e1d5495c5246dcb81f21be8800891b78c15df15e707a73a470bf1e76de09c10901f874ae6d6d9a42be6435c1b967dc29415bbfa983eb6a08251d681008d0d1b4b9f03064e8af8fb938a7fdba322e322d2daa85f669259a75e11e099256f43c3a6bba5fbe20ee833bf9c2c53db293ffadadffb8d2df3a3d0bae82780b60514a1fd01437b303de187d1fe8fb88560bb6a560fff9e17de996f3b93074dd72dd879f3fc3d1a8860de2cffa6082ca656eec5152000c1c7ef08f3c3abee57c17eac4f0ee4446576998aa5c2ef5a9b25b24620f2671eb94a4eb1643754abd6661a86e7b2d044b1293fe2a7e700334693e2ced5e366b865b59b7ae0f730102818100e0009bae6a06e8f0789b2d16658a951b11bd4ad02a12ef4c710438a01339878cac4bb11dda788d4b50126a5d97cca267aea13cdb9baec27f63b7ebef1043a6344959c7d399722d73823630041290c512f7a5e52eb1076406f5e7ad3acb6b2ed64a08d2bc62375877b497a9ad9b7e84da0ce5538648a7c33f8505d6a7e1f5f78102818100cf49752e9bc2b4a63fb8e86915da1a29bbd81e575a32e3ea40b0a3b95062f331a3f6852148201d59b8fab755d51a44b000af990a3be0febb6c5cf19fc522dca30a6c9d16a2d683f49c1e4b65e303d7d5c53822fbaf0dfdc65b8dfcddd2a56494857b0a0c8c4426fc9e5b932f0360469b174c6b0cc6d2713876d794af26f7ec7b028181008fcb1424f45f172d36deb624c86e1ba552cfe6b4962dad7bae98fd1894febb2aec77726d2d8f717445246d2f4380d348276bcdbb53c6ed8805254dc91af1b241a24c85e0298287f6bc41b8b5048df65464b113dbd33c6153ae8b584283ce7c348735fec17b72f7d17016638fd45f753cdc466245b3622e0e1a8052f9562e250102818023e073eeb838cfe98257efa9d8856247dce24006206f747123f72eaf31519f03f57c0278cb31fbc27eb8ae28a5f4a0f4d1799304696ebcc815ae5487b1a82205fa14e86f7589a95719fa48547f21382720b6619fac21c0cda7250122278646cd49f90cb93541ca79a8b2f2db8d3b099d683feabb506236046ed54b3fb17ff1a70281801e78082019813b90f5e3dedb61f2d5ff56037eca7903f0300ef316421903d7d9755a7398ce47ca763522b830d406e3cd986e4abea09333b65d1233557d2ba789cbf4c0a259d17b65649414cc3e1a8cea74eff31d87c6b9095e2764b44b54a2bc38185936a9aa2fe6688caa7c1c675e07264873eb60db82bd9360f48bafbe01b8",
			signature:  []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 103, 253, 209, 217, 208, 208, 69, 90, 35, 176, 207, 192, 104, 152, 152, 219, 116, 177, 234, 133, 188, 14, 177, 229, 123, 154, 57, 104, 31, 124, 124, 141, 101, 86, 188, 10, 94, 253, 34, 62, 200, 78, 154, 173, 2, 33, 185, 212, 136, 249, 52, 3, 77, 83, 252, 87, 159, 139, 159, 148, 107, 75, 88, 211, 25, 1, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 181, 96, 196, 151, 124, 5, 62, 233, 141, 199, 176, 17, 156, 105, 139, 60, 215, 214, 132, 178, 18, 142, 76, 95, 63, 85, 107, 248, 56, 159, 4, 8, 141, 138, 235, 190, 138, 167, 229, 51, 175, 160, 147, 199, 155, 85, 179, 163, 214, 208, 20, 208, 140, 10, 4, 201, 138, 233, 117, 69, 189, 66, 171, 213, 38, 100, 171, 195, 110, 161, 137, 183, 54, 147, 238, 67, 216, 246, 48, 179, 236, 253, 179, 154, 56, 211, 126, 0, 144, 117, 68, 139, 176, 82, 253, 61, 44, 166, 218, 185, 199, 212, 221, 192, 54, 195, 202, 252, 236, 212, 33, 185, 105, 211, 160, 75, 158, 110, 181, 71, 14, 151, 9, 153, 46, 32, 37, 126, 244, 161, 214, 119, 115, 63, 47, 23, 111, 108, 239, 249, 247, 25, 127, 50, 164, 183, 214, 237, 56, 9, 180, 77, 16, 144, 252, 27, 82, 42, 62, 119, 201, 26, 130, 198, 216, 156, 180, 214, 88, 68, 176, 81, 88, 13, 84, 152, 89, 226, 38, 164, 150, 107, 232, 101, 91, 181, 121, 193, 39, 118, 125, 253, 183, 210, 62, 139, 186, 239, 180, 181, 18, 223, 81, 120, 90, 205, 97, 64, 207, 117, 159, 199, 244, 18, 182, 5, 93, 196, 8, 236, 155, 79, 112, 73, 48, 39, 55, 67, 140, 218, 21, 252, 32, 223, 105, 22, 114, 221, 85, 28, 28, 137, 181, 58, 38, 190, 154, 235, 80, 200, 51, 54, 68, 207, 214, 251, 2, 3, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			user:       []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			address:    []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			value:      big.NewInt(10),
			bits:       SUINT8_T,
		},

		// Test case 2: same address, different RSA keys
		{
			privateKey: "308204bc020100300d06092a864886f70d0101010500048204a6308204a20201000282010100a9ae6c22ea488d536b60a700091227270d7403f94698873a81915800474b4fdf30766d066230fe0f82bd6051f38b30601f225a6a5a86fad4aedfca263dea7c4726014b5932fb48480999080edcaab6042e5061c1dca7adc0ecc8ead1e2ed3bfc4ff0b9b43a26e506b81ae3e5e6428b84482952f0f3cfd0368dcec96286b60c529ef64038b59cd530dfe742816c8e5c862faa9e0f43b370d6806cd7d708a413b5213b6546389dcf6f5ec805d343ce48d8c0ff30b0d18748b93b827893511291774d718ff0d90d90043c934e35031888e831624d0bf8b421e37f49eee8c9fa3f8eb691c615726a7674b9f625209ed12e6464fac2e3505f84ac5a5480905615095f020301000102820100180d43036ea5857035fff24c1d5261bdb5b8cf38b8c5602319409ff2677e0914004b991d56dd23a0d1386f7c7902d982ebdc33bd7042ed2fd3f0a18d4028dfcae4b1399c003a56e9972ab100b7a3746a2d4d1ee8f03d231cfe08bb785ad6a3dd1a511611b24dd71857ba6ab97e251ff4f5419e4c7752eac1ab8ce1f0ec5ac66e2837c3bf94bf9aea586cb552b9c959d94a147e4a6201f38216fbe3269211f0094ed779b4d503a89d645ce254b90f9a560d068fea1711ada8c576fa0ff61050c10899fced9c35a62c33e378db1e7adf3e82b6005d9c0897fa27f881081d023913c65aa03ba69d95707a2681145f493859b53344bc0ffc6dbed8f84c8a629a3a7902818100b9af28a8d8527fe85b09a4da663679f2536ec2504fe6e7fe5fd27756d77713173b7bcac65528ec2ad43573c623f21d1f71f5eb961e3466d9abf63f0fe81b89b4324298860229ce2fcf10198dea597c4f8d328788dcd0434cb90b9ed95933e7799f09131b743ce6fd8bfea86db572cf49796869ff56af6e5463f6ccf0733ff96502818100e9efe450595bb8d4de823dfaad594cf0ea2cba71054c46e38a7d2024309c52959b234cf6707b7bf6638b236fe5ea7fba89f249e3f8c40f2cb32fc1354a4b86d1f5855cee8f7b25c43d9bb165ff2092d88a0c48d7f28eb5136d7666c02cc3460cf80d61aa4396bef20873caeb6e5f53e1ce4e66c2de3c78fb8f8b81abe8086d730281804db4918d6749cf214bc7d3675a52fde17d2ce2c07d4fa2527f833251f3456f85cf6cd4c4ff2a6afad967ad15844174128ebc5d64ab2b3ec765015e0ea811ae24eccb95ccaee713d44a10f0c0c50bc1cc00c8de9355e509e4f7a3774c79da10ca82d5675b9bdf48c35e6ca9cb8f9d8645b73b0cf0c0341635d6c797a82072eb4902818058931a114a242e717ae6396d66a13f3ea08bdaf3dc1bab6390161c4b579478b8688b0f22e827f921ab430d61daddd50ade1c3cd9f260d996052a79af21b8430dd036749f66f82bae87dd21680b175c425cd295ea1dcee6c4ba577044272eb0a14c72549e51050cbb3b740c4ae3f9781b3130023c9a44af522061a3f160e37ffd0281806e54b359af83ef508b56cdaddd87380c007ca103cd5454be80b076d794011b76e5ec354dce61d002e3ec44be31391a94fd0b78dca2ffa72fde5d05297982c868ffbc41bdc043f075512d482821454e0a7010f412950b02f8444a0b289ec2cb2c94f0ce7510907950b31a29e878e380c649810550c63adb9fe4615d98ea33f341",
			signature:  []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 103, 198, 101, 100, 216, 47, 19, 68, 79, 20, 113, 159, 214, 232, 81, 104, 213, 74, 55, 171, 219, 8, 125, 221, 253, 179, 231, 98, 97, 210, 204, 122, 238, 7, 134, 100, 98, 61, 251, 232, 59, 185, 184, 34, 132, 136, 108, 6, 213, 194, 152, 200, 87, 201, 79, 119, 184, 195, 182, 5, 2, 129, 156, 28, 72, 0, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 169, 174, 108, 34, 234, 72, 141, 83, 107, 96, 167, 0, 9, 18, 39, 39, 13, 116, 3, 249, 70, 152, 135, 58, 129, 145, 88, 0, 71, 75, 79, 223, 48, 118, 109, 6, 98, 48, 254, 15, 130, 189, 96, 81, 243, 139, 48, 96, 31, 34, 90, 106, 90, 134, 250, 212, 174, 223, 202, 38, 61, 234, 124, 71, 38, 1, 75, 89, 50, 251, 72, 72, 9, 153, 8, 14, 220, 170, 182, 4, 46, 80, 97, 193, 220, 167, 173, 192, 236, 200, 234, 209, 226, 237, 59, 252, 79, 240, 185, 180, 58, 38, 229, 6, 184, 26, 227, 229, 230, 66, 139, 132, 72, 41, 82, 240, 243, 207, 208, 54, 141, 206, 201, 98, 134, 182, 12, 82, 158, 246, 64, 56, 181, 156, 213, 48, 223, 231, 66, 129, 108, 142, 92, 134, 47, 170, 158, 15, 67, 179, 112, 214, 128, 108, 215, 215, 8, 164, 19, 181, 33, 59, 101, 70, 56, 157, 207, 111, 94, 200, 5, 211, 67, 206, 72, 216, 192, 255, 48, 176, 209, 135, 72, 185, 59, 130, 120, 147, 81, 18, 145, 119, 77, 113, 143, 240, 217, 13, 144, 4, 60, 147, 78, 53, 3, 24, 136, 232, 49, 98, 77, 11, 248, 180, 33, 227, 127, 73, 238, 232, 201, 250, 63, 142, 182, 145, 198, 21, 114, 106, 118, 116, 185, 246, 37, 32, 158, 209, 46, 100, 100, 250, 194, 227, 80, 95, 132, 172, 90, 84, 128, 144, 86, 21, 9, 95, 2, 3, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			user:       []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			address:    []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			value:      big.NewInt(10),
			bits:       SUINT8_T,
		},

		// Test case 3: different address
		{
			privateKey: "308204bc020100300d06092a864886f70d0101010500048204a6308204a20201000282010100a9ae6c22ea488d536b60a700091227270d7403f94698873a81915800474b4fdf30766d066230fe0f82bd6051f38b30601f225a6a5a86fad4aedfca263dea7c4726014b5932fb48480999080edcaab6042e5061c1dca7adc0ecc8ead1e2ed3bfc4ff0b9b43a26e506b81ae3e5e6428b84482952f0f3cfd0368dcec96286b60c529ef64038b59cd530dfe742816c8e5c862faa9e0f43b370d6806cd7d708a413b5213b6546389dcf6f5ec805d343ce48d8c0ff30b0d18748b93b827893511291774d718ff0d90d90043c934e35031888e831624d0bf8b421e37f49eee8c9fa3f8eb691c615726a7674b9f625209ed12e6464fac2e3505f84ac5a5480905615095f020301000102820100180d43036ea5857035fff24c1d5261bdb5b8cf38b8c5602319409ff2677e0914004b991d56dd23a0d1386f7c7902d982ebdc33bd7042ed2fd3f0a18d4028dfcae4b1399c003a56e9972ab100b7a3746a2d4d1ee8f03d231cfe08bb785ad6a3dd1a511611b24dd71857ba6ab97e251ff4f5419e4c7752eac1ab8ce1f0ec5ac66e2837c3bf94bf9aea586cb552b9c959d94a147e4a6201f38216fbe3269211f0094ed779b4d503a89d645ce254b90f9a560d068fea1711ada8c576fa0ff61050c10899fced9c35a62c33e378db1e7adf3e82b6005d9c0897fa27f881081d023913c65aa03ba69d95707a2681145f493859b53344bc0ffc6dbed8f84c8a629a3a7902818100b9af28a8d8527fe85b09a4da663679f2536ec2504fe6e7fe5fd27756d77713173b7bcac65528ec2ad43573c623f21d1f71f5eb961e3466d9abf63f0fe81b89b4324298860229ce2fcf10198dea597c4f8d328788dcd0434cb90b9ed95933e7799f09131b743ce6fd8bfea86db572cf49796869ff56af6e5463f6ccf0733ff96502818100e9efe450595bb8d4de823dfaad594cf0ea2cba71054c46e38a7d2024309c52959b234cf6707b7bf6638b236fe5ea7fba89f249e3f8c40f2cb32fc1354a4b86d1f5855cee8f7b25c43d9bb165ff2092d88a0c48d7f28eb5136d7666c02cc3460cf80d61aa4396bef20873caeb6e5f53e1ce4e66c2de3c78fb8f8b81abe8086d730281804db4918d6749cf214bc7d3675a52fde17d2ce2c07d4fa2527f833251f3456f85cf6cd4c4ff2a6afad967ad15844174128ebc5d64ab2b3ec765015e0ea811ae24eccb95ccaee713d44a10f0c0c50bc1cc00c8de9355e509e4f7a3774c79da10ca82d5675b9bdf48c35e6ca9cb8f9d8645b73b0cf0c0341635d6c797a82072eb4902818058931a114a242e717ae6396d66a13f3ea08bdaf3dc1bab6390161c4b579478b8688b0f22e827f921ab430d61daddd50ade1c3cd9f260d996052a79af21b8430dd036749f66f82bae87dd21680b175c425cd295ea1dcee6c4ba577044272eb0a14c72549e51050cbb3b740c4ae3f9781b3130023c9a44af522061a3f160e37ffd0281806e54b359af83ef508b56cdaddd87380c007ca103cd5454be80b076d794011b76e5ec354dce61d002e3ec44be31391a94fd0b78dca2ffa72fde5d05297982c868ffbc41bdc043f075512d482821454e0a7010f412950b02f8444a0b289ec2cb2c94f0ce7510907950b31a29e878e380c649810550c63adb9fe4615d98ea33f341",
			signature:  []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 103, 198, 101, 100, 216, 47, 19, 68, 79, 20, 113, 159, 214, 232, 81, 104, 213, 74, 55, 171, 219, 8, 125, 221, 253, 179, 231, 98, 97, 210, 204, 122, 238, 7, 134, 100, 98, 61, 251, 232, 59, 185, 184, 34, 132, 136, 108, 6, 213, 194, 152, 200, 87, 201, 79, 119, 184, 195, 182, 5, 2, 129, 156, 28, 72, 0, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 169, 174, 108, 34, 234, 72, 141, 83, 107, 96, 167, 0, 9, 18, 39, 39, 13, 116, 3, 249, 70, 152, 135, 58, 129, 145, 88, 0, 71, 75, 79, 223, 48, 118, 109, 6, 98, 48, 254, 15, 130, 189, 96, 81, 243, 139, 48, 96, 31, 34, 90, 106, 90, 134, 250, 212, 174, 223, 202, 38, 61, 234, 124, 71, 38, 1, 75, 89, 50, 251, 72, 72, 9, 153, 8, 14, 220, 170, 182, 4, 46, 80, 97, 193, 220, 167, 173, 192, 236, 200, 234, 209, 226, 237, 59, 252, 79, 240, 185, 180, 58, 38, 229, 6, 184, 26, 227, 229, 230, 66, 139, 132, 72, 41, 82, 240, 243, 207, 208, 54, 141, 206, 201, 98, 134, 182, 12, 82, 158, 246, 64, 56, 181, 156, 213, 48, 223, 231, 66, 129, 108, 142, 92, 134, 47, 170, 158, 15, 67, 179, 112, 214, 128, 108, 215, 215, 8, 164, 19, 181, 33, 59, 101, 70, 56, 157, 207, 111, 94, 200, 5, 211, 67, 206, 72, 216, 192, 255, 48, 176, 209, 135, 72, 185, 59, 130, 120, 147, 81, 18, 145, 119, 77, 113, 143, 240, 217, 13, 144, 4, 60, 147, 78, 53, 3, 24, 136, 232, 49, 98, 77, 11, 248, 180, 33, 227, 127, 73, 238, 232, 201, 250, 63, 142, 182, 145, 198, 21, 114, 106, 118, 116, 185, 246, 37, 32, 158, 209, 46, 100, 100, 250, 194, 227, 80, 95, 132, 172, 90, 84, 128, 144, 86, 21, 9, 95, 2, 3, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			user:       []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 48, 189, 174, 66, 109, 60, 189, 66, 233, 212, 29, 35, 149, 143, 172, 106, 216, 49, 15, 129, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			address:    []byte{48, 189, 174, 66, 109, 60, 189, 66, 233, 212, 29, 35, 149, 143, 172, 106, 216, 49, 15, 129},
			value:      big.NewInt(10),
			bits:       SUINT8_T,
		},

		// Test case 4: ERC-191: Signed Data
		{
			privateKey: "308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100b560c4977c053ee98dc7b0119c698b3cd7d684b2128e4c5f3f556bf8389f04088d8aebbe8aa7e533afa093c79b55b3a3d6d014d08c0a04c98ae97545bd42abd52664abc36ea189b73693ee43d8f630b3ecfdb39a38d37e009075448bb052fd3d2ca6dab9c7d4ddc036c3cafcecd421b969d3a04b9e6eb5470e9709992e20257ef4a1d677733f2f176f6ceff9f7197f32a4b7d6ed3809b44d1090fc1b522a3e77c91a82c6d89cb4d65844b051580d549859e226a4966be8655bb579c127767dfdb7d23e8bbaefb4b512df51785acd6140cf759fc7f412b6055dc408ec9b4f7049302737438cda15fc20df691672dd551c1c89b53a26be9aeb50c8333644cfd6fb020301000102820100030c9f3b1724e1d5495c5246dcb81f21be8800891b78c15df15e707a73a470bf1e76de09c10901f874ae6d6d9a42be6435c1b967dc29415bbfa983eb6a08251d681008d0d1b4b9f03064e8af8fb938a7fdba322e322d2daa85f669259a75e11e099256f43c3a6bba5fbe20ee833bf9c2c53db293ffadadffb8d2df3a3d0bae82780b60514a1fd01437b303de187d1fe8fb88560bb6a560fff9e17de996f3b93074dd72dd879f3fc3d1a8860de2cffa6082ca656eec5152000c1c7ef08f3c3abee57c17eac4f0ee4446576998aa5c2ef5a9b25b24620f2671eb94a4eb1643754abd6661a86e7b2d044b1293fe2a7e700334693e2ced5e366b865b59b7ae0f730102818100e0009bae6a06e8f0789b2d16658a951b11bd4ad02a12ef4c710438a01339878cac4bb11dda788d4b50126a5d97cca267aea13cdb9baec27f63b7ebef1043a6344959c7d399722d73823630041290c512f7a5e52eb1076406f5e7ad3acb6b2ed64a08d2bc62375877b497a9ad9b7e84da0ce5538648a7c33f8505d6a7e1f5f78102818100cf49752e9bc2b4a63fb8e86915da1a29bbd81e575a32e3ea40b0a3b95062f331a3f6852148201d59b8fab755d51a44b000af990a3be0febb6c5cf19fc522dca30a6c9d16a2d683f49c1e4b65e303d7d5c53822fbaf0dfdc65b8dfcddd2a56494857b0a0c8c4426fc9e5b932f0360469b174c6b0cc6d2713876d794af26f7ec7b028181008fcb1424f45f172d36deb624c86e1ba552cfe6b4962dad7bae98fd1894febb2aec77726d2d8f717445246d2f4380d348276bcdbb53c6ed8805254dc91af1b241a24c85e0298287f6bc41b8b5048df65464b113dbd33c6153ae8b584283ce7c348735fec17b72f7d17016638fd45f753cdc466245b3622e0e1a8052f9562e250102818023e073eeb838cfe98257efa9d8856247dce24006206f747123f72eaf31519f03f57c0278cb31fbc27eb8ae28a5f4a0f4d1799304696ebcc815ae5487b1a82205fa14e86f7589a95719fa48547f21382720b6619fac21c0cda7250122278646cd49f90cb93541ca79a8b2f2db8d3b099d683feabb506236046ed54b3fb17ff1a70281801e78082019813b90f5e3dedb61f2d5ff56037eca7903f0300ef316421903d7d9755a7398ce47ca763522b830d406e3cd986e4abea09333b65d1233557d2ba789cbf4c0a259d17b65649414cc3e1a8cea74eff31d87c6b9095e2764b44b54a2bc38185936a9aa2fe6688caa7c1c675e07264873eb60db82bd9360f48bafbe01b8",
			signature:  []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 103, 147, 14, 246, 175, 180, 41, 10, 135, 170, 116, 16, 140, 109, 201, 238, 94, 206, 31, 5, 236, 20, 84, 32, 12, 31, 24, 121, 255, 76, 106, 120, 67, 83, 127, 73, 142, 158, 228, 244, 215, 37, 69, 238, 243, 105, 225, 62, 226, 20, 126, 175, 106, 178, 211, 176, 99, 169, 4, 227, 24, 244, 243, 133, 47, 27, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 181, 96, 196, 151, 124, 5, 62, 233, 141, 199, 176, 17, 156, 105, 139, 60, 215, 214, 132, 178, 18, 142, 76, 95, 63, 85, 107, 248, 56, 159, 4, 8, 141, 138, 235, 190, 138, 167, 229, 51, 175, 160, 147, 199, 155, 85, 179, 163, 214, 208, 20, 208, 140, 10, 4, 201, 138, 233, 117, 69, 189, 66, 171, 213, 38, 100, 171, 195, 110, 161, 137, 183, 54, 147, 238, 67, 216, 246, 48, 179, 236, 253, 179, 154, 56, 211, 126, 0, 144, 117, 68, 139, 176, 82, 253, 61, 44, 166, 218, 185, 199, 212, 221, 192, 54, 195, 202, 252, 236, 212, 33, 185, 105, 211, 160, 75, 158, 110, 181, 71, 14, 151, 9, 153, 46, 32, 37, 126, 244, 161, 214, 119, 115, 63, 47, 23, 111, 108, 239, 249, 247, 25, 127, 50, 164, 183, 214, 237, 56, 9, 180, 77, 16, 144, 252, 27, 82, 42, 62, 119, 201, 26, 130, 198, 216, 156, 180, 214, 88, 68, 176, 81, 88, 13, 84, 152, 89, 226, 38, 164, 150, 107, 232, 101, 91, 181, 121, 193, 39, 118, 125, 253, 183, 210, 62, 139, 186, 239, 180, 181, 18, 223, 81, 120, 90, 205, 97, 64, 207, 117, 159, 199, 244, 18, 182, 5, 93, 196, 8, 236, 155, 79, 112, 73, 48, 39, 55, 67, 140, 218, 21, 252, 32, 223, 105, 22, 114, 221, 85, 28, 28, 137, 181, 58, 38, 190, 154, 235, 80, 200, 51, 54, 68, 207, 214, 251, 2, 3, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			user:       []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 18, 52, 99, 164, 176, 101, 114, 46, 153, 17, 93, 108, 34, 47, 38, 125, 156, 171, 181, 36, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			address:    []byte{18, 52, 99, 164, 176, 101, 114, 46, 153, 17, 93, 108, 34, 47, 38, 125, 156, 171, 181, 36},
			value:      big.NewInt(10),
			bits:       SUINT8_T,
		},
	}

	var userKeys [][]byte

	// Act and Assert
	for _, testCase := range testCases {
		t.Run("", func(t *testing.T) {

			// Generate a new EVM for the on\off board functions
			evm := NewEVM(BlockContext{}, TxContext{}, nil, params.TestChainConfig, Config{})
			evm.Origin.SetBytes(testCase.address)
			// Create an instance of mpcContract
			mpc := &mpcContract{}
			mpc.SetParams(evm, common.Address{}, common.Address{})

			// Run getUserKey
			getKeyInput := make([]byte, FUNC_SIG_SIZE)
			binary.BigEndian.PutUint32(getKeyInput[:FUNC_SIG_SIZE], signatureGetKey)
			getKeyInput = append(getKeyInput, testCase.signature...) // Append the PK and signature
			encryptedKey, err := mpc.Run(getKeyInput)
			if err != nil {
				require.NoError(t, err, "Expected no error")
			}

			// Get the bytes of the RSA private key
			rsaPrivateKey, err := hex.DecodeString(testCase.privateKey)
			if err != nil {
				require.NoError(t, err, "Expected no error")
			}
			// Decrypt the generated user aes key using the RSA private key
			userKey, err := decryptRSA(rsaPrivateKey, encryptedKey[64:])

			if err != nil {
				require.NoError(t, err, "Expected no error")
			}

			userKeys = append(userKeys, userKey) // Insert the key for later check
			// Run setPublic to get a gt value
			value, err := runSetPublic(testCase.value, testCase.bits, mpc)
			if err != nil {
				require.NoError(t, err, "Expected no error")
			}

			// Run offboard to get a ct value
			offboardInput := make([]byte, FUNC_SIG_SIZE)
			binary.BigEndian.PutUint32(offboardInput[:FUNC_SIG_SIZE], signatureOffboardToUser)
			offboardInput = append(offboardInput, testCase.bits)                                // Append the metadata
			offboardInput = append(offboardInput, make([]byte, METADATA_SIZE-UNIRY_MD_SIZE)...) // Append the metadata to 32 bytes
			offboardInput = append(offboardInput, value...)
			offboardInput = append(offboardInput, testCase.user...)
			ciphertext, err := mpc.Run(offboardInput)
			if err != nil {
				require.NoError(t, err, "Expected no error")
			}

			// Get the ciphertext values r, AES(r)^pt
			size := len(ciphertext) / 2
			cipher := ciphertext[:size]
			r := ciphertext[size:]

			// Decrypt the ciphertext using the user aes key
			mpcOutput, err := decrypt(userKey, r, cipher)

			// Check if the decryption output matches the expected output
			actualOutput := new(big.Int).SetBytes(mpcOutput)
			if actualOutput.Cmp(testCase.value) != 0 {
				assert.Equal(t, testCase.value, actualOutput, "Expected output does not match actual output")
			}

		})
	}

	// Check that the keys of the same sender are equal
	assert.Equal(t, userKeys[0], userKeys[1], "Expected keys to be equal")

	// Check that the keys of different senders are not equal
	assert.NotEqual(t, userKeys[0], userKeys[2], "Expected keys to be different")

}

func decryptRSA(privateKeyBytes []byte, ciphertext []byte) ([]byte, error) {
	// Parse private key from DER format
	privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyBytes)
	if err != nil {
		fmt.Println("Error parsing private key:", err)
		return nil, err
	}

	// Convert parsedKey to *rsa.PrivateKey
	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		fmt.Println("Error: Parsed key is not an RSA private key")
		return nil, fmt.Errorf("parsed key is not an RSA private key")
	}

	// Decrypt message using RSA private key with OAEP padding
	decryptedMessage, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPrivateKey, ciphertext, nil)
	if err != nil {
		fmt.Println("Error decrypting message:", err)
		return nil, err
	}

	return decryptedMessage, nil
}

func SignIT(sender, addr, funcSig, ct, key []byte) ([]byte, error) {
	// Ensure all input sizes are the correct length
	if len(sender) != ADDR_SIZE {
		return nil, fmt.Errorf("Invalid sender address length: %d bytes, must be %d bytes", len(sender), ADDR_SIZE)
	}
	if len(addr) != ADDR_SIZE {
		return nil, fmt.Errorf("Invalid contract address length: %d bytes, must be %d bytes", len(addr), ADDR_SIZE)
	}
	if len(funcSig) != FUNC_SIG_SIZE {
		return nil, fmt.Errorf("Invalid signature size: %d bytes, must be %d bytes", len(funcSig), FUNC_SIG_SIZE)
	}
	if len(ct) != CIPHER_TEXT_SIZE {
		return nil, fmt.Errorf("Invalid ct length: %d bytes, must be %d bytes", len(ct), CIPHER_TEXT_SIZE)
	}
	// Ensure the key is the correct length
	if len(key) != CIPHER_TEXT_SIZE {
		return nil, fmt.Errorf("Invalid key length: %d bytes, must be %d bytes", len(key), CIPHER_TEXT_SIZE)
	}

	// Create the message to be signed by appending all inputs
	message := append(sender, addr...)
	message = append(message, funcSig...)
	message = append(message, ct...)

	return Sign(message, key)
}

// Sign is a function that hashes a message using the Keccak-256 algorithm and then signs the hashed message using ECDSA.
// If all steps are successful, it returns the signature and no error.
func Sign(message, key []byte) ([]byte, error) {

	// Create an ECDSA private key from raw bytes
	privateKey, err := crypto.ToECDSA(key)
	if err != nil {
		return nil, fmt.Errorf("Failed to create ECDSA private key: %v", err)
	}

	// Hash the concatenated message using Keccak-256
	hash := crypto.Keccak256(message)

	// Sign the message
	signature, err := crypto.Sign(hash, privateKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to sign message: %v", err)
	}

	return signature, nil
}
