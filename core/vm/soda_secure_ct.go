// This file defines functionality for authenticated memory and authenticated storage management of cipher-texts.
//
// Overview:
// This file encapsulates functionality related to authenticated memory operations within the EVM.
// It provides mechanisms for managing valid execution depths associated with cipher-texts
// and securely storing valid cipher-texts in a special storage called authenticated storage.
//
// Key Functionality:
// - Tracking and updating valid execution depths for cipher-texts in authenticated memory.
// - Validating and loading cipher-texts into authenticated memory.
// - Storing validated cipher-texts securely in the authenticated storage state based on the original contract's location hash.

package vm

import (
	mapset "github.com/deckarep/golang-set"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// insertToAuthenticatedMemory adds the current ct to the set of valid ct's for a certain depth.
// execution depths associated with a given cipher-text in authenticated memory.
//
// Parameters:
//   - evm:  A reference to the Ethereum Virtual Machine (EVM) instance, providing access to the interpreter.
//   - ct:  The cipher-text to add to the set of valid cipher-texts for the current execution depth.
//
// The function first checks if the current depth of the EVM exists in the `validCts` map of the EVM's interpreter.
// If it does, it retrieves the set of valid cipher-texts for that depth and checks if the given cipher-text `ct` is already present in this set.
// If the given cipher-text `ct` is not present in the set, it adds it.
// If the current depth does not exist in the `validCts` map, it creates a new set with the given cipher-text `ct` and adds it to the map at the current depth.
func insertToAuthenticatedMemory(evm *EVM, ct [common.HashLength]byte) {
	// fmt.Println("insertToauthenticatedMemory ct : ", ct)
	if validCTSet, ok := evm.interpreter.validCts[evm.depth]; ok {
		if !validCTSet.Contains(ct) {
			validCTSet.Add(ct)
		}
	} else {
		evm.interpreter.validCts[evm.depth] = mapset.NewSet(ct)
		// fmt.Println("added depth to authenticated cipher-text memory in a new set", evm.depth, ct)
	}
}

// isValidInauthenticatedMemory checks if a given cipher-text `ct` is present in the set of valid cipher-texts at the current depth.
//
// Parameters:
//   - evm: A pointer to the Ethereum Virtual Machine (EVM).
//   - ct:  The cipher-text to be checked.
//
// Returns:
//   - A boolean indicating whether the cipher-text is valid.
//
// This function checks if a given `ct` is present in the set of valid CTs at the current depth.
// It first checks if the current depth of the EVM exists in the `validCts` map.
// If it does, it retrieves the set of valid CTs for that depth and checks if the given `ct` is present in this set.
// If the given `ct` is present in the set, it returns true.
// If the given `ct` is not present in the set, or if the current depth does not exist in the `validCts` map, it returns false.
func isValidInAuthenticatedMemory(evm *EVM, ct [common.HashLength]byte) bool {
	// fmt.Println("isValidInauthenticatedMemory: ct  is", ct, evm.depth)
	if validCTSet, ok := evm.interpreter.validCts[evm.depth]; ok {
		if validCTSet.Contains(ct) {
			// fmt.Println("isValidInauthenticatedMemory ok : ct  is, depth ", ct, evm.depth)
			return true
		}
	}
	return false
}

// insertToAuthenticatedMemoryFromStorage cheks if a given cipher-text is valid and if so
// loads it into authenticated memory.
//
// Parameters:
//   - val:          The hash value to be validated and loaded which is infact the cipher-text
//   - interpreter:  A pointer to the Ethereum Virtual Machine (EVM) interpreter.
//   - addr:         The Ethereum address associated with the cipher-text.
//
// Returns:
//   - An error if the validation or loading process encounters an issue.
//
// The function first checks if the cipher-text value is already present in authenticated
// memory. If it is, no action is needed, and the function returns nil.
//
// If the cipher-text is not in authenticated memory, the function generates an
// attached contract address using the provided Ethereum address which populates the
// validated cipher-text in authenticated storage. It then
// retrieves the cipher-text stored in authenticated storage associated with that
// contract address.
//
// If the retrieved cipher-text matches the input val, it is considered a valid
// cipher-text, and the function adds it to the set of valid cipher-texts  in authenticate memory.
func insertToAuthenticatedMemoryFromStorage(loc, val common.Hash, interpreter *EVMInterpreter, addr common.Address) error {
	// First check if it is already in memory
	if isValidInAuthenticatedMemory(interpreter.evm, val) {
		return nil // No action needed, already in authenticated memory
	}

	// Generate the attached contract address containing the validated storage
	authenticatedStorage := crypto.CreateAddress(addr, 0)
	ct := interpreter.evm.StateDB.GetState(authenticatedStorage, loc)
	// fmt.Println("insertToAuthenticatedMemoryFromStorage: cipher text is", ct)
	// fmt.Println("insertToAuthenticatedMemoryFromStorage: val  is", val)
	// fmt.Println("insertToAuthenticatedMemoryFromStorage: authenticatedStorage, loc, depth  is", authenticatedStorage, loc, interpreter.evm.depth)
	// fmt.Println("insertToAuthenticatedMemoryFromStorage: addr  is", addr)

	// Check that the val is the ct in the authenticated storage, otherwise this is not a valid ct
	if ct.Hex() == val.Hex() && (ct != common.Hash{}) {
		// Add the ct to the valid Cts map in memory
		insertToAuthenticatedMemory(interpreter.evm, ct)

		// fmt.Println("Validated and loaded cipher-text to memory", val.Hex(), ct.Hex())
	}
	return nil
}

// validateAndStoreCt validates a given cipher-text (ct) and, if valid,
// stores it securely in the authenticated storage state.
// The function takes the locacion hash (loc), cipher-text (ct),
// EVM interpreter (interpreter), and Ethereum address (addr) as parameters.
//
// Parameters:
//   - loc: Location  representing the location ,as it is in the original
//     contract, where the cipher-text is stored.
//   - ct: Cipher-text to be validated and stored in the loc in the authenticated storage.
//   - interpreter: EVMInterpreter instance where the authenticate memory map is defined.
//   - addr: Ethereum address of the original contract, this address is used to create the
//     attached contract address of the authenticated storage.
//
// The function performs the following steps:
// 1. Generates the attached protected storage contract address based on the original contract address.
// 2. Checks if the cipher-text is valid in memory by calling isValidInauthenticatedMemory function.
// 3. If valid, persists the cipher-text in the authenticated storage in the EVM state.
// 4. If not valid, removes the previously persisted cipher-text from storage.
//
// Note: The function uses the Ethereum StateDB for state manipulation.
func validateAndStoreCt(loc common.Hash, ct common.Hash, interpreter *EVMInterpreter, addr common.Address) {
	authenticatedStorage := crypto.CreateAddress(addr, 0)
	// fmt.Println("validateAndStoreCt: location hash is, ct ", loc, ct.Hex())
	// fmt.Println("validateAndStoreCt: authenticated storage is ", authenticatedStorage, ct.Hex())

	// First check if it is in memory
	if isValidInAuthenticatedMemory(interpreter.evm, ct) { // valid cipher-text: in memory
		// Persist the ct in the authenticated storage
		interpreter.evm.StateDB.SetState(authenticatedStorage, loc, ct)
		// fmt.Println("validateAndStoreCt: Persisted to authenticated storage", authenticatedStorage, interpreter.evm.depth, loc.Hex(), ct.Hex())
		// fmt.Println("validateAndStoreCt: Persisted to authenticated storage", addr, interpreter.evm.depth, loc.Hex(), ct.Hex())
	} else { // Not valid remove if it was previously persisted
		// Get previous
		prevCt := interpreter.evm.StateDB.GetState(authenticatedStorage, loc)

		if prevCt != (common.Hash{}) { // There is a non-empty ct in the authenticated storage
			// Remove it from storage by zeroing it
			interpreter.evm.StateDB.SetState(authenticatedStorage, loc, common.Hash{})
		}
	}
}
