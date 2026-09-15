package crypto_test

import (
	"fmt"

	"github.com/mheers/google-find-my-tools-go/pkg/googlefindmy/crypto"
)

// ExampleGenerateEID derives a tracker's rotating EID for a point in time.
func ExampleGenerateEID() {
	identityKey := make([]byte, 32) // replace with the recovered EIK
	eid, err := crypto.GenerateEID(identityKey, 1_700_000_000)
	if err != nil {
		panic(err)
	}
	fmt.Printf("EID length: %d\n", len(eid))
	// Output: EID length: 20
}
