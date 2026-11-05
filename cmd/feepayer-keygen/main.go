// Command feepayer-keygen generates the fee payer keypair on the operator's machine, stores it in Keychain and prints only the
// public address. The secret reaches the security tool on stdin: an argument would show in the process list.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/mr-tron/base58"
)

const (
	keychainItem    = "sealedin-fee-payer"
	keychainAccount = "admin"
	securityTool    = "security"
)

func main() {
	if err := run(os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "feepayer-keygen:", err)
		os.Exit(1)
	}
}

func itemExists() bool {
	// Without -w this reads the item's attributes, never its secret.
	return exec.Command(securityTool, "find-generic-password", "-s", keychainItem).Run() == nil //nolint:noctx // a one-shot tool
}

// run refuses an existing item: overwriting it would lose the only copy of a key that may hold SOL.
func run(stdout io.Writer) error {
	if itemExists() {
		return fmt.Errorf("Keychain item %s already exists; nothing changed", keychainItem) //nolint:staticcheck // a product name
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	cmd := exec.Command(securityTool, "-i") //nolint:noctx // a one-shot tool
	line := fmt.Sprintf("add-generic-password -s %s -a %s -w %s\n", keychainItem, keychainAccount, base58.Encode(private))
	cmd.Stdin = strings.NewReader(line)
	if err = cmd.Run(); err != nil { // output left unattached, so nothing it prints can carry the secret
		return errors.New("the security tool failed")
	}
	if !itemExists() { // interactive mode can exit 0 after a failed command
		return errors.New("the Keychain item was not created")
	}
	_, err = fmt.Fprintln(stdout, base58.Encode(public))
	return err
}
