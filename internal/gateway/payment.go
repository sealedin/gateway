package gateway

import (
	"encoding/hex"
	"fmt"
	"os"
)

// Dev-only payment settings, read only on the unattested branch; none of these names is in the measured compose.
const (
	DevFeePayerSeedEnv = "SEALEDIN_DEV_FEE_PAYER_SEED"
	// FeePayerSeedBytes is an Ed25519 seed.
	FeePayerSeedBytes = 32
	devNetworkEnv     = "SEALEDIN_DEV_PAYMENT_NETWORK"
	devTreasuryEnv    = "SEALEDIN_DEV_TREASURY"
	devAssetEnv       = "SEALEDIN_DEV_PAYMENT_ASSET"
)

const (
	// TreasuryPlaceholder fails every address parse, so nothing can pay to it; scripts/check-release-pins.sh and the
	// attested identity refuse to run while Treasury holds it.
	TreasuryPlaceholder = "TREASURY-PLACEHOLDER-NOT-AN-ADDRESS"
	// Treasury is the wallet purchases pay to: measured like the price sheet, never operator config. Its USDC associated
	// token account must exist before the first purchase, since a transfer to a missing account fails.
	Treasury = "CfYWUgC78FTM7gnt9nwGTRRRadK6ZME9ctMdmqpxCzBT"
	// PaymentNetwork is the CAIP-2 id of Solana mainnet.
	PaymentNetwork = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
	// PaymentAsset is the USDC mint on that network.
	PaymentAsset = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
)

// TreasuryConfigured says whether the operator's address replaced the placeholder.
func TreasuryConfigured() bool { return addressSet(Treasury) }

func addressSet(address string) bool { return address != TreasuryPlaceholder }

// Terms is what a purchase pays: the one source of both the signed catalog and the 402 challenge.
type Terms struct {
	Network  string
	Treasury string
	Asset    string
}

// MeasuredTerms are the terms of every attested deployment.
func MeasuredTerms() Terms {
	return Terms{Network: PaymentNetwork, Treasury: Treasury, Asset: PaymentAsset}
}

// DevTerms are the unattested stack's terms from its environment, for a devnet trial.
func DevTerms() Terms {
	return Terms{Network: os.Getenv(devNetworkEnv), Treasury: os.Getenv(devTreasuryEnv), Asset: os.Getenv(devAssetEnv)}
}

// DecodeFeePayerSeed reads the fee payer seed in the form the identity publishes and the dev setting uses: hex.
func DecodeFeePayerSeed(text string) ([FeePayerSeedBytes]byte, error) {
	var seed [FeePayerSeedBytes]byte
	raw, err := hex.DecodeString(text)
	if err != nil || len(raw) != FeePayerSeedBytes {
		return seed, fmt.Errorf("fee payer seed must be %d hex bytes", FeePayerSeedBytes)
	}
	copy(seed[:], raw)
	return seed, nil
}
