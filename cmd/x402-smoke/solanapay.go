package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/mr-tron/base58"

	"github.com/sealedin/gateway/internal/solanarpc"
	"github.com/sealedin/gateway/internal/x402"
	"github.com/sealedin/gateway/internal/x402/x402client"
)

const (
	claimPath      = "/v1/keys/claim"
	claimPolls     = 40
	claimPollEvery = 3 * time.Second
	baseUnitsUSD   = 1_000_000
)

// claimFlow is the wallet-free part of buying by Solana Pay: a local signer in the wallet's place. What a real wallet does with
// a QR code cannot be checked here.
func (c *client) claimFlow(ctx context.Context, rpcURL, amountUSD string) error {
	var code [x402.ClaimCodeBytes]byte
	if _, err := rand.Read(code[:]); err != nil {
		return err
	}
	text := base58.Encode(code[:])
	reference, err := x402.ParseClaimCode(text)
	if err != nil {
		return err
	}
	if err = c.sendTransfer(ctx, rpcURL, amountUSD, reference); err != nil {
		return err
	}
	body, err := json.Marshal(map[string]string{"code": text})
	if err != nil {
		return err
	}
	first, err := c.pollClaim(ctx, string(body))
	if err != nil {
		return err
	}
	again, err := c.post(ctx, claimPath, string(body), nil)
	if err != nil {
		return err
	}
	if again.status != http.StatusOK || again.body["key"] != first.body["key"] {
		return fmt.Errorf("a repeated claim gave %d and another key", again.status)
	}
	return nil
}

func (c *client) sendTransfer(ctx context.Context, rpcURL, amountUSD string, reference solana.PublicKey) error {
	terms, err := c.readCatalog(ctx)
	if err != nil {
		return err
	}
	treasury, err := solana.PublicKeyFromBase58(terms.PayTo)
	if err != nil {
		return fmt.Errorf("catalog pay_to: %w", err)
	}
	mint, err := solana.PublicKeyFromBase58(terms.Asset)
	if err != nil {
		return fmt.Errorf("catalog asset: %w", err)
	}
	usd, err := strconv.ParseFloat(amountUSD, 64)
	if err != nil {
		return fmt.Errorf("amount: %w", err)
	}
	node := &solanarpc.Client{URL: rpcURL, HTTP: c.http}
	blockhash, _, err := node.LatestBlockhash(ctx)
	if err != nil {
		return err
	}
	hash, err := solana.HashFromBase58(blockhash)
	if err != nil {
		return fmt.Errorf("blockhash: %w", err)
	}
	raw, err := x402client.SolanaPayTransfer{Payer: c.wallet, Treasury: treasury, Mint: mint, Amount: uint64(usd * baseUnitsUSD),
		Reference: reference, Blockhash: hash}.Build()
	if err != nil {
		return err
	}
	id, err := node.Send(ctx, raw)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(c.out, "solana pay: sent %s under reference %s\n", id, reference)
	return nil
}

func (c *client) pollClaim(ctx context.Context, body string) (response, error) {
	for range claimPolls {
		got, err := c.post(ctx, claimPath, body, nil)
		if err != nil {
			return response{}, err
		}
		switch got.status {
		case http.StatusOK:
			if got.body["key"] == nil {
				return response{}, errors.New("a claim without a bearer gave no key")
			}
			return got, nil
		case http.StatusAccepted, http.StatusTooManyRequests, http.StatusServiceUnavailable:
		default:
			return response{}, fmt.Errorf("claim: %d: %v", got.status, got.body)
		}
		select {
		case <-ctx.Done():
			return response{}, ctx.Err()
		case <-time.After(claimPollEvery):
		}
	}
	return response{}, errors.New("claim: nothing confirmed in time")
}
