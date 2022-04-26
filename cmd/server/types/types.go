package types

import "github.com/whyrusleeping/go-did"

type RegisterBody struct {
	InitialKey          did.DID                `json:"initialKey"`
	InitialVerification did.VerificationMethod `json:"initialVerification"`
}

type RegisterResponse struct {
	ID       did.DID      `json:"id"`
	Document did.Document `json:"document"`
}

type ErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Details string `json:"details"`
}
