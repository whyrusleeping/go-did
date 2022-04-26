package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/urfave/cli/v2"
	"github.com/whyrusleeping/go-did"
	"github.com/whyrusleeping/go-did/cmd/server/types"
)

const defaultServer = "http://localhost:5555"

func main() {
	app := cli.NewApp()

	app.Commands = []*cli.Command{
		registerCmd,
		genKeyCmd,
		updateDocCmd,
		getDocCmd,
	}

	app.RunAndExitOnError()
}

var registerCmd = &cli.Command{
	Name: "register",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "server",
			Value: defaultServer,
		},
	},
	Action: func(cctx *cli.Context) error {
		if !cctx.Args().Present() {
			return fmt.Errorf("must specify key file to use for identity")
		}

		keyfi := cctx.Args().First()

		k, err := loadKey(keyfi)
		if err != nil {
			return err
		}

		id, err := did.DIDFromKey(k.Public())
		if err != nil {
			return err
		}

		j, err := jwk.FromRaw(k.Public())
		if err != nil {
			return err
		}

		body := &RegisterBody{
			InitialKey: id,
			InitialVerification: did.VerificationMethod{
				ID:   id,
				Type: "JsonWebKey2020",
				//Controller         string        `json:"controller"`
				PublicKeyJwk: &did.PublicKeyJwk{j},
			},
		}

		b, err := json.Marshal(body)
		if err != nil {
			return err
		}

		req, err := http.NewRequest("POST", cctx.String("server")+"/", bytes.NewReader(b))
		if err != nil {
			return err
		}

		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode != 200 {
			return fmt.Errorf("request failed, status %d", resp.StatusCode)
		}

		var resval types.RegisterResponse
		if err := json.NewDecoder(resp.Body).Decode(&resval); err != nil {
			return err
		}

		fmt.Println("new id: ", resval.ID)

		if err := writeDocument(resval.Document, "document.json"); err != nil {
			return err
		}

		return nil
	},
}

func loadKey(keyfi string) (ed25519.PrivateKey, error) {
	data, err := ioutil.ReadFile(keyfi)
	if err != nil {
		return nil, err
	}

	kb, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, err
	}

	k := ed25519.NewKeyFromSeed(kb)
	return k, nil
}

func writeDocument(doc did.Document, fname string) error {
	fi, err := os.Create(fname)
	if err != nil {
		return err
	}
	defer fi.Close()

	return json.NewEncoder(fi).Encode(doc)
}

func loadDocument(fname string) (*did.Document, error) {
	b, err := ioutil.ReadFile(fname)
	if err != nil {
		return nil, err
	}

	var doc did.Document
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}

	return &doc, nil
}

// copied from server/main.go
type RegisterBody struct {
	InitialKey          did.DID                `json:"initialKey"`
	InitialVerification did.VerificationMethod `json:"initialVerification"`
}

var genKeyCmd = &cli.Command{
	Name: "genkey",
	Action: func(cctx *cli.Context) error {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}

		fmt.Println(hex.EncodeToString(priv.Seed()))
		return nil
	},
}

var updateDocCmd = &cli.Command{
	Name: "update-doc",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "server",
			Value: defaultServer,
		},
	},
	Action: func(cctx *cli.Context) error {
		if cctx.Args().Len() != 2 {
			return fmt.Errorf("must specify key file and updated document")
		}

		k, err := loadKey(cctx.Args().Get(0))
		if err != nil {
			return err
		}

		doc, err := loadDocument(cctx.Args().Get(1))
		if err != nil {
			return err
		}

		sd, err := did.SignDocument(doc, k)
		if err != nil {
			return err
		}

		b, err := json.Marshal(sd)
		if err != nil {
			return err
		}

		req, err := http.NewRequest("POST", cctx.String("server")+"/"+doc.ID.String(), bytes.NewReader(b))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode != 200 {
			return fmt.Errorf("update failed, status %d", resp.StatusCode)
		}

		return nil
	},
}

var getDocCmd = &cli.Command{
	Name: "get-doc",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "server",
			Value: defaultServer,
		},
	},
	Action: func(cctx *cli.Context) error {
		if cctx.Args().Len() != 1 {
			return fmt.Errorf("must specify key file and updated document")
		}

		id, err := did.ParseDID(cctx.Args().First())
		if err != nil {
			return err
		}

		req, err := http.NewRequest("GET", cctx.String("server")+"/"+id.String(), nil)
		if err != nil {
			return err
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode != 200 {
			return fmt.Errorf("get failed, status %d", resp.StatusCode)
		}

		var sd did.SignedDocument
		if err := json.NewDecoder(resp.Body).Decode(&sd); err != nil {
			return err
		}

		b, err := json.MarshalIndent(sd, "", "  ")
		if err != nil {
			return err
		}

		fmt.Println(string(b))

		return nil
	},
}
