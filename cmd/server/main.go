package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/whyrusleeping/go-did"
	"github.com/whyrusleeping/go-did/cmd/server/types"
)

const didmethod = "whyd"

type Server struct {
	store map[did.DID]*did.SignedDocument
	slk   sync.Mutex
}

func NewServer() *Server {
	return &Server{
		store: make(map[did.DID]*did.SignedDocument),
	}
}

func (s *Server) getDocument(id did.DID) (*did.SignedDocument, bool) {
	s.slk.Lock()
	defer s.slk.Unlock()

	d, ok := s.store[id]
	return d, ok
}

func (s *Server) handleGetDocument(c echo.Context) error {
	id, err := did.ParseDID(c.Param("did"))
	if err != nil {
		return err
	}

	doc, ok := s.getDocument(id)
	if !ok {
		return c.JSON(404, map[string]string{"error": "not found"})
	}

	// TODO: should we be returning signed objects?
	return c.JSON(200, doc)
}

func (s *Server) pubkeyForID(id did.DID) (*did.PubKey, error) {
	doc, ok := s.getDocument(id)
	if !ok {
		return nil, fmt.Errorf("no registered account for that did")
	}

	// TODO: support more than one verification method
	return doc.Document.GetPublicKey("")
}

func (s *Server) updateDocument(id did.DID, doc *did.SignedDocument) error {
	s.slk.Lock()
	defer s.slk.Unlock()
	s.store[id] = doc
	return nil
}

func (s *Server) handleUpdateDocument(c echo.Context) error {
	id, err := did.ParseDID(c.Param("did"))
	if err != nil {
		return err
	}

	var sd did.SignedDocument
	if err := c.Bind(&sd); err != nil {
		return err
	}

	pubk, err := s.pubkeyForID(id)
	if err != nil {
		return err
	}

	if err := did.VerifyDocumentSignature(&sd, pubk); err != nil {
		return err
	}

	if err := s.updateDocument(id, &sd); err != nil {
		return err
	}

	return c.JSON(200, map[string]string{"status": "ok"})
}

func (s *Server) handleCreateDocument(c echo.Context) error {
	var body types.RegisterBody
	if err := c.Bind(&body); err != nil {
		return err
	}

	pubk, err := body.InitialVerification.GetPublicKey()
	if err != nil {
		return err
	}
	_ = pubk // probably should have them sign something?

	ndid, err := DidFromRegisterBody(&body)
	if err != nil {
		return err
	}

	initdoc := did.Document{
		Context: []string{
			did.CtxDIDv1,
			did.CtxSecEd25519_2020v1,
			did.CtxSecX25519_2019v1,
		},
		ID:                 ndid,
		VerificationMethod: []did.VerificationMethod{body.InitialVerification},
	}

	// TODO: how to pick their DID?
	if err := s.updateDocument(ndid, &did.SignedDocument{Document: &initdoc}); err != nil {
		return err
	}

	return c.JSON(200, types.RegisterResponse{
		ID:       ndid,
		Document: initdoc,
	})
}

func DidFromRegisterBody(body *types.RegisterBody) (did.DID, error) {
	// TODO: idk probably something better
	b, err := json.Marshal(body)
	if err != nil {
		return did.DID{}, err
	}

	h := sha256.Sum256(b)

	dstr := fmt.Sprintf("did:%s:%x", didmethod, h)

	return did.ParseDID(dstr)
}

func main() {

	s := NewServer()

	e := echo.New()
	e.Use(middleware.Logger())
	e.GET("/:did", s.handleGetDocument)
	e.POST("/:did", s.handleUpdateDocument)
	e.POST("/", s.handleCreateDocument)

	e.Start(":5555")
}
