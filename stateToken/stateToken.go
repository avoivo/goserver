package stateToken

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Manager is used for generating and veryfing state tokens
type Manager interface {
	Generate() (token string, err error)
	Verify(token string) (valid bool, err error)
}

type manager struct {
	key []byte
}

func (m *manager) Generate() (token string, err error) {

	t := time.Now()
	message := []byte(fmt.Sprintf("%v", t))

	if encrypted, e := encrypt(m.key, message); e != nil {
		err = e
	} else {
		token = base64.StdEncoding.EncodeToString(encrypted)
	}
	return
}

func (m *manager) Verify(token string) (valid bool, err error) {
	valid = false

	if t, e := base64.StdEncoding.DecodeString(token); e != nil {
		err = e
	} else {
		if _, e := decrypt(m.key, t); e != nil {
			err = e
		} else {
			valid = true
		}
	}

	return
}

func encrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return ciphertext, nil
}

func decrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(text) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return nil, err
	}
	return data, nil

}

// New instantiates a Manager.
func New(secret string) (m Manager, err error) {

	if len(secret) == 0 {
		err = errors.New("secret should not be empty")
		return
	}

	if len(secret) > 32 {
		err = errors.New("secret should not be more than 32 characters long")
		return
	}

	maxLengh := 16

	if len(secret) > 24 {
		maxLengh = 32
	} else if len(secret) > 16 {
		maxLengh = 24
	}

	key := []byte(secret + strings.Repeat(" ", maxLengh-len(secret)))

	m = &manager{key: key}
	return
}
