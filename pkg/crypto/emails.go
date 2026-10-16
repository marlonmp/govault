package crypto

import (
	"crypto/rand"
	"math/big"
	"strings"
)


const (
	OTPLen = 6
	OTPCharset = "0123456789"
)

func GenerateOTP() string {
	var sb strings.Builder
	charsetOptions := big.NewInt(int64(len(OTPCharset)))
	for i := 0; i < OTPLen; i++ {
		idx, _ := rand.Int(rand.Reader, charsetOptions)
		sb.WriteByte(OTPCharset[idx.Int64()])
	}
	return sb.String()
}
