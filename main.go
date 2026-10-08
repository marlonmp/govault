package main

import (
	// "crypto/x509"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/1Password/srp"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/marlonmp/govault/internal/crypto"
	"github.com/marlonmp/govault/internal/user"
)

//
// type KeysetAAA struct {
// 	ID         uuid.UUID `json:"uuid"`
// 	EncSalt    []byte    `json:"enc_salt"`
// 	AuthSalt   []byte    `json:"auth_salt"`
// 	EncSymKey  []byte    `json:"enc_sym_key"`
// 	EncPrivKey []byte    `json:"enc_priv_key"`
// 	PubKey     []byte    `json:"pub_key"`
// }
//
type KeysetPayload struct {
	ID         uuid.UUID       `json:"uuid"`
	EncSymKey  *crypto.EncJWK `json:"enc_sym_key"`
	EncPrivKey *crypto.EncJWK `json:"enc_priv_key"`
	PubKey     jwk.RSAPublicKey `json:"pub_key"`
}
//
// func bigIntFromBytes(bytes []byte) *big.Int {
// 	result := new(big.Int)
// 	for _, b := range bytes {
// 		result.Lsh(result, 8)
// 		result.Add(result, big.NewInt(int64(b)))
// 	}
// 	return result
// }
//
// func main() {
// 	jwk.PublicKeyer
// 	password := []byte("MyW3akP4$sworD")
// 	user := user.User{ID: uuid.New(), Nickname: "test user", Email: "user@test.com"}
// 	secretKey := crypto.GeneratSecretKey(user.ID)
// 	version := []byte("client-v'")
// 	// generate auk and priv keys
// 	encSalt := crypto.GenerateRandomKey(crypto.EncrytionSaltLen)
// 	auk, err := crypto.TwoSecretKeyDerivation(password, secretKey, encSalt, version, user)
// 	if err != nil {
// 		fmt.Println("cannot generate auk:", err)
// 		return
// 	}
// 	priv, err := crypto.GeneratePrivateKey()
// 	if err != nil {
// 		fmt.Println("cannot generate private key:", err)
// 		return
// 	}
// 	privBytes := x509.MarshalPKCS1PrivateKey(priv)
// 	encPrivKey, err := crypto.EncryptAESGCM(privBytes, auk)
// 	if err != nil {
// 		fmt.Println("cannot generate private key:", err)
// 		return
// 	}
// 	pubKeyBytes := x509.MarshalPKCS1PublicKey(&priv.PublicKey)
// 	// geretare srp
// 	authSalt := crypto.GenerateRandomKey(crypto.AuthenticationSaltLen)
// 	srpx, err := crypto.TwoSecretKeyDerivation(password, secretKey, authSalt, version, user)
// 	if err != nil {
// 		fmt.Println("cannot generate srpx:", err)
// 		return
// 	}
// 	x := bigIntFromBytes(srpx)
// 	group := srp.KnownGroups[srp.RFC5054Group3072]
// 	cli := srp.NewSRPClient(group, x, nil)
// 	if cli == nil {
// 		fmt.Println("cannot create client srp", err)
// 		return
// 	}
// 	v, err := cli.Verifier()
// 	if err != nil {
// 		fmt.Println("cannot generate verifier:", err)
// 		return
// 	}
// 	encSymKey := v.Bytes()
// 	ka := KeysetAAA{
// 		ID:         uuid.New(),
// 		EncSalt:    encSalt,
// 		AuthSalt:   authSalt,
// 		EncSymKey:  encSymKey,
// 		EncPrivKey: encPrivKey,
// 		PubKey:     pubKeyBytes,
// 	}
// 	d, err := json.Marshal(ka)
// 	if err != nil {
// 		fmt.Println("cannot marshal:", err)
// 		return
// 	}
// 	fmt.Println(string(d))
// 	data := `
// 	{
// 	  "uuid": "b3ec4373-defb-4168-8a41-3970d4897eea",
// 	  "enc_sym_key": {
// 	    "kid": "mp",
// 	    "enc": "A256GCM",
// 		"kty": "oct",
// 	    "cty": "b5+jwk+json",
// 	    "alg": "PEBS2g-HS256",
// 	    "p2s": "ln4bFrqfXW/Clcb56jOH3S2mtu6dQwHJesBE35yUcLs=",
// 	    "p2c": 650000,
// 	    "data": "yBwQFEUtBvt6mwWGJ/t7G28X9oRXgLNip84wx3uj03ecxLjCTmfc7sBzTz76n/ABPW3YXHY1aHct8M1rUGjsENe2nWSFib29/5ZkDynaKH31I45XW4/ODSLecglX8wph+HA1aAhpxR7ZBh7yrFNAMtWx+c89wOEyQFG4Z11NjIuJnEpKnH98uKTPCrj6pG+qQsqTpuUxApVnaQSWFaFvHLX+mYnnqpDLeOpdcgyVxvxGNv6sBzlvXXhQieEUltU09OuCLFGwhwu5mitr2PUGziuwHuD9L/RBmmYq1pP5i+6VR4EmQ/Qol88QLOxcAsjm1o/eVWcfEOQHAkVup34ngGAHTTIlZKQ2H9z+Fg8QTVIl9CkvukZobGMUzOvaOkpfSs3pqvYyOGVaB7XJgxSq2JBELq8qKgC+LUx+WYmyMGwd7JbpNI1W4k74EarDVIUbey8YdGr5jxJNJgL8WKlivPjD+bQl4GZKhZyAC77klI9skq0bS7OqQIGZCZyVLQlV"
// 	  },
// 	  "enc_priv_key": {
// 	    "kid": "942bed84-c57b-4ad7-9e6f-12c27e072ba3",
// 	    "enc": "A256GCM",
// 		"kty": "oct",
// 	    "cty": "b5+jwk+json",
// 	    "data": "YOSzvq6/vX8BllBMkN6I+i/9qsVHeY6iGTBspCbt9Zh0xLGa3hHJ/Qd2XN7jpGPtMDAtVK4wqDQCs0RdCkLlCmaU0wIc22usSIDHwzQjSrg1lJ09rVMfvbQ3s3dYSHdWaCitGT/CeMdT4D+tEKILcx4Pai7iqQolrAX7Tr15z7GydFP66lyaJcX+c3iAPTIR3T8Sgye53Vq4S86YdztcFqoQUAEZEBSITnVIlRiCbH3G3HI1xoftn/DPutpxmkLw0MMlrW+bAEJYZ/jDJsKDYhDLoxEQj+nMvugq+xN8p2hSdayxxQJpyRy2UEbe3fgtgobJ5ptB2Uy30g4cxStdpgDSEsLd8AEF9N1MQqsr+auZ5VRxjvJuJIL+Mwt3fsINQ/yVbdKrodnXPGIlL5RYWEhcbe2TYc2bzq3fXU0pX1CRLlUiZpsWEn7hSUGCe1qiogJDuo2LWkELvCrkco6Wst6MDlvCzw4VToQ0uyMDL8a30EOgojKEHHZaEsPmVTSOv3rPsVhZmDMkyucZfrCaewF8U1qdFWrxVF8+8RpjXJrRAU+0ZzBuLR5kfaHBQCmWV0BYKzzm9ffuPaT+vocsEz+66Kaa0/Aoz65jMXDgUqiVQ2K00PH07xVYhVsDmlxrO0yeDJfuzPtmcRP8Dtedq/ajGeBapiqO9WhdUQFk8RVc/Hs/uJLD5qtERciXKEhsH2pV/9jOkLtDk8MwEj1hsGUtz9ih5Ec8XloufO6/S2kyRfU3SKWzPPbKJgooqJb0X85KzKhwZAmc8Ul5c6swjFkNsFqhld1w9oZawYkS1YzElmEHIB4I3qK+znXg9HFog/73ySX/GKsaCdYk1pkWGc4L4bCEnQ8oJ8ZqyAyxk5lqlSfrZMJHMebxmvGs2ILVwvxGgWR4X+HQ+48FQYTdX+PQ+GPGQlfdymD1KxEoeagARdI0xHktLcFBx7K6MWKRUBoV3NPSH64c/sl0na19JMlQ/AoRhe7Ewd7TnX+hlbVOCi+sxxORS8Ci7YnCHWfHHRLqjZq7MhJuNJu62GBddTmpclzPw1YmswqjJGOHqZwy2ONr1fF8wVWpu49XX0OKqDAIFOkLoWIeCmj3p5/3korFvKD4BcIiY0O5rNHsPXfqCwI0bgs9/FxOflLLkE4HD5JeI8siyuALMkVBd6L1E3uzbDTagpoSr31uFZbrWOl7NgovYUJ2151OSqmIvxdtTFaVOcpIHzlqieaueiU/fYrwWLHRnpsqL0MoUqtOfUxu+dZQ7v4gxVs9axjq6RwLA6Cm1N6LLZVybppuN+L+tz5DaYTdQdX5SLx6LpS9UL++ZpehiLioKDV51t4hge54D7fiB0n+EbanHrQvilQmUY4KuSE4MNxExj4V/kSGNM58hi/z9yUP2kMv6Ek+VmwFL9KIxHxtmUnx7T1Y9mkuzr9ia6ILgU1V+LBTBmn7bUkyoRkqfZfVSwflvNVfEasdzAgsFV0WvpzEsnpDmJgQHtuMXHGHt7k0/Nxv2iPg5o+M3Qd0qyoLAH3trtFDSSoR0UjdkyWXcVph9YCQ8nSKeOg3hMwwmksdjnqBDaPrHRv50fbneaGz2CBqDLsWianpG8aPR7BKdBP6yNZI+dNV/Hjmtw=="
// 	  },
// 	  "pub_key": {
// 	    "kid": "ea84ab9f-fbef-4b62-b06e-6e660a7d6623",
// 	    "alg": "RSA-OAEP-256",
// 	    "e": "AQAB",
// 	    "key_ops": ["encrypt"],
// 	    "kty": "RSA",
// 	    "n": "MIIBCgKCAQEAz5PEyf0rf5p5nNPhpGZdKaffMxIGgCZMukC29nO5m/fdbLIhxVxeytW5qEyzmzFGwNvgNWqYzNeivXOEqDtK8Tnn3yIjRrCv/cGFjQgA8gtLd0U4vvAQLEPvbvZp4tIGLOAeOgyAdDLa7w1A7mEfe5jQdPJp1ksVaSb7sm8e8jNcu1fj/i3TndJaa+xWWLfmiUei84CCpWGnRALBBDHw29hM4Bbx3d6UUVqIZWWudBz0urSqJBoIUEDjZlq6+tn53HM+y99zfJMSzcuJoOXInWwiMI3+HqD7FtQJohgf5vkF6ip99UK3X2hTUSN6BTOQ67wLLm5mHkoAZFtRWYevGQIDAQAB"
// 	  }
// 	}`
// 	var payload KeysetPayload
// 	err = json.Unmarshal([]byte(data), &payload)
// 	if err != nil {
// 		fmt.Println("cannot unmarshal the payload:", err)
// 		return
// 	}
// 	bencSymKey, err := jwk.ParseKey(payload.EncSymKey)
// 	if err != nil {
// 		fmt.Println("cannot parse enc sym key:", err)
// 	}
// 	bencPrivKey, err := jwk.ParseKey(payload.EncPrivKey)
// 	if err != nil {
// 		fmt.Println("cannot parse enc priv key:", err)
// 	}
// 	bPubKey, err := jwk.ParseKey(payload.PubKey)
// 	if err != nil {
// 		fmt.Println("cannot parse pub key:", err)
// 	}
// 	n, _ := bPubKey.Field("n")
// 	if v, ok := n.([]byte); ok {
// 		pu, err := x509.ParsePKCS1PublicKey(v)
// 		if err != nil {
// 			println("jrr")
// 		} else {
// 			fmt.Println("pub", pu.Size())
// 		}
// 	}
// 	fmt.Println(bencSymKey, bencPrivKey, bPubKey.KeyType())
// }

func bigIntFromBytes(bytes []byte) *big.Int {
	result := new(big.Int)
	for _, b := range bytes {
		result.Lsh(result, 8)
		result.Add(result, big.NewInt(int64(b)))
	}
	return result
}

func main() {
	password := []byte("MyW3akP4$sworD!in!pssword456123")
	user := user.User{ID: uuid.New(), Nickname: "test user", Email: "user@test.com"}
	secretKey := crypto.GeneratSecretKey(user.ID)
	version := []byte("client-v'")
	// generate auk and priv keys
	encSalt := crypto.GenerateRandomKey(crypto.EncrytionSaltLen)
	auk, err := crypto.TwoSecretKeyDerivation(password, secretKey, encSalt, version, user)
	if err != nil {
		fmt.Println("cannot generate auk:", err)
		return
	}
	priv, err := crypto.GeneratePrivateKey()
	if err != nil {
		fmt.Println("cannot generate private key:", err)
		return
	}
	// geretare srp
	authSalt := crypto.GenerateRandomKey(crypto.AuthenticationSaltLen)
	srpx, err := crypto.TwoSecretKeyDerivation(password, secretKey, authSalt, version, user)
	if err != nil {
		fmt.Println("cannot generate srpx:", err)
		return
	}
	x := bigIntFromBytes(srpx)
	group := srp.KnownGroups[srp.RFC5054Group3072]
	cli := srp.NewSRPClient(group, x, nil)
	if cli == nil {
		fmt.Println("cannot create client srp", err)
		return
	}

	payload := &KeysetPayload{ID: uuid.New()}
	privKey, err := jwk.Import[jwk.RSAPrivateKey](priv)
	if err != nil {
		fmt.Println("cannot create the priv key", err)
		return
	}
	privKey.Set("kid", uuid.New().String())
	privKey.Set("ext", false)
	privKey.Set("key_ops", []string{"decrypt"})
	privKey.Set("alg", "RSA-OAEP-256")

	encPrivKey, err := crypto.ImportEncPrivKey(privKey, auk)
	if err != nil {
		fmt.Println("cannot create the enc priv key", err)
		return
	}

	pubKey, err := jwk.Import[jwk.RSAPublicKey](&priv.PublicKey)
	if err != nil {
		fmt.Println("cannot create the pub key", err)
		return
	}

	pubKey.Set("kid", uuid.New().String())
	pubKey.Set("ext", true)
	pubKey.Set("key_ops", []string{"encrypt"})
	pubKey.Set("alg", "RSA-OAEP-256")

	aukKey, err := jwk.Import[jwk.SymmetricKey](auk)
	if err != nil {
		fmt.Println("cannot create auk key", err)
		return
	}
	aukKey.Set("kid", "mp")
	aukKey.Set("ext", false)
	aukKey.Set("key_ops", []string{"encrypt", "dercypt"})

	encAukKey, err := crypto.ImportEncSymKey(aukKey, password, secretKey)
	if err != nil {
		fmt.Println("cannot create enc sym key", err)
		return
	}

	payload.PubKey = pubKey
	payload.EncPrivKey = encPrivKey
	payload.EncSymKey = encAukKey

	payloadJson, err := json.Marshal(payload)
	if err != nil {
		fmt.Println("cannot marshal", err)
	}
	fmt.Println(string(payloadJson))
}
