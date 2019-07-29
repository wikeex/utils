package utils

import (
	"golang.org/x/crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
)

const (
	SALTCHARS  = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	ITERATIONS = 50000
)

func GenSalt(length int) *[]byte {
	var saltSlice []byte
	for i := 0; i <= length; i++ {
		c := SALTCHARS[rand.Intn(62)]
		saltSlice = append(saltSlice, c)
	}
	return &saltSlice
}

func GeneratePasswordHash(password string) string {
	salt := GenSalt(8)
	dk := pbkdf2.Key([]byte(password), *salt, ITERATIONS, 32, sha256.New)
	strDk := hex.EncodeToString(dk)
	strSalt := hex.EncodeToString(*salt)

	// 要把pbkdf2头加上去，具体参考数据库中加密过后的密码字段
	passwordHash := strings.Join([]string{"pbkdf2:sha256:50000", strSalt, strDk}, "$")
	return passwordHash
}

func CheckPasswordHash(password string, passwordHash string) (bool, error) {
	passwordArray := strings.Split(passwordHash, "$")
	if len(passwordArray) != 3 {
		return false, fmt.Errorf("passwordHash is not valid")
	} else {
		salt := passwordArray[1]
		hashDk := passwordArray[2]

		dk := pbkdf2.Key([]byte(password), []byte(salt), ITERATIONS, 32, sha256.New)
		if hashDk == hex.EncodeToString(dk) {
			return true, nil
		} else {
			return false, nil
		}
	}
}
