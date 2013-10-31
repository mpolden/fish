package fish

import (
    "bytes"
    "code.google.com/p/go.crypto/blowfish"
    "strings"
)

func pad(src []byte, mod int) []byte {
    remainder := len(src) % mod
    if remainder != 0 {
        return append(src, bytes.Repeat([]byte{0}, mod-remainder)...)
    }
    return src
}

func blowfishEncrypt(key string, src []byte) ([]byte, error) {
    cipher, err := blowfish.NewCipher([]byte(key))
    if err != nil {
        return nil, err
    }
    const bs = blowfish.BlockSize
    dst := make([]byte, len(src))
    for i := 0; i < len(src); i += bs {
        cipher.Encrypt(dst[i:i+bs], src[i:i+bs])
    }
    return dst, nil
}

func blowfishDecrypt(key string, src []byte) ([]byte, error) {
    cipher, err := blowfish.NewCipher([]byte(key))
    if err != nil {
        return nil, err
    }
    const bs = blowfish.BlockSize
    dst := make([]byte, len(src))
    for i := 0; i < len(src); i += bs {
        cipher.Decrypt(dst[i:i+bs], src[i:i+bs])
    }
    return bytes.TrimRight(dst, "\x00"), nil
}

// Base64Encode returns a custom base64 encoding of src. If the size of src is
// not a multiple of 8, src will be padded with \x00 bytes
func Base64Encode(src []byte) string {
    charset := "./0123456789abcdefghijklmnopqrstuvwxyz" +
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    // Ensure src is padded to a multiple of 8
    src = pad(src, 8)

    buf := make([]byte, len(src)/2*3)
    left := 0
    right := 0
    k := -1
    var v int

    for n := 0; k < len(src)-1; {
        for _, count := range []uint8{24, 16, 8, 0} {
            k++
            v = int(src[k])
            left += v << count
        }
        for _, count := range []uint8{24, 16, 8, 0} {
            k++
            v = int(src[k])
            right += v << count
        }
        for i := 0; i < 6; i++ {
            buf[n] = charset[right&0x3F]
            n++
            right >>= 6
        }
        for i := 0; i < 6; i++ {
            buf[n] = charset[left&0x3F]
            n++
            left >>= 6
        }
    }
    return string(buf)
}

// Base64Decode returns the bytes represented by base64 src
func Base64Decode(src []byte) []byte {
    charset := []byte("./0123456789abcdefghijklmnopqrstuvwxyz" +
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ")

    buf := make([]byte, len(src)/3*2)
    k := -1

    for n := 0; k < len(src)-1; {
        left := 0
        right := 0
        var v int
        var w int
        var z int
        for i := uint8(0); i < 6; i++ {
            k++
            v = bytes.IndexByte(charset, src[k])
            right |= v << (i * 6)
        }
        for i := uint8(0); i < 6; i++ {
            k++
            v = bytes.IndexByte(charset, src[k])
            left |= v << (i * 6)
        }
        for i := uint8(0); i < 4; i++ {
            w = left & (0xFF << ((3 - i) * 8))
            z = w >> ((3 - i) * 8)
            buf[n] = byte(z)
            n++
        }
        for i := uint8(0); i < 4; i++ {
            w = right & (0xFF << ((3 - i) * 8))
            z = w >> ((3 - i) * 8)
            buf[n] = byte(z)
            n++
        }
    }
    return buf
}

// Encrypt returns the given message encrypted using key. If the size of
// message is not a multiple of 8, message will be padded with \x00 bytes.
func Encrypt(key string, message string) (string, error) {
    enc, err := blowfishEncrypt(key, pad([]byte(message), 8))
    if err != nil {
        return "", err
    }
    return "+OK " + Base64Encode(enc), nil
}

// IsEncrypted returns true if the s has a valid encryption prefix.
func IsEncrypted(s string) bool {
    return strings.HasPrefix(s, "+OK ") || strings.HasPrefix(s, "mcps ")
}

// Decrypt returns the given message decrypted using key. If message does not
// have any encryption prefix, the message is returned unmodified.
func Decrypt(key string, message string) (string, error) {
    if strings.HasPrefix(message, "+OK ") {
        message = message[4:]
    } else if strings.HasPrefix(message, "mcps ") {
        message = message[5:]
    } else {
        return message, nil
    }
    dec, err := blowfishDecrypt(key, Base64Decode([]byte(message)))
    if err != nil {
        return "", err
    }
    return string(dec), nil
}
