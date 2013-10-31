package fish

import "testing"

func Test_Base64Encode(t *testing.T) {
    src := "The quick brown fox jumps over the lazy dog"
    expected := "xzkrL/ui4oi/uSQrJ/M746F/KPkrE/uuRpA/O/wqz/QX46N/uyBsv/G/" +
        "gnC/.......qQpy/"

    enc := Base64Encode([]byte(src))
    if enc != expected {
        t.Fatalf("%s != %s", expected, enc)
    }

    if len(Base64Encode([]byte(""))) != 0 {
        t.Fatalf("Expected empty string")
    }
}

func Test_Base64Decode(t *testing.T) {
    src := "xzkrL/ui4oi/uSQrJ/M746F/KPkrE/uuRpA/O/wqz/QX46N/uyBsv/G/gnC/" +
        ".......qQpy/"
    expected := "The quick brown fox jumps over the lazy dog" +
        "\x00\x00\x00\x00\x00"

    dec := Base64Decode([]byte(src))
    if string(dec) != expected {
        t.Fatalf("%s != %s", expected, dec)
    }

    if len(Base64Decode([]byte(""))) != 0 {
        t.Fatalf("Expected empty string")
    }
}

func Test_IsEncrypted(t *testing.T) {
    if s := "+OK foo"; !IsEncrypted(s) {
        t.Fatalf("Expected true for %s", s)
    }
    if s := "mcps foo"; !IsEncrypted(s) {
        t.Fatalf("Expected true for %s", s)
    }
    if s := "foo"; IsEncrypted(s) {
        t.Fatalf("Expected false for %s", s)
    }
}

func Test_Encrypt(t *testing.T) {
    src := "The quick brown fox jumps over the lazy dog"
    key := "unladen swallow"
    expected := "+OK zT/uX.Z4Q3A/G4YzZ02hMhT1mAsBo.iVKz71YPSQz/trfT4/" +
        "srrS611D5Qz.cnm/71snKIp0"

    actual, err := Encrypt(key, src)
    if err != nil {
        t.Fatal(err)
    }
    if actual != expected {
        t.Fatalf("%s != %s", actual, expected)
    }
}

func Test_Decrypt_Plain(t *testing.T) {
    src := "plain"
    key := "unladen swallow"

    actual, err := Decrypt(key, src)
    if err != nil {
        t.Fatal(err)
    }
    if actual != src {
        t.Fatalf("%s != %s", actual, src)
    }
}

func Test_Decrypt_OkPrefix(t *testing.T) {
    src := "+OK zT/uX.Z4Q3A/G4YzZ02hMhT1mAsBo.iVKz71YPSQz/trfT4/" +
        "srrS611D5Qz.cnm/71snKIp0"
    key := "unladen swallow"
    expected := "The quick brown fox jumps over the lazy dog"

    actual, err := Decrypt(key, src)
    if err != nil {
        t.Fatal(err)
    }
    if actual != expected {
        t.Fatalf("%s != %s", actual, expected)
    }
}

func Test_Decrypt_McpsPrefix(t *testing.T) {
    src := "mcps zT/uX.Z4Q3A/G4YzZ02hMhT1mAsBo.iVKz71YPSQz/trfT4/" +
        "srrS611D5Qz.cnm/71snKIp0"
    key := "unladen swallow"
    expected := "The quick brown fox jumps over the lazy dog"

    actual, err := Decrypt(key, src)
    if err != nil {
        t.Fatal(err)
    }
    if actual != expected {
        t.Fatalf("%s != %s", actual, expected)
    }
}
