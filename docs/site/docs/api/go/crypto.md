# Go Cryptography API

The `crypto` package provides Aethelred's post-quantum cryptographic primitives: hybrid ECDSA+Dilithium3 signatures, Kyber768 key encapsulation, and supporting hash and KDF functions.

## Import

```go
import "github.com/aethelred/sdk-go/crypto"
```

## Key Generation

### GenerateKeyPair

Generates a hybrid ECDSA (secp256k1) + Dilithium3 key pair.

```go
func GenerateKeyPair() (*KeyPair, error)
```

```go
kp, err := crypto.GenerateKeyPair()
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Address: %s\n", kp.Address())
```

### KeyPair

```go
type KeyPair struct {
    // contains private fields
}

func (kp *KeyPair) PublicKey() *PublicKey
func (kp *KeyPair) Address() string
func (kp *KeyPair) Sign(msg []byte) (*HybridSignature, error)
func (kp *KeyPair) Export(password string) ([]byte, error)
```

### ImportKeyPair

```go
func ImportKeyPair(data []byte, password string) (*KeyPair, error)
```

## Hybrid Signatures

Every message is signed with both ECDSA (secp256k1) and Dilithium3. Both must verify for the signature to be valid.

### Sign

```go
func (kp *KeyPair) Sign(msg []byte) (*HybridSignature, error)
```

### Verify

```go
func Verify(pubKey *PublicKey, msg []byte, sig *HybridSignature) (bool, error)
```

### HybridSignature

```go
type HybridSignature struct {
    ECDSA      []byte   // 64 bytes (r || s)
    Dilithium3 []byte   // ~2,420 bytes
}

func (s *HybridSignature) Bytes() []byte
```

## Key Encapsulation (Kyber768)

### GenerateKEMKeyPair

```go
func GenerateKEMKeyPair() (*KEMKeyPair, error)
```

### Encapsulate

```go
func Encapsulate(publicKey *KEMPublicKey) (sharedSecret []byte, ciphertext []byte, err error)
```

### Decapsulate

```go
func (kp *KEMKeyPair) Decapsulate(ciphertext []byte) ([]byte, error)
```

```go
alice, _ := crypto.GenerateKEMKeyPair()
sharedSecret, ciphertext, _ := crypto.Encapsulate(alice.PublicKey())
aliceSecret, _ := alice.Decapsulate(ciphertext)
// sharedSecret == aliceSecret (32 bytes)
```

| Parameter | Size |
|---|---|
| Kyber768 public key | 1,184 bytes |
| Kyber768 secret key | 2,400 bytes |
| Kyber768 ciphertext | 1,088 bytes |
| Shared secret | 32 bytes |

## Hashing

```go
func SHA3256(data []byte) [32]byte
func SHA3512(data []byte) [64]byte
func BLAKE3(data []byte) [32]byte
```

## Key Derivation

```go
func HKDF(secret, salt, info []byte, length int) ([]byte, error)
```

## Keyring

```go
func NewKeyring(backend KeyringBackend, dir string) (*Keyring, error)
```

| Backend | Description |
|---|---|
| `KeyringBackendOS` | OS credential store (macOS Keychain, Linux SecretService) |
| `KeyringBackendFile` | Encrypted file on disk |
| `KeyringBackendTest` | Unencrypted, for testing only |

## Related Pages

- [Cryptography Overview](/cryptography/overview) -- algorithm details
- [Security Parameters](/cryptography/security-parameters) -- key sizes and security levels
- [Key Management](/cryptography/key-management) -- rotation, backup, recovery
- [HSM Deployment](/cryptography/hsm-deployment) -- hardware key storage
