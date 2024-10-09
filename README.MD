# Time-Lock Encryption

### Build and Run the Service

```bash
cargo build --release
cargo run --release
```

The service will start listening on `127.0.0.1:3030`.

## Usage

### Encrypt a Message

Use the `/encrypt` endpoint to encrypt a message that can only be decrypted after a specified delay.

```bash
curl -X POST \
     -H "Content-Type: application/json" \
     -d '{"message": "Hello, future!", "delay_seconds": 60}' \
     http://127.0.0.1:3030/encrypt
```

#### Sample Response:

```json
{
    "ciphertext": "BASE64_ENCODED_CIPHERTEXT"
}
```

### Decrypt a Message

Use the `/decrypt` endpoint to decrypt a previously encrypted message once the delay has elapsed.

```bash
curl -X POST \
     -H "Content-Type: application/json" \
     -d '{"ciphertext": "BASE64_ENCODED_CIPHERTEXT"}' \
     http://127.0.0.1:3030/decrypt
```

#### Sample Response:

```json
{
    "message": "Hello, future!"
}
```
