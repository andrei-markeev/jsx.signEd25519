## Signing with Ed25519 algorithm in Openresty

This module provides FFI interface to create signatures using EdDSA Ed25519 algorithm. It uses openssl to do the signing. Openresty's `ngx_http_lua_ffi_decode_base64` function is used for decoding private key from base64.

### How to use

Copy file `lib/resty/signEd25519.lua` to the `resty` folder under `lualib`, e.g. `/usr/local/openresty/site/lualib/resty`.

Use in your code like this:

```lua
local eddsa = require("resty.eddsa")

-- private key in base64
local keyInBase64 = "123456789+abcdefghijklmnopqrstuvwxyz+123450="

eddsa.signEd25519(keyInBase64, "message to sign")
```

**NB!** The key should be in RAW format, so e.g. if you have a PEM file (you can generate one using command `openssl genpkey -algorithm ed25519 -outform PEM -out private_key.pem`), you would need to do something like this:

```console
$ openssl pkey -in private_key.pem -noout -text | sed 1,2d | tr -d '\n\r :' | xxd -r -p | base64
```

### TypescriptToLua users:

Install from NPM:

```bash
npm i resty.eddsa
```

Then use from TS like this:

```ts
import {signEd25519} from "resty.eddsa"

signEd25519(privateKeyInBase64, "message to sign");
```
