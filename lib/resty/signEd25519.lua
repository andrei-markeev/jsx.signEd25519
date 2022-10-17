local ffi = require "ffi"
local ffi_C = ffi.C
local ffi_new = ffi.new
local ffi_string = ffi.string
local ffi_gc = ffi.gc
local unsigned_char = ffi.typeof "unsigned char[?]"

ffi.cdef[[

    int ngx_http_lua_ffi_decode_base64(const unsigned char *src, size_t len, unsigned char *dst, size_t *dlen);

    typedef struct evp_pkey_st EVP_PKEY;
    typedef struct engine_st ENGINE;
    typedef struct env_md_ctx_st EVP_MD_CTX;
    typedef struct env_md_st EVP_MD;
    typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;

    EVP_PKEY *EVP_PKEY_new_raw_private_key(int type, ENGINE *e, const unsigned char *key, size_t keylen);
    void EVP_PKEY_free(EVP_PKEY *key);

    EVP_MD_CTX *EVP_MD_CTX_new();
    void EVP_MD_CTX_free(EVP_MD_CTX *ctx);

    int EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
    int EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *sigret, size_t *siglen, const unsigned char *tbs, size_t tbslen);

]]

local function signEd25519(keyInBase64, payload)
    local rawKey = ffi_new(unsigned_char, 33)
    local buf = ffi_new(unsigned_char, 65)
    local len = ffi_new("size_t[1]", 2)

    local decodeResult = ffi_C.ngx_http_lua_ffi_decode_base64(keyInBase64, #keyInBase64, rawKey, len)
    if decodeResult == 0 then
        ngx.log(ngx.ERR, "Failed to decode private key from base64");
        return nil
    end

    local privateKey = ffi_C.EVP_PKEY_new_raw_private_key(1087, nil, rawKey, 32)
    if privateKey == nil then
        ngx.log(ngx.ERR, "EVP_PKEY_new_raw_private_key failed");
        return nil
    end
    ffi_gc(privateKey, ffi_C.EVP_PKEY_free)

    local ctx = ffi_C.EVP_MD_CTX_new()
    if ctx == nil then
        ngx.log(ngx.ERR, "EVP_MD_CTX_new failed");
        return nil
    end
    ffi_gc(ctx, ffi_C.EVP_MD_CTX_free)

    local initResult = ffi_C.EVP_DigestSignInit(ctx, nil, nil, nil, privateKey)
    if initResult <= 0 then
        ngx.log(ngx.ERR, "EVP_DigestSignInit failed: ", initResult);
        return nil
    end

    len[0] = 64;
    local signResult = ffi_C.EVP_DigestSign(ctx, buf, len, payload, #payload)
    if signResult <= 0 then
        ngx.log(ngx.ERR, "EVP_DigestSign failed: ", signResult);
        return nil
    end

    return ffi_string(buf, len[0])
end

return {
    signEd25519 = signEd25519
}