declare module "resty.signEd25519" {
    /** Returns signature for the specified payload.
     * Note: private key should be in RAW format, so if you have a PEM file, you would need to do something like
     * `openssl pkey -in private_key.pem -noout -text | sed 1,2d | tr -d '\n\r :' | xxd -r -p | base64`,
     * and then pass the resulting value into this function.
    */
    export function signEd25519(privateKeyInBase64: string, payloadToSign: string): string;
}
