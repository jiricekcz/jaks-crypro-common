export const KEY_TYPES = ["EC", "RSA", "oct"] as const;
export const KEY_USES = ["sig", "enc"] as const;
export const KEY_OPERATIONS = [
    "sign",
    "verify",
    "encrypt",
    "decrypt",
    "wrapKey",
    "unwrapKey",
    "deriveKey",
    "deriveBits",
] as const;

export type KeyType = typeof KEY_TYPES[number];
export type KeyUse = typeof KEY_USES[number];
export type KeyOperation = typeof KEY_OPERATIONS[number];

export const PUBLIC_KEY_OPERATIONS = ["verify"] as const;
export const PRIVATE_KEY_OPERATIONS = ["sign", "decrypt", "unwrapKey", "deriveKey", "deriveBits"] as const;
export const SYMMETRIC_KEYS_OPERATIONS = ["sign", "verify", "encrypt", "decrypt"] as const;

export type PublicKeyOperation = typeof PUBLIC_KEY_OPERATIONS[number];
export type PrivateKeyOperation = typeof PRIVATE_KEY_OPERATIONS[number];
export type SymmetricKeyOperation = typeof SYMMETRIC_KEYS_OPERATIONS[number];

export const EC_ALGORITHMS = ["ES256", "ES384", "ES512"] as const;
export const RSA_ALGORITHMS = ["RS256", "RS384", "RS512"] as const;
export const HMAC_ALGORITHMS = ["HS256", "HS384", "HS512"] as const;

export const ALGORITHMS = [...EC_ALGORITHMS, ...RSA_ALGORITHMS, ...HMAC_ALGORITHMS] as const;

export type ECAlgorithm = typeof EC_ALGORITHMS[number];
export type RSAAlgorithm = typeof RSA_ALGORITHMS[number];
export type HMACAlgorithm = typeof HMAC_ALGORITHMS[number];

export type Algorithm = typeof ALGORITHMS[number];
/**
 * @see https://www.rfc-editor.org/rfc/rfc7517
 */
export type JWK = JWK_EC | JWK_RSA | JWK_OCT;
export interface JWKBase {
    kty: KeyType;
    use: KeyUse;
    key_ops: KeyOperation[];
    alg?: Algorithm;
    kid?: string;
    x5u?: string;
    x5c?: string[];
    x5t?: string;
    "x5t#S256"?: string;
}
export type JWK_EC = JWK_EC_Private | JWK_EC_Public;
export type JWK_EC_Public = JWK_EC_Public_Sign | JWK_EC_Public_Encrypt;
export type JWK_EC_Private = JWK_EC_Private_Sign | JWK_EC_Private_Encrypt;
export interface JWK_EC_Public_Sign extends JWKBase {
    kty: "EC";
    use: "sig";
    key_ops: "verify"[];
    alg: ECAlgorithm;

    crv: "P-256" | "P-384" | "P-521";
    x: string;
    y: string;
}
export interface JWK_EC_Public_Encrypt extends JWKBase {
    kty: "EC";
    use: "enc";
    key_ops: ("encrypt" | "wrapKey")[];
    alg: ECAlgorithm;

    crv: "P-256" | "P-384" | "P-521";
    x: string;
    y: string;
}
export interface JWK_EC_Private_Sign extends JWKBase {
    kty: "EC";
    use: "sig";
    key_ops: ("sign" | "verify")[];
    alg: ECAlgorithm;

    crv: "P-256" | "P-384" | "P-521";
    x: string;
    y: string;
    d: string;
}
export interface JWK_EC_Private_Encrypt extends JWKBase {
    kty: "EC";
    use: "enc";
    key_ops: ("decrypt" | "unwrapKey")[];
    alg: ECAlgorithm;

    crv: "P-256" | "P-384" | "P-521";
    x: string;
    y: string;
    d: string;
}

export type JWK_RSA = JWK_RSA_Private | JWK_RSA_Public;
export type JWK_RSA_Public = JWK_RSA_Public_Sign | JWK_RSA_Public_Encrypt;
export type JWK_RSA_Private = JWK_RSA_Private_Sign | JWK_RSA_Private_Encrypt;
export interface JWK_RSA_Public_Sign extends JWKBase {
    kty: "RSA";
    use: "sig";
    key_ops: "verify"[];
    alg: RSAAlgorithm;

    n: string;
    e: string;
}

export interface JWK_RSA_Public_Encrypt extends JWKBase {
    kty: "RSA";
    use: "enc";
    key_ops: ("encrypt" | "wrapKey")[];
    alg: RSAAlgorithm;

    n: string;
    e: string;
}

export interface JWK_RSA_Private_Sign extends JWKBase {
    kty: "RSA";
    use: "sig";
    key_ops: ("sign" | "verify")[];
    alg: RSAAlgorithm;

    n: string;
    e: string;
    d: string;
    p: string;
    q: string;
    dp: string;
    dq: string;
    qi: string;
}

export interface JWK_RSA_Private_Encrypt extends JWKBase {
    kty: "RSA";
    use: "enc";
    key_ops: ("decrypt" | "unwrapKey")[];
    alg: RSAAlgorithm;

    n: string;
    e: string;
    d: string;
    p: string;
    q: string;
    dp: string;
    dq: string;
    qi: string;
}

export interface JWK_OCT extends JWKBase {
    kty: "oct";
    k: string;
}
