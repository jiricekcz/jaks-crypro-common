import { DataResponse } from "./dataResponse";
import { JWK, ECAlgorithm, RSAAlgorithm, HMACAlgorithm, KeyOperation, KeyUse } from "./jwk";
import b64ArrayBuffer from "base64-arraybuffer";

export type AsymmetricDSAlgorithm = ECAlgorithm | RSAAlgorithm;
export type SymmetricDSAlgorithm = HMACAlgorithm;

export type PrivateKey = Key<"private">;
export type PublicKey = Key<"public">;
export type SymmetricKey = Key<"secret">;

export const KEY_TYPES = ["private", "public", "secret"] as const;
export type KeyType = typeof KEY_TYPES[number];

export type KeyAlgorithmsMap = {
    private: AsymmetricDSAlgorithm;
    public: AsymmetricDSAlgorithm;
    secret: SymmetricDSAlgorithm;
};

export abstract class CryptoClient {
    abstract sign(algorithm: AsymmetricDSAlgorithm, key: Key<"private">, data: ArrayBuffer): Promise<SignedData>;
    abstract verify(
        algorithm: AsymmetricDSAlgorithm,
        key: Key<"public">,
        signature: ArrayBuffer,
        data: ArrayBuffer
    ): Promise<boolean>;
    abstract signSymmetric(algorithm: SymmetricDSAlgorithm, key: Key<"secret">, data: ArrayBuffer): Promise<SignedData>;
    async verifySymmetric(
        algorithm: SymmetricDSAlgorithm,
        key: Key<"secret">,
        signature: Signature,
        data: ArrayBuffer
    ): Promise<boolean> {
        const signed = await this.signSymmetric(algorithm, key, data);
        return signed.signature.equals(signature);
    }

    abstract encrypt(algorithm: AsymmetricDSAlgorithm, key: Key<"public">, data: ArrayBuffer): Promise<DataResponse>;
    abstract decrypt(algorithm: AsymmetricDSAlgorithm, key: Key<"private">, data: ArrayBuffer): Promise<DataResponse>;
    abstract encryptSymmetric(
        algorithm: SymmetricDSAlgorithm,
        key: Key<"secret">,
        data: ArrayBuffer
    ): Promise<DataResponse>;
    abstract decryptSymmetric(
        algorithm: SymmetricDSAlgorithm,
        key: Key<"secret">,
        data: ArrayBuffer
    ): Promise<DataResponse>;

    abstract generateSymmetricKey(algorithm: SymmetricDSAlgorithm, use: KeyUse, keySize: number): Promise<Key<"secret">>;
    abstract generateRSAAsymmetricKey(algorithm: RSAAlgorithm, use: KeyUse, keySize: number): Promise<KeyPair>;
    abstract generateECAsymmetricKey(algorithm: ECAlgorithm, use: KeyUse, curve: "P-256" | "P-384" | "P-521"): Promise<KeyPair>;

}
export class Key<T extends KeyType> {
    protected readonly _jwk: JWK;

    constructor(jwk: JWK) {
        this._jwk = jwk;
    }
    public get type(): T {
        if (this._jwk.kty == "oct") return "secret" as T;
        if (
            (this._jwk.key_ops as KeyOperation[]).includes("sign") ||
            (this._jwk.key_ops as KeyOperation[]).includes("decrypt")
        )
            return "private" as T;
        return "public" as T;
    }

    setAlgorithm(algorithm: KeyAlgorithmsMap[T]): void {
        this._jwk.alg = algorithm;
    }

    setKeyID(keyID: string): void {
        this._jwk.kid = keyID;
    }

    setX5U(x5u: string): void {
        this._jwk.x5u = x5u;
    }

    setX5C(x5c: string[]): void {
        this._jwk.x5c = x5c;
    }

    setX5T(x5t: string): void {
        this._jwk.x5t = x5t;
    }

    setX5T256(x5t256: string): void {
        this._jwk["x5t#S256"] = x5t256;
    }

    toJSON(): JWK {
        return this._jwk;
    }
}

export class KeyPair {
    public readonly publicKey: PublicKey;
    public readonly privateKey: PrivateKey;
    constructor(publicKey: PublicKey, privateKey: PrivateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }
    setAlgorithm(algorithm: KeyAlgorithmsMap["private"]): void {
        this.privateKey.setAlgorithm(algorithm);
        this.publicKey.setAlgorithm(algorithm);
    }

    setKeyID(keyID: string): void {
        this.privateKey.setKeyID(keyID);
        this.publicKey.setKeyID(keyID);
    }

    setX5U(x5u: string): void {
        this.privateKey.setX5U(x5u);
        this.publicKey.setX5U(x5u);
    }

    setX5C(x5c: string[]): void {
        this.privateKey.setX5C(x5c);
        this.publicKey.setX5C(x5c);
    }

    setX5T(x5t: string): void {
        this.privateKey.setX5T(x5t);
        this.publicKey.setX5T(x5t);
    }

    setX5T256(x5t256: string): void {
        this.privateKey.setX5T256(x5t256);
        this.publicKey.setX5T256(x5t256);
    }
}

export class Signature {
    private readonly _signature: ArrayBuffer;
    constructor(signature: ArrayBuffer) {
        this._signature = signature;
    }
    get signature(): ArrayBuffer {
        return this._signature;
    }
    toBase64(): string {
        return b64ArrayBuffer.encode(this._signature);
    }
    toUInt8Array(): Uint8Array {
        return new Uint8Array(this._signature);
    }
    equals(other: Signature): boolean {
        const buff1 = this.toUInt8Array();
        const buff2 = other.toUInt8Array();

        if (buff1.length != buff2.length) return false;
        for (let i = 0; i < buff1.length; i++) {
            if (buff1[i] != buff2[i]) return false;
        }
        return true;
    }

    static fromBase64(base64: string): Signature {
        return new Signature(b64ArrayBuffer.decode(base64));
    }
}

export class SignedData {
    private readonly _data: ArrayBuffer;
    private readonly _signature: Signature;
    constructor(data: ArrayBuffer, signature: Signature) {
        this._data = data;
        this._signature = signature;
    }
    get data(): ArrayBuffer {
        return this._data;
    }
    get signature(): Signature {
        return this._signature;
    }
}
