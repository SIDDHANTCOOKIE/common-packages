import { Type, type Static } from "@sinclair/typebox";
import { Value } from "@sinclair/typebox/value";

const SHA256_HEX = "^[0-9a-fA-F]{64}$";
const HTTP_URL = "^https?://[^\\s]+$";
const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;
const SECP256K1_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

export const fileSchema = Type.Object({
  name: Type.String({ minLength: 1 }),
  unencryptedFileHash: Type.String({ pattern: SHA256_HEX }),
  size: Type.Integer({ minimum: 0, maximum: MAX_SAFE_INTEGER }),
  type: Type.String({ minLength: 1 }),
  parent: Type.String(),
  uploadedAt: Type.Integer({ minimum: 0, maximum: MAX_SAFE_INTEGER }),
  servers: Type.Array(Type.String({ pattern: HTTP_URL }), { minItems: 1, uniqueItems: true }),
  encryptionKey: Type.String({ pattern: SHA256_HEX }),
  encryptionAlgorithm: Type.Literal("aes-gcm"),
  previewHash: Type.Optional(Type.String({ pattern: SHA256_HEX })),
  blobHash: Type.String({ pattern: SHA256_HEX }),
  chunkSize: Type.Integer({ minimum: 1, maximum: MAX_SAFE_INTEGER }),
}, { additionalProperties: false });

export type File = Static<typeof fileSchema>;

export const folderSchema = Type.Object({
  name: Type.String({ minLength: 1 }),
  parent: Type.String(),
}, { additionalProperties: false });

export type Folder = Static<typeof folderSchema>;

export const encryptionKeyMetadataSchema = Type.Object({
  encryptionKey: Type.String({ pattern: SHA256_HEX }),
  previousKeys: Type.Optional(Type.Array(Type.String({ pattern: SHA256_HEX }))),
}, { additionalProperties: false });

export type EncryptionKeyMetadata = Static<typeof encryptionKeyMetadataSchema>;

function hasValidEncryptionKey(value: File): boolean {
  const scalar = BigInt(`0x${value.encryptionKey}`);
  return scalar > 0n && scalar < SECP256K1_ORDER;
}

export function isValidEncryptionKey(value: string): boolean {
  const scalar = BigInt(`0x${value}`);
  return scalar > 0n && scalar < SECP256K1_ORDER;
}

export function isFile(value: unknown): value is File {
  return Value.Check(fileSchema, value) && hasValidEncryptionKey(value);
}

export function assertFile(value: unknown): asserts value is File {
  if (isFile(value)) return;
  if (Value.Check(fileSchema, value) && !hasValidEncryptionKey(value)) {
    throw new Error("Invalid NIP-FS file metadata: /encryptionKey: Expected a valid secp256k1 private key");
  }
  const details = [...Value.Errors(fileSchema, value)]
    .map((error) => `${error.path || "/"}: ${error.message}`)
    .join("; ");
  throw new Error(`Invalid NIP-FS file metadata: ${details}`);
}

export function isFolder(value: unknown): value is Folder {
  return Value.Check(folderSchema, value);
}

export function assertFolder(value: unknown): asserts value is Folder {
  if (isFolder(value)) return;
  const details = [...Value.Errors(folderSchema, value)]
    .map((error) => `${error.path || "/"}: ${error.message}`)
    .join("; ");
  throw new Error(`Invalid NIP-FS folder metadata: ${details}`);
}

export function isEncryptionKeyMetadata(value: unknown): value is EncryptionKeyMetadata {
  return Value.Check(encryptionKeyMetadataSchema, value)
    && isValidEncryptionKey(value.encryptionKey)
    && (value.previousKeys ?? []).every(isValidEncryptionKey);
}

export function assertEncryptionKeyMetadata(value: unknown): asserts value is EncryptionKeyMetadata {
  if (isEncryptionKeyMetadata(value)) return;
  if (Value.Check(encryptionKeyMetadataSchema, value)) {
    throw new Error("Invalid encryption key metadata: /encryptionKey: Expected a valid secp256k1 private key");
  }
  const details = [...Value.Errors(encryptionKeyMetadataSchema, value)]
    .map((error) => `${error.path || "/"}: ${error.message}`)
    .join("; ");
  throw new Error(`Invalid encryption key metadata: ${details}`);
}
