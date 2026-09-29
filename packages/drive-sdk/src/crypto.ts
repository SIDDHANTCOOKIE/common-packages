import { generateSecretKey, getPublicKey, nip44 } from "nostr-tools";
import { bytesToHex, hexToBytes } from "nostr-tools/utils";
import { sha256Hex } from "./encoding.js";
import { toBlobFile, type BlobFile, type FileEntry } from "./file-entry.js";
import type { File } from "./schema.js";
import { DEFAULT_CHUNK_SIZE } from "./constants.js";
import type { EncryptedFile } from "./types.js";

const AES_GCM_TAG_BYTES = 16;
const NONCE_BYTES = 12;

function assertChunkSize(chunkSize: number): void {
  if (!Number.isSafeInteger(chunkSize) || chunkSize <= 0) {
    throw new Error("chunkSize must be a positive safe integer");
  }
}

export function conversationKeyFromSecret(secretHex: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/i.test(secretHex)) throw new Error("encryptionKey must be a 32-byte hex private key");
  const secret = hexToBytes(secretHex);
  return nip44.v2.utils.getConversationKey(secret, getPublicKey(secret));
}

function segmentNonce(index: number, isLast: boolean): Uint8Array {
  const nonce = new Uint8Array(NONCE_BYTES);
  let value = BigInt(index);
  for (let offset = 10; offset >= 0; offset -= 1) {
    nonce[offset] = Number(value & 0xffn);
    value >>= 8n;
  }
  nonce[11] = isLast ? 1 : 0;
  return nonce;
}

async function aesKey(encryptionKey: string, usage: KeyUsage): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    conversationKeyFromSecret(encryptionKey) as BufferSource,
    "AES-GCM",
    false,
    [usage],
  );
}

function sourceBytes(source: Blob | Uint8Array): Promise<Uint8Array> | Uint8Array {
  if (source instanceof Uint8Array) return source;
  return source.arrayBuffer().then((value) => new Uint8Array(value));
}

export async function encryptFile(
  source: Blob | Uint8Array,
  options: { chunkSize?: number; encryptionKey?: string } = {},
): Promise<EncryptedFile> {
  const chunkSize = options.chunkSize ?? DEFAULT_CHUNK_SIZE;
  assertChunkSize(chunkSize);
  const plaintext = await sourceBytes(source);
  const encryptionKey = options.encryptionKey ?? bytesToHex(generateSecretKey());
  const key = await aesKey(encryptionKey, "encrypt");
  const segmentCount = Math.max(1, Math.ceil(plaintext.byteLength / chunkSize));
  const encrypted = new Uint8Array(plaintext.byteLength + segmentCount * AES_GCM_TAG_BYTES);
  let encryptedOffset = 0;

  for (let index = 0; index < segmentCount; index += 1) {
    const isLast = index === segmentCount - 1;
    const segment = plaintext.subarray(index * chunkSize, Math.min(plaintext.byteLength, (index + 1) * chunkSize));
    const sealed = new Uint8Array(await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: segmentNonce(index, isLast) as BufferSource },
      key,
      segment as BufferSource,
    ));
    encrypted.set(sealed, encryptedOffset);
    encryptedOffset += sealed.byteLength;
  }

  return {
    bytes: encrypted,
    blobHash: await sha256Hex(encrypted),
    encryptionKey,
    unencryptedFileHash: await sha256Hex(plaintext),
    size: plaintext.byteLength,
    chunkSize,
  };
}

export async function decryptFileBytes(encryptedBlob: Uint8Array, source: File | FileEntry | BlobFile): Promise<Uint8Array> {
  const file = toBlobFile(source);
  if (await sha256Hex(encryptedBlob) !== file.blobHash.toLowerCase()) {
    throw new Error("Encrypted blob hash does not match file metadata");
  }

  const segmentCount = Math.max(1, Math.ceil(file.size / file.chunkSize));
  const expectedEncryptedSize = file.size + segmentCount * AES_GCM_TAG_BYTES;
  if (encryptedBlob.byteLength !== expectedEncryptedSize) {
    throw new Error("Encrypted blob size does not match file metadata");
  }

  const key = await aesKey(file.encryptionKey, "decrypt");
  const plaintext = new Uint8Array(file.size);
  let encryptedOffset = 0;
  let plaintextOffset = 0;
  for (let index = 0; index < segmentCount; index += 1) {
    const isLast = index === segmentCount - 1;
    const plaintextLength = isLast ? file.size - index * file.chunkSize : file.chunkSize;
    const sealedLength = plaintextLength + AES_GCM_TAG_BYTES;
    try {
      const segment = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: segmentNonce(index, isLast) as BufferSource },
        key,
        encryptedBlob.subarray(encryptedOffset, encryptedOffset + sealedLength) as BufferSource,
      );
      plaintext.set(new Uint8Array(segment), plaintextOffset);
    } catch (error) {
      throw new Error(`Failed to decrypt NIP-FS segment ${index}`, { cause: error });
    }
    encryptedOffset += sealedLength;
    plaintextOffset += plaintextLength;
  }

  // Optional in the app's metadata shape: verified whenever it is there.
  if (file.unencryptedFileHash !== undefined && await sha256Hex(plaintext) !== file.unencryptedFileHash.toLowerCase()) {
    throw new Error("Decrypted file hash does not match file metadata");
  }
  return plaintext;
}
