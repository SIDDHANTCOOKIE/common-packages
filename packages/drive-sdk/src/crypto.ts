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

/**
 * Number of segments a file of `size` bytes splits into. Always at least 1: an empty file still has
 * exactly one, empty, last segment. An exact multiple of `chunkSize` gets no trailing empty segment.
 */
export function segmentCount(size: number, chunkSize: number): number {
  return Math.max(1, Math.ceil(size / chunkSize));
}

/**
 * The NIP-FS per-segment nonce: an 11-byte big-endian counter, then 0x01 on the final segment and 0x00
 * otherwise. Never random and never stored; the decryptor rebuilds it from a segment's position.
 */
function segmentNonce(index: number, isLast: boolean): Uint8Array {
  if (!Number.isInteger(index) || index < 0) throw new Error(`Segment index must be a non-negative integer, got ${index}`);
  // BigInt, not bit ops: JS shifts truncate to 32 bits past 2^31.
  let value = BigInt(index);
  if (value >= 1n << 88n) throw new Error(`Segment index too large to encode in 11 bytes: ${index}`);
  const nonce = new Uint8Array(NONCE_BYTES);
  for (let offset = 10; offset >= 0; offset -= 1) {
    nonce[offset] = Number(value & 0xffn);
    value >>= 8n;
  }
  nonce[11] = isLast ? 1 : 0;
  return nonce;
}

function importBlobKey(blobKey: Uint8Array, usage: KeyUsage): Promise<CryptoKey> {
  if (blobKey.length !== 32) throw new Error(`blobKey must be 32 bytes, got ${blobKey.length}`);
  return crypto.subtle.importKey("raw", blobKey as BufferSource, "AES-GCM", false, [usage]);
}

/** The 32-byte AES key a file's `encryptionKey` secret yields: its NIP-44 self conversation key. */
export function deriveBlobKey(encryptionKey: string): Uint8Array {
  return conversationKeyFromSecret(encryptionKey);
}

/**
 * Encrypts one NIP-FS segment: AES-256-GCM directly under `blobKey` (no HKDF) with the positional
 * nonce. Output is `ciphertext || tag(16)`. Pure and per-segment, so a host can stream. Rejects an
 * index that overflows the 11-byte counter.
 */
export async function encryptSegment(plaintext: Uint8Array, blobKey: Uint8Array, index: number, isLast: boolean): Promise<Uint8Array> {
  const key = await importBlobKey(blobKey, "encrypt");
  return new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: segmentNonce(index, isLast) as BufferSource }, key, plaintext as BufferSource));
}

/**
 * Inverse of {@link encryptSegment}. `isLast` means the FILE's last segment, not the last one in a
 * fetched range. A wrong index or flag fails the GCM tag instead of returning wrong plaintext.
 */
export async function decryptSegment(payload: Uint8Array, blobKey: Uint8Array, index: number, isLast: boolean): Promise<Uint8Array> {
  const key = await importBlobKey(blobKey, "decrypt");
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: segmentNonce(index, isLast) as BufferSource }, key, payload as BufferSource));
}

/** Ciphertext bytes of the segment at `index`: the last one is short. */
export function segmentFrameLength(file: { size: number; chunkSize: number }, index: number): number {
  const total = segmentCount(file.size, file.chunkSize);
  return (index === total - 1 ? file.size - file.chunkSize * (total - 1) : file.chunkSize) + AES_GCM_TAG_BYTES;
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
  // The buffered path is the per-segment primitive in a loop, so the two can never drift apart.
  const blobKey = deriveBlobKey(encryptionKey);
  const total = segmentCount(plaintext.byteLength, chunkSize);
  const encrypted = new Uint8Array(plaintext.byteLength + total * AES_GCM_TAG_BYTES);
  let encryptedOffset = 0;

  for (let index = 0; index < total; index += 1) {
    const segment = plaintext.subarray(index * chunkSize, Math.min(plaintext.byteLength, (index + 1) * chunkSize));
    const sealed = await encryptSegment(segment, blobKey, index, index === total - 1);
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

  const total = segmentCount(file.size, file.chunkSize);
  const expectedEncryptedSize = file.size + total * AES_GCM_TAG_BYTES;
  if (encryptedBlob.byteLength !== expectedEncryptedSize) {
    throw new Error("Encrypted blob size does not match file metadata");
  }

  const blobKey = deriveBlobKey(file.encryptionKey);
  const plaintext = new Uint8Array(file.size);
  let encryptedOffset = 0;
  let plaintextOffset = 0;
  for (let index = 0; index < total; index += 1) {
    const plaintextLength = index === total - 1 ? file.size - index * file.chunkSize : file.chunkSize;
    const sealedLength = plaintextLength + AES_GCM_TAG_BYTES;
    try {
      const segment = await decryptSegment(encryptedBlob.subarray(encryptedOffset, encryptedOffset + sealedLength), blobKey, index, index === total - 1);
      plaintext.set(segment, plaintextOffset);
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
