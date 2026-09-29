import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "nostr-tools/utils";
import { BlobOverrunError, BlobTruncatedError, IntegrityError, RangeNotSatisfiedError } from "./errors.js";
import { decryptSegment, deriveBlobKey, segmentCount, segmentFrameLength } from "./crypto.js";
import { toBlobFile, type BlobFile, type FileEntry } from "./file-entry.js";
import type { File } from "./schema.js";

/** Structural subset of a ReadableStreamDefaultReader. */
export interface ByteReader {
  read(): Promise<{ done: boolean; value?: Uint8Array }>;
}

/**
 * Wraps a byte reader with an exact-count `readExactly`, buffering across whatever chunk sizes the
 * network actually delivers so callers can pull segment frames regardless of how TCP/HTTP chunked
 * the response.
 */
function createFrameReader(reader: ByteReader) {
  let buffered = new Uint8Array(0);
  let done = false;

  async function fill(n: number): Promise<void> {
    while (buffered.length < n && !done) {
      const chunk = await reader.read();
      if (chunk.done) {
        done = true;
        break;
      }
      const value = chunk.value;
      if (!value || value.length === 0) continue;
      const next = new Uint8Array(buffered.length + value.length);
      next.set(buffered, 0);
      next.set(value, buffered.length);
      buffered = next;
    }
  }

  return {
    /** Exactly `n` bytes, or BlobTruncatedError: a short read is a truncated blob, never "the whole thing". */
    async readExactly(n: number): Promise<Uint8Array> {
      await fill(n);
      if (buffered.length < n) throw new BlobTruncatedError(`Downloaded blob ended early: expected ${n} more byte(s), got ${buffered.length}`);
      const out = buffered.subarray(0, n);
      buffered = buffered.subarray(n);
      return out;
    },
    /**
     * The overrun counterpart of readExactly's truncation check. Each segment's GCM tag already
     * authenticates its own bytes, so trailing ciphertext is not a forgeable payload — but it is still a
     * corrupted or tampered blob that must not be accepted as matching the declared size. Call once,
     * after the last expected readExactly.
     */
    async assertExhausted(): Promise<void> {
      if (buffered.length > 0) throw new BlobOverrunError(`Downloaded blob has ${buffered.length} unexpected trailing byte(s) past the last segment`);
      const chunk = await reader.read();
      if (!chunk.done && chunk.value && chunk.value.length > 0) throw new BlobOverrunError("Downloaded blob has unexpected trailing data past the last segment");
    },
  };
}

/**
 * NIP-FS single-blob download as a stream: reads `chunkSize + 16`-byte frames off the raw blob
 * response, decrypts each, and yields plaintext segments in order. Peak memory is about one segment.
 *
 *  - Throws BlobTruncatedError if the stream ends early and BlobOverrunError if it has bytes left
 *    after the last segment.
 *  - Verifies `unencryptedFileHash` incrementally (when the metadata carries one) and throws
 *    IntegrityError after the last segment. Everything yielded before that throw is unverified:
 *    a consumer writing to disk must treat the throw as failure and discard what it wrote.
 */
export async function* streamDecrypt(reader: ByteReader, source: File | FileEntry | BlobFile): AsyncGenerator<Uint8Array> {
  const file = toBlobFile(source);
  const blobKey = deriveBlobKey(file.encryptionKey);
  const total = segmentCount(file.size, file.chunkSize);
  const frames = createFrameReader(reader);
  const hasher = file.unencryptedFileHash === undefined ? null : sha256.create();

  for (let index = 0; index < total; index += 1) {
    const frame = await frames.readExactly(segmentFrameLength(file, index));
    const plaintext = await decryptSegment(frame, blobKey, index, index === total - 1);
    hasher?.update(plaintext);
    yield plaintext;
  }

  await frames.assertExhausted();
  if (hasher && file.unencryptedFileHash !== undefined) {
    const actual = bytesToHex(hasher.digest());
    if (actual !== file.unencryptedFileHash.toLowerCase()) {
      throw new IntegrityError(`File integrity check failed: expected hash ${file.unencryptedFileHash}, got ${actual}`);
    }
  }
}

/** One ciphertext range response. `satisfied` is true only for a real partial response (206). */
export interface RangeResponse {
  bytes: Uint8Array;
  satisfied: boolean;
}

export type FetchRange = (range: { start: number; end: number }) => Promise<RangeResponse>;

/**
 * Reads and decrypts the plaintext byte range [start, end] (inclusive) of a single-blob file,
 * fetching only the ciphertext segments that range overlaps.
 *
 * `fetchRange` gets an inclusive ciphertext byte range and must report whether the server honored it.
 * Range support is optional per BUD-01: a server that ignores it answers 200 with the whole blob, and
 * decoding that as if it started at the requested offset fails every GCM tag — or worse, appears to
 * work only for offset 0. So an unsatisfied response is never decoded: RangeNotSatisfiedError is
 * thrown and the caller falls back to streaming.
 *
 * Two easy mistakes, both avoided: the file's LAST segment is shorter than `chunkSize`, and `isLast`
 * means the FILE's last segment, not the last one in this range.
 */
export async function decryptRange(
  source: File | FileEntry | BlobFile,
  start: number,
  end: number,
  fetchRange: FetchRange,
): Promise<Uint8Array> {
  const file = toBlobFile(source);
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || end < start) {
    throw new RangeError(`Invalid plaintext range ${start}-${end}`);
  }
  if (file.size === 0) return new Uint8Array(0);
  if (start >= file.size) throw new RangeError(`Range start ${start} is past the end of a ${file.size}-byte file`);

  const { chunkSize, size } = file;
  const total = segmentCount(size, chunkSize);
  const frameSize = chunkSize + 16;
  const lastPlaintext = Math.min(end, size - 1);
  const first = Math.floor(start / chunkSize);
  const last = Math.floor(lastPlaintext / chunkSize);
  const blobStart = first * frameSize;
  const blobEnd = Math.min(size + 16 * total, (last + 1) * frameSize) - 1;

  const response = await fetchRange({ start: blobStart, end: blobEnd });
  if (!response.satisfied) throw new RangeNotSatisfiedError();
  const expected = blobEnd - blobStart + 1;
  if (response.bytes.length !== expected) {
    throw new BlobTruncatedError(`Range response has ${response.bytes.length} byte(s), expected ${expected}`);
  }

  const blobKey = deriveBlobKey(file.encryptionKey);
  const parts: Uint8Array[] = [];
  let offset = 0;
  for (let index = first; index <= last; index += 1) {
    const length = segmentFrameLength(file, index);
    parts.push(await decryptSegment(response.bytes.subarray(offset, offset + length), blobKey, index, index === total - 1));
    offset += length;
  }
  const joined = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let at = 0;
  for (const part of parts) {
    joined.set(part, at);
    at += part.length;
  }
  const head = start - first * chunkSize;
  return joined.subarray(head, head + (lastPlaintext - start + 1));
}
