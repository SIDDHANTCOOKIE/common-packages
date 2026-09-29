import { describe, expect, it, vi } from "vitest";
import {
  BlobOverrunError,
  BlobTruncatedError,
  decryptFileBytes,
  decryptRange,
  decryptSegment,
  deriveBlobKey,
  encryptFile,
  encryptSegment,
  IntegrityError,
  LegacyChunkedFileError,
  RangeNotSatisfiedError,
  segmentCount,
  segmentFrameLength,
  streamDecrypt,
  type BlobFile,
  type ByteReader,
} from "../src/index.js";

const KEY = "0a".repeat(32);

function bytes(length: number): Uint8Array {
  return Uint8Array.from({ length }, (_, i) => (i * 7 + 3) % 251);
}

async function fixture(size: number, chunkSize: number, withHash = true) {
  const plaintext = bytes(size);
  const enc = await encryptFile(plaintext, { chunkSize, encryptionKey: KEY });
  const file: BlobFile = {
    size: enc.size,
    chunkSize,
    blobHash: enc.blobHash,
    encryptionKey: KEY,
    ...(withHash ? { unencryptedFileHash: enc.unencryptedFileHash } : {}),
    servers: ["https://one.example"],
    type: "application/octet-stream",
  };
  return { plaintext, enc, file };
}

/** Delivers `blob` in the given chunk sizes (cycling), like a network would. */
function readerOf(blob: Uint8Array, chunkSizes: number[] = [blob.length || 1]): ByteReader & { reads: number } {
  let offset = 0;
  let i = 0;
  const reader = {
    reads: 0,
    async read() {
      reader.reads += 1;
      if (offset >= blob.length) return { done: true };
      const size = chunkSizes[i++ % chunkSizes.length]!;
      const value = blob.subarray(offset, offset + size);
      offset += size;
      return { done: false, value };
    },
  };
  return reader;
}

async function collect(gen: AsyncGenerator<Uint8Array>): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  for await (const part of gen) parts.push(part);
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}

describe("segment primitives", () => {
  it("segmentCount: at least one, no trailing empty segment for exact multiples", () => {
    expect(segmentCount(0, 8)).toBe(1);
    expect(segmentCount(1, 8)).toBe(1);
    expect(segmentCount(8, 8)).toBe(1);
    expect(segmentCount(9, 8)).toBe(2);
    expect(segmentCount(16, 8)).toBe(2);
    expect(segmentCount(17, 8)).toBe(3);
  });

  it("segmentFrameLength: the last frame is short", () => {
    const f = { size: 17, chunkSize: 8 };
    expect([0, 1, 2].map((i) => segmentFrameLength(f, i))).toEqual([24, 24, 17]);
    expect(segmentFrameLength({ size: 0, chunkSize: 8 }, 0)).toBe(16);
  });

  it("per-segment encryption is byte-identical to the buffered blob", async () => {
    for (const size of [0, 1, 7, 8, 9, 16, 17, 100]) {
      const { plaintext, enc } = await fixture(size, 8);
      const key = deriveBlobKey(KEY);
      const total = segmentCount(size, 8);
      const parts: Uint8Array[] = [];
      for (let i = 0; i < total; i += 1) {
        parts.push(await encryptSegment(plaintext.subarray(i * 8, Math.min(size, (i + 1) * 8)), key, i, i === total - 1));
      }
      const joined = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
      let at = 0;
      for (const p of parts) { joined.set(p, at); at += p.length; }
      expect(joined).toEqual(enc.bytes);
      expect(await decryptFileBytes(enc.bytes, (await fixture(size, 8)).file)).toEqual(plaintext);
    }
  });

  it("authenticates position and the last flag", async () => {
    const key = deriveBlobKey(KEY);
    const sealed = await encryptSegment(bytes(8), key, 3, false);
    await expect(decryptSegment(sealed, key, 3, false)).resolves.toEqual(bytes(8));
    await expect(decryptSegment(sealed, key, 4, false)).rejects.toThrow();
    await expect(decryptSegment(sealed, key, 3, true)).rejects.toThrow();
  });

  it("rejects a segment index that overflows the 11-byte counter, and bad indexes and keys", async () => {
    const key = deriveBlobKey(KEY);
    await expect(encryptSegment(bytes(1), key, 2 ** 88, false)).rejects.toThrow("too large");
    await expect(encryptSegment(bytes(1), key, 1e30, true)).rejects.toThrow("too large");
    await expect(encryptSegment(bytes(1), key, -1, false)).rejects.toThrow("non-negative");
    await expect(encryptSegment(bytes(1), key, 1.5, false)).rejects.toThrow("non-negative");
    await expect(decryptSegment(bytes(20), key, Number.NaN, false)).rejects.toThrow("non-negative");
    await expect(encryptSegment(bytes(1), new Uint8Array(16), 0, false)).rejects.toThrow("32 bytes");
    // Just below the limit still encodes (and round-trips with the same index).
    const big = 2 ** 53 - 1;
    const sealed = await encryptSegment(bytes(2), key, big, false);
    await expect(decryptSegment(sealed, key, big, false)).resolves.toEqual(bytes(2));
  });

  it("buffered decrypt does not require unencryptedFileHash but checks it when present", async () => {
    const { plaintext, enc, file } = await fixture(20, 8, false);
    await expect(decryptFileBytes(enc.bytes, file)).resolves.toEqual(plaintext);
    const { file: hashed } = await fixture(20, 8, true);
    await expect(decryptFileBytes(enc.bytes, { ...hashed, unencryptedFileHash: "f".repeat(64) })).rejects.toThrow("Decrypted file hash");
  });
});

describe("streamDecrypt", () => {
  it.each([
    ["one big chunk", [1000]],
    ["one byte at a time", [1]],
    ["odd, frame-straddling chunks", [5, 19, 3, 40]],
    ["exactly one frame per read", [24]],
  ])("decrypts across arbitrary network chunking: %s", async (_name, chunking) => {
    const { plaintext, enc, file } = await fixture(83, 8);
    await expect(collect(streamDecrypt(readerOf(enc.bytes, chunking), file))).resolves.toEqual(plaintext);
  });

  it("yields plaintext segments in order, holding about one frame at a time", async () => {
    const { plaintext, enc, file } = await fixture(20, 8);
    const seen: number[] = [];
    for await (const part of streamDecrypt(readerOf(enc.bytes, [7]), file)) seen.push(part.length);
    expect(seen).toEqual([8, 8, 4]);
    expect(plaintext.length).toBe(20);
  });

  it("handles an empty file and an exact-multiple file", async () => {
    for (const size of [0, 16]) {
      const { plaintext, enc, file } = await fixture(size, 8);
      await expect(collect(streamDecrypt(readerOf(enc.bytes), file))).resolves.toEqual(plaintext);
    }
  });

  it("skips empty reads without treating them as the end", async () => {
    const { plaintext, enc, file } = await fixture(20, 8);
    const queue: Array<{ done: boolean; value?: Uint8Array }> = [
      { done: false, value: new Uint8Array(0) },
      { done: false },
      { done: false, value: enc.bytes },
      { done: true },
    ];
    const reader: ByteReader = { read: async () => queue.shift() ?? { done: true } };
    await expect(collect(streamDecrypt(reader, file))).resolves.toEqual(plaintext);
  });

  describe("REGRESSION: truncation and overrun", () => {
    it("throws on a truncated blob — never hands back a short file", async () => {
      const { enc, file } = await fixture(83, 8);
      for (const cut of [1, 16, enc.bytes.length - 5]) {
        const truncated = enc.bytes.subarray(0, enc.bytes.length - cut);
        await expect(collect(streamDecrypt(readerOf(truncated, [13]), file))).rejects.toBeInstanceOf(BlobTruncatedError);
      }
      await expect(collect(streamDecrypt(readerOf(new Uint8Array(0)), file))).rejects.toBeInstanceOf(BlobTruncatedError);
    });

    it("throws on trailing bytes in the same read as the last frame", async () => {
      const { enc, file } = await fixture(20, 8);
      const padded = new Uint8Array(enc.bytes.length + 3);
      padded.set(enc.bytes);
      await expect(collect(streamDecrypt(readerOf(padded), file))).rejects.toBeInstanceOf(BlobOverrunError);
    });

    it("throws on trailing data that arrives in a later read", async () => {
      const { enc, file } = await fixture(20, 8);
      const padded = new Uint8Array(enc.bytes.length + 1);
      padded.set(enc.bytes);
      await expect(collect(streamDecrypt(readerOf(padded, [enc.bytes.length, 1]), file))).rejects.toBeInstanceOf(BlobOverrunError);
    });

    it("throws when the stream keeps sending an entire extra frame", async () => {
      const { enc, file } = await fixture(16, 8);
      const doubled = new Uint8Array(enc.bytes.length * 2);
      doubled.set(enc.bytes);
      doubled.set(enc.bytes, enc.bytes.length);
      await expect(collect(streamDecrypt(readerOf(doubled, [10]), file))).rejects.toBeInstanceOf(BlobOverrunError);
    });

    it("throws on a reordered or tampered segment via the GCM tag", async () => {
      const { enc, file } = await fixture(24, 8);
      const swapped = new Uint8Array(enc.bytes);
      swapped.set(enc.bytes.subarray(24, 48), 0);
      swapped.set(enc.bytes.subarray(0, 24), 24);
      await expect(collect(streamDecrypt(readerOf(swapped), file))).rejects.toThrow();
      const flipped = new Uint8Array(enc.bytes);
      flipped[3] ^= 1;
      await expect(collect(streamDecrypt(readerOf(flipped), file))).rejects.toThrow();
    });
  });

  it("verifies unencryptedFileHash incrementally and throws IntegrityError on a mismatch", async () => {
    const { enc, file } = await fixture(30, 8);
    const wrong = { ...file, unencryptedFileHash: "e".repeat(64) };
    const out: number[] = [];
    await expect((async () => { for await (const p of streamDecrypt(readerOf(enc.bytes), wrong)) out.push(p.length); })())
      .rejects.toBeInstanceOf(IntegrityError);
    expect(out).toEqual([8, 8, 8, 6]); // segments were already yielded: consumers must discard on throw
  });

  it("does not verify a hash the metadata does not carry (app-shaped files)", async () => {
    const { plaintext, enc, file } = await fixture(30, 8, false);
    await expect(collect(streamDecrypt(readerOf(enc.bytes), file))).resolves.toEqual(plaintext);
  });

  it("refuses a legacy chunked file before reading anything", async () => {
    const reader = readerOf(new Uint8Array(1));
    await expect(collect(streamDecrypt(reader, { legacyChunked: true } as never))).rejects.toBeInstanceOf(LegacyChunkedFileError);
    expect(reader.reads).toBe(0);
  });
});

describe("decryptRange", () => {
  async function serve(size: number, chunkSize: number) {
    const { plaintext, enc, file } = await fixture(size, chunkSize);
    const calls: Array<{ start: number; end: number }> = [];
    const fetchRange = vi.fn(async ({ start, end }: { start: number; end: number }) => {
      calls.push({ start, end });
      return { bytes: enc.bytes.slice(start, end + 1), satisfied: true };
    });
    return { plaintext, enc, file, calls, fetchRange };
  }

  it.each([
    [0, 0], [0, 7], [3, 5], [7, 8], [8, 15], [5, 40], [0, 82], [60, 82], [82, 82], [41, 41],
  ])("returns exactly plaintext[%i..%i] and fetches only the covering segments", async (start, end) => {
    const { plaintext, file, calls, fetchRange } = await serve(83, 8);
    const out = await decryptRange(file, start, end, fetchRange);
    expect(out).toEqual(plaintext.subarray(start, end + 1));
    const first = Math.floor(start / 8);
    const last = Math.floor(Math.min(end, 82) / 8);
    expect(calls).toEqual([{ start: first * 24, end: Math.min(83 + 16 * 11, (last + 1) * 24) - 1 }]);
  });

  it("clamps an end past the file, and handles the short last segment", async () => {
    const { plaintext, file, fetchRange } = await serve(83, 8);
    expect(await decryptRange(file, 80, 10_000, fetchRange)).toEqual(plaintext.subarray(80));
    expect(fetchRange).toHaveBeenCalledWith({ start: 240, end: 83 + 16 * 11 - 1 });
  });

  it("uses isLast for the FILE's last segment, not the last segment of the range", async () => {
    const { plaintext, file, fetchRange } = await serve(83, 8);
    // Range ends mid-file: the final segment it touches is NOT the file's last.
    expect(await decryptRange(file, 10, 20, fetchRange)).toEqual(plaintext.subarray(10, 21));
  });

  it("handles an empty file and an exact-multiple file", async () => {
    const empty = await serve(0, 8);
    expect(await decryptRange(empty.file, 0, 0, empty.fetchRange)).toEqual(new Uint8Array(0));
    expect(empty.fetchRange).not.toHaveBeenCalled();
    const exact = await serve(16, 8);
    expect(await decryptRange(exact.file, 8, 15, exact.fetchRange)).toEqual(exact.plaintext.subarray(8));
  });

  describe("REGRESSION: a server that ignores Range", () => {
    it("tells the caller instead of decoding misaligned bytes", async () => {
      const { enc, file } = await fixture(83, 8);
      // 200 with the WHOLE blob: for a request at segment 4 this would be garbage.
      const ignoring = vi.fn(async () => ({ bytes: enc.bytes, satisfied: false }));
      await expect(decryptRange(file, 40, 50, ignoring)).rejects.toBeInstanceOf(RangeNotSatisfiedError);
      // Even for offset 0, where the bytes happen to line up, an unsatisfied range is not decoded.
      await expect(decryptRange(file, 0, 5, ignoring)).rejects.toBeInstanceOf(RangeNotSatisfiedError);
    });

    it("rejects a satisfied response of the wrong length", async () => {
      const { enc, file } = await fixture(83, 8);
      const short = async () => ({ bytes: enc.bytes.slice(0, 10), satisfied: true });
      await expect(decryptRange(file, 0, 20, short)).rejects.toBeInstanceOf(BlobTruncatedError);
    });
  });

  it("validates its arguments", async () => {
    const { file, fetchRange } = await serve(83, 8);
    await expect(decryptRange(file, -1, 5, fetchRange)).rejects.toThrow(RangeError);
    await expect(decryptRange(file, 5, 4, fetchRange)).rejects.toThrow(RangeError);
    await expect(decryptRange(file, 1.5, 4, fetchRange)).rejects.toThrow(RangeError);
    await expect(decryptRange(file, 83, 90, fetchRange)).rejects.toThrow("past the end");
    expect(fetchRange).not.toHaveBeenCalled();
  });
});
