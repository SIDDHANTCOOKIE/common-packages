import { BLOSSOM_AUTH_KIND } from "./constants.js";
import { BlossomHttpError } from "./errors.js";
import type { BlossomTransport, FileSigner } from "./types.js";
import { bytesToBase64, sha256Hex, throwIfAborted } from "./encoding.js";

function trimServer(server: string): string {
  return server.replace(/\/+$/, "");
}

/**
 * Statuses on which a BUD-06 preflight is a real refusal. Deliberately narrow: only a status the server
 * cannot recover from on retry counts — 403 (forbidden), 413 (too large), 415 (unsupported type).
 * Everything else non-2xx is INCONCLUSIVE and must fall through to the real PUT: 404/501 mean BUD-06 is
 * not implemented (verified against live servers that 404 the probe yet accept the PUT), 429 and 5xx
 * are transient per BUD-06's own table, and a timeout says nothing about the upload. A probe that
 * fails transiently must never permanently disqualify a server the real request would have accepted.
 */
export const DEFINITIVE_REFUSAL_STATUSES: ReadonlySet<number> = new Set([403, 413, 415]);

export interface FetchTransportOptions {
  /** How long the BUD-06 preflight may take before it is treated as inconclusive. Default 15000. */
  canAcceptTimeoutMs?: number;
}

function reason(response: Response): string {
  return response.headers.get("X-Reason") || response.statusText || `HTTP ${response.status}`;
}

export function createFetchBlossomTransport(
  fetchImplementation: typeof fetch = fetch,
  options: FetchTransportOptions = {},
): BlossomTransport {
  const canAcceptTimeoutMs = options.canAcceptTimeoutMs ?? 15_000;
  return {
    async upload({ server, bytes, authorization, signal, onBytes }) {
      throwIfAborted(signal);
      const response = await fetchImplementation(`${trimServer(server)}/upload`, {
        method: "PUT",
        headers: {
          ...(authorization ? { Authorization: authorization } : {}),
          "Content-Type": "application/octet-stream",
          "X-SHA-256": await sha256Hex(bytes),
        },
        body: bytes as unknown as BodyInit,
        signal,
      });
      if (!response.ok) throw new BlossomHttpError(reason(response) || `Blossom upload failed (${response.status})`, response.status);
      onBytes?.(bytes.byteLength, bytes.byteLength);
    },

    async canAccept({ server, size, sha256, type, authorization, signal }) {
      throwIfAborted(signal);
      let response: Response;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), canAcceptTimeoutMs);
      const onAbort = () => controller.abort();
      signal?.addEventListener("abort", onAbort, { once: true });
      try {
        response = await fetchImplementation(`${trimServer(server)}/upload`, {
          method: "HEAD",
          headers: {
            ...(authorization ? { Authorization: authorization } : {}),
            "X-Content-Length": String(size),
            "X-Content-Type": type || "application/octet-stream",
            "X-SHA-256": sha256,
          },
          signal: controller.signal,
        });
      } catch {
        // A caller's own abort is not "inconclusive"; a network failure or our timeout is.
        throwIfAborted(signal);
        return { ok: true };
      } finally {
        clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
      }
      if (response.ok || !DEFINITIVE_REFUSAL_STATUSES.has(response.status)) return { ok: true };
      return { ok: false, reason: reason(response), status: response.status };
    },

    async download({ server, hash, expectedSize, authorization, signal, onBytes }) {
      throwIfAborted(signal);
      const response = await fetchImplementation(`${trimServer(server)}/${hash}`, {
        ...(authorization ? { headers: { Authorization: authorization } } : {}),
        signal,
      });
      if (!response.ok) throw new BlossomHttpError(reason(response) || `Blossom download failed (${response.status})`, response.status);
      const contentLength = Number(response.headers.get("content-length"));
      if (expectedSize !== undefined && Number.isFinite(contentLength) && contentLength > expectedSize) {
        await response.body?.cancel();
        throw new Error("Blossom response exceeds expected encrypted file size");
      }
      if (!response.body) return new Uint8Array();

      const reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      let received = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        received += value.byteLength;
        if (expectedSize !== undefined && received > expectedSize) {
          await reader.cancel();
          throw new Error("Blossom response exceeds expected encrypted file size");
        }
        chunks.push(value);
        onBytes?.(received, Number.isFinite(contentLength) && contentLength > 0 ? contentLength : expectedSize ?? received);
      }
      const bytes = new Uint8Array(received);
      let offset = 0;
      for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.byteLength;
      }
      return bytes;
    },

    async downloadStream({ server, hash, authorization, signal }) {
      throwIfAborted(signal);
      const response = await fetchImplementation(`${trimServer(server)}/${hash}`, {
        ...(authorization ? { headers: { Authorization: authorization } } : {}),
        signal,
      });
      if (!response.ok) throw new BlossomHttpError(reason(response), response.status);
      if (!response.body) return { read: async () => ({ done: true }) };
      return response.body.getReader();
    },

    async downloadRange({ server, hash, start, end, authorization, signal }) {
      throwIfAborted(signal);
      const response = await fetchImplementation(`${trimServer(server)}/${hash}`, {
        headers: { ...(authorization ? { Authorization: authorization } : {}), Range: `bytes=${start}-${end}` },
        signal,
      });
      if (!response.ok) throw new BlossomHttpError(reason(response), response.status);
      // The status alone says whether Range was honored: 206 yes, 200 means the whole blob came back.
      return { bytes: new Uint8Array(await response.arrayBuffer()), satisfied: response.status === 206 };
    },

    async exists({ server, hash, authorization, signal }) {
      throwIfAborted(signal);
      const response = await fetchImplementation(`${trimServer(server)}/${hash}`, {
        method: "HEAD",
        ...(authorization ? { headers: { Authorization: authorization } } : {}),
        signal,
      });
      if (response.ok) return true;
      if (response.status === 404) return false;
      // Anything else is "cannot tell": throw rather than answer false, so callers do not gamble.
      throw new BlossomHttpError(`Cannot determine whether the blob exists (${response.status})`, response.status);
    },

    async delete({ server, hash, authorization, signal }) {
      throwIfAborted(signal);
      const response = await fetchImplementation(`${trimServer(server)}/${hash}`, {
        method: "DELETE",
        headers: { Authorization: authorization },
        signal,
      });
      // Already gone is success.
      if (response.ok || response.status === 404) return;
      throw new BlossomHttpError(reason(response), response.status);
    },
  };
}

export async function createBlossomAuthorization(
  signer: FileSigner,
  verb: "upload" | "get" | "delete",
  hashes: readonly string[],
  content: string,
  expiresIn: number,
  now: () => number,
): Promise<string> {
  const pubkey = await signer.getPublicKey();
  const createdAt = now();
  const event = await signer.signEvent({
    kind: BLOSSOM_AUTH_KIND,
    created_at: createdAt,
    content,
    tags: [["t", verb], ["expiration", String(createdAt + expiresIn)], ...hashes.map((hash) => ["x", hash])],
  });
  if (event.pubkey !== pubkey) throw new Error("Signer returned an authorization event for a different pubkey");
  return `Nostr ${bytesToBase64(new TextEncoder().encode(JSON.stringify(event)))}`;
}
