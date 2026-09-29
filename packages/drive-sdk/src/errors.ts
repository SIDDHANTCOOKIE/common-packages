import type { DriveKeyStatus } from "./drive-key.js";

/** Base class so hosts can `instanceof`-branch on anything this package throws deliberately. */
export class DriveSdkError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = new.target.name;
  }
}

/** A Blossom server answered with a non-success status. `status` drives retry and refusal decisions. */
export class BlossomHttpError extends DriveSdkError {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

/** A server refused an upload up front (BUD-06 preflight: 403/413/415). No PUT was attempted. */
export class UploadRefusedError extends DriveSdkError {
  constructor(message: string, readonly status?: number) {
    super(message);
  }
}

export interface ServerFailure {
  server: string;
  error: unknown;
  /** True when the server refused at the preflight and no upload was attempted. */
  refused: boolean;
}

/** No server took the blob. `failures` is the honest per-server account. */
export class AllServersFailedError extends DriveSdkError {
  constructor(readonly failures: ServerFailure[]) {
    super(
      `Unable to upload to any Blossom server: ${failures
        .map((f) => `${f.server} (${f.error instanceof Error ? f.error.message : String(f.error)})`)
        .join("; ")}`,
    );
  }
}

/**
 * Minting was refused. Carries the verdict that caused it so the host can show
 * the right message: `empty-confirmed` is the only status that ever permits it.
 */
export class DriveKeyMintRefusedError extends DriveSdkError {
  constructor(
    message: string,
    readonly status: DriveKeyStatus | { kind: "already-minted" } | { kind: "in-flight" },
  ) {
    super(message);
  }
}

/** An operation needed a resolved keyring and the status was not `ready`. */
export class DriveKeyUnavailableError extends DriveSdkError {
  constructor(readonly status: DriveKeyStatus) {
    super(
      status.kind === "unresolved"
        ? `Drive Key unresolved: ${status.reason}`
        : "No Drive Key exists yet for this identity",
    );
  }
}

/** A publish would have removed a secret the keyring already holds. Never allowed. */
export class DriveKeyDroppedError extends DriveSdkError {}

/**
 * The file predates the NIP-FS single-blob layout: one Blossom blob per chunk (`chunks`, no
 * `blobHash`). It parses and lists, but the SDK cannot decrypt it — see docs/adr/0002.
 */
export class LegacyChunkedFileError extends DriveSdkError {
  constructor(readonly fileId?: string) {
    super("This file uses the legacy per-chunk blob layout, which this SDK cannot download or reuse");
  }
}

/** File metadata that is neither the spec shape nor the app's current shape. */
export class InvalidFileMetadataError extends DriveSdkError {}

/**
 * An operation would have to translate an app-shaped file (folder = a path string, no parent id)
 * into the spec's parent-id model, which cannot be done without inventing an id.
 */
export class AppShapedFileError extends DriveSdkError {
  constructor(operation: string) {
    super(`Cannot ${operation} a file written by the formstr-drive app: it places files by folder path, not by parent id`);
  }
}

/** The blob stream ended before every segment arrived. */
export class BlobTruncatedError extends DriveSdkError {}

/** The blob stream carried bytes past the last segment. */
export class BlobOverrunError extends DriveSdkError {}

/** The decrypted plaintext does not hash to `unencryptedFileHash`. */
export class IntegrityError extends DriveSdkError {}

/** The server ignored the Range header (answered 200 with the whole blob); nothing was decoded. */
export class RangeNotSatisfiedError extends DriveSdkError {
  constructor() {
    super("The server ignored the Range request (200 instead of 206); refusing to decode misaligned bytes");
  }
}

/** The pasted/decoded share link is malformed, has the wrong key, or points at something that is not a file share. */
export class InvalidShareLinkError extends DriveSdkError {}

/** No event was found at the link's coordinate within the timeout (bad link, or relays unreachable). */
export class ShareNotFoundError extends DriveSdkError {
  constructor() {
    super("This share link could not be found. It may be invalid, or the relays are unreachable.");
  }
}

/** Revoking needs the Drive Key that authored the share; the keyring no longer holds it. */
export class ShareKeyMissingError extends DriveSdkError {
  constructor(pubkey: string) {
    super(`This share was created with a Drive Key this keyring does not hold (${pubkey})`);
  }
}

/** Folder sharing (`t=container`) is out of scope for this SDK. */
export class FolderShareUnsupportedError extends DriveSdkError {
  constructor(operation = "resolve") {
    super(`Folder shares are not supported (cannot ${operation} a t=container share)`);
  }
}
