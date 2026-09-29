import type { DriveKeyStatus } from "./drive-key.js";

/** Base class so hosts can `instanceof`-branch on anything this package throws deliberately. */
export class DriveSdkError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = new.target.name;
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
