import { hexToBytes } from "nostr-tools/utils";
import { keyringEntries, type DriveKeyring } from "./drive-key.js";
import { buildEvent, decryptWithKeys, tagValue } from "./events.js";
import { readFileMetadata, type FileEntry } from "./file-entry.js";
import { assertFile, assertFolder, type File, type Folder } from "./schema.js";
import {
  type CreatedFileMetadata,
  type CreatedFolderMetadata,
  type FileMetadataInputs,
  type FolderMetadataInputs,
} from "./types.js";

const ALPHANUMERIC = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

export function randomDTag(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  return Array.from(bytes, (byte) => ALPHANUMERIC[byte % ALPHANUMERIC.length]).join("");
}

/** New events are always encrypted AND signed with the active Drive Key — resolved once, together. */
export function signingMaterial(keyring: DriveKeyring): { conversationKey: Uint8Array; signingKey: Uint8Array } {
  return { conversationKey: keyring.active.conversationKey, signingKey: hexToBytes(keyring.active.secretKeyHex) };
}

export function createFileMetadata(inputs: FileMetadataInputs): CreatedFileMetadata {
  const { keyring, d, createdAt, client, uploadedAt = Date.now(), ...values } = inputs;
  const file: File = { ...values, uploadedAt, encryptionAlgorithm: "aes-gcm" };
  assertFile(file);
  const id = d ?? randomDTag();
  const event = buildEvent({
    subtype: "files",
    d: id,
    payload: file,
    ...signingMaterial(keyring),
    ...(createdAt !== undefined ? { createdAt } : {}),
    ...(client !== undefined ? { client } : {}),
  });
  return { d: id, file, event };
}

export function decryptFileMetadata(content: string, keys: Uint8Array | readonly Uint8Array[]): File {
  const value = decryptWithKeys(content, keys);
  assertFile(value);
  return value;
}

/** Lenient counterpart of decryptFileMetadata: reads either wire shape, from a full event. */
export function decryptFileEntry(event: { content: string; pubkey: string; created_at: number; tags: string[][] }, keys: Uint8Array | readonly Uint8Array[]): FileEntry {
  const id = tagValue(event, "d");
  if (!id) throw new Error("File metadata event has no d tag");
  return readFileMetadata(decryptWithKeys(event.content, keys), { id, author: event.pubkey, createdAt: event.created_at });
}

export function createFolderMetadata(inputs: FolderMetadataInputs): CreatedFolderMetadata {
  const { keyring, d, createdAt, client, ...values } = inputs;
  const folder: Folder = values;
  assertFolder(folder);
  const id = d ?? randomDTag();
  const event = buildEvent({
    subtype: "folder",
    d: id,
    payload: folder,
    ...signingMaterial(keyring),
    ...(createdAt !== undefined ? { createdAt } : {}),
    ...(client !== undefined ? { client } : {}),
  });
  return { d: id, folder, event };
}

export function decryptFolderMetadata(content: string, keys: Uint8Array | readonly Uint8Array[]): Folder {
  const value = decryptWithKeys(content, keys);
  assertFolder(value);
  return value;
}

/** Conversation keys of a keyring, active first — the order metadata decryption tries them. */
export function keyringConversationKeys(keyring: DriveKeyring): Uint8Array[] {
  return keyringEntries(keyring).map((entry) => entry.conversationKey);
}
