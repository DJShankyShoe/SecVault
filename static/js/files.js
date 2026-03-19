import * as crypto from "./crypto.js";

import { api, toast } from "./api.js";

import { state } from "./state.js";

import { verifyAndPinPublicKeys } from "./key-pinning.js";

/*
 * FILE FLOW OVERVIEW
 * - Encrypts filenames/content client-side before upload.
 * - Uses ratchet-derived per-version keys for updates.
 * - Verifies signatures and pinned keys before download.
 */

// Decrypts and returns a display filename for a file entry.
async function decryptFilename(file) {
  try {
    // Unwrap file root key via recipient-specific shared secret.
    const sharedSecret = await crypto.x25519DeriveSharedSecret(
      state.x25519Priv,
      await crypto.importX25519Public(file.ephemeralPub),
    );
    // HKDF context keeps wrap-key derivation isolated from all other key uses.
    const wrapKey = await crypto.hkdf(sharedSecret, "file_key_wrap", 32);
    let rootKey;
    try {
      const wrapAad = crypto.strToBytes(file.file_id + "||" + state.email);
      // Owner path: wrapped root key includes AAD binding to fileId + owner email.
      rootKey = await crypto.aesGcmDecrypt(
        wrapKey,
        file.wrapNonce,
        file.rootKey,
        wrapAad,
      );
    } catch (err) {
      // Shared-user path: legacy/shared wraps may omit AAD.
      rootKey = await crypto.aesGcmDecrypt(
        wrapKey,
        file.wrapNonce,
        file.rootKey,
      );
    }
    const fileKey = await crypto.deriveFileKeyForVersion(rootKey, file.version);
    const aad = crypto.strToBytes(file.file_id + "||" + file.owner);
    const filenameBytes = await crypto.aesGcmDecrypt(
      fileKey,
      file.filename_nonce,
      file.filename_enc,
      aad,
    );
    return crypto.bytesToStr(filenameBytes);
  } catch (err) {
    console.error("Failed to decrypt filename:", err);
    return "Encrypted File";
  }
}

// Loads all files, decrypts names, and renders the file list UI.
export async function loadFiles() {
  const fileList = document.getElementById("file-list");
  if (!fileList) return;
  try {
    fileList.innerHTML =
      '<div style="text-align:center;padding:2rem"><span class="spinner"></span> Loading files...</div>';
    const response = await api("GET", "/api/files");
    if (!response.files || response.files.length === 0) {
      fileList.innerHTML = `\n                <div style="text-align:center;padding:2rem;color:var(--muted)">\n                    <div style="font-size:1.1rem;margin-bottom:0.5rem;color:var(--text)">No files yet</div>\n                    <div style="font-size:0.85rem;color:var(--muted)">Upload your first file to get started</div>\n                </div>\n            `;
      return;
    }
    // Decrypt all names first so rendering stays fast and deterministic.
    const filesWithNames = await Promise.all(
      response.files.map(async (file) => {
        const filename = await decryptFilename(file);
        return {
          ...file,
          decryptedFilename: filename,
        };
      }),
    );
    fileList.innerHTML = filesWithNames
      .map(
        (file) =>
          `\n            <div class="file-item" data-file-id="${file.file_id}">\n                <div class="file-icon">📄</div>\n                <div class="file-info">\n                    <div class="file-name">${escapeHtml(file.decryptedFilename)}</div>\n                    <div class="file-meta">\n                        Owner: ${escapeHtml(file.owner)} • \n                        Version: ${file.version} • \n                        ${new Date(file.uploaded_at * 1e3).toLocaleDateString()}\n                    </div>\n                </div>\n                <div class="file-actions">\n                    ${(() => {
            const perms = file.permissions
              ? file.permissions.split(",")
              : ["read", "modify"];
            const hasModify = perms.includes("modify");
            const hasRead = perms.includes("read");
            let buttons = "";
            if (hasModify) {
              buttons += `\n                                <button class="btn-icon" onclick="updateFile('${file.file_id}')" title="Update/Modify">\n                                    ✏️\n                                </button>\n                            `;
            }
            if (hasRead) {
              buttons += `\n                                <button class="btn-icon" onclick="downloadFile('${file.file_id}')" title="Download">\n                                    ⬇️\n                                </button>\n                            `;
            }
            if (file.owner === state.email) {
              buttons += `\n                                <button class="btn-icon" onclick="manageACL('${file.file_id}')" title="Manage Access">\n                                    👥\n                                </button>\n                            `;
            }
            if (file.owner === state.email) {
              buttons += `\n                                <button class="btn-icon" onclick="deleteFile('${file.file_id}')" title="Delete">\n                                    🗑️\n                                </button>\n                            `;
            }
            return buttons;
          })()}\n                </div>\n            </div>\n        `,
      )
      .join("");
  } catch (err) {
    console.error("Failed to load files:", err);
    fileList.innerHTML = `\n            <div style="text-align:center;padding:2rem;color:var(--danger)">\n                ⚠️ Failed to load files: ${err.message}\n            </div>\n        `;
  }
}

// Encrypts and uploads a newly selected file, then refreshes the list.
export async function handleFileUpload(e) {
  e.preventDefault();
  const fileInput = document.getElementById("file-input");
  const uploadBtn = document.getElementById("upload-btn");
  if (!fileInput.files || !fileInput.files[0]) {
    toast("Please select a file", "error");
    return;
  }
  if (!state.userSymKey || !state.x25519Priv || !state.ed25519Priv) {
    toast(
      "Crypto keys not in memory. Please re-login to upload files.",
      "error",
    );
    return;
  }
  const file = fileInput.files[0];
  uploadBtn.disabled = true;
  uploadBtn.innerHTML = '<span class="spinner"></span> Uploading...';
  try {
    const content = await file.arrayBuffer();
    const fileId = generateFileId();
    // AAD binds encrypted blobs to immutable identity metadata.
    const aad = crypto.strToBytes(fileId + "||" + state.email);
    // New files start at ratchet version 1.
    const ratchet = crypto.initializeRatchet();
    const keys = await crypto.deriveVersionKeys(ratchet.rootKey, 1);
    // fileKey encrypts payload; chainKey is reserved to derive next version keys.
    const filenameEnc = await crypto.aesGcmEncrypt(
      keys.fileKey,
      crypto.strToBytes(file.name),
      aad,
    );
    const contentEnc = await crypto.aesGcmEncrypt(keys.fileKey, content, aad);
    const contentHash = await crypto.sha256(content);
    const version = 1;
    const signedData = crypto.strToBytes(
      fileId + "||" + crypto.b64encode(contentHash) + "||" + version,
    );
    // Signature gives non-repudiation and tamper detection for this version.
    const contentSig = await crypto.ed25519Sign(state.ed25519Priv, signedData);
    // Ephemeral ECDH pair gives per-file forward secrecy for wrapped root keys.
    const ephemeralPair = await crypto.generateX25519KeyPair();
    const sharedSecret = await crypto.x25519DeriveSharedSecret(
      ephemeralPair.privateKey,
      state.x25519Pub,
    );
    const wrapKey = await crypto.hkdf(sharedSecret, "file_key_wrap", 32);
    const wrapAad = crypto.strToBytes(fileId + "||" + state.email);
    const wrappedRootKey = await crypto.aesGcmEncrypt(
      wrapKey,
      ratchet.rootKey,
      wrapAad,
    );
    // Only ephemeral public key is stored; ephemeral private key remains client-only.
    const ephemeralPub = await crypto.exportX25519Public(
      ephemeralPair.publicKey,
    );
    const chainKeyEnc = await crypto.aesGcmEncrypt(
      state.userSymKey,
      keys.chainKey,
    );
    // Store ciphertext plus wrapped root/chain keys used by future versions.
    await api("POST", "/api/files", {
      fileId: fileId,
      filename_nonce: filenameEnc.nonce,
      filename_enc: filenameEnc.ciphertext,
      content_nonce: contentEnc.nonce,
      content_enc: contentEnc.ciphertext,
      contentHash: crypto.b64encode(contentHash),
      contentSig: contentSig,
      wrappedKey: wrappedRootKey.ciphertext,
      wrapNonce: wrappedRootKey.nonce,
      ephemeralPub: ephemeralPub,
      chainKeyEnc: chainKeyEnc.ciphertext,
      chainKeyNonce: chainKeyEnc.nonce,
    });
    toast("File uploaded successfully! (v1 with Double Ratchet)", "success");
    fileInput.value = "";
    uploadBtn.disabled = false;
    uploadBtn.innerHTML = "📤 Upload File";
    await loadFiles();
  } catch (err) {
    console.error("Upload error:", err);
    toast(err.message, "error");
    uploadBtn.disabled = false;
    uploadBtn.innerHTML = "📤 Upload File";
  }
}

// Downloads, decrypts, verifies signature, and saves a file locally.
window.downloadFile = async function (fileId) {
  if (!state.userSymKey || !state.x25519Priv || !state.ed25519Priv) {
    toast(
      "Crypto keys not in memory. Please re-login to download files.",
      "error",
    );
    return;
  }
  try {
    toast("Downloading file...", "info");
    const fileData = await api("GET", `/api/files/${fileId}/download`);
    // Version gate prevents access to versions above granted maxVersion.
    if (!crypto.canAccessVersion(fileData.version, fileData.maxVersion)) {
      throw new Error(
        `Access denied: version ${fileData.version} exceeds your max_version ${fileData.maxVersion}`,
      );
    }
    const sharedSecret = await crypto.x25519DeriveSharedSecret(
      state.x25519Priv,
      await crypto.importX25519Public(fileData.ephemeralPub),
    );
    const wrapKey = await crypto.hkdf(sharedSecret, "file_key_wrap", 32);
    let rootKey;
    try {
      const wrapAad = crypto.strToBytes(fileId + "||" + state.email);
      // Owner unwrap path with AAD binding.
      rootKey = await crypto.aesGcmDecrypt(
        wrapKey,
        fileData.wrapNonce,
        fileData.rootKey,
        wrapAad,
      );
    } catch (err) {
      // Shared unwrap path without AAD binding.
      rootKey = await crypto.aesGcmDecrypt(
        wrapKey,
        fileData.wrapNonce,
        fileData.rootKey,
      );
    }
    const fileKey = await crypto.deriveFileKeyForVersion(
      rootKey,
      fileData.version,
    );
    // Re-derive hash from decrypted plaintext before signature verification.
    const aad = crypto.strToBytes(fileId + "||" + fileData.owner);
    let content;
    try {
      content = await crypto.aesGcmDecrypt(
        fileKey,
        fileData.content_nonce,
        fileData.content_enc,
        aad,
      );
    } catch (err) {
      console.error("Decryption failed:", err);
      throw new Error(
        "Failed to decrypt file. This file may have been uploaded before Double Ratchet was enabled. Please delete and re-upload it.",
      );
    }
    const recomputedHash = await crypto.sha256(content);
    const signedData = crypto.strToBytes(
      fileId +
        "||" +
        crypto.b64encode(recomputedHash) +
        "||" +
        fileData.version,
    );
    // Verify key pinning before using signer public key.
    const ownerKeys = await api(
      "GET",
      `/api/users/${fileData.last_modified_by}/public-keys`,
    );
    await verifyAndPinPublicKeys(
      ownerKeys.email,
      ownerKeys.x25519Public,
      ownerKeys.ed25519Public,
      false,
    );
    const ownerEd25519Pub = await crypto.importEd25519Public(
      ownerKeys.ed25519Public,
    );
    const signatureValid = await crypto.ed25519Verify(
      ownerEd25519Pub,
      fileData.content_sig,
      signedData,
    );
    if (!signatureValid) {
      throw new Error(
        "Content signature verification failed! File may be forged.",
      );
    }
    const filename = crypto.bytesToStr(
      await crypto.aesGcmDecrypt(
        fileKey,
        fileData.filename_nonce,
        fileData.filename_enc,
        aad,
      ),
    );
    const blob = new Blob([content]);
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast("File downloaded and verified!", "success");
  } catch (err) {
    console.error("Download error:", err);
    toast(err.message, "error");
  }
};

// Deletes a file after user confirmation and reloads the file list.
window.deleteFile = async function (fileId) {
  if (!confirm("Are you sure you want to delete this file?")) return;
  try {
    await api("DELETE", `/api/files/${fileId}`);
    toast("File deleted", "success");
    await loadFiles();
  } catch (err) {
    console.error("Delete error:", err);
    toast(err.message, "error");
  }
};

// Generates a compact random file identifier.
function generateFileId() {
  return crypto
    .b64encode(crypto.getRandomBytes(16))
    .replace(/[^a-zA-Z0-9]/g, "")
    .substring(0, 16);
}

// Escapes HTML-sensitive characters via textContent roundtrip.
function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

// Updates file content by ratcheting to next version and uploading ciphertext.
window.updateFile = async function (fileId) {
  if (!state.userSymKey || !state.x25519Priv || !state.ed25519Priv) {
    toast("Crypto keys not in memory. Please re-login.", "error");
    return;
  }
  const input = document.createElement("input");
  input.type = "file";
  input.accept = "*/*";
  input.onchange = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    try {
      toast("Updating file...", "info");
      const content = await file.arrayBuffer();
      const fileData = await api("GET", `/api/files/${fileId}`);
      const fileRow = await api("GET", `/api/files/${fileId}/download`);
      const hasRead = fileData.permissions.includes("read");
      const hasModify = fileData.permissions.includes("modify");
      let chainKeyBytes;
      if (hasRead) {
        // Users with read can unwrap root key and deterministically recover chain progression.
        const sharedSecret = await crypto.x25519DeriveSharedSecret(
          state.x25519Priv,
          await crypto.importX25519Public(fileRow.ephemeralPub),
        );
        const wrapKey = await crypto.hkdf(sharedSecret, "file_key_wrap", 32);
        let rootKey;
        try {
          const wrapAad = crypto.strToBytes(fileId + "||" + state.email);
          rootKey = await crypto.aesGcmDecrypt(
            wrapKey,
            fileRow.wrapNonce,
            fileRow.rootKey,
            wrapAad,
          );
        } catch (err) {
          rootKey = await crypto.aesGcmDecrypt(
            wrapKey,
            fileRow.wrapNonce,
            fileRow.rootKey,
          );
        }
        const currentVersion = fileData.version;
        if (currentVersion === 1) {
          chainKeyBytes = await crypto.hkdf(rootKey, "chain_v1", 32);
        } else {
          chainKeyBytes = await crypto.hkdf(rootKey, "chain_v1", 32);
          for (let v = 2; v <= currentVersion; v++) {
            chainKeyBytes = await crypto.hkdf(chainKeyBytes, `chain_v${v}`, 32);
          }
        }
      } else if (hasModify) {
        // Modify-only fallback uses pre-wrapped chain key if available.
        if (!fileRow.user_chain_ephemeral_pub) {
          throw new Error(
            "This file was shared before chain key support. Ask owner to re-share.",
          );
        }
        const sharedSecret = await crypto.x25519DeriveSharedSecret(
          state.x25519Priv,
          await crypto.importX25519Public(fileRow.user_chain_ephemeral_pub),
        );
        const wrapKey = await crypto.hkdf(sharedSecret, "file_key_wrap", 32);
        chainKeyBytes = await crypto.aesGcmDecrypt(
          wrapKey,
          fileRow.user_chain_key_nonce,
          fileRow.user_chain_key_wrapped,
        );
      } else {
        throw new Error("You do not have modify permission");
      }
      const currentVersion = fileData.version;
      // Move forward exactly one version and derive fresh content keys.
      const ratcheted = await crypto.ratchetForward(
        chainKeyBytes,
        currentVersion,
      );
      const aad = crypto.strToBytes(fileId + "||" + fileData.owner);
      const filenameEnc = await crypto.aesGcmEncrypt(
        ratcheted.fileKey,
        crypto.strToBytes(file.name),
        aad,
      );
      const contentEnc = await crypto.aesGcmEncrypt(
        ratcheted.fileKey,
        content,
        aad,
      );
      const contentHash = await crypto.sha256(content);
      const version = ratcheted.version;
      const signedData = crypto.strToBytes(
        fileId + "||" + crypto.b64encode(contentHash) + "||" + version,
      );
      const contentSig = await crypto.ed25519Sign(
        state.ed25519Priv,
        signedData,
      );
      const newChainKeyEnc = await crypto.aesGcmEncrypt(
        state.userSymKey,
        ratcheted.chainKey,
      );
      // Modify signature is separate from content signature for ACL/audit attribution.
      const nonce = crypto.b64encode(crypto.getRandomBytes(16));
      const timestamp = Date.now();
      const modifyData = crypto.strToBytes(
        `modify||${fileId}||${state.email}||${nonce}||${timestamp}`,
      );
      const modifySig = await crypto.ed25519Sign(state.ed25519Priv, modifyData);
      await api("PUT", `/api/files/${fileId}`, {
        filename_nonce: filenameEnc.nonce,
        filename_enc: filenameEnc.ciphertext,
        content_nonce: contentEnc.nonce,
        content_enc: contentEnc.ciphertext,
        contentHash: crypto.b64encode(contentHash),
        contentSig: contentSig,
        modifySig: modifySig,
        nonce: nonce,
        timestamp: timestamp,
        chainKeyEnc: newChainKeyEnc.ciphertext,
        chainKeyNonce: newChainKeyEnc.nonce,
      });
      toast(
        `File updated successfully! (v${currentVersion} → v${version} 🔐)`,
        "success",
      );
      await loadFiles();
    } catch (err) {
      console.error("Update error:", err);
      toast("Failed to update: " + err.message, "error");
    }
  };
  input.click();
};
