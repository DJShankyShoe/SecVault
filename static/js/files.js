/**
 * SecVault v3.0 - File Operations (Email-only)
 */

import * as crypto from './crypto.js';
import { api, toast } from './api.js';
import { state } from './state.js';

/**
 * Load and display files
 */
/**
 * Decrypt filename for display
 */
async function decryptFilename(file) {
    try {
        // Get file key
        const sharedSecret = await crypto.x25519DeriveSharedSecret(
            state.x25519Priv,
            await crypto.importX25519Public(file.ephemeral_pub)
        );
        const wrapKey = await crypto.hkdf(sharedSecret, 'file_key_wrap', 32);
        const wrapAad = crypto.strToBytes(file.file_id + '||' + state.email);
        const fileKey = await crypto.aesGcmDecrypt(wrapKey, file.wrap_nonce, file.wrapped_key, wrapAad);
        
        // Decrypt filename
        const aad = crypto.strToBytes(file.file_id + '||' + file.owner);
        const filenameBytes = await crypto.aesGcmDecrypt(
            fileKey,
            file.filename_nonce,
            file.filename_enc,
            aad
        );
        
        return crypto.bytesToStr(filenameBytes);
    } catch (err) {
        console.error('Failed to decrypt filename:', err);
        return 'Encrypted File';
    }
}
export async function loadFiles() {
    const fileList = document.getElementById('file-list');
    if (!fileList) return;
    
    try {
        fileList.innerHTML = '<div style="text-align:center;padding:2rem"><span class="spinner"></span> Loading files...</div>';
        
        const response = await api('GET', '/api/files');
        
        if (!response.files || response.files.length === 0) {
            fileList.innerHTML = `
                <div style="text-align:center;padding:2rem;color:var(--muted)">
                    <div style="font-size:1.1rem;margin-bottom:0.5rem;color:var(--text)">No files yet</div>
                    <div style="font-size:0.85rem;color:var(--muted)">Upload your first file to get started</div>
                </div>
            `;
            return;
        }
        
        // Decrypt all filenames first
        const filesWithNames = await Promise.all(
            response.files.map(async (file) => {
                const filename = await decryptFilename(file);
                return { ...file, decryptedFilename: filename };
            })
        );
        
        fileList.innerHTML = filesWithNames.map(file => `
            <div class="file-item" data-file-id="${file.file_id}">
                <div class="file-icon">📄</div>
                <div class="file-info">
                    <div class="file-name">${escapeHtml(file.decryptedFilename)}</div>
                    <div class="file-meta">
                        Owner: ${escapeHtml(file.owner)} • 
                        Version: ${file.version} • 
                        ${new Date(file.uploaded_at * 1000).toLocaleDateString()}
                    </div>
                </div>
                <div class="file-actions">
                    ${(() => {
                        const perms = file.permissions ? file.permissions.split(',') : ['read', 'modify'];
                        const hasModify = perms.includes('modify');
                        const hasRead = perms.includes('read');
                        
                        let buttons = '';
                        
                        // 1. Edit (if has modify permission)
                        if (hasModify) {
                            buttons += `
                                <button class="btn-icon" onclick="updateFile('${file.file_id}')" title="Update/Modify">
                                    ✏️
                                </button>
                            `;
                        }
                        
                        // 2. Download (if has read permission)
                        if (hasRead) {
                            buttons += `
                                <button class="btn-icon" onclick="downloadFile('${file.file_id}')" title="Download">
                                    ⬇️
                                </button>
                            `;
                        }
                        
                        // 3. ACL (if owner)
                        if (file.owner === state.email) {
                            buttons += `
                                <button class="btn-icon" onclick="manageACL('${file.file_id}')" title="Manage Access">
                                    👥
                                </button>
                            `;
                        }
                        
                        // 4. Delete (if owner)
                        if (file.owner === state.email) {
                            buttons += `
                                <button class="btn-icon" onclick="deleteFile('${file.file_id}')" title="Delete">
                                    🗑️
                                </button>
                            `;
                        }
                        return buttons;
                    })()}
                </div>
            </div>
        `).join('');
        
    } catch (err) {
        console.error('Failed to load files:', err);
        fileList.innerHTML = `
            <div style="text-align:center;padding:2rem;color:var(--danger)">
                ⚠️ Failed to load files: ${err.message}
            </div>
        `;
    }
}

/**
 * Upload file
 */
export async function handleFileUpload(e) {
    e.preventDefault();
    
    const fileInput = document.getElementById('file-input');
    const uploadBtn = document.getElementById('upload-btn');
    
    if (!fileInput.files || !fileInput.files[0]) {
        toast('Please select a file', 'error');
        return;
    }
    
    if (!state.userSymKey || !state.x25519Priv || !state.ed25519Priv) {
        toast('Crypto keys not in memory. Please re-login to upload files.', 'error');
        return;
    }
    
    const file = fileInput.files[0];
    uploadBtn.disabled = true;
    uploadBtn.innerHTML = '<span class="spinner"></span> Uploading...';
    
    try {
        const content = await file.arrayBuffer();
        const fileKey = crypto.getRandomBytes(32);
        const fileId = generateFileId();
        const aad = crypto.strToBytes(fileId + '||' + state.email);
        
        const filenameEnc = await crypto.aesGcmEncrypt(
            fileKey,
            crypto.strToBytes(file.name),
            aad
        );
        
        const contentEnc = await crypto.aesGcmEncrypt(
            fileKey,
            content,
            aad
        );
        
        const contentHash = await crypto.sha256(content);
        const version = 1;
        const signedData = crypto.strToBytes(
            fileId + '||' + crypto.b64encode(contentHash) + '||' + version
        );
        const contentSig = await crypto.ed25519Sign(state.ed25519Priv, signedData);
        
        const ephemeralPair = await crypto.generateX25519KeyPair();
        const sharedSecret = await crypto.x25519DeriveSharedSecret(
            ephemeralPair.privateKey,
            state.x25519Pub
        );
        const wrapKey = await crypto.hkdf(sharedSecret, 'file_key_wrap', 32);
        
        const wrapAad = crypto.strToBytes(fileId + '||' + state.email);
        const wrappedKey = await crypto.aesGcmEncrypt(wrapKey, fileKey, wrapAad);
        
        const ephemeralPub = await crypto.exportX25519Public(ephemeralPair.publicKey);
        
        await api('POST', '/api/files', {
            fileId: fileId,
            filename_nonce: filenameEnc.nonce,
            filename_enc: filenameEnc.ciphertext,
            content_nonce: contentEnc.nonce,
            content_enc: contentEnc.ciphertext,
            contentHash: crypto.b64encode(contentHash),
            contentSig: contentSig,
            wrapped_key: wrappedKey.ciphertext,
            wrap_nonce: wrappedKey.nonce,
            ephemeral_pub: ephemeralPub
        });
        
        toast('File uploaded successfully!', 'success');
        fileInput.value = '';
        uploadBtn.disabled = false;
        uploadBtn.innerHTML = '📤 Upload File';
        
        await loadFiles();
        
    } catch (err) {
        console.error('Upload error:', err);
        toast(err.message, 'error');
        uploadBtn.disabled = false;
        uploadBtn.innerHTML = '📤 Upload File';
    }
}

/**
 * Download file
 */
window.downloadFile = async function(fileId) {
    if (!state.userSymKey || !state.x25519Priv || !state.ed25519Priv) {
        toast('Crypto keys not in memory. Please re-login to download files.', 'error');
        return;
    }
    
    try {
        toast('Downloading file...', 'info');
        
        const fileData = await api('GET', `/api/files/${fileId}/download`);
        
        
        const sharedSecret = await crypto.x25519DeriveSharedSecret(
            state.x25519Priv,
            await crypto.importX25519Public(fileData.ephemeral_pub)
        );
        const wrapKey = await crypto.hkdf(sharedSecret, 'file_key_wrap', 32);
        
        const wrapAad = crypto.strToBytes(fileId + '||' + state.email);
        const fileKey = await crypto.aesGcmDecrypt(
            wrapKey,
            fileData.wrap_nonce,
            fileData.wrapped_key,
            wrapAad
        );
        
        const aad = crypto.strToBytes(fileId + '||' + fileData.owner);
        const content = await crypto.aesGcmDecrypt(
            fileKey,
            fileData.content_nonce,
            fileData.content_enc,
            aad
        );
        
        const recomputedHash = await crypto.sha256(content);
        const signedData = crypto.strToBytes(
            fileId + '||' + crypto.b64encode(recomputedHash) + '||' + fileData.version
        );
        
        const ownerKeys = await api('GET', `/api/users/${fileData.last_modified_by}/public-keys`);
        const ownerEd25519Pub = await crypto.importEd25519Public(ownerKeys.ed25519Public);
        
        const signatureValid = await crypto.ed25519Verify(
            ownerEd25519Pub,
            fileData.content_sig,
            signedData
        );
        
        if (!signatureValid) {
            throw new Error('Content signature verification failed! File may be forged.');
        }
        
        const filename = crypto.bytesToStr(
            await crypto.aesGcmDecrypt(
                fileKey,
                fileData.filename_nonce,
                fileData.filename_enc,
                aad
            )
        );
        
        const blob = new Blob([content]);
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        toast('File downloaded and verified!', 'success');
        
    } catch (err) {
        console.error('Download error:', err);
        toast(err.message, 'error');
    }
};

/**
 * Delete file
 */
window.deleteFile = async function(fileId) {
    if (!confirm('Are you sure you want to delete this file?')) return;
    
    try {
        await api('DELETE', `/api/files/${fileId}`);
        toast('File deleted', 'success');
        await loadFiles();
    } catch (err) {
        console.error('Delete error:', err);
        toast(err.message, 'error');
    }
};

function generateFileId() {
    return crypto.b64encode(crypto.getRandomBytes(16)).replace(/[^a-zA-Z0-9]/g, '').substring(0, 16);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Update/Modify file
 */
window.updateFile = async function(fileId) {
    if (!state.userSymKey || !state.x25519Priv || !state.ed25519Priv) {
        toast('Crypto keys not in memory. Please re-login.', 'error');
        return;
    }
    
    // Create file input dialog
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '*/*';
    
    input.onchange = async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        
        try {
            toast('Updating file...', 'info');
            
            // Read file content
            const content = await file.arrayBuffer();
            
            // Fetch current file data to get the file key
            const fileData = await api('GET', `/api/files/${fileId}`);
        
            
            // Unwrap the file key
            const sharedSecret = await crypto.x25519DeriveSharedSecret(
                state.x25519Priv,
                await crypto.importX25519Public(fileData.ephemeral_pub)
            );
            const wrapKey = await crypto.hkdf(sharedSecret, 'file_key_wrap', 32);
            const wrapAad = crypto.strToBytes(fileId + '||' + state.email);
            const fileKey = await crypto.aesGcmDecrypt(
                wrapKey,
                fileData.wrap_nonce,
                fileData.wrapped_key,
                wrapAad
            );
            
            // Encrypt new content with the SAME file key
            const aad = crypto.strToBytes(fileId + '||' + fileData.owner);
            
            const filenameEnc = await crypto.aesGcmEncrypt(
                fileKey,
                crypto.strToBytes(file.name),
                aad
            );
            
            const contentEnc = await crypto.aesGcmEncrypt(
                fileKey,
                content,
                aad
            );
            
            // Hash and sign new content
            const contentHash = await crypto.sha256(content);
            const version = fileData.version + 1;
            const signedData = crypto.strToBytes(
                fileId + '||' + crypto.b64encode(contentHash) + '||' + version
            );
            const contentSig = await crypto.ed25519Sign(state.ed25519Priv, signedData);
            
            // Sign the modify action for audit log
            const modifyData = crypto.strToBytes(
                fileId + '||modify||' + state.email + '||' + Date.now()
            );
            const modifySig = await crypto.ed25519Sign(state.ed25519Priv, modifyData);
            
            // Update file
            await api('PUT', `/api/files/${fileId}`, {
                filename_nonce: filenameEnc.nonce,
                filename_enc: filenameEnc.ciphertext,
                content_nonce: contentEnc.nonce,
                content_enc: contentEnc.ciphertext,
                contentHash: crypto.b64encode(contentHash),
                contentSig: contentSig,
                modifySig: modifySig
            });
            
            toast('File updated successfully!', 'success');
            
            // Reload file list
            await loadFiles();
            
        } catch (err) {
            console.error('Update error:', err);
            toast('Failed to update: ' + err.message, 'error');
        }
    };
    
    input.click();
};
