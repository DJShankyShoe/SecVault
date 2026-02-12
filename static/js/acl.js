/**
 * SecVault v3.0 - Access Control List (Pinpointed debugging)
 */

import * as crypto from './crypto.js';
import { api, toast } from './api.js';
import { state } from './state.js';

window.manageACL = async function(fileId) {
    if (!state.userSymKey || !state.x25519Priv || !state.ed25519Priv) {
        toast('Crypto keys not in memory', 'error');
        return;
    }
    
    try {
        const fileData = await api('GET', `/api/files/${fileId}`);
        const aclData = await api('GET', `/api/files/${fileId}/access`);
        
        const modal = document.createElement('div');
        modal.className = 'modal-overlay';
        modal.id = 'acl-modal';
        modal.innerHTML = `
            <div class="modal">
                <div class="modal-header">
                    <h2>👥 Manage File Access</h2>
                    <button class="modal-close" onclick="closeACLModal()">✕</button>
                </div>
                <div class="modal-body">
                    <div class="acl-section">
                        <h3>Current Access</h3>
                        <p style="color: var(--muted); font-size: 0.85rem; margin-bottom: 1rem;">Control who can read and/or modify this file</p>
                        <div class="user-list">
                            ${aclData.users.map(user => `
                                <div class="user-item ${user.email === fileData.owner ? 'owner-item' : ''}">
                                    <div class="user-permissions">
                                        ${user.email === fileData.owner ? '' : `
                                            <span class="perm-badge ${user.permissions.includes('read') ? 'has-read' : 'no-read'}" title="${user.permissions.includes('read') ? 'Has Read' : 'No Read'}">
                                                📖
                                            </span>
                                            <span class="perm-badge ${user.permissions.includes('modify') ? 'has-modify' : 'no-modify'}" title="${user.permissions.includes('modify') ? 'Has Modify' : 'No Modify'}">
                                                ✏️
                                            </span>
                                        `}
                                    </div>
                                    <div class="user-info">
                                        <span class="user-email">${escapeHtml(user.email)}</span>
                                        ${user.email === fileData.owner ? `
                                            <span class="owner-badge">Owner</span>
                                        ` : ''}
                                    </div>
                                    <div class="user-actions">
                                        ${user.email !== state.email && user.email !== fileData.owner ? `
                                            <button class="btn-action" onclick="editPermissions('${fileId}', '${escapeHtml(user.email)}', ${JSON.stringify(user.permissions).replace(/"/g, '&quot;')})" title="Edit Permissions">
                                                ✏️ Edit
                                            </button>
                                            <button class="btn-action revoke" onclick="revokeAccess('${fileId}', '${escapeHtml(user.email)}')">
                                                Revoke
                                            </button>
                                        ` : ''}
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                    
                    <div class="acl-section">
                        <h3>Grant Access</h3>
                        <form id="grant-form" onsubmit="grantAccess(event, '${fileId}')">
                            <div class="field">
                                <label for="target-email">User Email</label>
                                <input type="email" id="target-email" name="email" required placeholder="user@example.com">
                            </div>
                            
                            <div class="field">
                                <label>Permissions</label>
                                <div style="display: flex; gap: 1rem; margin-top: 0.5rem;">
                                    <label style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;">
                                        <input type="checkbox" name="perm-read" id="perm-read" checked>
                                        <span>📖 Read (Download)</span>
                                    </label>
                                    <label style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;">
                                        <input type="checkbox" name="perm-modify" id="perm-modify" checked>
                                        <span>✏️ Modify (Update)</span>
                                    </label>
                                </div>
                                <small style="color: var(--muted); font-size: 0.75rem; display: block; margin-top: 0.5rem;">
                                    Select at least one permission
                                </small>
                            </div>
                            
                            <button type="submit" class="btn btn-primary" id="grant-btn">
                                Grant Access
                            </button>
                        </form>
                    </div>
                    
                    <div class="acl-section">
                        <h3>Audit Log</h3>
                        <div class="audit-log">
                            ${aclData.aclLog.length === 0 ? `
                                <div style="color:var(--muted);text-align:center;padding:1rem">No ACL changes yet</div>
                            ` : aclData.aclLog.map(log => `
                                <div class="audit-item">
                                    <span class="audit-action ${log.action === 'grant' ? 'grant' : log.action === 'revoke' ? 'revoke' : log.action === 'update_permissions' ? 'update' : 'modify'}">
                                        ${log.action === 'grant' ? '✓ Granted' : log.action === 'revoke' ? '✕ Revoked' : log.action === 'update_permissions' ? '🔄 Updated Permissions' : '✏️ Modified'}
                                    </span>
                                    <span class="audit-target">${escapeHtml(log.target_user)}</span>
                                    <span class="audit-time">${new Date(log.timestamp * 1000).toLocaleString()}</span>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
        
    } catch (err) {
        toast('Failed to load access control: ' + err.message, 'error');
    }
};

window.grantAccess = async function(e, fileId) {
    e.preventDefault();
    
    const form = e.target;
    const targetEmail = form.email.value.trim().toLowerCase();
    
    // Get selected permissions
    const permRead = document.getElementById('perm-read').checked;
    const permModify = document.getElementById('perm-modify').checked;
    const permissions = [];
    if (permRead) permissions.push('read');
    if (permModify) permissions.push('modify');
    
    const grantBtn = document.getElementById('grant-btn');
    const modalBody = document.querySelector('#acl-modal .modal-body');
    
    const oldError = modalBody.querySelector('.error-message');
    if (oldError) oldError.remove();
    
    if (permissions.length === 0) {
        showModalError(modalBody, 'Please select at least one permission');
        return;
    }
    
    if (!targetEmail) {
        showModalError(modalBody, 'Please enter an email address');
        return;
    }
    
    if (targetEmail === state.email) {
        showModalError(modalBody, 'You already have access to this file');
        return;
    }
    
    grantBtn.disabled = true;
    grantBtn.innerHTML = '<span class="spinner"></span> Granting...';
    
    try {
        
        // Fetch file
        let fileData;
        try {
            fileData = await api('GET', `/api/files/${fileId}`);
        } catch (err) {
            throw new Error('Failed to fetch file: ' + err.message);
        }
        
        // Fetch target user's public key
        let targetKeys;
        try {
            targetKeys = await api('GET', `/api/users/${targetEmail}/public-keys`);
        } catch (err) {
            throw new Error('User not found or keys unavailable');
        }
        
        // Import OUR ephemeral public key
        let ourEphemeralPub;
        try {
            ourEphemeralPub = await crypto.importX25519Public(fileData.ephemeral_pub);
        } catch (err) {
            throw new Error('Failed to import our ephemeral key');
        }
        
        // Derive shared secret with OUR key
        let sharedSecret;
        try {
            sharedSecret = await crypto.x25519DeriveSharedSecret(state.x25519Priv, ourEphemeralPub);
        } catch (err) {
            throw new Error('Failed to derive shared secret with our key');
        }
        
        // Derive wrap key
        let wrapKey;
        try {
            wrapKey = await crypto.hkdf(sharedSecret, 'file_key_wrap', 32);
        } catch (err) {
            throw new Error('Failed to derive wrap key');
        }
        
        // Unwrap file key
        let fileKey;
        try {
            
            
            const aadString = fileId + '||' + state.email;
            const wrapAad = crypto.strToBytes(aadString);
            
            
            fileKey = await crypto.aesGcmDecrypt(wrapKey, fileData.wrap_nonce, fileData.wrapped_key, wrapAad);
        } catch (err) {
            
            // Try to check if it's really us
            console.error('   Emails match?', state.email === fileData.owner);
            
            throw new Error('Failed to unwrap file key - see console for details');
        }
        // Generate NEW ephemeral keypair
        let ephemeralPair;
        try {
            ephemeralPair = await crypto.generateX25519KeyPair();
        } catch (err) {
            throw new Error('Failed to generate ephemeral keypair');
        }
        
        // Import TARGET user's public key
        let targetPubKey;
        try {
            targetPubKey = await crypto.importX25519Public(targetKeys.x25519Public);
        } catch (err) {
            console.error('   Raw key value:', targetKeys.x25519Public);
            throw new Error('Failed to import target public key');
        }
        
        // Derive shared secret with TARGET
        let targetSharedSecret;
        try {
            targetSharedSecret = await crypto.x25519DeriveSharedSecret(ephemeralPair.privateKey, targetPubKey);
        } catch (err) {
            console.error('   Ephemeral private key usages:', ephemeralPair.privateKey.usages);
            console.error('   Target public key usages:', targetPubKey.usages);
            console.error('   Ephemeral private extractable:', ephemeralPair.privateKey.extractable);
            console.error('   Target public extractable:', targetPubKey.extractable);
            throw new Error('Failed to derive shared secret with target - THIS IS THE FAILING STEP');
        }
        
        // Derive target wrap key
        let targetWrapKey;
        try {
            targetWrapKey = await crypto.hkdf(targetSharedSecret, 'file_key_wrap', 32);
        } catch (err) {
            throw new Error('Failed to derive target wrap key');
        }
        
        // Wrap file key for target
        let targetWrappedKey;
        try {
            const targetWrapAad = crypto.strToBytes(fileId + '||' + targetEmail);
            targetWrappedKey = await crypto.aesGcmEncrypt(targetWrapKey, fileKey, targetWrapAad);
        } catch (err) {
            throw new Error('Failed to wrap file key');
        }
        
        // Export ephemeral public key
        let ephemeralPub;
        try {
            ephemeralPub = await crypto.exportX25519Public(ephemeralPair.publicKey);
        } catch (err) {
            throw new Error('Failed to export ephemeral public key');
        }
        
        // Sign ACL operation
        let aclSig;
        try {
            const aclData = crypto.strToBytes(fileId + '||grant||' + targetEmail + '||' + Date.now());
            aclSig = await crypto.ed25519Sign(state.ed25519Priv, aclData);
        } catch (err) {
            throw new Error('Failed to sign ACL operation');
        }
        
        // Send to server
        try {
            await api('POST', `/api/files/${fileId}/access`, {
                targetEmail: targetEmail,
                wrappedKey: targetWrappedKey.ciphertext,
                wrapNonce: targetWrappedKey.nonce,
                ephemeralPub: ephemeralPub,
                aclSig: aclSig,
                permissions: permissions
            });
        } catch (err) {
            throw new Error('Server rejected: ' + err.message);
        }
        
        toast('Access granted successfully!', 'success');
        
        closeACLModal();
        setTimeout(() => manageACL(fileId), 300);
        
    } catch (err) {
        console.error('   Error:', err);
        console.error('   Message:', err.message);
        
        showModalError(modalBody, err.message || 'Failed to grant access');
        
        grantBtn.disabled = false;
        grantBtn.innerHTML = 'Grant Access';
    }
};

window.revokeAccess = async function(fileId, targetEmail) {
    if (!confirm(`Revoke access for ${targetEmail}?`)) return;
    
    try {
        const aclData = crypto.strToBytes(fileId + '||revoke||' + targetEmail + '||' + Date.now());
        const aclSig = await crypto.ed25519Sign(state.ed25519Priv, aclData);
        
        await api('DELETE', `/api/files/${fileId}/access/${targetEmail}`, {
            aclSig: aclSig,
                permissions: permissions
        });
        
        toast('Access revoked', 'success');
        
        closeACLModal();
        setTimeout(() => manageACL(fileId), 300);
        
    } catch (err) {
        console.error('Revoke error:', err);
        toast('Failed to revoke access: ' + err.message, 'error');
    }
};

window.closeACLModal = function() {
    const modal = document.getElementById('acl-modal');
    if (modal) modal.remove();
};

function showModalError(modalBody, errorText) {
    const errorDiv = document.createElement('div');
    errorDiv.className = 'error-message';
    errorDiv.style = 'background: rgba(231, 76, 60, 0.1); border: 1px solid rgba(231, 76, 60, 0.3); border-radius: 8px; padding: 0.75rem; margin-bottom: 1rem;';
    errorDiv.innerHTML = `<span style="color: #e74c3c; font-size: 0.85rem; font-weight: 600;">✕ ${escapeHtml(errorText)}</span>`;
    
    modalBody.insertBefore(errorDiv, modalBody.firstChild);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Edit permissions for an existing user
 */
window.editPermissions = async function(fileId, userEmail, currentPermissions) {
    // Close current modal
    closeACLModal();
    
    // Create edit modal
    const modal = document.createElement('div');
    modal.className = 'modal-overlay';
    modal.id = 'edit-perm-modal';
    modal.innerHTML = `
        <div class="modal" style="max-width: 480px;">
            <div class="modal-header">
                <h2>✏️ Edit Permissions</h2>
                <button class="modal-close" onclick="closeEditPermModal('${fileId}')">✕</button>
            </div>
            <div class="modal-body">
                <p style="color: var(--muted); margin-bottom: 1rem; font-size: 0.9rem;">
                    Editing permissions for: <strong>${escapeHtml(userEmail)}</strong>
                </p>
                
                <div id="edit-perm-error" style="display: none; background: rgba(231, 76, 60, 0.1); border: 1px solid rgba(231, 76, 60, 0.3); border-radius: 8px; padding: 0.75rem; margin-bottom: 1rem;">
                    <span style="color: #e74c3c; font-size: 0.85rem; font-weight: 600;">
                        ✕ <span id="edit-perm-error-message">Error</span>
                    </span>
                </div>
                
                <form id="edit-perm-form">
                    <div class="field">
                        <label>Permissions</label>
                        <div style="display: flex; gap: 1rem; margin-top: 0.5rem;">
                            <label style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;">
                                <input type="checkbox" name="edit-perm-read" id="edit-perm-read" ${currentPermissions.includes('read') ? 'checked' : ''}>
                                <span>📖 Read (Download)</span>
                            </label>
                            <label style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;">
                                <input type="checkbox" name="edit-perm-modify" id="edit-perm-modify" ${currentPermissions.includes('modify') ? 'checked' : ''}>
                                <span>✏️ Modify (Update)</span>
                            </label>
                        </div>
                        <small style="color: var(--muted); font-size: 0.75rem; display: block; margin-top: 0.5rem;">
                            Select at least one permission
                        </small>
                    </div>
                    
                    <div style="display: flex; gap: 0.75rem; margin-top: 1.5rem;">
                        <button type="submit" class="btn btn-primary" id="update-perm-btn">
                            Update Permissions
                        </button>
                        <button type="button" class="btn btn-secondary" onclick="closeEditPermModal('${fileId}')">
                            Cancel
                        </button>
                    </div>
                </form>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    
    document.getElementById('edit-perm-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        await updatePermissions(fileId, userEmail);
    });
};

window.closeEditPermModal = function(fileId) {
    const modal = document.getElementById('edit-perm-modal');
    if (modal) modal.remove();
    
    // Reopen ACL modal
    setTimeout(() => manageACL(fileId), 300);
};

async function updatePermissions(fileId, userEmail) {
    const updateBtn = document.getElementById('update-perm-btn');
    const errorDiv = document.getElementById('edit-perm-error');
    const errorMsg = document.getElementById('edit-perm-error-message');
    
    if (errorDiv) errorDiv.style.display = 'none';
    
    // Get selected permissions
    const permRead = document.getElementById('edit-perm-read').checked;
    const permModify = document.getElementById('edit-perm-modify').checked;
    const permissions = [];
    if (permRead) permissions.push('read');
    if (permModify) permissions.push('modify');
    
    if (permissions.length === 0) {
        if (errorDiv && errorMsg) {
            errorMsg.textContent = 'Please select at least one permission';
            errorDiv.style.display = 'block';
        }
        return;
    }
    
    updateBtn.disabled = true;
    updateBtn.innerHTML = '<span class="spinner"></span> Updating...';
    
    try {
        // Sign the update action
        const updateData = crypto.strToBytes(
            fileId + '||update_permissions||' + userEmail + '||' + Date.now()
        );
        const updateSig = await crypto.ed25519Sign(state.ed25519Priv, updateData);
        
        await api('PATCH', `/api/files/${fileId}/access/${userEmail}`, {
            permissions: permissions,
            updateSig: updateSig
        });
        
        toast('Permissions updated successfully!', 'success');
        
        closeEditPermModal(fileId);
        
    } catch (err) {
        console.error('Update permissions error:', err);
        
        if (errorDiv && errorMsg) {
            errorMsg.textContent = err.message || 'Failed to update permissions';
            errorDiv.style.display = 'block';
        }
        
        updateBtn.disabled = false;
        updateBtn.innerHTML = 'Update Permissions';
    }
}
