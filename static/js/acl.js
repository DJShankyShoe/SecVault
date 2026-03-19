import * as crypto from "./crypto.js";

import { api, toast } from "./api.js";

import { state } from "./state.js";

import { verifyAndPinPublicKeys } from "./key-pinning.js";

/*
 * ACL OVERVIEW
 * - Builds ACL management modals fully via DOM APIs.
 * - Signs grant/revoke/update payloads to support server-side integrity checks.
 * - Wraps file/root chain keys per recipient when sharing access.
 */

// Generates a base64 nonce used for signed ACL operations.
function generateNonce() {
    const nonceBytes = crypto.getRandomBytes(16);
    return crypto.b64encode(nonceBytes);
}

// Opens ACL management modal, fetches ACL data, and wires interactions.
window.manageACL = async function(fileId) {
    if (!state.userSymKey || !state.x25519Priv || !state.ed25519Priv) {
        toast("Crypto keys not in memory", "error");
        return;
    }
    try {
        const fileData = await api("GET", `/api/files/${fileId}`);
        const aclData = await api("GET", `/api/files/${fileId}/access`);
        const modal = createACLModal(fileId, fileData, aclData);
        document.body.appendChild(modal);
        attachACLEventListeners(fileId, fileData);
    } catch (err) {
        toast(err.message, "error");
    }
};

// Builds the ACL modal shell and appends section blocks.
function createACLModal(fileId, fileData, aclData) {
    const overlay = document.createElement("div");
    overlay.className = "modal-overlay";
    overlay.id = "acl-modal";
    const modalDiv = document.createElement("div");
    modalDiv.className = "modal";
    const header = document.createElement("div");
    header.className = "modal-header";
    const title = document.createElement("h2");
    title.textContent = "👥 Manage File Access";
    const closeBtn = document.createElement("button");
    closeBtn.className = "modal-close";
    closeBtn.textContent = "✕";
    closeBtn.setAttribute("data-action", "close-modal");
    header.appendChild(title);
    header.appendChild(closeBtn);
    const body = document.createElement("div");
    body.className = "modal-body";
    const currentAccessSection = createCurrentAccessSection(fileId, fileData, aclData);
    body.appendChild(currentAccessSection);
    const grantSection = createGrantAccessSection(fileId);
    body.appendChild(grantSection);
    const auditSection = createAuditLogSection(aclData);
    body.appendChild(auditSection);
    modalDiv.appendChild(header);
    modalDiv.appendChild(body);
    overlay.appendChild(modalDiv);
    return overlay;
}

// Renders current access entries for all users on the file.
function createCurrentAccessSection(fileId, fileData, aclData) {
    const section = document.createElement("div");
    section.className = "acl-section";
    const heading = document.createElement("h3");
    heading.textContent = "Current Access";
    const description = document.createElement("p");
    description.style.color = "var(--muted)";
    description.style.fontSize = "0.85rem";
    description.style.marginBottom = "1rem";
    description.textContent = "Control who can read and/or modify this file";
    const userList = document.createElement("div");
    userList.className = "user-list";
    aclData.users.forEach(user => {
        const userItem = createUserItem(fileId, fileData, user);
        userList.appendChild(userItem);
    });
    section.appendChild(heading);
    section.appendChild(description);
    section.appendChild(userList);
    return section;
}

// Renders one user row with permissions and available actions.
function createUserItem(fileId, fileData, user) {
    const item = document.createElement("div");
    item.className = "user-item";
    if (user.email === fileData.owner) {
        item.classList.add("owner-item");
    }
    const permsDiv = document.createElement("div");
    permsDiv.className = "user-permissions";
    if (user.email !== fileData.owner) {
        const readBadge = document.createElement("span");
        readBadge.className = "perm-badge";
        const hasRead = user.permissions.includes("read") || user.permissions.includes("modify");
        readBadge.classList.add(hasRead ? "has-read" : "no-read");
        readBadge.title = user.permissions.includes("read") ? "Has Read" : user.permissions.includes("modify") ? "Has Read (via Modify)" : "No Read";
        readBadge.textContent = "📖";
        const modifyBadge = document.createElement("span");
        modifyBadge.className = "perm-badge";
        modifyBadge.classList.add(user.permissions.includes("modify") ? "has-modify" : "no-modify");
        modifyBadge.title = user.permissions.includes("modify") ? "Has Modify" : "No Modify";
        modifyBadge.textContent = "✏️";
        permsDiv.appendChild(readBadge);
        permsDiv.appendChild(modifyBadge);
    }
    const infoDiv = document.createElement("div");
    infoDiv.className = "user-info";
    const emailSpan = document.createElement("span");
    emailSpan.className = "user-email";
    emailSpan.textContent = user.email;
    infoDiv.appendChild(emailSpan);
    if (user.email === fileData.owner) {
        const ownerBadge = document.createElement("span");
        ownerBadge.className = "owner-badge";
        ownerBadge.textContent = "Owner";
        infoDiv.appendChild(ownerBadge);
    }
    const actionsDiv = document.createElement("div");
    actionsDiv.className = "user-actions";
    if (user.email !== state.email && user.email !== fileData.owner) {
        const editBtn = document.createElement("button");
        editBtn.className = "btn-action";
        editBtn.title = "Edit Permissions";
        editBtn.textContent = "✏️ Edit";
        editBtn.setAttribute("data-action", "edit-permissions");
        editBtn.setAttribute("data-file-id", fileId);
        editBtn.setAttribute("data-user-email", user.email);
        editBtn.setAttribute("data-permissions", JSON.stringify(user.permissions));
        const revokeBtn = document.createElement("button");
        revokeBtn.className = "btn-action revoke";
        revokeBtn.textContent = "Revoke";
        revokeBtn.setAttribute("data-action", "revoke-access");
        revokeBtn.setAttribute("data-file-id", fileId);
        revokeBtn.setAttribute("data-user-email", user.email);
        actionsDiv.appendChild(editBtn);
        actionsDiv.appendChild(revokeBtn);
    }
    item.appendChild(permsDiv);
    item.appendChild(infoDiv);
    item.appendChild(actionsDiv);
    return item;
}

// Renders the form used to grant new access to a target user.
function createGrantAccessSection(fileId) {
    const section = document.createElement("div");
    section.className = "acl-section";
    const heading = document.createElement("h3");
    heading.textContent = "Grant Access";
    const form = document.createElement("form");
    form.id = "grant-form";
    form.setAttribute("data-file-id", fileId);
    const emailField = document.createElement("div");
    emailField.className = "field";
    const emailLabel = document.createElement("label");
    emailLabel.setAttribute("for", "target-email");
    emailLabel.textContent = "User Email";
    const emailInput = document.createElement("input");
    emailInput.type = "email";
    emailInput.id = "target-email";
    emailInput.name = "email";
    emailInput.required = true;
    emailInput.placeholder = "user@example.com";
    emailField.appendChild(emailLabel);
    emailField.appendChild(emailInput);
    const permsField = document.createElement("div");
    permsField.className = "field";
    const permsLabel = document.createElement("label");
    permsLabel.textContent = "Permissions";
    const checkboxContainer = document.createElement("div");
    checkboxContainer.style.display = "flex";
    checkboxContainer.style.gap = "1rem";
    checkboxContainer.style.marginTop = "0.5rem";
    const readLabel = document.createElement("label");
    readLabel.style.display = "flex";
    readLabel.style.alignItems = "center";
    readLabel.style.gap = "0.5rem";
    readLabel.style.cursor = "pointer";
    const readCheckbox = document.createElement("input");
    readCheckbox.type = "checkbox";
    readCheckbox.name = "perm-read";
    readCheckbox.id = "perm-read";
    readCheckbox.checked = true;
    const readSpan = document.createElement("span");
    readSpan.textContent = "📖 Read (Download)";
    readLabel.appendChild(readCheckbox);
    readLabel.appendChild(readSpan);
    const modifyLabel = document.createElement("label");
    modifyLabel.style.display = "flex";
    modifyLabel.style.alignItems = "center";
    modifyLabel.style.gap = "0.5rem";
    modifyLabel.style.cursor = "pointer";
    const modifyCheckbox = document.createElement("input");
    modifyCheckbox.type = "checkbox";
    modifyCheckbox.name = "perm-modify";
    modifyCheckbox.id = "perm-modify";
    modifyCheckbox.checked = true;
    const modifySpan = document.createElement("span");
    modifySpan.textContent = "✏️ Modify (Update)";
    modifyLabel.appendChild(modifyCheckbox);
    modifyLabel.appendChild(modifySpan);
    checkboxContainer.appendChild(readLabel);
    checkboxContainer.appendChild(modifyLabel);
    modifyCheckbox.addEventListener("change", function() {
        if (modifyCheckbox.checked) {
            readCheckbox.checked = true;
        }
    });
    readCheckbox.addEventListener("change", function() {
        if (!readCheckbox.checked && modifyCheckbox.checked) {
            readCheckbox.checked = true;
            toast("❌ Modify permission requires Read permission", "error");
        }
    });
    const helpText = document.createElement("small");
    helpText.style.color = "var(--muted)";
    helpText.style.fontSize = "0.75rem";
    helpText.style.display = "block";
    helpText.style.marginTop = "0.5rem";
    helpText.textContent = "Note: Modify permission automatically grants Read access";
    permsField.appendChild(permsLabel);
    permsField.appendChild(checkboxContainer);
    permsField.appendChild(helpText);
    const submitBtn = document.createElement("button");
    submitBtn.type = "submit";
    submitBtn.className = "btn btn-primary";
    submitBtn.id = "grant-btn";
    submitBtn.textContent = "Grant Access";
    form.appendChild(emailField);
    form.appendChild(permsField);
    form.appendChild(submitBtn);
    section.appendChild(heading);
    section.appendChild(form);
    return section;
}

// Renders audit history entries for ACL changes.
function createAuditLogSection(aclData) {
    const section = document.createElement("div");
    section.className = "acl-section";
    const heading = document.createElement("h3");
    heading.textContent = "Audit Log";
    const logDiv = document.createElement("div");
    logDiv.className = "audit-log";
    if (aclData.aclLog.length === 0) {
        const emptyMsg = document.createElement("p");
        emptyMsg.style.color = "var(--muted)";
        emptyMsg.style.fontStyle = "italic";
        emptyMsg.textContent = "No audit log entries yet";
        logDiv.appendChild(emptyMsg);
    } else {
        aclData.aclLog.forEach(entry => {
            const logEntry = document.createElement("div");
            logEntry.className = "log-entry";
            const action = document.createElement("strong");
            action.textContent = entry.action.toUpperCase();
            const details = document.createElement("span");
            details.textContent = ` ${entry.target_user} by ${entry.performed_by}`;
            const timestamp = document.createElement("small");
            timestamp.textContent = new Date(entry.timestamp * 1e3).toLocaleString();
            logEntry.appendChild(action);
            logEntry.appendChild(details);
            logEntry.appendChild(document.createElement("br"));
            logEntry.appendChild(timestamp);
            logDiv.appendChild(logEntry);
        });
    }
    section.appendChild(heading);
    section.appendChild(logDiv);
    return section;
}

// Attaches all ACL modal event handlers (close, grant, edit, revoke).
function attachACLEventListeners(fileId, fileData) {
    const closeBtn = document.querySelector('[data-action="close-modal"]');
    if (closeBtn) {
        closeBtn.addEventListener("click", closeACLModal);
    }
    const overlay = document.getElementById("acl-modal");
    if (overlay) {
        overlay.addEventListener("click", e => {
            if (e.target === overlay) {
                closeACLModal();
            }
        });
    }
    const grantForm = document.getElementById("grant-form");
    if (grantForm) {
        grantForm.addEventListener("submit", async e => {
            e.preventDefault();
            await handleGrantAccess(fileId);
        });
    }
    const editButtons = document.querySelectorAll('[data-action="edit-permissions"]');
    editButtons.forEach(btn => {
        btn.addEventListener("click", async () => {
            const userEmail = btn.getAttribute("data-user-email");
            const permissions = JSON.parse(btn.getAttribute("data-permissions"));
            await handleEditPermissions(fileId, userEmail, permissions);
        });
    });
    const revokeButtons = document.querySelectorAll('[data-action="revoke-access"]');
    revokeButtons.forEach(btn => {
        btn.addEventListener("click", async () => {
            const userEmail = btn.getAttribute("data-user-email");
            await handleRevokeAccess(fileId, userEmail);
        });
    });
}

// Handles grant-access submission including key wrapping and signature.
async function handleGrantAccess(fileId) {
    const form = document.getElementById("grant-form");
    const submitBtn = document.getElementById("grant-btn");
    const targetEmail = form.email.value.trim().toLowerCase();
    const readChecked = document.getElementById("perm-read").checked;
    const modifyChecked = document.getElementById("perm-modify").checked;
    if (!readChecked && !modifyChecked) {
        toast("Select at least one permission", "error");
        return;
    }
    // Permission list is constructed from checkboxes and signed before send.
    const permissions = [];
    if (readChecked) permissions.push("read");
    if (modifyChecked) permissions.push("modify");
    submitBtn.disabled = true;
    submitBtn.textContent = "Fetching keys...";
    try {
        const keysData = await api("GET", `/api/users/${targetEmail}/public-keys`);
        // TOFU pin-check prevents silent key substitution for known contacts.
        await verifyAndPinPublicKeys(keysData.email, keysData.x25519Public, keysData.ed25519Public, true);
        submitBtn.textContent = "Wrapping key...";
        const recipientX25519Pub = await crypto.importX25519Public(keysData.x25519Public);
        // Owner unwraps root key, then re-wraps it for the target recipient.
        const fileData = await api("GET", `/api/files/${fileId}`);
        const sharedSecret = await crypto.x25519DeriveSharedSecret(state.x25519Priv, await crypto.importX25519Public(fileData.ephemeralPub));
        const wrapKey = await crypto.hkdf(sharedSecret, "file_key_wrap", 32);
        const wrapAad = crypto.strToBytes(fileId + "||" + state.email);
        const rootKeyBytes = await crypto.aesGcmDecrypt(wrapKey, fileData.wrapNonce, fileData.rootKey, wrapAad);
        // Recipient gets a fresh wrap based on recipient public key + ephemeral sender key.
        const wrapped = await crypto.x25519Wrap(recipientX25519Pub, rootKeyBytes);
        const currentVersion = fileData.version;
        let chainKeyBytes;
        if (currentVersion === 1) {
            chainKeyBytes = await crypto.hkdf(rootKeyBytes, "chain_v1", 32);
        } else {
            chainKeyBytes = await crypto.hkdf(rootKeyBytes, "chain_v1", 32);
            for (let v = 2; v <= currentVersion; v++) {
                chainKeyBytes = await crypto.hkdf(chainKeyBytes, `chain_v${v}`, 32);
            }
        }
        const wrappedChainKey = await crypto.x25519Wrap(recipientX25519Pub, chainKeyBytes);
        submitBtn.textContent = "Signing...";
        const nonce = generateNonce();
        const timestamp = Date.now();
        // Sorting keeps client/server signature payload deterministic.
        const sortedPerms = permissions.sort().join(",");
        // Signed ACL payload covers action + target + permissions + freshness fields.
        const aclDataStr = `grant||${fileId}||${targetEmail}||${sortedPerms}||${nonce}||${timestamp}`;
        const aclData = crypto.strToBytes(aclDataStr);
        const aclSig = await crypto.ed25519Sign(state.ed25519Priv, aclData);
        submitBtn.textContent = "Granting access...";
        await api("POST", `/api/files/${fileId}/access`, {
            targetEmail: targetEmail,
            wrappedKey: wrapped.ciphertext,
            wrapNonce: wrapped.nonce,
            ephemeralPub: wrapped.ephemeralPub,
            wrappedChainKey: wrappedChainKey.ciphertext,
            chainKeyNonce: wrappedChainKey.nonce,
            chainKeyEphemeralPub: wrappedChainKey.ephemeralPub,
            permissions: permissions,
            aclSig: aclSig,
            nonce: nonce,
            timestamp: timestamp
        });
        toast(`Access granted to ${targetEmail}`, "success");
        closeACLModal();
        setTimeout(() => window.manageACL(fileId), 300);
    } catch (err) {
        toast(err.message, "error");
        submitBtn.disabled = false;
        submitBtn.textContent = "Grant Access";
    }
}

// Revokes target user access after signed confirmation.
async function handleRevokeAccess(fileId, targetEmail) {
    if (!confirm(`Revoke access for ${targetEmail}?`)) {
        return;
    }
    try {
        const nonce = generateNonce();
        const timestamp = Date.now();
        // Revoke payload includes nonce + timestamp to prevent replay attacks.
        const aclData = crypto.strToBytes(`revoke||${fileId}||${targetEmail}||${nonce}||${timestamp}`);
        const aclSig = await crypto.ed25519Sign(state.ed25519Priv, aclData);
        await api("DELETE", `/api/files/${fileId}/access/${targetEmail}`, {
            aclSig: aclSig,
            nonce: nonce,
            timestamp: timestamp
        });
        toast(`Access revoked for ${targetEmail}`, "success");
        closeACLModal();
        setTimeout(() => window.manageACL(fileId), 300);
    } catch (err) {
        toast(err.message, "error");
    }
}

// Opens the edit-permissions modal for a selected user.
async function handleEditPermissions(fileId, userEmail, currentPermissions) {
    const editModal = createEditPermissionsModal(fileId, userEmail, currentPermissions);
    document.body.appendChild(editModal);
    const closeBtn = editModal.querySelector('[data-action="close-edit-modal"]');
    if (closeBtn) {
        closeBtn.addEventListener("click", () => {
            document.getElementById("edit-perm-modal").remove();
        });
    }
    const updateForm = editModal.querySelector("#update-perm-form");
    if (updateForm) {
        updateForm.addEventListener("submit", async e => {
            e.preventDefault();
            await handleUpdatePermissions(fileId, userEmail);
        });
    }
}

// Builds the edit-permissions modal UI and preselects current permissions.
function createEditPermissionsModal(fileId, userEmail, currentPermissions) {
    const overlay = document.createElement("div");
    overlay.className = "modal-overlay";
    overlay.id = "edit-perm-modal";
    overlay.style.zIndex = "10001";
    const modalDiv = document.createElement("div");
    modalDiv.className = "modal";
    modalDiv.style.maxWidth = "400px";
    const header = document.createElement("div");
    header.className = "modal-header";
    const title = document.createElement("h3");
    title.textContent = "Edit Permissions";
    const closeBtn = document.createElement("button");
    closeBtn.className = "modal-close";
    closeBtn.textContent = "✕";
    closeBtn.setAttribute("data-action", "close-edit-modal");
    header.appendChild(title);
    header.appendChild(closeBtn);
    const body = document.createElement("div");
    body.className = "modal-body";
    const userInfo = document.createElement("p");
    userInfo.style.marginBottom = "1rem";
    const userLabel = document.createElement("strong");
    userLabel.textContent = "User: ";
    const userEmailSpan = document.createElement("span");
    userEmailSpan.textContent = userEmail;
    userInfo.appendChild(userLabel);
    userInfo.appendChild(userEmailSpan);
    const form = document.createElement("form");
    form.id = "update-perm-form";
    form.setAttribute("data-file-id", fileId);
    form.setAttribute("data-user-email", userEmail);
    const field = document.createElement("div");
    field.className = "field";
    const label = document.createElement("label");
    label.textContent = "Permissions";
    const checkboxContainer = document.createElement("div");
    checkboxContainer.style.display = "flex";
    checkboxContainer.style.flexDirection = "column";
    checkboxContainer.style.gap = "0.75rem";
    checkboxContainer.style.marginTop = "0.5rem";
    const readLabel = document.createElement("label");
    readLabel.style.display = "flex";
    readLabel.style.alignItems = "center";
    readLabel.style.gap = "0.5rem";
    readLabel.style.cursor = "pointer";
    const readCheckbox = document.createElement("input");
    readCheckbox.type = "checkbox";
    readCheckbox.name = "edit-perm-read";
    readCheckbox.id = "edit-perm-read";
    readCheckbox.checked = currentPermissions.includes("read");
    const readSpan = document.createElement("span");
    readSpan.textContent = "📖 Read (Download)";
    readLabel.appendChild(readCheckbox);
    readLabel.appendChild(readSpan);
    const modifyLabel = document.createElement("label");
    modifyLabel.style.display = "flex";
    modifyLabel.style.alignItems = "center";
    modifyLabel.style.gap = "0.5rem";
    modifyLabel.style.cursor = "pointer";
    const modifyCheckbox = document.createElement("input");
    modifyCheckbox.type = "checkbox";
    modifyCheckbox.name = "edit-perm-modify";
    modifyCheckbox.id = "edit-perm-modify";
    modifyCheckbox.checked = currentPermissions.includes("modify");
    const modifySpan = document.createElement("span");
    modifySpan.textContent = "✏️ Modify (Update)";
    modifyLabel.appendChild(modifyCheckbox);
    modifyLabel.appendChild(modifySpan);
    checkboxContainer.appendChild(readLabel);
    checkboxContainer.appendChild(modifyLabel);
    modifyCheckbox.addEventListener("change", function() {
        if (modifyCheckbox.checked) {
            readCheckbox.checked = true;
        }
    });
    readCheckbox.addEventListener("change", function() {
        if (!readCheckbox.checked && modifyCheckbox.checked) {
            readCheckbox.checked = true;
            toast("❌ Modify permission requires Read permission", "error");
        }
    });
    const helpText = document.createElement("small");
    helpText.style.color = "var(--muted)";
    helpText.style.fontSize = "0.75rem";
    helpText.style.display = "block";
    helpText.style.marginTop = "0.5rem";
    helpText.textContent = "Note: Modify permission automatically grants Read access";
    checkboxContainer.appendChild(helpText);
    field.appendChild(label);
    field.appendChild(checkboxContainer);
    const submitBtn = document.createElement("button");
    submitBtn.type = "submit";
    submitBtn.className = "btn btn-primary";
    submitBtn.id = "update-perm-btn";
    submitBtn.style.marginTop = "1rem";
    submitBtn.textContent = "Update Permissions";
    form.appendChild(field);
    form.appendChild(submitBtn);
    body.appendChild(userInfo);
    body.appendChild(form);
    modalDiv.appendChild(header);
    modalDiv.appendChild(body);
    overlay.appendChild(modalDiv);
    return overlay;
}

// Submits permission updates with signed payload and refreshes ACL view.
async function handleUpdatePermissions(fileId, userEmail) {
    const submitBtn = document.getElementById("update-perm-btn");
    const readChecked = document.getElementById("edit-perm-read").checked;
    const modifyChecked = document.getElementById("edit-perm-modify").checked;
    if (!readChecked && !modifyChecked) {
        toast("Select at least one permission", "error");
        return;
    }
    const permissions = [];
    if (readChecked) permissions.push("read");
    if (modifyChecked) permissions.push("modify");
    submitBtn.disabled = true;
    submitBtn.textContent = "Updating...";
    try {
        const nonce = generateNonce();
        const timestamp = Date.now();
        // Keep canonical ordering so signature input is stable.
        const sortedPerms = permissions.sort().join(",");
        // Update signature binds permission change to actor + freshness values.
        const updateData = crypto.strToBytes(`update_permissions||${fileId}||${userEmail}||${sortedPerms}||${nonce}||${timestamp}`);
        const updateSig = await crypto.ed25519Sign(state.ed25519Priv, updateData);
        await api("PATCH", `/api/files/${fileId}/access/${userEmail}`, {
            permissions: permissions,
            updateSig: updateSig,
            nonce: nonce,
            timestamp: timestamp
        });
        toast("Permissions updated", "success");
        document.getElementById("edit-perm-modal").remove();
        closeACLModal();
        setTimeout(() => window.manageACL(fileId), 300);
    } catch (err) {
        toast(err.message, "error");
        submitBtn.disabled = false;
        submitBtn.textContent = "Update Permissions";
    }
}

// Closes the main ACL modal if present.
function closeACLModal() {
    const modal = document.getElementById("acl-modal");
    if (modal) {
        modal.remove();
    }
}

// Exposes ACL modal close helper for existing UI wiring.
window.closeACLModal = closeACLModal;