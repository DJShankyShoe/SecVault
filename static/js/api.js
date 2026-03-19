import { state } from "./state.js";

const API_BASE = "";

/*
 * API LAYER OVERVIEW
 * - api(): single wrapper for JSON requests/responses.
 * - toast(): shared notification UI for user feedback.
 */

// Sends JSON API requests and returns parsed JSON or throws a normalized error.
export async function api(method, path, body = null, authenticated = true) {
    const headers = {
        "Content-Type": "application/json"
    };

    const options = {
        method: method,
        headers: headers,
        credentials: "same-origin"
    };

    if (body) options.body = JSON.stringify(body);

    // Centralized fetch call so auth/cookie behavior is consistent everywhere.
    const response = await fetch(API_BASE + path, options);
    const json = await response.json().catch(() => ({}));

    // Normalize backend errors to a single Error shape used by callers.
    if (!response.ok) throw new Error(json.error || `HTTP ${response.status}`);

    return json;
}

// Displays temporary toast notifications for success/error/info user feedback.
export function toast(message, type = "info", duration = 4e3) {
    const icons = {
        success: "✓",
        error: "✕",
        info: "ℹ"
    };
    const container = document.getElementById("toast-container");
    if (!container) {
        console.error("❌ Toast container not found!");
        return;
    }

    const toastEl = document.createElement("div");
    toastEl.className = `toast toast-${type}`;
    toastEl.innerHTML = `\n        <span class="toast-icon">${icons[type] || "ℹ"}</span>\n        <span class="toast-msg">${message}</span>\n    `;

    container.appendChild(toastEl);

    // Enter animation -> visible state.
    setTimeout(() => toastEl.classList.add("show"), 10);

    // Exit animation shortly before removal.
    setTimeout(() => {
        toastEl.classList.remove("show");
        toastEl.classList.add("hide");
    }, duration - 300);

    // Final cleanup to keep DOM small.
    setTimeout(() => toastEl.remove(), duration);
}