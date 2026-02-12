/**
 * SecVault v3.0 - API Client
 */

import { state } from './state.js';

const API_BASE = '';

export async function api(method, path, body = null, authenticated = true) {
    const headers = { 'Content-Type': 'application/json' };
    
    if (authenticated) {
        const token = state.token;
        if (token) {
            headers['Authorization'] = 'Bearer ' + token;
        } else {
            console.warn('⚠️ API call requires auth but no token available');
        }
    }
    
    const options = { method, headers };
    if (body) options.body = JSON.stringify(body);
    
    const response = await fetch(API_BASE + path, options);
    const json = await response.json().catch(() => ({}));
    
    if (!response.ok) throw new Error(json.error || `HTTP ${response.status}`);
    return json;
}

export function toast(message, type = 'info', duration = 4000) {
    
    const icons = { success: '✓', error: '✕', info: 'ℹ' };
    const container = document.getElementById('toast-container');
    
    if (!container) {
        console.error('❌ Toast container not found!');
        return;
    }
    
    const toastEl = document.createElement('div');
    toastEl.className = `toast toast-${type}`;
    toastEl.innerHTML = `
        <span class="toast-icon">${icons[type] || 'ℹ'}</span>
        <span class="toast-msg">${message}</span>
    `;
    
    container.appendChild(toastEl);
    
    // Trigger animation
    setTimeout(() => toastEl.classList.add('show'), 10);
    
    // Hide animation
    setTimeout(() => {
        toastEl.classList.remove('show');
        toastEl.classList.add('hide');
    }, duration - 300);
    
    // Remove from DOM
    setTimeout(() => toastEl.remove(), duration);
}
