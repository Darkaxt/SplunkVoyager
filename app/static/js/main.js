/**
 * vConfirm: the confirmation dialog for every destructive action. Resolves to false (cancel, Escape, click
 * outside) or true; with `type`, the confirm button stays disabled until that exact text is typed, and the
 * promise resolves to the typed text.
 *   await vConfirm({title, lines: [..], label: 'Delete', type: 'name to type'})
 */
function vConfirm(o) {
    o = typeof o === 'string' ? {title: o} : (o || {});
    if (!document.getElementById('vconfirm-style')) {
        const st = document.createElement('style');
        st.id = 'vconfirm-style';
        st.textContent = `
dialog.vconfirm { position:fixed; inset:0; margin:auto; height:fit-content; border:1px solid #5a2a2a; border-radius:8px; background:#1d1f23; color:#e6edf3; padding:0; max-width:560px; width:calc(100% - 40px); box-shadow:0 20px 60px #000a; }
dialog.vconfirm::backdrop { background:#0009; }
dialog.vconfirm .vc-b { padding:18px 20px 6px; }
dialog.vconfirm h3 { margin:0 0 10px; font-size:16px; color:#ff8a84; font-weight:600; }
dialog.vconfirm ul { margin:0 0 10px 18px; padding:0; line-height:1.55; font-size:13.5px; color:#c9d1d9; }
dialog.vconfirm label { display:block; font-size:13px; color:#9aa4b2; margin:10px 0 4px; }
dialog.vconfirm label b { color:#e6edf3; font-family:Consolas,monospace; font-weight:600; user-select:all; }
dialog.vconfirm input { width:100%; box-sizing:border-box; background:#111214; border:1px solid #3a3d44; color:#e6edf3; border-radius:5px; padding:7px 9px; font:13px Consolas,monospace; }
dialog.vconfirm .vc-a { display:flex; justify-content:flex-end; gap:8px; padding:12px 20px 16px; }
dialog.vconfirm button { border-radius:5px; padding:6px 14px; font-size:13px; cursor:pointer; border:1px solid #3a3d44; background:#2a2c31; color:#e6edf3; }
dialog.vconfirm button.vc-ok { background:#8e2b26; border-color:#b8433c; color:#fff; font-weight:600; }
dialog.vconfirm button.vc-ok:disabled { opacity:.4; cursor:not-allowed; }`;
        document.head.appendChild(st);
    }
    const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
    const dlg = document.createElement('dialog');
    dlg.className = 'vconfirm';
    dlg.innerHTML = `<div class="vc-b"><h3>${esc(o.title || 'Are you sure?')}</h3>
        ${(o.lines || []).length ? `<ul>${o.lines.map(l => `<li>${esc(l)}</li>`).join('')}</ul>` : ''}
        ${o.type ? `<label>Type <b>${esc(o.type)}</b> to confirm</label><input type="text" autocomplete="off" spellcheck="false">` : ''}</div>
      <div class="vc-a"><button type="button" class="vc-no">Cancel</button><button type="button" class="vc-ok">${esc(o.label || 'Confirm')}</button></div>`;
    document.body.appendChild(dlg);
    const ok = dlg.querySelector('.vc-ok'), no = dlg.querySelector('.vc-no'), inp = dlg.querySelector('input');
    return new Promise(resolve => {
        const done = v => { dlg.close(); dlg.remove(); resolve(v); };
        if (inp) {
            ok.disabled = true;
            inp.addEventListener('input', () => { ok.disabled = inp.value !== o.type; });
            inp.addEventListener('keydown', e => { if (e.key === 'Enter' && !ok.disabled) done(inp.value); });
        }
        ok.onclick = () => done(inp ? inp.value : true);
        no.onclick = () => done(false);
        dlg.addEventListener('cancel', e => { e.preventDefault(); done(false); });
        dlg.addEventListener('click', e => { if (e.target === dlg) done(false); });
        dlg.showModal();
        (inp || no).focus();          // the safe choice has the focus: Enter alone never confirms
    });
}

/**
 * SplunkVoyager main JavaScript file
 * Contains common functionality used across the application
 */

// Global utility functions

/**
 * Format a date string in a more readable format
 * @param {string} dateString - ISO date string
 * @returns {string} Formatted date string
 */
function formatDate(dateString) {
    if (!dateString) return '-';
    
    const date = new Date(dateString);
    return date.toLocaleString();
}

/**
 * Display an error message
 * @param {string} message - Error message to display
 * @param {HTMLElement} container - Container element to display the error in
 */
function showError(message, container = null) {
    if (!container) {
        // Create toast-style notification
        const toast = document.createElement('div');
        toast.className = 'toast toast-error';
        toast.textContent = message;
        
        document.body.appendChild(toast);
        
        // Remove after 5 seconds
        setTimeout(() => {
            toast.classList.add('toast-hide');
            setTimeout(() => {
                document.body.removeChild(toast);
            }, 300);
        }, 5000);
    } else {
        // Display in specified container
        container.innerHTML = `
            <div class="error-message">
                <strong>Error:</strong> ${message}
            </div>
        `;
        container.style.display = 'block';
    }
}

/**
 * Show a success message
 * @param {string} message - Success message to display
 */
function showSuccess(message) {
    // Create toast-style notification
    const toast = document.createElement('div');
    toast.className = 'toast toast-success';
    toast.textContent = message;
    
    document.body.appendChild(toast);
    
    // Remove after 5 seconds
    setTimeout(() => {
        toast.classList.add('toast-hide');
        setTimeout(() => {
            document.body.removeChild(toast);
        }, 300);
    }, 5000);
}

/**
 * Make an API request
 * @param {string} url - API endpoint URL
 * @param {Object} options - Fetch options
 * @returns {Promise} - Promise resolving to the API response
 */
async function apiRequest(url, options = {}) {
    try {
        const response = await fetch(url, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...(options.headers || {})
            }
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.message || 'API request failed');
        }
        
        return data;
    } catch (error) {
        console.error('API request error:', error);
        throw error;
    }
}

/**
 * Formats a JavaScript object/value as an HTML string with indentation
 * and syntax highlighting using recursive formatting.
 * @param {any} json - The data to format.
 * @returns {string} HTML string containing the formatted JSON.
 */
function formatJSON(json) {
    // Initial parsing if input is a string
    if (typeof json === 'string') {
        try {
            // Only parse if it looks like JSON
            const trimmedJson = json.trim();
            if ((trimmedJson.startsWith('{') && trimmedJson.endsWith('}')) || (trimmedJson.startsWith('[') && trimmedJson.endsWith(']'))) {
                json = JSON.parse(trimmedJson);
            } else {
                // Not JSON-like string, escape and return in pre
                 return `<pre class="json-formatter">${escapeHTML(json)}</pre>`;
            }
        } catch (error) {
             // Parsing failed, return escaped original string in pre
            console.warn("formatJSON: Input string looked like JSON but failed parsing.", error);
            return `<pre class="json-formatter error">${escapeHTML(json)}</pre>`;
        }
    }

    // --- Recursive helper function with indentation level ---
    function formatValue(value, level = 0) {
        const indentSize = 2; // Number of spaces per indent level
        const currentIndent = ' '.repeat(level * indentSize);
        const childIndent = ' '.repeat((level + 1) * indentSize); // Indent for children

        if (value === null) return '<span class="json-null">null</span>';
        if (value === undefined) return '<span class="json-null">undefined</span>'; // Or handle differently

        switch (typeof value) {
            case 'boolean':
                return `<span class="json-boolean">${value}</span>`;
            case 'number':
                return `<span class="json-number">${value}</span>`;
            case 'string':
                // Escape the string content itself
                return `<span class="json-string">"${escapeHTML(value)}"</span>`;
            case 'object':
                if (Array.isArray(value)) {
                    // --- Array Formatting with Indentation ---
                    if (value.length === 0) return '[]';
                    const arrayItems = value.map(v => `${childIndent}${formatValue(v, level + 1)}`); // Indent each item
                    return `[<br>${arrayItems.join(',<br>')}<br>${currentIndent}]`; // Indent closing bracket
                } else {
                    // --- Object Formatting with Indentation ---
                    const entries = Object.entries(value);
                    if (entries.length === 0) return '{}';
                    const objectItems = entries.map(([k, v]) => {
                        // Escape the key string before adding spans
                        const escapedKey = escapeHTML(k);
                        return `${childIndent}<span class="json-key">"${escapedKey}"</span>: ${formatValue(v, level + 1)}`; // Indent each key-value pair
                    });
                    return `{<br>${objectItems.join(',<br>')}<br>${currentIndent}}`; // Indent closing bracket
                }
            default:
                // Fallback for other types (e.g., functions - unlikely in pure JSON)
                return escapeHTML(String(value));
        }
    }

    // --- Wrap the final result in a <pre> tag ---
    // Call the recursive function starting at level 0
    const formattedContent = formatValue(json, 0);
    return `<pre class="json-formatter">${formattedContent}</pre>`;
}

/**
 * Escape HTML special characters
 * @param {string} str - String to escape
 * @returns {string} Escaped string
 */
function escapeHTML(str) {
    return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

/**
 * Export data as a downloadable file
 * @param {Object|Array|string} data - Data to export
 * @param {string} filename - Name of the file
 * @param {string} type - MIME type of the file
 */
function exportData(data, filename, type) {
    let content;
    
    if (type === 'application/json') {
        if (typeof data === 'object') {
            content = JSON.stringify(data, null, 2);
        } else {
            content = data;
        }
    } else if (type === 'text/csv') {
        if (typeof data === 'object') {
            if (Array.isArray(data)) {
                // Convert array of objects to CSV
                if (data.length === 0) {
                    content = '';
                } else {
                    const headers = Object.keys(data[0]);
                    const rows = [
                        headers.join(','),
                        ...data.map(obj => headers.map(header => {
                            const value = obj[header];
                            if (value === null || value === undefined) return '';
                            if (typeof value === 'string') {
                                // Escape quotes and wrap in quotes if needed
                                if (value.includes(',') || value.includes('"') || value.includes('\n')) {
                                    return `"${value.replace(/"/g, '""')}"`;
                                }
                                return value;
                            }
                            return String(value);
                        }).join(','))
                    ];
                    content = rows.join('\n');
                }
            } else {
                // Convert object to CSV
                const rows = Object.entries(data).map(([key, value]) => `${key},${value}`);
                content = rows.join('\n');
            }
        } else {
            content = data;
        }
    } else {
        content = String(data);
    }
    
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.style.display = 'none';
    
    document.body.appendChild(a);
    a.click();
    
    setTimeout(() => {
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }, 100);
}

/**
 * Copy text to clipboard
 * @param {string} text - Text to copy
 * @returns {Promise<boolean>} - Whether the copy operation was successful
 */
async function copyToClipboard(text) {
    try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(text);
            return true;
        } else {
            // Fallback method
            const textarea = document.createElement('textarea');
            textarea.value = text;
            textarea.style.position = 'fixed';
            document.body.appendChild(textarea);
            textarea.focus();
            textarea.select();
            
            const successful = document.execCommand('copy');
            document.body.removeChild(textarea);
            return successful;
        }
    } catch (error) {
        console.error('Error copying to clipboard:', error);
        return false;
    }
}

/**
 * Helper function to get a specific cookie by name.
 * @param {string} name - The name of the cookie.
 * @returns {string|null} The value of the cookie or null if not found.
 */
function getCookie(name) {
    const nameEQ = name + "=";
    const ca = document.cookie.split(';');
    for(let i = 0; i < ca.length; i++) {
        let c = ca[i];
        while (c.charAt(0) === ' ') c = c.substring(1, c.length);
        if (c.indexOf(nameEQ) === 0) return c.substring(nameEQ.length, c.length);
    }
    return null;
}

/**
 * Fetches active sessions and updates the user dropdown in the header.
 */
async function updateUserDropdown() {
    // Find the necessary elements
    const usernameSpan = document.getElementById('user-dropdown-username');
    const sessionListContainer = document.getElementById('user-dropdown-session-list');
    const sessionDetailsLink = document.getElementById('user-dropdown-session-details-link');
    const toggleLink = document.getElementById('user-dropdown-toggle-link');

    // Only proceed if we are in the "logged-in" state structure
    if (!usernameSpan || !sessionListContainer || !sessionDetailsLink || !toggleLink) {
        // console.log("User dropdown elements not found (likely logged out state). Skipping dropdown update.");
        return;
    }

    console.log("Fetching active sessions for header dropdown...");

    try {
        // Uses apiRequest helper defined above
        const response = await apiRequest('/api/sessions/active');

        if (response.status === 'success' && Array.isArray(response.active_sessions)) {
            const activeSessions = response.active_sessions;
            const preferredSessionId = getCookie('preferred_session_id'); // Get preference

            let currentUser = null;
            if (preferredSessionId) {
                // Find the session matching the cookie preference
                currentUser = activeSessions.find(s => String(s.id) === preferredSessionId);
            }

            // Fallback: If cookie preference is invalid/missing, use the first active session
            if (!currentUser && activeSessions.length > 0) {
                 currentUser = activeSessions[0];
                 console.log("Header: Preferred session not active or cookie missing, defaulting display to first active session.");
            }

            if (currentUser) {
                // Update username display
                usernameSpan.textContent = escapeHTML(currentUser.username || 'Unknown'); // Use escapeHTML
                 usernameSpan.title = `${escapeHTML(currentUser.username)}@${escapeHTML(currentUser.domain)}`;

                // Update Session Details link href
                 sessionDetailsLink.href = `/session/${currentUser.id}`; // Assumes simple URL structure

                // Clear previous session list items
                sessionListContainer.innerHTML = '';

                // Populate the "Switch Account" list
                activeSessions.forEach(session => {
                    const link = document.createElement('a');
                    link.href = `/set_active_session/${session.id}`; // Link to trigger preference change
                    link.className = 'account-switch-item';
                    link.textContent = `${escapeHTML(session.username)}@${escapeHTML(session.domain)}`;
                    link.title = `Switch to ${escapeHTML(session.username)}@${escapeHTML(session.domain)}`;

                    // Add 'active' class if this session matches the currently displayed user
                    if (currentUser && session.id === currentUser.id) {
                        link.classList.add('active');
                    }

                    sessionListContainer.appendChild(link);
                });

            } else {
                // Logged-in structure rendered, but couldn't determine a user (e.g., API returned empty list)
                console.warn("Header: Could not determine current user, although logged-in structure exists.");
                usernameSpan.textContent = 'Error';
                sessionListContainer.innerHTML = '<div class="dropdown-message">No active user found.</div>';
            }
        } else {
            console.error("Header: API request for active sessions failed or invalid data:", response?.message);
            if (sessionListContainer) {
                 sessionListContainer.innerHTML = '<div class="dropdown-message">Error loading sessions.</div>';
            }
        }
    } catch (error) {
        console.error("Header: Error fetching active sessions:", error);
        if (sessionListContainer) {
           sessionListContainer.innerHTML = '<div class="dropdown-message">Network error loading sessions.</div>';
        }
    }
}

// Initialize tab functionality
document.addEventListener('DOMContentLoaded', () => {
    // Tab functionality
    const tabs = document.querySelectorAll('.tab');
    
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const tabId = tab.getAttribute('data-tab');
            
            // Remove active class from all tabs
            document.querySelectorAll('.tab').forEach(t => {
                t.classList.remove('active');
            });
            
            // Hide all tab content
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            
            // Activate the selected tab
            tab.classList.add('active');
            const tabContent = document.getElementById(tabId);
            if (tabContent) {
                tabContent.classList.add('active');
            }
        });
    });
    
    // Add toast container if it doesn't exist
    if (!document.querySelector('.toast-container')) {
        const toastContainer = document.createElement('div');
        toastContainer.className = 'toast-container';
        document.body.appendChild(toastContainer);
    }
	
	updateUserDropdown();
	setInterval(updateUserDropdown, 60000);
});

// Add toast styles
(function() {
    const style = document.createElement('style');
    style.textContent = `
        .toast-container {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 9999;
        }
        
        .toast {
            padding: 12px 20px;
            margin-bottom: 10px;
            border-radius: 4px;
            color: white;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.2);
            animation: fadeIn 0.3s ease;
            max-width: 300px;
        }
        
        .toast-success {
            background-color: #2ecc71;
        }
        
        .toast-error {
            background-color: #e74c3c;
        }
        
        .toast-hide {
            animation: fadeOut 0.3s ease;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        @keyframes fadeOut {
            from { opacity: 1; transform: translateY(0); }
            to { opacity: 0; transform: translateY(-20px); }
        }
        
        .error-message {
            background-color: #f8d7da;
            color: #721c24;
            padding: 12px;
            border-radius: 4px;
            margin-bottom: 15px;
        }
    `;
    document.head.appendChild(style);
})();