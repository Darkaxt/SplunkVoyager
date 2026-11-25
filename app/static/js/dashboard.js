/**
 * SplunkVoyager Dashboard JavaScript
 * Handles dynamic updates for the dashboard page (e.g., index.html)
 */

// Assume utility functions (apiRequest, showError, formatDate, escapeHTML) are loaded from main.js

const ACTIVE_SESSIONS_UPDATE_INTERVAL = 30000; // 30 seconds in milliseconds
let activeSessionsIntervalId = null; // To store the interval ID

/**
 * Fetches active sessions from the API and updates the DOM.
 */
async function updateActiveSessions() {
    const listContainer = document.getElementById('active-sessions-list');
    if (!listContainer) {
        console.warn("Active sessions container '#active-sessions-list' not found.");
        // Stop trying if the container isn't there
        if (activeSessionsIntervalId) {
            clearInterval(activeSessionsIntervalId);
            activeSessionsIntervalId = null;
            console.log("Stopped active sessions update interval.");
        }
        return;
    }

    console.log("Fetching active sessions..."); // Log fetching attempt

    try {
        const response = await apiRequest('/api/sessions/active'); // Uses helper from main.js

        if (response.status === 'success' && response.active_sessions) {
            const sessions = response.active_sessions;
            console.log(`Found ${sessions.length} active sessions.`); // Log result count

            // Clear previous content (including loading message/spinner)
            listContainer.innerHTML = '';

            if (sessions.length > 0) {
                sessions.forEach(session => {
                    // Create card element for each session
                    const card = document.createElement('div');
                    card.className = 'card'; // Use existing card styles

                    const cardHeader = document.createElement('div');
                    cardHeader.className = 'card-header';
                    cardHeader.innerHTML = `
                        <h3 class="card-title">
                            <span class="status-indicator status-active"></span>
                            ${escapeHTML(session.domain || 'Unknown Domain')}
                        </h3>
                    `;

                    const cardBody = document.createElement('div');
                    cardBody.className = 'card-body';
                    cardBody.innerHTML = `
                        <p><strong>Username:</strong> ${escapeHTML(session.username || 'N/A')}</p>
                        <p><strong>Last Active:</strong> <span class="date-format">${escapeHTML(session.last_active || '-')}</span></p>
                    `;

                    const cardFooter = document.createElement('div');
                    cardFooter.className = 'card-footer';
                    cardFooter.innerHTML = `
                        <a href="/session/${session.id}" class="btn">View Details</a>
                        <a href="/query?domain=${encodeURIComponent(session.domain || '')}" class="btn btn-success">Execute Query</a>
                    `;

                    card.appendChild(cardHeader);
                    card.appendChild(cardBody);
                    card.appendChild(cardFooter);

                    listContainer.appendChild(card);
                });

                // Format dates within the newly added cards
                listContainer.querySelectorAll('.date-format').forEach(element => {
                    const dateString = element.textContent.trim();
                    if (dateString && dateString !== '-') {
                        try { element.textContent = formatDate(dateString); }
                        catch(e) { console.error("Date format error", e); }
                    }
                });

            } else {
                // Display the "No active sessions" message
                listContainer.innerHTML = `
                    <div class="card">
                        <div class="card-body">
                            <p>No active sessions available. Install the userscript to extract cookies from Splunk.</p>
                            <p>Once installed, visit your Splunk instance and the cookies will automatically be sent to SplunkVoyager.</p>
                        </div>
                    </div>
                `;
            }
        } else {
            // Handle API error status, but don't clear the list, maybe show small indicator?
            console.error("API request for active sessions failed:", response.message);
            // Optionally display a subtle error without replacing content if desired
            // listContainer.insertAdjacentHTML('beforeend', '<p class="text-danger small">Error updating sessions.</p>');
        }
    } catch (error) {
        // Handle network/fetch errors
        console.error("Error fetching active sessions:", error);
        // Avoid clearing the list on network errors, maybe just log or show subtle indicator
        // showError("Could not update active sessions list."); // Optional user feedback
    }
}


// --- Initialization ---
document.addEventListener('DOMContentLoaded', () => {
    // Perform initial fetch immediately
    updateActiveSessions();

    // Set up periodic updates only if the container exists
    if (document.getElementById('active-sessions-list')) {
        if (activeSessionsIntervalId) {
             clearInterval(activeSessionsIntervalId); // Clear any existing interval
        }
        activeSessionsIntervalId = setInterval(updateActiveSessions, ACTIVE_SESSIONS_UPDATE_INTERVAL);
        console.log(`Started active sessions update interval (${ACTIVE_SESSIONS_UPDATE_INTERVAL / 1000}s).`);
    }
});

// Optional: Clear interval if the user navigates away (more relevant for SPAs)
// window.addEventListener('beforeunload', () => {
//     if (activeSessionsIntervalId) {
//         clearInterval(activeSessionsIntervalId);
//     }
// });