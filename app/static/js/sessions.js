/**
 * SplunkVoyager sessions page JavaScript
 * Handles session management functionality
 */

document.addEventListener('DOMContentLoaded', () => {
    // Add event listeners for session actions
    setupSessionActions();
    
    // Format dates
    formatDates();
});

/**
 * Set up event listeners for session actions
 */
function setupSessionActions() {
    // Invalidate session buttons
    const invalidateButtons = document.querySelectorAll('[data-action="invalidate"]');
    
    invalidateButtons.forEach(button => {
        button.addEventListener('click', async (event) => {
            const sessionId = button.getAttribute('data-session-id');
            
            if (!sessionId) {
                showError('Session ID not found');
                return;
            }
            
            if (!confirm('Are you sure you want to invalidate this session?')) {
                return;
            }
            
            try {
                const response = await apiRequest(`/api/session/${sessionId}/invalidate`, {
                    method: 'POST'
                });
                
                if (response.status === 'success') {
                    showSuccess('Session invalidated successfully');
                    // Reload the page to reflect the changes
                    window.location.reload();
                } else {
                    showError(response.message || 'Failed to invalidate session');
                }
            } catch (error) {
                showError(error.message || 'Failed to invalidate session');
            }
        });
    });
    
    // Refresh sessions button
    const refreshButton = document.getElementById('refresh-sessions');
    if (refreshButton) {
        refreshButton.addEventListener('click', () => {
            window.location.reload();
        });
    }
}

/**
 * Format date strings in the session list
 */
function formatDates() {
    // Find all elements with date information
    const dateElements = document.querySelectorAll('.date-format');
    
    dateElements.forEach(element => {
        const dateString = element.textContent.trim();
        if (dateString && dateString !== '-') {
            element.textContent = formatDate(dateString);
        }
    });
}

/**
 * Validate a session
 * @param {number} sessionId - ID of the session to validate
 */
async function validateSession(sessionId) {
    if (!sessionId) {
        showError('Session ID not found');
        return;
    }
    
    try {
        const response = await apiRequest(`/api/session/${sessionId}/validate`, {
            method: 'POST'
        });
        
        if (response.status === 'success') {
            if (response.is_valid) {
                showSuccess('Session is valid');
            } else {
                showError('Session is no longer valid');
            }
            // Reload the page to reflect the changes
            window.location.reload();
        } else {
            showError(response.message || 'Failed to validate session');
        }
    } catch (error) {
        showError(error.message || 'Failed to validate session');
    }
}

// Add event listeners for validate buttons if on session detail page
const validateButton = document.getElementById('validate-session-btn');
if (validateButton) {
    validateButton.addEventListener('click', () => {
        const sessionId = validateButton.getAttribute('data-session-id');
        validateSession(sessionId);
    });
}

// Add event listeners for invalidate session button if on session detail page
const invalidateButton = document.getElementById('invalidate-session-btn');
if (invalidateButton) {
    invalidateButton.addEventListener('click', async () => {
        const sessionId = invalidateButton.getAttribute('data-session-id');
        
        if (!sessionId) {
            showError('Session ID not found');
            return;
        }
        
        if (!confirm('Are you sure you want to invalidate this session?')) {
            return;
        }
        
        try {
            const response = await apiRequest(`/api/session/${sessionId}/invalidate`, {
                method: 'POST'
            });
            
            if (response.status === 'success') {
                showSuccess('Session invalidated successfully');
                // Reload the page to reflect the changes
                window.location.reload();
            } else {
                showError(response.message || 'Failed to invalidate session');
            }
        } catch (error) {
            showError(error.message || 'Failed to invalidate session');
        }
    });
}