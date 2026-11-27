// session_detail.js

document.addEventListener('DOMContentLoaded', function() {
    // Get config values from window object
    const config = window.sessionDetailConfig || {};
    
    // Format dates (No changes needed here)
    document.querySelectorAll('.date-format').forEach(element => {
        const dateString = element.textContent.trim();
        if (dateString && dateString !== '-') {
            try {
                 element.textContent = formatDate(dateString); // Assumes formatDate is in main.js
            } catch(e) { console.error("Date format error", e); }
        }
    });

    // Validate session button (Modified to use config)
    const validateButton = document.getElementById('validate-session-btn');
    if (validateButton) {
        validateButton.addEventListener('click', async () => {
            const sessionId = validateButton.getAttribute('data-session-id') || config.sessionId;
            if (!sessionId) { showError('Session ID not found for validation.'); return; }
             try {
                validateButton.disabled = true; validateButton.textContent = 'Validating...';
                const response = await apiRequest(`/api/session/${sessionId}/validate`, { method: 'POST' });
                if (response.status === 'success') {
                    if (response.is_valid) { showSuccess('Session is valid'); }
                    else { showError('Session is no longer valid'); }
                    window.location.reload();
                } else {
                    showError(response.message || 'Failed to validate session');
                    validateButton.disabled = false; validateButton.textContent = 'Validate Session';
                }
            } catch (error) {
                showError(error.message || 'Failed to validate session');
                validateButton.disabled = false; validateButton.textContent = 'Validate Session';
            }
        });
    }

    // Invalidate session button (Modified to use config)
    const invalidateButton = document.getElementById('invalidate-session-btn');
    if (invalidateButton) {
        invalidateButton.addEventListener('click', async () => {
            const sessionId = invalidateButton.getAttribute('data-session-id') || config.sessionId;
            if (!sessionId) { showError('Session ID not found for invalidation.'); return; }
            if (!await vConfirm({title: 'Invalidate this session?', label: 'Invalidate', lines: ['Its stored cookies are deleted and Voyager stops using it.', 'Searches and exports that rely on it wait until an open Splunk tab sends a new session.']})) return;
             try {
                invalidateButton.disabled = true; invalidateButton.textContent = 'Invalidating...';
                const response = await apiRequest(`/api/session/${sessionId}/invalidate`, { method: 'POST' });
                if (response.status === 'success') {
                    showSuccess('Session invalidated successfully');
                    window.location.reload();
                } else {
                    showError(response.message || 'Failed to invalidate session');
                    invalidateButton.disabled = false; invalidateButton.textContent = 'Invalidate Session';
                }
            } catch (error) {
                showError(error.message || 'Failed to invalidate session');
                invalidateButton.disabled = false; invalidateButton.textContent = 'Invalidate Session';
            }
        });
    }

    // Re-run query buttons (Using data attributes from HTML)
    document.querySelectorAll('.rerun-query-btn').forEach(button => {
        button.addEventListener('click', async (event) => {
            event.preventDefault();

            const definitionId = button.getAttribute('data-definition-id');
            const domain = button.getAttribute('data-domain');

            if (!definitionId || !domain) {
                showError('Missing data required to re-run query (Definition ID or Domain).');
                return;
            }

            if (!await vConfirm({title: 'Re-run this query?', label: 'Re-run', lines: ['A new search runs on Splunk and its results replace the cached ones.']})) {
                return;
            }

            button.disabled = true;
            button.textContent = 'Refreshing...';
            const originalText = 'Re-run';

            try {
                const response = await apiRequest(`/api/query/definition/${definitionId}/rerun`, {
                    method: 'POST',
                    body: JSON.stringify({ domain: domain })
                });

                if (response.status === 'success') {
                    showSuccess(`Query Definition ${definitionId} refresh initiated (New Execution ID: ${response.execution_id}). Results updated.`);
                    setTimeout(() => window.location.reload(), 1500);
                } else if (response.status === 'pending') {
                    showWarning(response.message || `Query Definition ${definitionId} refresh is already in progress.`);
                } else {
                    showError(response.message || `Failed to re-run query definition ${definitionId}.`);
                }
            } catch (error) {
                showError(error.message || `Error occurred while trying to re-run query definition ${definitionId}.`);
            } finally {
                button.disabled = false;
                button.textContent = originalText;
            }
        });
    });

    // Delete execution buttons (Using data attributes from HTML)
    document.querySelectorAll('.delete-execution-btn').forEach(button => {
        button.addEventListener('click', async () => {
            const executionId = button.getAttribute('data-execution-id');

            if (!await vConfirm({title: 'Delete this query execution record?', label: 'Delete record', lines: ['Its stored results are removed.', "If it is the query's last execution, the saved query is removed too.", 'This cannot be undone.']})) {
                return;
            }

            if (!executionId) {
                showError('Execution ID not found for delete button.');
                return;
            }

            try {
                button.disabled = true;

                const response = await apiRequest(`/api/query/execution/${executionId}/delete`, {
                    method: 'POST'
                });

                if (response.status === 'success') {
                    showSuccess('Query execution deleted successfully');
                    // Remove the row from the table smoothly
                    const row = button.closest('tr');
                    if (row) {
                        row.style.transition = 'opacity 0.5s ease';
                        row.style.opacity = '0';
                        setTimeout(() => row.remove(), 500);
                    }
                } else {
                    showError(response.message || 'Failed to delete query execution');
                    button.disabled = false;
                }
            } catch (error) {
                showError(error.message || 'Failed to delete query execution');
                button.disabled = false;
            }
        });
    });
});