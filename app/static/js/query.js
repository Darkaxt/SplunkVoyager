/**
 * SplunkVoyager query page JavaScript
 * Handles query execution and result display
 */

// Assume common utility functions (formatDate, showError, showSuccess, apiRequest, formatJSON, escapeHTML, exportData, copyToClipboard)
// are available globally, potentially loaded from main.js

let currentDomain = '';
let currentSessionId = '';

document.addEventListener('DOMContentLoaded', () => {
    // Initialize UI elements
    initQueryUI();

    // Initialize datetime pickers
    initDateTimePickers();

    // Check URL parameters for domain selection
    checkUrlParams();
});

/**
 * Initialize the query UI elements
 */
function initQueryUI() {
    // Domain select change handler
    const domainSelect = document.getElementById('domain-select');
    if (domainSelect) {
        domainSelect.addEventListener('change', async () => {
            currentDomain = domainSelect.value;
            currentSessionId = domainSelect.options[domainSelect.selectedIndex]?.getAttribute('data-session-id'); // Added optional chaining

            if (currentDomain && currentSessionId) {
                // Load recent query executions for this domain/session
                await loadRecentExecutions(currentSessionId); // <-- Renamed function call
            } else {
                const recentQueriesContainer = document.getElementById('recent-queries');
                if(recentQueriesContainer) recentQueriesContainer.innerHTML = '<p>Select a domain to see recent execution history.</p>'; // <-- Updated text
            }
        });
    }

    // Predefined time range select handler
    const timeRangeSelect = document.getElementById('time-range');
    if (timeRangeSelect) {
        timeRangeSelect.addEventListener('change', () => {
            const value = timeRangeSelect.value;
            const earliestInput = document.getElementById('earliest-time');
            const latestInput = document.getElementById('latest-time');
            if (!earliestInput || !latestInput) return; // Exit if inputs not found

            if (value) {
                if (value === 'rt') {
                    earliestInput.value = 'rt';
                    latestInput.value = 'rt';
                } else if (value.startsWith('@')) {
                    earliestInput.value = value;
                    latestInput.value = 'now';
                } else {
                    earliestInput.value = value;
                    latestInput.value = 'now';
                }
            }
        });
    }

    // Execute query button
    const executeButton = document.getElementById('execute-query-btn');
    if (executeButton) {
        executeButton.addEventListener('click', executeQuery);
    }

    // Clear results button
    const clearButton = document.getElementById('clear-results-btn');
    if (clearButton) {
        clearButton.addEventListener('click', clearResults);
    }
}

/**
 * Initialize datetime pickers
 */
function initDateTimePickers() {
    const earliestTimeBtn = document.getElementById('earliest-time-picker-btn');
    const earliestTimePicker = document.getElementById('earliest-time-picker');
    const earliestTimeClose = document.getElementById('earliest-time-picker-close');
    const earliestTimeApply = document.getElementById('earliest-time-apply');
    const earliestDate = document.getElementById('earliest-date');
    const earliestTimeInput = document.getElementById('earliest-time-input');
    const earliestRelative = document.getElementById('earliest-relative');
    const earliestTimeValue = document.getElementById('earliest-time'); // Target input field

    if (earliestTimeBtn && earliestTimePicker && earliestTimeValue && earliestDate && earliestTimeInput && earliestRelative && earliestTimeClose && earliestTimeApply) {
        earliestDate.valueAsDate = new Date(); // Set default date
        earliestTimeBtn.addEventListener('click', () => { earliestTimePicker.style.display = 'block'; });
        earliestTimeClose.addEventListener('click', () => { earliestTimePicker.style.display = 'none'; });
        earliestTimeApply.addEventListener('click', () => {
            const relativeValue = earliestRelative.value;
            if (relativeValue) {
                earliestTimeValue.value = relativeValue;
            } else {
                const dateValue = earliestDate.value;
                const timeValue = earliestTimeInput.value || '00:00:00';
                if (dateValue) {
                    earliestTimeValue.value = formatDateForSplunk(dateValue, timeValue);
                }
            }
            earliestTimePicker.style.display = 'none';
        });
    } else {
        console.warn("One or more earliest time picker elements not found.");
    }

    const latestTimeBtn = document.getElementById('latest-time-picker-btn');
    const latestTimePicker = document.getElementById('latest-time-picker');
    const latestTimeClose = document.getElementById('latest-time-picker-close');
    const latestTimeApply = document.getElementById('latest-time-apply');
    const latestDate = document.getElementById('latest-date');
    const latestTimeInput = document.getElementById('latest-time-input');
    const latestRelative = document.getElementById('latest-relative');
    const latestTimeValue = document.getElementById('latest-time'); // Target input field

    if (latestTimeBtn && latestTimePicker && latestTimeValue && latestDate && latestTimeInput && latestRelative && latestTimeClose && latestTimeApply) {
        latestDate.valueAsDate = new Date(); // Set default date
        latestTimeBtn.addEventListener('click', () => { latestTimePicker.style.display = 'block'; });
        latestTimeClose.addEventListener('click', () => { latestTimePicker.style.display = 'none'; });
        latestTimeApply.addEventListener('click', () => {
            const relativeValue = latestRelative.value;
            if (relativeValue) {
                latestTimeValue.value = relativeValue;
            } else {
                const dateValue = latestDate.value;
                const timeValue = latestTimeInput.value || '23:59:59'; // Default end of day
                if (dateValue) {
                    latestTimeValue.value = formatDateForSplunk(dateValue, timeValue);
                }
            }
            latestTimePicker.style.display = 'none';
        });
    } else {
        console.warn("One or more latest time picker elements not found.");
    }

    // Close pickers when clicking outside
    document.addEventListener('click', (event) => {
        if (earliestTimePicker && earliestTimeBtn && !earliestTimePicker.contains(event.target) && event.target !== earliestTimeBtn && !earliestTimeBtn.contains(event.target)) {
            earliestTimePicker.style.display = 'none';
        }
        if (latestTimePicker && latestTimeBtn && !latestTimePicker.contains(event.target) && event.target !== latestTimeBtn && !latestTimeBtn.contains(event.target)) {
            latestTimePicker.style.display = 'none';
        }
    });
}


/**
 * Format a date for Splunk
 * @param {string} dateStr - Date string in YYYY-MM-DD format
 * @param {string} timeStr - Time string in HH:MM:SS format
 * @returns {string} Formatted date string for Splunk (MM/DD/YYYY:HH:MM:SS)
 */
function formatDateForSplunk(dateStr, timeStr) {
    try {
        const date = new Date(dateStr + 'T00:00:00'); // Ensure local timezone is used for parsing date part
        if (isNaN(date.getTime())) { // Check for invalid date
             console.error("Invalid date string provided to formatDateForSplunk:", dateStr);
             return ''; // Return empty string or handle error appropriately
        }
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const day = String(date.getDate()).padStart(2, '0');
        const year = date.getFullYear();
        // Basic time validation (HH:MM:SS)
        if (!/^\d{2}:\d{2}:\d{2}$/.test(timeStr)) {
            console.warn("Invalid time string provided to formatDateForSplunk:", timeStr, "using 00:00:00");
            timeStr = '00:00:00';
        }
        return `${month}/${day}/${year}:${timeStr}`;
    } catch (e) {
        console.error("Error formatting date for Splunk:", e);
        return '';
    }
}

/**
 * Check URL parameters for pre-selecting domain and query
 */
function checkUrlParams() {
    const urlParams = new URLSearchParams(window.location.search);
    const domain = urlParams.get('domain');
    const query = urlParams.get('query');
    const earliest = urlParams.get('earliest');
    const latest = urlParams.get('latest');

    const domainSelect = document.getElementById('domain-select');
    const queryInput = document.getElementById('query-text');
    const earliestInput = document.getElementById('earliest-time');
    const latestInput = document.getElementById('latest-time');


    if (domain && domainSelect) {
        for (let i = 0; i < domainSelect.options.length; i++) {
            if (domainSelect.options[i].value === domain) {
                domainSelect.selectedIndex = i;
                currentDomain = domain;
                currentSessionId = domainSelect.options[i].getAttribute('data-session-id');
                const event = new Event('change'); // Trigger change to load history
                domainSelect.dispatchEvent(event);
                break;
            }
        }
    }
    if (query && queryInput) { queryInput.value = query; }
    if (earliest && earliestInput) { earliestInput.value = earliest; }
    if (latest && latestInput) { latestInput.value = latest; }
}


/**
 * Load recent query executions for the selected session
 * @param {string} sessionId - ID of the session
 */
async function loadRecentExecutions(sessionId) {
    if (!sessionId) return;

    const container = document.getElementById('recent-queries');
    if (!container) { console.error("Recent queries container not found."); return; }
    container.innerHTML = '<div class="spinner"></div><p>Loading recent execution history...</p>'; // Use spinner

    try {
        const response = await apiRequest(`/api/session/${sessionId}/query_executions`); // Assumes apiRequest is global

        if (response.status === 'success' && response.executions && Array.isArray(response.executions)) {
            const executions = response.executions;

            if (executions.length > 0) {
                let html = '<div class="recent-queries-list">';
                executions.slice(0, 5).forEach(execution => {
                    const statusClass = execution.status === 'completed' ? 'active' :
                                      execution.status === 'pending' || execution.status === 'running' ? 'pending' : 'inactive';
                    const statusTitle = execution.status ? execution.status.charAt(0).toUpperCase() + execution.status.slice(1) : 'Unknown';

                    const queryText = execution.query_text || 'No query text available';
                    const createdAt = execution.created_at ? formatDate(execution.created_at) : 'Unknown date'; // Assumes formatDate is global

                    html += `
                    <div class="recent-query">
                        <div class="recent-query-header">
                            <span class="status-indicator status-${statusClass}" title="${statusTitle}"></span>
                            <span class="date-format">${createdAt}</span>
                        </div>
                        <div class="recent-query-text" title="${escapeHTML(queryText)}">${escapeHTML(queryText)}</div>
                        <div class="recent-query-actions">
                            <a href="/query/execution/${execution.execution_id}" class="btn btn-sm">View Results</a>
                            <button class="btn btn-success btn-sm load-query-btn"
                                    data-query="${escapeHTML(queryText)}"
                                    data-earliest="${escapeHTML(execution.earliest_time || '')}"
                                    data-latest="${escapeHTML(execution.latest_time || '')}">Load Query</button>
                        </div>
                    </div>`;
                });
                html += '</div>';
                container.innerHTML = html;

                // Add event listeners after innerHTML is set
                container.querySelectorAll('.load-query-btn').forEach(button => {
                    button.addEventListener('click', () => {
                        const queryText = button.getAttribute('data-query');
                        const earliest = button.getAttribute('data-earliest');
                        const latest = button.getAttribute('data-latest');
                        const queryInput = document.getElementById('query-text');
                        const earliestInput = document.getElementById('earliest-time');
                        const latestInput = document.getElementById('latest-time');
                        if(queryInput) queryInput.value = queryText;
                        if(earliestInput) earliestInput.value = earliest;
                        if(latestInput) latestInput.value = latest;
                    });
                });
            } else {
                 container.innerHTML = '<p>No recent execution history for this session.</p>';
            }

        } else {
             console.error("Failed to load recent executions or invalid format:", response);
             container.innerHTML = `<p>Could not load recent execution history. ${response.message || ''}</p>`;
        }
    } catch (error) {
        console.error('Error loading recent executions:', error);
        container.innerHTML = '<p>Error loading recent execution history.</p>';
    }
}

/**
 * Execute a Splunk query
 */
async function executeQuery() {
    const domain = currentDomain;
    const queryInput = document.getElementById('query-text');
    const earliestInput = document.getElementById('earliest-time');
    const latestInput = document.getElementById('latest-time');

    if (!queryInput || !earliestInput || !latestInput) {
         showError("Query input fields not found."); return;
    }

    const query = queryInput.value.trim();
    const earliestTime = earliestInput.value.trim();
    const latestTime = latestInput.value.trim();

    if (!domain) { showError('Please select a domain'); return; }
    if (!query) { showError('Please enter a query'); return; }

    const loadingIndicator = document.getElementById('loading-indicator');
    const resultsContainer = document.getElementById('query-results');
    const errorContainer = document.getElementById('error-message');
    const executeButton = document.getElementById('execute-query-btn');

    if(loadingIndicator) loadingIndicator.style.display = 'block';
    if(resultsContainer) resultsContainer.style.display = 'none';
    if(errorContainer) errorContainer.style.display = 'none';
    if(executeButton) executeButton.disabled = true; // Disable button during execution

    try {
        const response = await apiRequest('/api/execute_query', {
            method: 'POST',
            body: JSON.stringify({
                domain,
                query,
                earliest_time: earliestTime || undefined,
                latest_time: latestTime || undefined
            })
        });

        displayQueryResults(response); // Display results whether success or failure reported by API

        if (currentSessionId && response.status === 'success') { // Only refresh history on success
            await loadRecentExecutions(currentSessionId);
        }
    } catch (error) {
        // Handle fetch/network errors
        displayQueryResults({ // Simulate an error response for display
             status: 'error',
             message: error.message || 'Network error or failed to reach API',
             execution_id: null,
             results: null
        });
    } finally {
        // Always re-enable button and hide spinner
        if(loadingIndicator) loadingIndicator.style.display = 'none';
        if(executeButton) executeButton.disabled = false;
    }
}

/**
 * Display query results
 * @param {Object} response - API response containing query results and execution_id
 */
function displayQueryResults(response) {
    const resultsContainer = document.getElementById('query-results');
    const resultStatus = document.getElementById('result-status');
    const resultExecutionId = document.getElementById('result-query-id'); // Using 'query-id' element for exec ID
    const resultTimestamp = document.getElementById('result-timestamp');
    const resultsData = document.getElementById('results-data');
    const errorContainer = document.getElementById('error-message');
    const errorText = document.getElementById('error-text');

    // Ensure all required elements exist
    if (!resultsContainer || !resultStatus || !resultExecutionId || !resultTimestamp || !resultsData || !errorContainer || !errorText) {
        console.error("One or more results display elements are missing from the DOM.");
        showError("UI Error: Cannot display results. Result elements missing."); // Show user feedback
        return;
    }

    errorContainer.style.display = 'none'; // Hide error initially
    resultsContainer.style.display = 'block'; // Show results container

    // Display Execution ID if available, regardless of success/failure
    if (response && response.execution_id) {
        resultExecutionId.textContent = `Execution ID: ${response.execution_id}`;
        resultExecutionId.style.display = 'block';
    } else {
        resultExecutionId.style.display = 'none'; // Hide if no ID
    }
    resultTimestamp.textContent = formatDate(new Date().toISOString()); // Timestamp of display

    if (response && response.status === 'success') {
        resultStatus.textContent = 'Completed';
        resultsData.innerHTML = ''; // Clear previous results/spinner

        const splunkResults = response.results;

        if (splunkResults && splunkResults.fields && splunkResults.rows && Array.isArray(splunkResults.fields) && Array.isArray(splunkResults.rows)) {
             if (splunkResults.rows.length > 0) {
                 const table = createEnhancedResultsTable(splunkResults.fields, splunkResults.rows);
                 resultsData.appendChild(table);
             } else {
                 resultsData.innerHTML = '<p>Query completed successfully, but returned 0 rows.</p>';
             }
        } else if (splunkResults !== null && splunkResults !== undefined) {
            resultsData.innerHTML = '<p>Query completed. Results format not recognized as table:</p>';
            if (typeof splunkResults === 'string') {
                resultsData.innerHTML += `<pre>${escapeHTML(splunkResults)}</pre>`;
            } else {
                resultsData.innerHTML += formatJSON(splunkResults);
            }
        } else {
             resultsData.innerHTML = '<p>Query completed successfully, but returned no results data.</p>';
        }
        addExportEventListeners(splunkResults); // Add export buttons for the results

    } else {
        // Handle API error response or other non-success status
        resultStatus.textContent = 'Failed';
        resultsData.innerHTML = ''; // Clear any previous results/spinner
        errorContainer.style.display = 'block';
        errorText.textContent = (response ? response.message : 'Unknown error') || 'Query execution failed.';
        addExportEventListeners(null); // Disable export buttons on failure
    }
}


/**
 * Create a table to display Splunk query results with enhanced functionality:
 * - Row numbering
 * - Pagination for large result sets
 * - Fixed headers when scrolling
 * - Dual horizontal scrollbars (top and bottom)
 * - Improved column width handling
 *
 * @param {Array} fields - Field names from Splunk results
 * @param {Array} rows - Data rows from Splunk results
 * @returns {HTMLElement} - Enhanced table container with the results
 */
function createEnhancedResultsTable(fields, rows) {
	// Create outer container for the table with pagination and controls
	const container = document.createElement('div');
	container.className = 'enhanced-results-container';

	// Set up pagination variables
	const rowsPerPageOptions = [25, 50, 100, 250, 500, 1000];
	let rowsPerPage = 100; // Default value
	let totalPages = Math.ceil(rows.length / rowsPerPage);
	let currentPage = 1;

	// Create pagination controls
	const paginationContainer = document.createElement('div');
	paginationContainer.className = 'pagination-controls';

	// Add pagination info
	const paginationInfo = document.createElement('div');
	paginationInfo.className = 'pagination-info';
	paginationContainer.appendChild(paginationInfo);

	// Add pagination buttons
	const paginationButtons = document.createElement('div');
	paginationButtons.className = 'pagination-buttons';

	// First page button
	const firstPageBtn = document.createElement('button');
	firstPageBtn.innerHTML = '«';
	firstPageBtn.className = 'pagination-btn';
	firstPageBtn.title = 'First Page';
	firstPageBtn.addEventListener('click', () => {
		if (currentPage > 1) {
			currentPage = 1;
			renderTablePage(currentPage);
		}
	});
	paginationButtons.appendChild(firstPageBtn);

	// Previous page button
	const prevPageBtn = document.createElement('button');
	prevPageBtn.innerHTML = '‹';
	prevPageBtn.className = 'pagination-btn';
	prevPageBtn.title = 'Previous Page';
	prevPageBtn.addEventListener('click', () => {
		if (currentPage > 1) {
			currentPage--;
			renderTablePage(currentPage);
		}
	});
	paginationButtons.appendChild(prevPageBtn);

	// Page number input and display
	const pageNumberContainer = document.createElement('div');
	pageNumberContainer.className = 'page-number-container';

	const pageNumberInput = document.createElement('input');
	pageNumberInput.type = 'number';
	pageNumberInput.min = 1;
	pageNumberInput.max = totalPages > 0 ? totalPages : 1; // Ensure max is at least 1
	pageNumberInput.value = currentPage;
	pageNumberInput.className = 'page-number-input';
	pageNumberInput.addEventListener('change', () => {
		let newPage = parseInt(pageNumberInput.value, 10);
		if (isNaN(newPage)) newPage = 1;
		if (newPage < 1) newPage = 1;
		if (newPage > totalPages) newPage = totalPages;
        if (totalPages === 0) newPage = 1; // Handle case with 0 rows

		currentPage = newPage;
		pageNumberInput.value = currentPage;
		renderTablePage(currentPage);
	});

	const pageCount = document.createElement('span');
	pageCount.className = 'page-count';
	pageCount.textContent = ` / ${totalPages > 0 ? totalPages : 1}`; // Display 1 if 0 pages

	pageNumberContainer.appendChild(pageNumberInput);
	pageNumberContainer.appendChild(pageCount);
	paginationButtons.appendChild(pageNumberContainer);

	// Next page button
	const nextPageBtn = document.createElement('button');
	nextPageBtn.innerHTML = '›';
	nextPageBtn.className = 'pagination-btn';
	nextPageBtn.title = 'Next Page';
	nextPageBtn.addEventListener('click', () => {
		if (currentPage < totalPages) {
			currentPage++;
			renderTablePage(currentPage);
		}
	});
	paginationButtons.appendChild(nextPageBtn);

	// Last page button
	const lastPageBtn = document.createElement('button');
	lastPageBtn.innerHTML = '»';
	lastPageBtn.className = 'pagination-btn';
	lastPageBtn.title = 'Last Page';
	lastPageBtn.addEventListener('click', () => {
		if (currentPage < totalPages) {
			currentPage = totalPages;
			renderTablePage(currentPage);
		}
	});
	paginationButtons.appendChild(lastPageBtn);

	// Rows per page selector
	const rowsPerPageContainer = document.createElement('div');
	rowsPerPageContainer.className = 'rows-per-page';

	const rowsPerPageLabel = document.createElement('label');
	rowsPerPageLabel.textContent = 'Rows per page: ';
    rowsPerPageLabel.htmlFor = 'rows-per-page-select-id'; // Added for accessibility

	const rowsPerPageSelect = document.createElement('select');
	rowsPerPageSelect.className = 'rows-per-page-select';
    rowsPerPageSelect.id = 'rows-per-page-select-id'; // Added for accessibility

	rowsPerPageOptions.forEach(value => {
		const option = document.createElement('option');
		option.value = value;
		option.textContent = value;
		if (value === rowsPerPage) {
			option.selected = true;
		}
		rowsPerPageSelect.appendChild(option);
	});

	rowsPerPageSelect.addEventListener('change', () => {
		const newRowsPerPage = parseInt(rowsPerPageSelect.value, 10);
		const currentTopRow = (currentPage - 1) * rowsPerPage + 1;

		// Calculate new page to keep approximately the same position
        totalPages = Math.ceil(rows.length / newRowsPerPage); // Recalculate total pages first
        if (totalPages === 0) totalPages = 1; // Ensure totalPages is at least 1

		const newCurrentPage = Math.max(1, Math.min(totalPages, Math.ceil(currentTopRow / newRowsPerPage)));

		// Update variables
		rowsPerPage = newRowsPerPage;
		currentPage = newCurrentPage;
		pageCount.textContent = ` / ${totalPages}`;
        pageNumberInput.max = totalPages; // Update max value for input

		// Render new page
		renderTablePage(currentPage);
	});

	rowsPerPageContainer.appendChild(rowsPerPageLabel);
	rowsPerPageContainer.appendChild(rowsPerPageSelect);

	// Create the table container wrapper for dual scrollbars
	const tableContainerWrapper = document.createElement('div');
	tableContainerWrapper.className = 'table-container-wrapper';

	// Create top horizontal scrollbar
	const topScrollContainer = document.createElement('div');
	topScrollContainer.className = 'horizontal-scroll-container';
	const topScrollContent = document.createElement('div');
	topScrollContent.className = 'horizontal-scroll-content';
	topScrollContainer.appendChild(topScrollContent);

	// Create table wrapper
	const tableWrapper = document.createElement('div');
	tableWrapper.className = 'table-wrapper';

	// Create table element
	const table = document.createElement('table');
	table.className = 'results-table';

	// Create header row
	const thead = document.createElement('thead');
	const headerRow = document.createElement('tr');

	// Add row number header
	const rowNumHeader = document.createElement('th');
	rowNumHeader.textContent = '#';
	rowNumHeader.className = 'row-number-cell';
	headerRow.appendChild(rowNumHeader);

	// Add field headers
	fields.forEach(field => {
		const th = document.createElement('th');
		th.textContent = (typeof field === 'object' && field !== null && field.name) ? field.name : String(field); // Handle null fields
		headerRow.appendChild(th);
	});

	thead.appendChild(headerRow);
	table.appendChild(thead);

	// Function to render table rows for current page
	function renderTablePage(page) {
		// Clear existing tbody if present
		const existingTbody = table.querySelector('tbody');
		if (existingTbody) {
			table.removeChild(existingTbody);
		}

		// Create table body
		const tbody = document.createElement('tbody');

		// Calculate start and end indexes for the current page
		const startIndex = (page - 1) * rowsPerPage;
		const endIndex = Math.min(startIndex + rowsPerPage, rows.length);

		// Add data rows for the current page
		for (let i = startIndex; i < endIndex; i++) {
			const rowData = rows[i]; // Assuming row is an array of cell values
            if (!Array.isArray(rowData)) {
                 console.warn(`Row at index ${i} is not an array:`, rowData);
                 continue; // Skip non-array rows
            }
			const tr = document.createElement('tr');

			// Add row number cell
			const rowNumCell = document.createElement('td');
			rowNumCell.textContent = (i + 1).toString();
			rowNumCell.className = 'row-number-cell';
			tr.appendChild(rowNumCell);

			// Add data cells - ensure we match the number of headers (excluding row number)
			for (let j = 0; j < fields.length; j++) {
                const cell = rowData[j]; // Get cell data by index
				const td = document.createElement('td');

				// Format cell content based on type
				if (cell === null || cell === undefined) {
					td.innerHTML = '<em>null</em>';
					td.className = 'cell-null';
				} else if (typeof cell === 'object') {
					td.innerHTML = formatJSON(cell); // Assumes formatJSON is global
					td.className = 'cell-object';
				} else if (typeof cell === 'boolean') {
					td.textContent = cell.toString();
					td.className = 'cell-boolean';
				} else if (!isNaN(cell) && typeof cell === 'number') {
					td.textContent = cell.toLocaleString(); // Add locale formatting for numbers
					td.className = 'cell-number';
				} else if (typeof cell === 'string' && (cell.startsWith('{') || cell.startsWith('['))) {
					// Try to parse JSON strings
					try {
						const parsed = JSON.parse(cell);
						td.innerHTML = formatJSON(parsed); // Assumes formatJSON is global
						td.className = 'cell-json';
					} catch (e) {
						td.textContent = cell; // Display as string if parsing fails
					}
				} else {
					td.textContent = cell; // Default to string representation
				}

				tr.appendChild(td);
			} // End cell loop

			tbody.appendChild(tr);
		} // End row loop

		table.appendChild(tbody);

		// Update pagination UI
		updatePaginationUI(page);

		// After rendering, synchronize scrollbars and adjust column widths
		// Use requestAnimationFrame for smoother updates after layout changes
		requestAnimationFrame(() => {
			synchronizeScrollbars();
			adjustColumnWidths();
		});
	}

	// Function to update pagination UI
	function updatePaginationUI(page) {
		// Calculate the range of rows being displayed
		const startRow = rows.length === 0 ? 0 : (page - 1) * rowsPerPage + 1;
		const endRow = Math.min(page * rowsPerPage, rows.length);

		// Update pagination info
		paginationInfo.textContent = `Showing ${startRow} to ${endRow} of ${rows.length} rows`;

		// Update pagination buttons state
		firstPageBtn.disabled = page <= 1; // Use <= 1 for robustness
		prevPageBtn.disabled = page <= 1;
		nextPageBtn.disabled = page >= totalPages; // Use >= totalPages
		lastPageBtn.disabled = page >= totalPages;

		// Update page number input
		pageNumberInput.value = page;
		pageNumberInput.disabled = totalPages <= 1; // Disable if only one page
	}

	// Function to synchronize horizontal scrollbars
	function synchronizeScrollbars() {
        // Debounce or throttle might be useful here if performance is an issue
        requestAnimationFrame(() => {
            const tableWidth = table.offsetWidth;
            topScrollContent.style.width = `${tableWidth}px`;

            // Only attach listeners once or remove previous ones
            const syncScroll = (event) => {
                 if (event.target === topScrollContainer) {
                     tableWrapper.scrollLeft = topScrollContainer.scrollLeft;
                 } else if (event.target === tableWrapper) {
                     topScrollContainer.scrollLeft = tableWrapper.scrollLeft;
                 }
            };

            topScrollContainer.removeEventListener('scroll', syncScroll);
            tableWrapper.removeEventListener('scroll', syncScroll);

            topScrollContainer.addEventListener('scroll', syncScroll, { passive: true });
            tableWrapper.addEventListener('scroll', syncScroll, { passive: true });

            // Initial sync in case widths changed
            tableWrapper.scrollLeft = topScrollContainer.scrollLeft;
        });
	}

	// Function to adjust column widths based on content (using double-click)
	function adjustColumnWidths() {
		const headers = table.querySelectorAll('th:not(.row-number-cell)');
		headers.forEach((header) => {
            // Remove previous listener if any to prevent duplicates
            header.ondblclick = null; // Simple way to remove previous inline handler if set

			// Double-click to expand/collapse column
			header.ondblclick = function() { // Use function declaration for 'this' context
				if (this.dataset.expanded === 'true') {
					// Collapse back to default (remove inline styles)
					this.style.width = '';
					this.style.minWidth = '';
					this.dataset.expanded = 'false';
                    this.title = 'Double-click to expand'; // Update title
				} else {
					// Expand to fit longest content
					const columnIndex = Array.from(this.parentNode.children).indexOf(this);
					if (columnIndex < 0) return; // Should not happen

                    const cells = table.querySelectorAll(`tbody tr td:nth-child(${columnIndex + 1})`);
					let maxContent = this.textContent?.length || 0; // Use optional chaining

					cells.forEach(cell => {
						const content = cell.textContent || '';
						if (content.length > maxContent) {
							maxContent = content.length;
						}
					});

                    // Estimate width (adjust multiplier and padding as needed)
					const charWidthEstimate = 8; // Average char width guess
                    const padding = 24; // Cell padding + borders
					const estimatedWidth = Math.max(this.offsetWidth, maxContent * charWidthEstimate + padding);
                    const maxWidth = 600; // Limit max expansion width

					const finalWidth = Math.min(maxWidth, estimatedWidth);

					this.style.width = `${finalWidth}px`;
					this.style.minWidth = `${finalWidth}px`; // Use minWidth too
					this.dataset.expanded = 'true';
                    this.title = 'Double-click to collapse'; // Update title
				}

				// After adjusting width, update the top scrollbar size
				synchronizeScrollbars();
			};
             // Initial title
             header.title = 'Double-click to expand/collapse';
		});

		// Add a tooltip (only once)
        if (!tableWrapper.querySelector('.column-tooltip')) {
            const tooltip = document.createElement('div');
            tooltip.className = 'column-tooltip';
            tooltip.textContent = 'Double-click column headers to expand/collapse';
            tooltip.style.cssText = 'position: absolute; top: -25px; right: 5px; font-size: 11px; color: #666; padding: 2px 5px; background-color: #f0f0f0; border-radius: 3px; opacity: 0.8; z-index: 5; display:none; transition: opacity 0.3s; pointer-events: none;';
            tableWrapper.appendChild(tooltip);

            // Show tooltip on hover over header row
            thead.addEventListener('mouseenter', () => { tooltip.style.display = 'block'; });
            thead.addEventListener('mouseleave', () => { tooltip.style.display = 'none'; });
        }


		// Ensure the top scrollbar is properly sized initially
		synchronizeScrollbars();
	}

	// Assemble the components
	paginationContainer.appendChild(paginationInfo);
	paginationContainer.appendChild(paginationButtons);
	paginationContainer.appendChild(rowsPerPageContainer);

	container.appendChild(paginationContainer);

	tableContainerWrapper.appendChild(topScrollContainer);
	tableContainerWrapper.appendChild(tableWrapper);
	tableWrapper.appendChild(table);
	container.appendChild(tableContainerWrapper);

	// Add result count to the footer
	const footer = document.createElement('div');
	footer.className = 'results-footer';
	footer.textContent = `${rows.length} result${rows.length !== 1 ? 's' : ''}`;
	container.appendChild(footer);

	// Render the first page
	renderTablePage(1);

	return container;
}


/**
 * Add event listeners for exporting results
 * @param {Object|Array|string|null} results - Query results
 */
function addExportEventListeners(results) {
    let exportContainer = document.getElementById('export-options-container'); // Use a dedicated container ID

    // Create container if it doesn't exist within the results area
    if (!exportContainer && document.getElementById('query-results')) {
        exportContainer = document.createElement('div');
        exportContainer.id = 'export-options-container';
        exportContainer.className = 'export-options'; // Use existing class for styling
        exportContainer.innerHTML = `
            <button id="export-json-btn" class="btn">Export JSON</button>
            <button id="export-csv-btn" class="btn">Export CSV</button>
            <button id="copy-results-btn" class="btn">Copy to Clipboard</button>
        `;
        // Insert after results metadata or at the start of results data area
        const resultsMeta = document.getElementById('results-metadata'); // Assuming you have this element
        if (resultsMeta && resultsMeta.parentNode) {
             resultsMeta.parentNode.insertBefore(exportContainer, resultsMeta.nextSibling);
        } else if (document.getElementById('results-data')) {
             document.getElementById('results-data').parentNode?.insertBefore(exportContainer, document.getElementById('results-data'));
        }
    }

    const exportJsonBtn = document.getElementById('export-json-btn');
    const exportCsvBtn = document.getElementById('export-csv-btn');
    const copyResultsBtn = document.getElementById('copy-results-btn');

    // JSON Export
    if (exportJsonBtn) {
        const canExportJson = results !== null && results !== undefined;
        exportJsonBtn.disabled = !canExportJson;
        exportJsonBtn.onclick = canExportJson ? () => {
            exportData(results, 'splunk_query_results.json', 'application/json'); // Assumes exportData global
        } : null;
    }

    // CSV Export
    if (exportCsvBtn) {
        const isTableData = results && results.fields && Array.isArray(results.fields) && results.rows && Array.isArray(results.rows);
        exportCsvBtn.disabled = !isTableData;
        exportCsvBtn.title = isTableData ? "" : "CSV export only available for table-formatted results";
        exportCsvBtn.onclick = isTableData ? () => {
            const fieldNames = results.fields.map(field => (typeof field === 'object' && field !== null) ? field.name : String(field));
            const csvContent = [
                fieldNames.map(name => `"${String(name).replace(/"/g, '""')}"`).join(','),
                ...results.rows.map(row =>
                    row.map(cell => {
                        if (cell === null || cell === undefined) return '';
                        let value = (typeof cell === 'object') ? JSON.stringify(cell) : String(cell);
                        // Quote if necessary
                        if (/[",\n\r]/.test(value)) {
                            return `"${value.replace(/"/g, '""')}"`;
                        }
                        return value;
                    }).join(',')
                )
            ].join('\n');
            exportData(csvContent, 'splunk_query_results.csv', 'text/csv;charset=utf-8;'); // Assumes exportData global
        } : null;
    }

    // Copy to Clipboard
    if (copyResultsBtn) {
        const canCopy = results !== null && results !== undefined;
        copyResultsBtn.disabled = !canCopy;
        copyResultsBtn.onclick = canCopy ? async () => {
            let text;
            const isTableData = results && results.fields && Array.isArray(results.fields) && results.rows && Array.isArray(results.rows);
            if (isTableData) {
                const fieldNames = results.fields.map(field => (typeof field === 'object' && field !== null) ? field.name : String(field));
                text = [
                    fieldNames.join('\t'), // Use Tab for clipboard friendliness
                    ...results.rows.map(row =>
                        row.map(cell => {
                            if (cell === null || cell === undefined) return '';
                            // Replace newline/tab characters within cell data
                            return String(cell).replace(/[\n\r\t]/g, ' ');
                        }).join('\t')
                    )
                ].join('\n');
            } else {
                text = typeof results === 'string' ? results : JSON.stringify(results, null, 2); // Pretty print JSON
            }
            const success = await copyToClipboard(text); // Assumes copyToClipboard global
            if (success) {
                showSuccess('Results copied to clipboard'); // Assumes showSuccess global
            } else {
                showError('Failed to copy results'); // Assumes showError global
            }
        } : null;
    }
}


/**
 * Clear query results display area
 */
function clearResults() {
    const resultsContainer = document.getElementById('query-results');
    const errorContainer = document.getElementById('error-message');
    const resultsData = document.getElementById('results-data');
    const errorText = document.getElementById('error-text');
    const exportContainer = document.getElementById('export-options-container');

    if(resultsContainer) resultsContainer.style.display = 'none';
    if(errorContainer) errorContainer.style.display = 'none';
    if(resultsData) resultsData.innerHTML = '';
    if(errorText) errorText.textContent = '';
    // Optionally remove or hide export buttons when clearing
    if (exportContainer) exportContainer.innerHTML = ''; // Or hide it: exportContainer.style.display = 'none';
}


// --- Add CSS ---
(function() {
    // Prevent adding styles multiple times if script is re-executed
    if (document.getElementById('splunkvoyager-query-styles')) return;

    const style = document.createElement('style');
    style.id = 'splunkvoyager-query-styles';
    style.textContent = `
        /* Recent Queries Styles */
        .recent-queries-list {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }
        .recent-query {
            background-color: #fff;
            border-radius: 5px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            padding: 1rem;
            display: flex;
            flex-direction: column;
            border: 1px solid #e9ecef;
        }
        .recent-query-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.75rem;
            font-size: 0.85rem;
            color: #6c757d;
        }
        .recent-query-header .status-indicator { margin-right: 5px; }
        .recent-query-text {
            font-family: Menlo, Monaco, Consolas, "Courier New", monospace;
            font-size: 0.875rem;
            background-color: #f8f9fa;
            padding: 0.5rem 0.75rem;
            border-radius: 4px;
            margin-bottom: 0.75rem;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            cursor: help;
            border: 1px solid #e9ecef;
            flex-grow: 1; /* Allow text area to grow */
        }
        .recent-query-actions {
            display: flex;
            gap: 0.5rem;
            margin-top: auto; /* Push actions to bottom */
        }
        .recent-query-actions .btn { font-size: 0.8rem; padding: 3px 8px;}

        /* Results Area Styles */
        #query-results {
            margin-top: 1.5rem;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 1.25rem;
            background-color: #ffffff;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
        }
        .results-metadata {
            margin-bottom: 1rem;
            font-size: 0.9em;
            color: #6c757d;
            display: flex;
            flex-wrap: wrap;
            gap: 1rem;
            padding-bottom: 0.75rem;
            border-bottom: 1px solid #e9ecef;
        }
        #results-data { margin-top: 1rem; }
        #loading-indicator { text-align: center; padding: 2rem; display: none; }
        #error-message { display: none; /* Handled by error message styling in main.js */ }
        .export-options { display: flex; flex-wrap: wrap; gap: 0.75rem; margin-top: 1rem; padding-top: 1rem; border-top: 1px solid #e9ecef;}

        /* Enhanced Table Styles */
        .enhanced-results-container { margin-top: 1rem; }
        .pagination-controls { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; flex-wrap: wrap; gap: 0.75rem; padding: 0.5rem; background-color: #f8f9fa; border-radius: 4px; border: 1px solid #e9ecef; }
        .pagination-info { font-size: 0.85em; color: #495057; }
        .pagination-buttons { display: flex; align-items: center; gap: 0.3rem; }
        .pagination-btn { padding: 4px 8px; font-size: 0.9em; border: 1px solid #ced4da; background-color: #fff; border-radius: 3px; cursor: pointer; transition: background-color 0.2s; }
        .pagination-btn:hover:not(:disabled) { background-color: #e9ecef; }
        .pagination-btn:disabled { opacity: 0.5; cursor: not-allowed; }
        .page-number-container { display: flex; align-items: center; gap: 0.3rem; }
        .page-number-input { width: 55px; text-align: center; padding: 4px; font-size: 0.9em; border: 1px solid #ced4da; border-radius: 3px; }
        .page-count { font-size: 0.9em; color: #6c757d; }
        .rows-per-page { display: flex; align-items: center; gap: 0.4rem; font-size: 0.85em; color: #495057; }
        .rows-per-page label { margin-bottom: 0; } /* Align label */
        .rows-per-page-select { padding: 4px; font-size: 0.9em; border: 1px solid #ced4da; border-radius: 3px; }
        .table-container-wrapper { position: relative; }
        .horizontal-scroll-container { overflow-x: auto; overflow-y: hidden; height: 18px; margin-bottom: -1px; background-color: #f1f3f5; border-radius: 3px; }
        .horizontal-scroll-content { height: 1px; }
        .table-wrapper { max-height: 65vh; /* Adjust max height */ overflow: auto; border: 1px solid #dee2e6; border-radius: 4px; }
        .results-table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
        .results-table thead { position: sticky; top: 0; z-index: 2; } /* Sticky header */
        .results-table th { background-color: #e9ecef; border: 1px solid #ced4da; padding: 0.6rem 0.75rem; text-align: left; font-weight: 600; white-space: nowrap; user-select: none; cursor: default; }
        .results-table th:not(.row-number-cell):hover { background-color: #dde2e6; } /* Hover effect */
        .results-table th.row-number-cell { width: 45px; text-align: center; position: sticky; left: 0; z-index: 1; background-color: #e9ecef; } /* Sticky row number */
        .results-table td { border: 1px solid #dee2e6; padding: 0.5rem 0.75rem; white-space: nowrap; max-width: 450px; overflow: hidden; text-overflow: ellipsis; background-color: #fff; /* Ensure TD background covers underlying sticky TH */ }
        .results-table td.row-number-cell { text-align: center; position: sticky; left: 0; z-index: 1; background-color: #f8f9fa; color: #6c757d; font-weight: 500; } /* Sticky row number */
        .results-table tbody tr:nth-child(even) td { background-color: #f8f9fa; }
        .results-table tbody tr:nth-child(even) td.row-number-cell { background-color: #f1f3f5; } /* Slightly different for even rows */
        .results-table tbody tr:hover td { background-color: #e9ecef; }
        .results-table tbody tr:hover td.row-number-cell { background-color: #dde2e6; }
        .cell-number { text-align: right; }
        .cell-boolean { text-align: center; }
        .cell-null { color: #adb5bd; font-style: italic; }
        .cell-object, .cell-json { font-family: Menlo, Monaco, Consolas, "Courier New", monospace; white-space: pre-wrap; font-size: 0.8em; max-width: 600px; }
        .results-footer { margin-top: 0.75rem; font-size: 0.85em; color: #6c757d; text-align: right; }
        .column-tooltip { /* Styles defined inline in JS, but can be moved here */ }

        /* Datetime Picker Styles */
        .time-picker-popup { display: none; position: absolute; background-color: #fff; border: 1px solid #ccc; box-shadow: 0 4px 8px rgba(0,0,0,0.15); z-index: 1000; padding: 15px; border-radius: 4px; width: 300px; }
        .time-picker-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
        .time-picker-header h4 { margin: 0; font-size: 1.1em; }
        .time-picker-close { background: none; border: none; font-size: 1.5em; cursor: pointer; padding: 0 5px; }
        .time-picker-section { margin-bottom: 15px; }
        .time-picker-section label { display: block; margin-bottom: 5px; font-weight: bold; font-size: 0.9em; }
        .time-picker-section input[type="date"], .time-picker-section input[type="time"], .time-picker-section select { width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 3px; font-size: 0.9em; }
        .time-picker-buttons { text-align: right; }
    `;
    document.head.appendChild(style);
})();