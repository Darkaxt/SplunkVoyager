// execution_detail.js

// Get global config and results data
const config = window.executionDetailConfig || {};
// queryResultsData is already defined in the template

document.addEventListener('DOMContentLoaded', function() {
    // Format dates (Assume formatDate is global)
    document.querySelectorAll('.date-format').forEach(element => {
        const dateString = element.textContent.trim();
        if (dateString && dateString !== '-') {
            try { element.textContent = formatDate(dateString); }
            catch(e) { console.error("Error formatting date:", dateString, e); }
        }
    });

    // Re-run query button
    const rerunButton = document.getElementById('rerun-query-btn');
    if (rerunButton) {
        rerunButton.addEventListener('click', async (event) => {
            event.preventDefault();

            // Get needed data from button attributes or config
            const definitionId = rerunButton.getAttribute('data-definition-id') || config.definitionId;
            const domain = rerunButton.getAttribute('data-domain') || config.domain;

            if (!definitionId || !domain) {
                showError('Missing data required to re-run query (Definition ID or Domain). Check button attributes.');
                return;
            }

            if (!confirm('Are you sure you want to re-run this query and refresh its cached results?')) {
                return;
            }

            rerunButton.disabled = true;
            rerunButton.textContent = 'Refreshing...';
            const originalText = 'Re-run Query';

            try {
                const response = await apiRequest(`/api/query/definition/${definitionId}/rerun`, {
                    method: 'POST',
                    body: JSON.stringify({ domain: domain })
                });

                if (response.status === 'success') {
                    showSuccess(`Query Definition ${definitionId} refresh initiated. Results updated.`);
                    setTimeout(() => window.location.reload(), 1500);
                } else if (response.status === 'pending') {
                    showWarning(response.message || `Query Definition ${definitionId} refresh is already in progress.`);
                } else {
                    showError(response.message || `Failed to re-run query definition ${definitionId}.`);
                }
            } catch (error) {
                showError(error.message || `Error occurred while trying to re-run query definition ${definitionId}.`);
            } finally {
                rerunButton.disabled = false;
                rerunButton.textContent = originalText;
            }
        });
    }

    // Delete execution button
    const deleteButton = document.getElementById('delete-execution-btn');
    if (deleteButton) {
        deleteButton.addEventListener('click', async () => {
            const executionId = deleteButton.getAttribute('data-execution-id') || config.executionId;
            if (!confirm('Are you sure you want to delete this query execution record?')) {
                return;
            }
            if (!executionId) {
                showError('Execution ID not found.');
                return;
            }
            try {
                deleteButton.disabled = true;
                const response = await apiRequest(`/api/query/execution/${executionId}/delete`, { method: 'POST' });
                if (response.status === 'success') {
                    showSuccess('Query execution deleted successfully');
                    // Redirect to the session detail page
                    window.location.href = config.sessionDetailUrl;
                } else {
                    showError(response.message || 'Failed to delete execution');
                    deleteButton.disabled = false;
                }
            } catch (error) {
                showError(error.message || 'Failed to delete execution');
                deleteButton.disabled = false;
            }
        });
    }

    // Display query results
    const resultsContainer = document.getElementById('results-data');
    const loadingSpinner = document.getElementById('results-loading');
    const exportButtonsContainer = document.getElementById('export-options-container');

    if (resultsContainer && loadingSpinner) {
        loadingSpinner.style.display = 'block';
        setTimeout(() => {
            try {
                const results = queryResultsData; // Use global variable
                resultsContainer.innerHTML = '';

                if (results === null || results === undefined) {
                    resultsContainer.innerHTML = '<p>No results data available for this execution.</p>';
                    if (exportButtonsContainer) exportButtonsContainer.style.display = 'none';
                } else {
                    if (results && results.fields && Array.isArray(results.fields) && results.rows && Array.isArray(results.rows)) {
                        if (results.rows.length > 0) {
                            const table = createEnhancedResultsTable(results.fields, results.rows);
                            resultsContainer.appendChild(table);
                        } else {
                            resultsContainer.innerHTML = '<p>Query completed successfully, but returned 0 rows.</p>';
                        }
                    } else if (results && typeof results === 'object') {
                        resultsContainer.innerHTML = formatJSON(results);
                    } else {
                        resultsContainer.innerHTML = `<pre>${escapeHTML(String(results))}</pre>`;
                    }
                    if (exportButtonsContainer) exportButtonsContainer.style.display = 'flex';
                    setupExportButtons(results);
                }
            } catch (e) {
                console.error('Error displaying results:', e);
                resultsContainer.innerHTML = `<div class="error-message">Error displaying results: ${escapeHTML(e.message)}</div>`;
                if (exportButtonsContainer) exportButtonsContainer.style.display = 'none';
                setupExportButtons(null);
            }
        }, 10);
    } else {
        if (exportButtonsContainer) exportButtonsContainer.style.display = 'none';
    }
});

// --- Helper Functions ---

/**
 * Create an enhanced table with pagination, scrolling, controlled wrapping,
 * and double-click column resizing.
 * @param {Array<string|{name: string}>} fields - Array of field names or objects with a 'name' property.
 * @param {Array<Array<any>>} rows - Array of arrays representing the data rows.
 * @returns {HTMLElement} - The container element holding the table and controls.
 */
function createEnhancedResultsTable(fields, rows) {
    // --- Configuration ---
    const rowsPerPageOptions = [25, 50, 100, 250, 500, 1000];
    const initialRowsPerPage = 100;
    const minLineLengthForManualBreak = 100; // Min characters before inserting <br>

    // --- State Variables ---
    let rowsPerPage = initialRowsPerPage;
    let totalPages = Math.ceil(rows.length / rowsPerPage);
    if (totalPages === 0) totalPages = 1;
    let currentPage = 1;

    // --- Create Main Container Elements ---
    const container = document.createElement('div');
    container.className = 'enhanced-results-container';

    const tableContainerWrapper = document.createElement('div');
    tableContainerWrapper.className = 'table-container-wrapper';

    const topScrollContainer = document.createElement('div');
    topScrollContainer.className = 'horizontal-scroll-container';
    const topScrollContent = document.createElement('div');
    topScrollContent.className = 'horizontal-scroll-content';
    topScrollContainer.appendChild(topScrollContent);

    const tableWrapper = document.createElement('div');
    tableWrapper.className = 'table-wrapper';

    const table = document.createElement('table');
    table.className = 'results-table';

    // --- Create Table Header (thead) ---
    const thead = document.createElement('thead');
    const headerRow = document.createElement('tr');
    const rowNumHeader = document.createElement('th');
    rowNumHeader.textContent = '#';
    rowNumHeader.className = 'row-number-cell';
    headerRow.appendChild(rowNumHeader);

    fields.forEach((field, index) => {
        const th = document.createElement('th');
        const fieldName = (typeof field === 'object' && field !== null && field.name) ? field.name : String(field);
        th.textContent = fieldName;
        // Apply styles based on column index if needed (e.g., for MDR_UUID min-width)
        // Example: If using nth-child CSS for min-width, no JS needed here.
        // If using classes:
        // if (index + 1 === 1) { th.classList.add('header-mdr-uuid'); }
        headerRow.appendChild(th);
    });
    thead.appendChild(headerRow);
    table.appendChild(thead);

    // --- Render Table Page Function ---
    function renderTablePage(page) {
        // Clear existing tbody
        const existingTbody = table.querySelector('tbody');
        if (existingTbody) table.removeChild(existingTbody);

        const tbody = document.createElement('tbody');
        const startIndex = (page - 1) * rowsPerPage;
        const endIndex = Math.min(startIndex + rowsPerPage, rows.length);

        for (let i = startIndex; i < endIndex; i++) {
            const rowData = rows[i];
            if (!Array.isArray(rowData)) {
                console.warn(`Row data at index ${i} is not an array, skipping.`);
                continue;
            }

            const tr = document.createElement('tr');

            // Add Row Number Cell
            const rowNumCell = document.createElement('td');
            rowNumCell.textContent = (i + 1).toString();
            rowNumCell.className = 'row-number-cell';
            tr.appendChild(rowNumCell);

            // Add Data Cells
            for (let j = 0; j < fields.length; j++) {
                 if (j >= rowData.length) {
                    const emptyTd = document.createElement('td');
                    tr.appendChild(emptyTd);
                    continue;
                 }

                const fieldInfo = fields[j];
                const fieldName = (typeof fieldInfo === 'object' && fieldInfo !== null && fieldInfo.name) ? fieldInfo.name : String(fieldInfo);
                const cellData = rowData[j];
                const td = document.createElement('td');

                let isFormatted = false; // Flag

                // --- Handle specific types FIRST (null, bool, number, JSON/Object) ---
                if (cellData === null || cellData === undefined) {
                    td.innerHTML = '<em>null</em>'; td.className = 'cell-null'; isFormatted = true;
                } else if (typeof cellData === 'boolean') {
                    td.textContent = cellData.toString(); td.className = 'cell-boolean'; isFormatted = true;
                } else if (typeof cellData === 'number') {
                    td.textContent = cellData.toLocaleString(); td.className = 'cell-number'; isFormatted = true;
                } else if (typeof cellData === 'object' || (typeof cellData === 'string' && (cellData.trim().startsWith('{') || cellData.trim().startsWith('[')))) {
                    try {
                        const jsonData = (typeof cellData === 'string') ? JSON.parse(cellData.trim()) : cellData;
                        td.innerHTML = formatJSON(jsonData); // Assumes formatJSON returns <pre>
                        td.className = (Array.isArray(jsonData)) ? 'cell-json' : 'cell-object';
                        isFormatted = true;
                    } catch(e) { console.warn("Failed to parse/format potential JSON cell:", cellData, e); }
                }
                // --- END Specific Type Logic ---


                // --- Handle regular strings AND apply manual line breaking ---
                if (!isFormatted) {
                    const cellText = String(cellData);
                    td.classList.add('cell-string'); // Add generic string class

                    // Add specific class if needed for styling (instead of nth-child)
                    if (j === 0) { td.classList.add('cell-mdr-uuid'); } // Example

                    // Apply manual line breaking
                    if (cellText.length > minLineLengthForManualBreak && cellText.includes(' ')) {
                        let resultHtml = '';
                        let currentIndex = 0;
                        const escapedText = escapeHTML(cellText);

                        while (currentIndex < escapedText.length) {
                            let searchBreakIndex = currentIndex + minLineLengthForManualBreak;
                            if (searchBreakIndex >= escapedText.length) {
                                resultHtml += escapedText.substring(currentIndex); break;
                            }
                            let breakIndex = escapedText.indexOf(' ', searchBreakIndex);
                            if (breakIndex === -1) {
                                resultHtml += escapedText.substring(currentIndex); break;
                            } else {
                                resultHtml += escapedText.substring(currentIndex, breakIndex) + '<br>';
                                currentIndex = breakIndex + 1;
                            }
                        }
                        td.innerHTML = resultHtml;
                    } else {
                        td.textContent = cellText; // Set as text if short or no spaces
                    }
                    isFormatted = true; // Mark as handled
                }
                // --- END String Handling ---

                tr.appendChild(td);
            } // end for loop (j - columns)
            tbody.appendChild(tr);
        } // end for loop (i - rows)

        table.appendChild(tbody);
        updatePaginationUI(page);

        // --- Call Adjustments AFTER tbody is appended ---
        requestAnimationFrame(() => {
            synchronizeScrollbars();
        });
    } // --- End renderTablePage ---


    // --- Pagination UI Elements and Logic ---
    // (Pagination elements: paginationContainer, paginationInfo, buttons, input, select etc.)
    // (Code is identical to previous correct version - omitted here for brevity)
    const paginationContainer = document.createElement('div');
    paginationContainer.className = 'pagination-controls';
    const paginationInfo = document.createElement('div');
    paginationInfo.className = 'pagination-info';
    paginationContainer.appendChild(paginationInfo);
    const paginationButtons = document.createElement('div');
    paginationButtons.className = 'pagination-buttons';
    const firstPageBtn = document.createElement('button'); firstPageBtn.innerHTML = '«'; firstPageBtn.className = 'pagination-btn'; firstPageBtn.title = 'First Page';
    firstPageBtn.addEventListener('click', () => { if (currentPage > 1) { currentPage = 1; renderTablePage(currentPage); } }); paginationButtons.appendChild(firstPageBtn);
    const prevPageBtn = document.createElement('button'); prevPageBtn.innerHTML = '‹'; prevPageBtn.className = 'pagination-btn'; prevPageBtn.title = 'Previous Page';
    prevPageBtn.addEventListener('click', () => { if (currentPage > 1) { currentPage--; renderTablePage(currentPage); } }); paginationButtons.appendChild(prevPageBtn);
    const pageNumberContainer = document.createElement('div'); pageNumberContainer.className = 'page-number-container';
    const pageNumberInput = document.createElement('input'); pageNumberInput.type = 'number'; pageNumberInput.min = 1; pageNumberInput.max = totalPages; pageNumberInput.value = currentPage; pageNumberInput.className = 'page-number-input';
    pageNumberInput.addEventListener('change', () => { let newPage = parseInt(pageNumberInput.value, 10); if (isNaN(newPage)) newPage = 1; if (newPage < 1) newPage = 1; if (newPage > totalPages) newPage = totalPages; currentPage = newPage; pageNumberInput.value = currentPage; renderTablePage(currentPage); });
    const pageCount = document.createElement('span'); pageCount.className = 'page-count'; pageCount.textContent = ` / ${totalPages}`;
    pageNumberContainer.appendChild(pageNumberInput); pageNumberContainer.appendChild(pageCount); paginationButtons.appendChild(pageNumberContainer);
    const nextPageBtn = document.createElement('button'); nextPageBtn.innerHTML = '›'; nextPageBtn.className = 'pagination-btn'; nextPageBtn.title = 'Next Page';
    nextPageBtn.addEventListener('click', () => { if (currentPage < totalPages) { currentPage++; renderTablePage(currentPage); } }); paginationButtons.appendChild(nextPageBtn);
    const lastPageBtn = document.createElement('button'); lastPageBtn.innerHTML = '»'; lastPageBtn.className = 'pagination-btn'; lastPageBtn.title = 'Last Page';
    lastPageBtn.addEventListener('click', () => { if (currentPage < totalPages) { currentPage = totalPages; renderTablePage(currentPage); } }); paginationButtons.appendChild(lastPageBtn);
    const rowsPerPageContainer = document.createElement('div'); rowsPerPageContainer.className = 'rows-per-page';
    const rowsPerPageLabel = document.createElement('label'); rowsPerPageLabel.textContent = 'Rows per page: '; const selectId = 'rows-per-page-select-id-' + Math.random().toString(36).substring(2, 9); rowsPerPageLabel.htmlFor = selectId;
    const rowsPerPageSelect = document.createElement('select'); rowsPerPageSelect.className = 'rows-per-page-select'; rowsPerPageSelect.id = selectId;
    rowsPerPageOptions.forEach(value => { const option = document.createElement('option'); option.value = value; option.textContent = value; if (value === rowsPerPage) option.selected = true; rowsPerPageSelect.appendChild(option); });
    rowsPerPageSelect.addEventListener('change', () => {
        const newRowsPerPage = parseInt(rowsPerPageSelect.value, 10);
        const firstRowIndexOfCurrentPage = (currentPage - 1) * rowsPerPage;
        totalPages = Math.ceil(rows.length / newRowsPerPage);
        if (totalPages === 0) totalPages = 1;
        let newCurrentPage = Math.floor(firstRowIndexOfCurrentPage / newRowsPerPage) + 1;
        newCurrentPage = Math.max(1, Math.min(totalPages, newCurrentPage));
        rowsPerPage = newRowsPerPage;
        currentPage = newCurrentPage;
        pageCount.textContent = ` / ${totalPages}`;
        pageNumberInput.max = totalPages;
        renderTablePage(currentPage);
    });
    rowsPerPageContainer.appendChild(rowsPerPageLabel); rowsPerPageContainer.appendChild(rowsPerPageSelect);
    paginationContainer.appendChild(paginationInfo); paginationContainer.appendChild(paginationButtons); paginationContainer.appendChild(rowsPerPageContainer);
    // --- End Pagination ---

    function updatePaginationUI(page) {
        const startRow = rows.length === 0 ? 0 : (page - 1) * rowsPerPage + 1;
        const endRow = Math.min(page * rowsPerPage, rows.length);
        paginationInfo.textContent = `Showing ${startRow} to ${endRow} of ${rows.length} rows`;
        firstPageBtn.disabled = page <= 1; prevPageBtn.disabled = page <= 1; nextPageBtn.disabled = page >= totalPages; lastPageBtn.disabled = page >= totalPages; pageNumberInput.value = page; pageNumberInput.disabled = totalPages <= 1;
    }

    // --- Scroll Synchronization Logic ---
    function synchronizeScrollbars() {
        requestAnimationFrame(() => {
            const tableWidth = table.offsetWidth;
            topScrollContent.style.width = `${tableWidth}px`;
            const syncScroll = (event) => {
                const source = event.target;
                const target = (source === topScrollContainer) ? tableWrapper : topScrollContainer;
                if (target.scrollLeft !== source.scrollLeft) { target.scrollLeft = source.scrollLeft; }
            };
            topScrollContainer.removeEventListener('scroll', syncScroll); tableWrapper.removeEventListener('scroll', syncScroll);
            topScrollContainer.addEventListener('scroll', syncScroll, { passive: true }); tableWrapper.addEventListener('scroll', syncScroll, { passive: true });
        });
    }

    // --- Assemble the Final Structure ---
    container.appendChild(paginationContainer);
    tableWrapper.appendChild(table);
    tableContainerWrapper.appendChild(topScrollContainer);
    tableContainerWrapper.appendChild(tableWrapper);
    container.appendChild(tableContainerWrapper);
    const footer = document.createElement('div');
    footer.className = 'results-footer';
    footer.textContent = `${rows.length} result${rows.length !== 1 ? 's' : ''}`;
    container.appendChild(footer);

    // --- Initial Render ---
    renderTablePage(1);

    // --- Initial Scroll Sync & Width Adjust---
    setTimeout(() => {
        synchronizeScrollbars();
    }, 50);
    window.addEventListener('resize', synchronizeScrollbars);
    // TODO: Need cleanup for resize listener

    return container;
}

/**
 * Set up export buttons for the results (Original Version)
 */
function setupExportButtons(results) {
    const exportJsonBtn = document.getElementById('export-json-btn');
    const exportCsvBtn = document.getElementById('export-csv-btn');
    const exportXlsxBtn = document.getElementById('export-xlsx-btn'); // Get the new button
    const copyResultsBtn = document.getElementById('copy-results-btn');
    const executionId = config.executionId; // Get execution ID from global config

    const isTableData = results && results.fields && Array.isArray(results.fields) && results.rows && Array.isArray(results.rows);
    const canExportOrCopy = results !== null && results !== undefined;

    // JSON Export
    if (exportJsonBtn) {
        exportJsonBtn.disabled = !canExportOrCopy;
        exportJsonBtn.onclick = canExportOrCopy ? () => exportData(results, `splunk_query_results_${executionId}.json`, 'application/json') : null;
    }

    // CSV Export
    if (exportCsvBtn) {
        exportCsvBtn.disabled = !isTableData;
        exportCsvBtn.title = isTableData ? "" : "CSV export only available for table-formatted results";
        exportCsvBtn.onclick = isTableData ? () => {
            const fieldNames = results.fields.map(field => (typeof field === 'object' && field !== null) ? field.name : String(field));
            const csvContent = [
                fieldNames.map(name => `"${String(name).replace(/"/g, '""')}"`).join(','), // Header row
                ...results.rows.map(row => row.map(cell => { // Data rows
                    if (cell === null || cell === undefined) return '';
                    let value = (typeof cell === 'object') ? JSON.stringify(cell) : String(cell);
                    // Quote if necessary
                    if (/[",\n\r]/.test(value)) return `"${value.replace(/"/g, '""')}"`;
                    return value;
                }).join(','))
            ].join('\n');
            exportData(csvContent, `splunk_query_results_${executionId}.csv`, 'text/csv;charset=utf-8;');
        } : null;
    }

    // XLSX Export (New)
    if (exportXlsxBtn) {
        exportXlsxBtn.disabled = !isTableData;
        exportXlsxBtn.title = isTableData ? "" : "XLSX export only available for table-formatted results";
        // When clicked, navigate the browser to the download endpoint
        exportXlsxBtn.onclick = isTableData ? () => {
            window.location.href = `/api/query/execution/${executionId}/export/xlsx`;
        } : null;
    }


    // Copy to Clipboard
    if (copyResultsBtn) {
        copyResultsBtn.disabled = !canExportOrCopy;
        copyResultsBtn.onclick = canExportOrCopy ? async () => {
            let text;
            if (isTableData) {
                const fieldNames = results.fields.map(field => (typeof field === 'object' && field !== null) ? field.name : String(field));
                text = [
                    fieldNames.join('\t'), // Header row (TSV for easy pasting)
                    ...results.rows.map(row => row.map(cell => (cell === null || cell === undefined) ? '' : String(cell).replace(/[\n\r\t]/g, ' ')).join('\t')) // Data rows
                ].join('\n');
            } else {
                text = typeof results === 'string' ? results : JSON.stringify(results, null, 2);
            }
            const success = await copyToClipboard(text);
            if (success) showSuccess('Results copied to clipboard');
            else showError('Failed to copy results');
        } : null;
    }
}

function exportData(data, filename, type) {
    const blobData = (typeof data === 'object' && type === 'application/json') ? JSON.stringify(data, null, 2) : data;
    const blob = new Blob([blobData], { type: type });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(link.href);
}