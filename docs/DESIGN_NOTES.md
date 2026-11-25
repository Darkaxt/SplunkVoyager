# Splunk Dashboard Framework - Project Design Summary

## Project Concept
A custom dashboard framework for Splunk that provides enhanced visualization capabilities through a Python backend and modern HTML5 frontend.

## Architecture Overview
- **Backend**: Python application that interfaces with Splunk
- **API Layer**: Custom API that translates web app requests into optimized SPL queries
- **Frontend**: HTML5 web application with dynamic visualizations
- **Authentication**: Browser-based authentication using either a headless browser approach or cookie extraction

## Core Feature: Process Tree Analysis Dashboard (Planned)
- Timeline representation of host sessions
- Detailed process information (PID, process path, session ID, command line)
- Dynamic search functionality
- Interactive process tree visualization with expandable/collapsable nodes
- Detailed process information on node selection

## Caching Strategy
- Use SQLite database for data storage (Encryption via SQLCipher planned).
- **Query Definition Caching**: Store unique query definitions (text + time range) along with their *canonical results* and execution status. Avoids re-executing identical queries.
- **Execution History**: Track each instance a user runs a query definition.
- Password protection for sensitive investigation data (Planned).
- Portable database design allows sharing investigation data between team members (Planned).
- Support for database placement in shared folders for collaborative analysis (Planned).
- Efficiently store and query process information across sessions (Planned).
- Support relationship mapping between processes for graph visualization (Planned).
- Implement a "past research" menu based on user's query execution history (Planned).
- Visual indicators for cache status and data freshness (Planned).
- Cache invalidation (re-running a query definition) only when forced by user or potentially via future time-based rules.

## UI Design (Partially Implemented / Planned)
- User account management in the top navigation bar:
  - Username display in the top-right corner that shows the currently active account
  - Dropdown menu for account management functions
  - "Switch Account" section listing all active sessions with visual indicator for current session
  - Session Details link to view detailed information about the active session
  - Cookie-based session preference to remember the user's selected account
  - Active user session identified server-side via `preferred_session_id` cookie or instance mapping fallback (`instance_user_mapping` table).
  - Header dropdown content (username, session list, details link) is populated/updated dynamically via client-side JavaScript (AJAX call to `/api/sessions/active`).
- Collapsible lateral panel containing (Planned):
  - Available dashboards list
  - Past analyzed entities with expandable hierarchy
  - Time ranges for each analyzed entity
  - Delete buttons with confirmation for entities and time ranges
- Main content area for dashboard visualization (Partially Implemented - Query Results)
- Timeline at the top with visual indicator of data coverage (Planned)
- Button to request additional data for extending the time range (Planned)

## Performance Considerations
- Targeted Ajax requests for node information (Planned for Process Tree)
- SQLite database for efficient data storage and retrieval.
- **Query Definition Hashing**: Use hashes for fast lookup of existing query definitions.
- Indexed queries for fast search functionality.
- Relationship tables for process link management (Planned).
- Frontend requesting only what needs to be displayed.
- JSON structure for efficient data transfer between backend and frontend.

## Security Considerations
- Database encryption using SQLCipher for protecting sensitive investigation data (Planned).
- Shared master password for team access to encrypted databases (Planned).
- Authentication for accessing Splunk data through browser sessions (Implemented via Cookies).
- Data access restricted to authorized team members through encryption (Planned).
- Option to set different passwords for different investigation databases if needed (Planned).

## Implementation Phases

### Phase 1: Authentication Foundation (Completed)
- Implemented browser cookie extraction approach using a userscript with Tampermonkey BETA
- Created a Flask server to receive and store cookies
- Established cookie validation mechanism
- Implemented session management with beaconing to keep sessions alive
- Added SQLite database for secure storage of session data
- Added support for HttpOnly cookies through Tampermonkey's GM_cookie API

### Phase 2: Splunk Connectivity (Completed)
- Created backend services for connecting to Splunk using authenticated sessions
- Implemented query execution functionality with proper CSRF token handling
- Built API endpoints for session management and query execution
- Added caching of session data in SQLite database
- Implemented time range parameters for queries
- **Refactored Query Handling**: Implemented tracking of query execution history per user, storing unique query definitions (text, time range) and their canonical results separately to avoid redundant storage and execution.

### Phase 3: Basic UI Implementation (Significant Progress)
- Developed web interface with session management (display, invalidate, dynamic active list).
- Implemented query execution page (`/query`) with datetime picker controls.
- Added results visualization (`/query/execution/<id>`) for Splunk queries using an enhanced table.
- Implemented query execution management (view definition results, re-run/refresh definitions, delete user execution history entries).
- Added export options for query results (JSON, CSV, clipboard).
- User account management implemented *** UPDATE: (User session identification via cookie/instance mapping and header display working. Header dropdown populated dynamically via AJAX.) ***
- *Next Steps for UI*: Collapsible panel, Process Tree Viz, Timeline, *** UPDATE: Refactor Re-run button interaction (see Next Steps section). ***

### Future Phases (not immediately planned)
- Enhanced process tree visualization with collapse/expand capabilities
- Timeline representation with session data
- Cross-session process graph visualization with linked nodes
- Advanced search functionality for process details across multiple sessions
- Additional dashboard types beyond process trees
- Refinement of database schema and query optimizations (ongoing)

## Database Schema Design (Current Core)
- **sessions Table**: Stores browser-based session information (domain, username, cookies, status, timestamps). Foreign Key for `cookies`. Links user context to `query_executions`.
- **cookies Table**: Stores individual cookie key-value pairs associated with a session.
+ *** ADD: instance_user_mapping Table ***: Stores the mapping between a running server instance and the last validated user for that instance. Used as a fallback for identifying the current user if the preference cookie is missing.
+   - `instance_identifier TEXT PRIMARY KEY` (e.g., hostname)
+   - `username TEXT NOT NULL`
+   - `domain TEXT NOT NULL`
+   - `last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP`
- **query_definitions Table**: Stores unique query definitions.
  - `id`, `query_hash` (UNIQUE, based on text+times), `query_text`, `earliest_time`, `latest_time`, `status` ('pending', 'running', 'completed', 'failed'), `sid` (Splunk Job ID), `results` (JSON), `created_at`, `completed_at`.
- **query_executions Table**: Tracks each time a user runs a query definition.
  - `id`, `query_definition_id` (FK to query_definitions), `username`, `domain`, `execution_time`, `session_id` (Optional FK to sessions for debug context).
- *(Planned Schema)*: `Endpoints Table`, `Processes Table`, `Process_Links Table` (as described previously).
- Appropriate indexes for optimized search and join performance.

## Deployment Approach
- Setup script (setup.bat) to:
  - Create Python virtual environment
  - Install dependencies (SQLite required, SQLCipher optional for encryption planned)
  - Launch web application in appropriate browser
- Fully portable solution requiring no additional server installation
- No administrative privileges needed beyond Python execution
- Support for both individual and team-based deployments
- Option to place encrypted SQLite database in shared network locations for collaborative investigations (Planned)
- Export/import functionality for sharing investigation results (Planned)

## Implementation Progress Summary (Consolidated)

### Phase 1: Authentication Foundation (Completed)
- Browser cookie extraction via Tampermonkey BETA userscript implemented.
- Flask backend receives, validates, stores (SQLite), and beacons sessions.

### Phase 2: Splunk Connectivity & Query Refactor (Completed)
- Backend services connect and execute queries against Splunk using stored sessions.
- CSRF handling implemented.
- Query storage refactored: Unique definitions (`query_definitions` table) store text, time range, status, and canonical results. User interactions (`query_executions` table) link users/domains to definitions and track execution time. API supports finding/creating/executing definitions and recording/updating user executions.

### Phase 3: Basic UI Implementation (Significant Progress)
- Core UI pages created (`index`, `sessions`, `query`, `session_detail`, `execution_detail`).
- Session management UI implemented (list, detail, invalidate, dynamic active list).
- Query execution page allows running queries with time ranges.
- Execution results page displays results (table/JSON), allows re-run (refresh), and history deletion.
- Export options implemented.
- User account management implemented

### Project Structure (Conceptual - verify actual file names)
SplunkVoyager/
├── app/
│   ├── `__init__.py`              # Flask application factory
│   ├── `config.py`                # Configuration settings
│   ├── models/
│   │   ├── `__init__.py`
│   │   └── `database.py`          # Database models and setup (QueryDefinition, QueryExecution)
│   ├── services/
│   │   ├── `session.py`           # Session validation and beaconing
│   │   └── `splunk.py`            # Splunk query execution service
│   ├── routes/
│   │   ├── `api.py`               # API endpoints (query execution/rerun, history, session status)
│   │   └── `views.py`             # Frontend routes (session_detail, execution_detail)
│   ├── static/
│   │   ├── css/
│   │   │   └── `style.css`        # Main consolidated stylesheet
│   │   ├── js/
│   │   │   ├── `main.js`          # Common utilities
│   │   │   ├── `sessions.js`      # Sessions page functionality
│   │   │   ├── `query.js`         # Query execution page functionality
│   │   │   └── `dashboard.js`     # Dashboard page specific JS (e.g., dynamic sessions)
│   │   └── img/                   # Images and icons
│   └── templates/
│       ├── `base.html`            # Base template
│       ├── `index.html`           # Dashboard homepage
│       ├── `sessions.html`        # Sessions management page
│       ├── `query.html`           # Query execution page
│       ├── `session_detail.html`  # Session details page (shows execution history)
│       └── `execution_detail.html`# Execution details page (shows definition results)
├── monitors/
│   ├── `__init__.py`
│   ├── `config.py`
│   ├── `database_monitor.py`
│   ├── `query_monitor.py`
│   ├── `session_monitor.py`
│   ├── `system_monitor.py`
│   └── `terminal_ui.py`
├── `run.py`                       # Application entry point
├── `setup.py`                     # Setup script
└── `requirements.txt`             # Dependencies

### Next Steps
1.  **UI/UX Refinements**:
    *   Consolidate remaining inline JS/CSS into static files.
    *   Enhance Query Execution History Display: ***
        - Consider adding columns to the "Query Execution History" table for:
        - Percentage completion (requires backend support during async execution).
        - Number of results/rows fetched.
        - Size (e.g., in bytes) of the stored results JSON.
2.  **Complete Splunk Connectivity**:
    *   Improve error handling for various Splunk API scenarios.
    *   (Lower Priority) Implement additional Splunk interactions (saved searches, dashboards).
    *   (Lower Priority) Add explicit support for switching between multiple Splunk endpoints if needed.
3.  **Enhance UI Implementation (Core Features)**:
    *   Develop the collapsible lateral panel design.
    *   Implement the process tree visualization foundation.
    *   Add timeline representation foundation.
4.  **Implement Security Features**:
    *   Integrate SQLCipher for database encryption.
    *   Implement password protection for database access.
    *   Create export/import functionality for sharing investigation results.
5.  **Future Enhancements**:
    *   Develop advanced search functionality (across definitions/executions).
    *   Implement cross-session process graph visualization.
    *   Add additional dashboard types beyond process trees.