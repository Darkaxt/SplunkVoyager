import sqlite3
import json
import datetime
import hashlib
from app.config import DB_PATH, logger

def generate_query_hash(query_text, earliest_time, latest_time):
    """Generates a SHA256 hash for a query definition."""
    norm_earliest = earliest_time if earliest_time else "NULL"
    norm_latest = latest_time if latest_time else "NULL"
    
    # Combine the elements in a fixed order
    hash_input = f"{query_text}|{norm_earliest}|{norm_latest}"
    
    return hashlib.sha256(hash_input.encode('utf-8')).hexdigest()

def dict_factory(cursor, row):
    """Convert database row to dictionary"""
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

def get_connection():
    """Get database connection with row factory set to dict_factory"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = dict_factory
    return conn

def init_db():
    """Initialize the database schema, creating tables if they don't exist."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            conn.execute("PRAGMA foreign_keys = ON;") # Ensure foreign key constraints are enabled

            # --- Sessions Table ---
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                username TEXT,
                is_active BOOLEAN DEFAULT 0,
                last_check TIMESTAMP,
                last_active TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')

            # --- Cookies Table ---
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS cookies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER,
                cookie_name TEXT NOT NULL,
                cookie_value TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
            )
            ''')

            # --- Query Definitions Table (Stores unique query + results) ---
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS query_definitions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                query_hash TEXT UNIQUE NOT NULL,     -- Hash of text+earliest+latest
                query_text TEXT NOT NULL,
                earliest_time TEXT,
                latest_time TEXT,
                status TEXT NOT NULL,             -- 'pending', 'running', 'completed', 'failed'
                sid TEXT,                         -- Splunk Job SID (nullable)
                results TEXT,                     -- JSON string of results or error info
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, -- When definition first seen
                completed_at TIMESTAMP            -- When execution for this definition finished
            )
            ''')

            # --- Query Executions Table (Links User+Domain to Definition) ---
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS query_executions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                query_definition_id INTEGER NOT NULL,
                username TEXT NOT NULL,             -- Store the persistent username
                domain TEXT NOT NULL,               -- Store domain for context
                execution_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP, -- When user ran it
                session_id INTEGER,                 -- Optional: Store session for debugging/context
                FOREIGN KEY (query_definition_id) REFERENCES query_definitions(id) ON DELETE CASCADE,
                FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE SET NULL -- Example: Keep exec history if session deleted
            )
            ''')
            
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS instance_user_mapping (
                instance_identifier TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                domain TEXT NOT NULL,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')

            # --- Add Indexes (safe to run multiple times) ---
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_domain ON sessions(domain)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_cookies_session_id ON cookies(session_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_query_definitions_hash ON query_definitions(query_hash)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_query_definitions_status ON query_definitions(status)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_query_definitions_sid ON query_definitions(sid)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_query_executions_def_id ON query_executions(query_definition_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_query_executions_user_domain ON query_executions(username, domain)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_query_executions_time ON query_executions(execution_time)')
            if 'session_id' in [col[1] for col in cursor.execute("PRAGMA table_info(query_executions)").fetchall()]: # Check if optional session_id exists before indexing
                 cursor.execute('CREATE INDEX IF NOT EXISTS idx_query_executions_session_id ON query_executions(session_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_instance_user_mapping_last_updated ON instance_user_mapping(last_updated)')

            conn.commit()
            logger.info("Database schema initialized/verified.")
    except Exception as e:
        logger.error(f"Error initializing database: {str(e)}")
        raise
        


class Session:
    """Session model for interacting with session data"""
    
    @staticmethod
    def create(domain, username, is_active=False):
        """Create a new session"""
        now = datetime.datetime.now().isoformat()
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """INSERT INTO sessions 
                       (domain, username, is_active, last_check, last_active) 
                       VALUES (?, ?, ?, ?, ?)""",
                    (domain, username, is_active, now, now if is_active else None)
                )
                session_id = cursor.lastrowid
                conn.commit()
                return session_id
        except Exception as e:
            logger.error(f"Error creating session: {str(e)}")
            raise
    
    @staticmethod
    def get_by_id(session_id):
        """Get session by ID"""
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
                return cursor.fetchone()
        except Exception as e:
            logger.error(f"Error getting session by ID: {str(e)}")
            return None
    
    @staticmethod
    def get_active_for_domain(domain):
        """Get active session for domain"""
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """SELECT * FROM sessions 
                       WHERE domain = ? AND is_active = 1 
                       ORDER BY last_active DESC LIMIT 1""",
                    (domain,)
                )
                return cursor.fetchone()
        except Exception as e:
            logger.error(f"Error getting active session for domain: {str(e)}")
            return None
            
    @staticmethod
    def get_active_for_user_domain(username, domain):
        """Get an active session for a specific username and domain."""
        if not username or not domain:
            return None
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """SELECT * FROM sessions
                       WHERE lower(username) = lower(?) AND lower(domain) = lower(?) AND is_active = 1
                       ORDER BY last_active DESC LIMIT 1""",
                    (username, domain)
                )
                return cursor.fetchone()
        except Exception as e:
            logger.error(f"Error getting active session for user '{username}' domain '{domain}': {str(e)}")
            return None
    
    @staticmethod
    def get_latest_for_domain(domain):
        """Get latest session for domain regardless of active status"""
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """SELECT * FROM sessions 
                       WHERE domain = ? 
                       ORDER BY created_at DESC LIMIT 1""",
                    (domain,)
                )
                return cursor.fetchone()
        except Exception as e:
            logger.error(f"Error getting latest session for domain: {str(e)}")
            return None
            
    @staticmethod
    def get_latest_for_user_domain(username, domain):
        """Get the most recent session for a specific username and domain, regardless of active status"""
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                # Ensure case-insensitivity if usernames might vary by case
                # Using lower() might impact index usage depending on DB collation
                cursor.execute(
                    """SELECT * FROM sessions
                       WHERE lower(username) = lower(?) AND lower(domain) = lower(?)
                       ORDER BY created_at DESC LIMIT 1""",
                    (username, domain)
                )
                return cursor.fetchone()
        except Exception as e:
            logger.error(f"Error getting latest session for user '{username}' domain '{domain}': {str(e)}")
            # Depending on desired error handling, you might return None or re-raise
            return None # Returning None allows process_cookies to handle it
    
    @staticmethod
    def update_status(session_id, is_active):
        """Update session status"""
        now = datetime.datetime.now().isoformat()
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                if is_active:
                    cursor.execute(
                        """UPDATE sessions 
                           SET is_active = 1, last_check = ?, last_active = ? 
                           WHERE id = ?""",
                        (now, now, session_id)
                    )
                else:
                    cursor.execute(
                        """UPDATE sessions 
                           SET is_active = 0, last_check = ? 
                           WHERE id = ?""",
                        (now, session_id)
                    )
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Error updating session status: {str(e)}")
            return False
    
    @staticmethod
    def get_all_active():
        """Get all active sessions"""
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """SELECT * FROM sessions 
                       WHERE is_active = 1 
                       ORDER BY last_active DESC"""
                )
                return cursor.fetchall()
        except Exception as e:
            logger.error(f"Error getting all active sessions: {str(e)}")
            return []
    
    @staticmethod
    def get_all_sessions():
        """Get all sessions"""
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """SELECT * FROM sessions 
                       ORDER BY last_active DESC"""
                )
                return cursor.fetchall()
        except Exception as e:
            logger.error(f"Error getting all sessions: {str(e)}")
            return []
    
    @staticmethod
    def get_domains():
        """Get all unique domains"""
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """SELECT DISTINCT domain FROM sessions"""
                )
                results = cursor.fetchall()
                return [r['domain'] for r in results]
        except Exception as e:
            logger.error(f"Error getting domains: {str(e)}")
            return []

class Cookie:
    """Cookie model for interacting with cookie data"""
    
    @staticmethod
    def add_cookies(session_id, cookies):
        """Add cookies for a session"""
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                for name, value in cookies.items():
                    cursor.execute(
                        """INSERT INTO cookies 
                           (session_id, cookie_name, cookie_value) 
                           VALUES (?, ?, ?)""",
                        (session_id, name, value)
                    )
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Error adding cookies: {str(e)}")
            return False
    
    @staticmethod
    def get_for_session(session_id):
        """Get cookies for a session"""
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """SELECT cookie_name, cookie_value 
                       FROM cookies 
                       WHERE session_id = ?""",
                    (session_id,)
                )
                cookies = {}
                for row in cursor.fetchall():
                    cookies[row['cookie_name']] = row['cookie_value']
                return cookies
        except Exception as e:
            logger.error(f"Error getting cookies for session: {str(e)}")
            return {}
            
        
    @staticmethod
    def delete_for_session(session_id):
        """Delete all cookies for a specific session"""
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM cookies WHERE session_id = ?", (session_id,))
                rows_deleted = cursor.rowcount
                conn.commit()
                if rows_deleted > 0:
                    logger.info(f"Deleted {rows_deleted} cookies for session_id {session_id}")
                return True
        except Exception as e:
            logger.error(f"Error deleting cookies for session {session_id}: {str(e)}")
            return False

class QueryDefinition:
    """Model for unique query definitions, including their execution status and results."""

    @staticmethod
    def find_by_hash(query_hash):
        """Finds an existing query definition by hash."""
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM query_definitions WHERE query_hash = ?", (query_hash,))
                return cursor.fetchone()
        except Exception as e:
            logger.error(f"Error finding query definition by hash {query_hash[:8]}: {str(e)}")
            return None

    @staticmethod
    def create_pending(query_text, earliest_time=None, latest_time=None):
        """Creates a new query definition record in 'pending' state."""
        query_hash = generate_query_hash(query_text, earliest_time, latest_time)
        now = datetime.datetime.now().isoformat()
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """INSERT INTO query_definitions
                       (query_hash, query_text, earliest_time, latest_time, status, created_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (query_hash, query_text, earliest_time, latest_time, 'pending', now)
                )
                definition_id = cursor.lastrowid
                conn.commit()
                logger.info(f"Created new PENDING query definition ID: {definition_id} for hash: {query_hash[:8]}...")
                return definition_id, query_hash # Return hash too
        except sqlite3.IntegrityError:
             # This means the hash already exists, which shouldn't happen if find_by_hash was called first.
             # Could indicate a race condition. Log error, maybe try finding it again.
             logger.error(f"IntegrityError on creating PENDING definition for hash {query_hash[:8]}. Hash likely exists.")
             existing = QueryDefinition.find_by_hash(query_hash)
             if existing:
                 return existing['id'], query_hash
             else:
                  # Should not happen
                  raise Exception(f"IntegrityError but definition not found for hash {query_hash[:8]}")
        except Exception as e:
            logger.error(f"Error creating pending query definition: {str(e)}")
            raise
            
    @staticmethod
    def get_by_status(status):
        """
        Get all query definitions with a specific status.
        
        Args:
            status (str): The status to filter by ('pending', 'running', 'completed', 'failed')
            
        Returns:
            list: A list of query definition dictionaries
        """
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """SELECT * FROM query_definitions 
                       WHERE status = ? 
                       ORDER BY created_at DESC""", 
                    (status,)
                )
                return cursor.fetchall()
        except Exception as e:
            logger.error(f"Error getting query definitions by status {status}: {str(e)}")
            return []

    @staticmethod
    def update_status(definition_id, status, results=None):
        """Update query definition status, results, and completed_at timestamp."""
        now = datetime.datetime.now().isoformat()
        results_json = None
        if results:
             try:
                  results_json = json.dumps(results, default=str)
             except Exception as json_err:
                  logger.error(f"Failed to serialize results JSON for definition {definition_id}: {json_err}")
                  results_json = json.dumps({"error": "Failed to serialize results", "details": str(json_err)})
                  status = 'failed' # Mark as failed if results can't be stored

        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                # Only set completed_at if status indicates completion or failure
                completed_time = now if status in ('completed', 'failed') else None
                cursor.execute(
                    """UPDATE query_definitions
                       SET status = ?, results = ?, completed_at = ?
                       WHERE id = ?""",
                    (status, results_json, completed_time, definition_id)
                )
                conn.commit()
                logger.info(f"Updated definition {definition_id} status to {status}")
                return True
        except Exception as e:
            logger.error(f"Error updating query definition {definition_id}: {str(e)}")
            return False

    @staticmethod
    def get_by_id(definition_id):
        """Get query definition by ID, processing results."""
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM query_definitions WHERE id = ?", (definition_id,))
                definition = cursor.fetchone()
                if definition and definition['results']:
                    try:
                        if isinstance(definition['results'], str):
                             definition['results'] = json.loads(definition['results'])
                    except Exception:
                        logger.warning(f"Could not decode results JSON for definition {definition_id}.")
                        pass # Leave as string
                return definition
        except Exception as e:
            logger.error(f"Error getting query definition by ID {definition_id}: {str(e)}")
            return None

    # --- Add search/recent methods if needed, targeting query_text ---
    @staticmethod
    def search_definitions(search_term, limit=100):
         """Search query definitions by text content."""
         try:
             with get_connection() as conn:
                 cursor = conn.cursor()
                 cursor.execute(
                     """SELECT * FROM query_definitions
                        WHERE query_text LIKE ?
                        ORDER BY created_at DESC
                        LIMIT ?""",
                     (f'%{search_term}%', limit)
                 )
                 return cursor.fetchall()
         except Exception as e:
             logger.error(f"Error searching query definitions: {str(e)}")
             return []
             
    @staticmethod
    def delete(definition_id):
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                # Ensure cascade delete handles executions, or handle manually if needed based on FK constraint
                cursor.execute("DELETE FROM query_definitions WHERE id = ?", (definition_id,))
                conn.commit()
                logger.info(f"Deleted query definition ID: {definition_id}")
                return True
        except Exception as e:
            logger.error(f"Error deleting query definition {definition_id}: {str(e)}")
            return False
            
    @staticmethod
    def set_running_with_sid(definition_id, sid):
        """Update query definition status to 'running' and store the SID."""
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                # Set status to running, store SID, clear results and completed_at
                cursor.execute(
                    """UPDATE query_definitions
                       SET status = ?, sid = ?, results = NULL, completed_at = NULL
                       WHERE id = ?""",
                    ('running', sid, definition_id)
                )
                conn.commit()
                logger.info(f"Set definition {definition_id} to running with SID {sid}")
                return True
        except Exception as e:
            logger.error(f"Error setting definition {definition_id} to running with SID: {str(e)}")
            return False

    # Modify get_by_status to include sid
    @staticmethod
    def get_by_status(status):
        """
        Get all query definitions with a specific status. Includes the 'sid' column.

        Args:
            status (str): The status to filter by ('pending', 'running', 'completed', 'failed')

        Returns:
            list: A list of query definition dictionaries
        """
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """SELECT * FROM query_definitions
                       WHERE status = ?
                       ORDER BY created_at DESC""",
                    (status,)
                )
                return cursor.fetchall()
        except Exception as e:
            logger.error(f"Error getting query definitions by status {status}: {str(e)}")
            return []

class QueryExecution:
    """Model for user query execution instances (links user to definition)."""

    @staticmethod
    def record_execution(query_definition_id, username, domain, session_id=None):
        """Records that a user executed a specific query definition."""
        # Use lower case for consistency if desired
        username_lower = username.lower() if username else None
        domain_lower = domain.lower() if domain else None

        if not username_lower or not domain_lower:
             logger.error("Cannot record execution: username or domain missing.")
             return None # Or raise error

        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """INSERT INTO query_executions
                       (query_definition_id, username, domain, session_id)
                       VALUES (?, ?, ?, ?)""",
                    (query_definition_id, username_lower, domain_lower, session_id)
                )
                execution_id = cursor.lastrowid
                conn.commit()
                logger.info(f"Recorded execution ID: {execution_id} for definition: {query_definition_id} by user: {username_lower}@{domain_lower}")
                return execution_id
        except Exception as e:
            logger.error(f"Error recording query execution: {str(e)}")
            # Don't raise here, as the main query might have succeeded.
            # The failure is just in recording the history.
            return None
            
    @staticmethod
    def find_latest_user_execution(query_definition_id, username, domain):
        """Finds the most recent execution record ID for a specific user/domain/definition."""
        username_lower = username.lower() if username else None
        domain_lower = domain.lower() if domain else None
        if not username_lower or not domain_lower: return None

        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """SELECT id FROM query_executions
                       WHERE query_definition_id = ? AND username = ? AND domain = ?
                       ORDER BY execution_time DESC
                       LIMIT 1""",
                    (query_definition_id, username_lower, domain_lower)
                )
                result = cursor.fetchone()
                return result['id'] if result else None
        except Exception as e:
            logger.error(f"Error finding latest user execution for def {query_definition_id}, user {username_lower}: {str(e)}")
            return None

    @staticmethod
    def update_user_execution_time(execution_id, session_id=None):
        """Updates the timestamp (and optionally session_id) of an existing execution record."""
        now_iso = datetime.datetime.now().isoformat()
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                params = [now_iso]
                sql = "UPDATE query_executions SET execution_time = ?"
                if session_id is not None:
                     sql += ", session_id = ?"
                     params.append(session_id)
                sql += " WHERE id = ?"
                params.append(execution_id)

                cursor.execute(sql, tuple(params))
                conn.commit()
                logger.info(f"Updated execution time for execution ID: {execution_id}")
                return True
        except Exception as e:
            logger.error(f"Error updating execution time for execution {execution_id}: {str(e)}")
            return False

    @staticmethod
    def insert_user_execution(query_definition_id, username, domain, session_id=None):
         """Inserts a new user execution record."""
         username_lower = username.lower() if username else None
         domain_lower = domain.lower() if domain else None
         if not username_lower or not domain_lower:
             logger.error("Cannot insert execution: username or domain missing.")
             return None

         try:
             with get_connection() as conn:
                 cursor = conn.cursor()
                 cursor.execute(
                     """INSERT INTO query_executions
                        (query_definition_id, username, domain, session_id)
                        VALUES (?, ?, ?, ?)""",
                     (query_definition_id, username_lower, domain_lower, session_id)
                 )
                 execution_id = cursor.lastrowid
                 conn.commit()
                 logger.info(f"Inserted new execution ID: {execution_id} for def: {query_definition_id} by user: {username_lower}@{domain_lower}")
                 return execution_id
         except Exception as e:
             logger.error(f"Error inserting query execution: {str(e)}")
             return None
             
    @staticmethod
    def record_or_update_user_execution(query_definition_id, username, domain, session_id=None):
        """
        Finds the latest execution for this user/def/domain and updates its time,
        or inserts a new execution record if none exists.
        Returns the ID of the relevant execution record.
        """
        latest_id = QueryExecution.find_latest_user_execution(query_definition_id, username, domain)
        if latest_id:
            updated = QueryExecution.update_user_execution_time(latest_id, session_id)
            return latest_id if updated else None # Return existing ID if update successful
        else:
            new_id = QueryExecution.insert_user_execution(query_definition_id, username, domain, session_id)
            return new_id # Return new ID

    @staticmethod
    def get_history_for_user_domain(username, domain, limit=50):
        """
        Get the user's LATEST execution for each unique query definition they ran
        on a specific domain.
        """
        username_lower = username.lower() if username else None
        domain_lower = domain.lower() if domain else None
        if not username_lower or not domain_lower: return []

        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                # Use ROW_NUMBER() window function for robustness against identical timestamps
                cursor.execute(
                    """WITH RankedExecutions AS (
                           SELECT
                               qe.*,
                               ROW_NUMBER() OVER(PARTITION BY qe.query_definition_id ORDER BY qe.execution_time DESC) as rn
                           FROM query_executions qe
                           WHERE qe.username = ? AND qe.domain = ?
                       )
                       SELECT
                           re.id as execution_id,
                           re.execution_time as created_at, -- Alias for template
                           re.username, re.domain, re.session_id,
                           qd.id as query_definition_id, qd.query_text, qd.earliest_time, qd.latest_time,
                           qd.status as status, -- Use simple 'status' alias
                           qd.completed_at as completed_at -- Select completion time
                       FROM RankedExecutions re
                       JOIN query_definitions qd ON re.query_definition_id = qd.id
                       WHERE re.rn = 1 -- Only get the latest one (rn=1) per definition
                       ORDER BY re.execution_time DESC
                       LIMIT ?""",
                    (username_lower, domain_lower, limit)
                )
                return cursor.fetchall()
        except Exception as e:
            logger.error(f"Error getting LATEST execution history for {username_lower}@{domain_lower}: {str(e)}")
            return []

    @staticmethod
    def get_execution_details(execution_id):
         """Get details for a specific execution ID, joining definition info."""
         try:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """SELECT
                           qe.id as execution_id, qe.execution_time, qe.username, qe.domain, qe.session_id,
                           qd.id as query_definition_id, qd.query_hash, qd.query_text, qd.earliest_time, qd.latest_time, qd.status, qd.results, qd.created_at as definition_created_at, qd.completed_at
                       FROM query_executions qe
                       JOIN query_definitions qd ON qe.query_definition_id = qd.id
                       WHERE qe.id = ?""",
                    (execution_id,)
                )
                execution = cursor.fetchone()
                if execution and execution['results']:
                    try:
                        if isinstance(execution['results'], str):
                             execution['results'] = json.loads(execution['results'])
                    except Exception:
                         logger.warning(f"Could not decode results JSON for execution {execution_id} (def {execution['query_definition_id']}).")
                         pass
                return execution
         except Exception as e:
             logger.error(f"Error getting details for execution {execution_id}: {str(e)}")
             return None
             
    @staticmethod
    def get_for_definition(definition_id, limit=None):
        """
        Get all execution records for a specific query definition.
        
        Args:
            definition_id (int): The query definition ID
            limit (int, optional): Maximum number of records to return
            
        Returns:
            list: A list of execution record dictionaries
        """
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                
                sql = """SELECT * FROM query_executions
                         WHERE query_definition_id = ?
                         ORDER BY execution_time DESC"""
                         
                params = [definition_id]
                
                if limit is not None:
                    sql += " LIMIT ?"
                    params.append(limit)
                    
                cursor.execute(sql, tuple(params))
                return cursor.fetchall()
        except Exception as e:
            logger.error(f"Error getting executions for definition {definition_id}: {str(e)}")
            return []

    @staticmethod
    def delete_user_execution(execution_id):
        """Deletes a specific user execution record. Does NOT delete the definition."""
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM query_executions WHERE id = ?", (execution_id,))
                conn.commit()
                logger.info(f"Deleted user query execution record ID: {execution_id}")
                return True
        except Exception as e:
            logger.error(f"Error deleting user query execution {execution_id}: {str(e)}")
            return False

    # --- Add methods for recent executions across all users if needed ---
    @staticmethod
    def get_recent_executions_all_users(limit=20):
         """Get recent executions across all users."""
         try:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                     """SELECT
                            qe.id as execution_id, qe.execution_time, qe.username, qe.domain,
                            qd.id as query_definition_id, qd.query_text, qd.earliest_time, qd.latest_time, qd.status as definition_status
                        FROM query_executions qe
                        JOIN query_definitions qd ON qe.query_definition_id = qd.id
                        ORDER BY qe.execution_time DESC
                        LIMIT ?""",
                     (limit,)
                )
                return cursor.fetchall()
         except Exception as e:
             logger.error(f"Error getting recent all-user executions: {str(e)}")
             return []
             
    @staticmethod
    def count_for_definition(definition_id):
        """Counts how many execution records reference a specific definition."""
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) as count FROM query_executions WHERE query_definition_id = ?", (definition_id,))
                result = cursor.fetchone()
                return result['count'] if result else 0
        except Exception as e:
            logger.error(f"Error counting executions for definition {definition_id}: {str(e)}")
            return -1 # Indicate error
            
class InstanceUserMapping:
    """Model for interacting with the instance_user_mapping table."""

    @staticmethod
    def update(instance_identifier, username, domain):
        """
        Inserts or replaces the mapping for a given instance identifier.
        Uses INSERT OR REPLACE for simplicity.
        """
        # Ensure consistent case for storage if desired
        username_lower = username.lower() if username else None
        domain_lower = domain.lower() if domain else None
        if not instance_identifier or not username_lower or not domain_lower:
            logger.error("Cannot update instance mapping: identifier, username, or domain missing.")
            return False

        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """INSERT OR REPLACE INTO instance_user_mapping
                       (instance_identifier, username, domain, last_updated)
                       VALUES (?, ?, ?, CURRENT_TIMESTAMP)""",
                       (instance_identifier, username_lower, domain_lower)
                )
                conn.commit()
                logger.info(f"Upserted instance mapping for '{instance_identifier}' -> {username_lower}@{domain_lower}")
                return True
        except Exception as e:
            logger.error(f"Error updating instance_user_mapping for '{instance_identifier}': {str(e)}")
            return False

    @staticmethod
    def get_by_instance(instance_identifier):
        """
        Retrieves the username and domain mapped to a given instance identifier.
        Returns a dictionary {'username': ..., 'domain': ...} or None if not found.
        """
        if not instance_identifier:
            return None
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT username, domain FROM instance_user_mapping WHERE instance_identifier = ?",
                    (instance_identifier,)
                )
                mapping = cursor.fetchone() # Fetch the mapping for this instance
                if mapping:
                     logger.debug(f"Found mapping for instance '{instance_identifier}': {mapping}")
                else:
                     logger.debug(f"No mapping found for instance '{instance_identifier}'.")
                return mapping # Returns dict or None
        except Exception as e:
            logger.error(f"Error retrieving mapping for instance '{instance_identifier}': {str(e)}")
            return None