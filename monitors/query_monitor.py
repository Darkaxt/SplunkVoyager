"""
Query monitor for SplunkVoyager Terminal Monitor
"""

import os
import sqlite3
import json
from datetime import datetime

from monitors.config import log, STANDALONE_MODE

class QueryMonitor:
    """Class to monitor Splunk query-related metrics"""
    
    def __init__(self, db_path):
        """Initialize query monitor"""
        self.db_path = db_path
        self.running_queries = []
        self.recent_executions = []
        self.failed_queries = []
        self.performance_stats = {
            'avg_duration': 0,
            'max_duration': 0,
            'min_duration': 0,
            'total_queries_today': 0,
            'queries_by_hour': {}
        }
        self.query_counts = {
            'pending': 0,
            'running': 0,
            'completed': 0,
            'failed': 0,
            'total': 0
        }
    
    def update(self):
        """Update query statistics"""
        try:
            if not os.path.exists(self.db_path):
                return
                
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Update query counts
            self._update_query_counts(cursor)
            
            # Get running queries
            self._update_running_queries(cursor)
            
            # Get recent successful executions
            self._update_recent_executions(cursor)
            
            # Get recent failed queries
            self._update_failed_queries(cursor)
            
            # Update performance statistics
            self._update_performance_stats(cursor)
            
            # Close connection
            conn.close()
            
        except Exception as e:
            log.error(f"Error updating query stats: {e}")
    
    def _update_query_counts(self, cursor):
        """Update query counts by status"""
        try:
            cursor.execute("""
                SELECT status, COUNT(*) 
                FROM query_definitions
                GROUP BY status;
            """)
            
            # Reset counts
            self.query_counts = {
                'pending': 0,
                'running': 0,
                'completed': 0,
                'failed': 0,
                'total': 0
            }
            
            # Update with actual counts
            for row in cursor.fetchall():
                status = row[0]
                count = row[1]
                if status in self.query_counts:
                    self.query_counts[status] = count
                self.query_counts['total'] += count
                
        except Exception as e:
            log.error(f"Error updating query counts: {e}")
    
    def _update_running_queries(self, cursor):
        """Update list of currently running queries"""
        try:
            cursor.execute("""
                SELECT qd.id, qd.query_text, qd.created_at, qd.results,
                       (SELECT username FROM query_executions qe 
                        WHERE qe.query_definition_id = qd.id 
                        ORDER BY execution_time DESC LIMIT 1) AS username,
                       (SELECT domain FROM query_executions qe 
                        WHERE qe.query_definition_id = qd.id 
                        ORDER BY execution_time DESC LIMIT 1) AS domain
                FROM query_definitions qd
                WHERE qd.status = 'running'
                ORDER BY qd.created_at DESC;
            """)
            
            running_queries = [dict(row) for row in cursor.fetchall()]
            
            # Process running queries to extract SID and progress
            self.running_queries = []
            for query in running_queries:
                progress_info = {'progress': 0, 'status': 'Unknown', 'sid': None}
                
                if query['results']:
                    try:
                        results = json.loads(query['results'])
                        if isinstance(results, dict):
                            if 'sid' in results:
                                progress_info['sid'] = results['sid']
                            
                            # Check for different possible progress indicators
                            if 'done_progress' in results:
                                progress_info['progress'] = results['done_progress'] * 100
                            elif 'progress' in results:
                                progress_info['progress'] = results['progress']
                            
                            # Get status info
                            if 'dispatch_state' in results:
                                progress_info['status'] = results['dispatch_state']
                    except Exception as e:
                        log.debug(f"Error parsing results JSON for query {query['id']}: {e}")
                
                query.update(progress_info)
                
                # Calculate elapsed time
                if query['created_at']:
                    try:
                        created = datetime.fromisoformat(query['created_at'].replace('Z', '+00:00'))
                        elapsed = (datetime.now() - created).total_seconds()
                        query['elapsed_seconds'] = elapsed
                    except Exception as e:
                        query['elapsed_seconds'] = 0
                        log.debug(f"Error calculating elapsed time: {e}")
                
                self.running_queries.append(query)
                
        except Exception as e:
            log.error(f"Error updating running queries: {e}")
    
    def _update_recent_executions(self, cursor):
        """Update list of recent successful query executions"""
        try:
            cursor.execute("""
                SELECT qe.id as execution_id, qe.username, qe.domain, qe.execution_time,
                       qd.id as definition_id, qd.query_text, qd.status, qd.completed_at, qd.created_at,
                       (julianday(qd.completed_at) - julianday(qd.created_at)) * 86400.0 as duration_seconds
                FROM query_executions qe
                JOIN query_definitions qd ON qe.query_definition_id = qd.id
                WHERE qd.status = 'completed'
                ORDER BY qe.execution_time DESC
                LIMIT 10;
            """)
            
            self.recent_executions = [dict(row) for row in cursor.fetchall()]
            
        except Exception as e:
            log.error(f"Error updating recent executions: {e}")
    
    def _update_failed_queries(self, cursor):
        """Update list of recently failed queries"""
        try:
            cursor.execute("""
                SELECT qd.id, qd.query_text, qd.created_at, qd.completed_at, qd.results,
                       (SELECT username FROM query_executions qe 
                        WHERE qe.query_definition_id = qd.id 
                        ORDER BY execution_time DESC LIMIT 1) AS username,
                       (SELECT domain FROM query_executions qe 
                        WHERE qe.query_definition_id = qd.id 
                        ORDER BY execution_time DESC LIMIT 1) AS domain
                FROM query_definitions qd
                WHERE qd.status = 'failed'
                ORDER BY qd.completed_at DESC
                LIMIT 5;
            """)
            
            failed_queries = [dict(row) for row in cursor.fetchall()]
            
            # Process failed queries to extract error messages
            self.failed_queries = []
            for query in failed_queries:
                error_info = {'error': 'Unknown error'}
                
                if query['results']:
                    try:
                        results = json.loads(query['results'])
                        if isinstance(results, dict) and 'error' in results:
                            error_info['error'] = results['error']
                    except Exception as e:
                        log.debug(f"Error parsing error results for query {query['id']}: {e}")
                
                query.update(error_info)
                self.failed_queries.append(query)
                
        except Exception as e:
            log.error(f"Error updating failed queries: {e}")
    
    def _update_performance_stats(self, cursor):
        """Update query performance statistics"""
        try:
            # Get average duration for completed queries
            cursor.execute("""
                SELECT 
                    AVG((julianday(completed_at) - julianday(created_at)) * 86400.0) as avg_duration,
                    MAX((julianday(completed_at) - julianday(created_at)) * 86400.0) as max_duration,
                    MIN((julianday(completed_at) - julianday(created_at)) * 86400.0) as min_duration
                FROM query_definitions
                WHERE status = 'completed' AND completed_at IS NOT NULL AND created_at IS NOT NULL;
            """)
            
            result = cursor.fetchone()
            if result:
                self.performance_stats['avg_duration'] = result['avg_duration'] or 0
                self.performance_stats['max_duration'] = result['max_duration'] or 0
                self.performance_stats['min_duration'] = result['min_duration'] or 0
            
            # Get total queries executed today
            cursor.execute("""
                SELECT COUNT(*) 
                FROM query_executions 
                WHERE execution_time >= date('now', 'start of day');
            """)
            
            self.performance_stats['total_queries_today'] = cursor.fetchone()[0]
            
            # Get queries by hour for the last 24 hours
            cursor.execute("""
                SELECT 
                    strftime('%Y-%m-%d %H:00:00', execution_time) as hour,
                    COUNT(*) as count
                FROM query_executions
                WHERE execution_time >= datetime('now', '-24 hours')
                GROUP BY hour
                ORDER BY hour;
            """)
            
            self.performance_stats['queries_by_hour'] = {
                row['hour']: row['count'] for row in cursor.fetchall()
            }
            
        except Exception as e:
            log.error(f"Error updating performance stats: {e}")
    
    def get_query_details(self, query_id):
        """Get detailed information about a specific query"""
        if not os.path.exists(self.db_path):
            return None
            
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get query definition
            cursor.execute("""
                SELECT *
                FROM query_definitions
                WHERE id = ?;
            """, (query_id,))
            
            query = dict(cursor.fetchone() or {})
            
            # Get executions for this query
            cursor.execute("""
                SELECT qe.id as execution_id, qe.username, qe.domain, qe.execution_time,
                       s.id as session_id, s.is_active as session_active
                FROM query_executions qe
                LEFT JOIN sessions s ON qe.session_id = s.id
                WHERE qe.query_definition_id = ?
                ORDER BY qe.execution_time DESC;
            """, (query_id,))
            
            executions = [dict(row) for row in cursor.fetchall()]
            
            # Parse results if available
            results_data = None
            if query.get('results'):
                try:
                    results_data = json.loads(query['results'])
                except Exception as e:
                    log.debug(f"Error parsing results JSON: {e}")
                    results_data = {"error": "Could not parse results JSON"}
            
            # Calculate execution time
            execution_time = None
            if query.get('created_at') and query.get('completed_at'):
                try:
                    created = datetime.fromisoformat(query['created_at'].replace('Z', '+00:00'))
                    completed = datetime.fromisoformat(query['completed_at'].replace('Z', '+00:00'))
                    execution_time = (completed - created).total_seconds()
                except Exception:
                    pass
            
            details = {
                'query': query,
                'executions': executions,
                'results_data': results_data,
                'execution_time': execution_time
            }
            
            conn.close()
            return details
            
        except Exception as e:
            log.error(f"Error getting query details for {query_id}: {e}")
            return None
    
    def get_queries_by_user(self, username, domain=None, limit=20):
        """Get queries executed by a specific user"""
        if not os.path.exists(self.db_path):
            return []
            
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            sql = """
                SELECT qe.id as execution_id, qe.username, qe.domain, qe.execution_time,
                       qd.id as definition_id, qd.query_text, qd.status, qd.completed_at, qd.created_at
                FROM query_executions qe
                JOIN query_definitions qd ON qe.query_definition_id = qd.id
                WHERE LOWER(qe.username) = LOWER(?)
            """
            
            params = [username]
            
            if domain:
                sql += " AND LOWER(qe.domain) = LOWER(?)"
                params.append(domain)
            
            sql += " ORDER BY qe.execution_time DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(sql, tuple(params))
            queries = [dict(row) for row in cursor.fetchall()]
            
            conn.close()
            return queries
            
        except Exception as e:
            log.error(f"Error getting queries for user {username}: {e}")
            return []