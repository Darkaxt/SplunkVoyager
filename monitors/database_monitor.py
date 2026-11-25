"""
Database monitor for SplunkVoyager Terminal Monitor
"""

import os
import sqlite3
import json
from datetime import datetime

from monitors.config import log, STANDALONE_MODE

class DatabaseMonitor:
    """Class to collect database statistics"""
    
    def __init__(self, db_path):
        """Initialize database monitor"""
        self.db_path = db_path
        self.file_size = 0
        self.tables = {}
        self.query_status_counts = {'pending': 0, 'running': 0, 'completed': 0, 'failed': 0}
        self.execution_counts = {'total': 0, 'last_hour': 0}
        self.growth_rate = 0
        self.last_size = 0
        self.last_check_time = datetime.now()
        self.vacuum_stats = {'last_run': None, 'last_size_before': 0, 'last_size_after': 0}
        self.index_stats = {}
    
    def update(self):
        """Update database statistics"""
        try:
            # File size and growth rate
            self._update_file_stats()
            
            # Database tables and contents
            if os.path.exists(self.db_path):
                self._update_db_stats()
            
        except Exception as e:
            log.error(f"Error updating database stats: {e}")
    
    def _update_file_stats(self):
        """Update file size and growth statistics"""
        try:
            if os.path.exists(self.db_path):
                current_size = os.path.getsize(self.db_path)
                
                # Calculate growth rate (bytes per second)
                now = datetime.now()
                time_diff = (now - self.last_check_time).total_seconds()
                if time_diff > 0 and self.last_size > 0:
                    self.growth_rate = (current_size - self.last_size) / time_diff
                
                self.last_size = current_size
                self.last_check_time = now
                self.file_size = current_size
            else:
                self.file_size = 0
                self.growth_rate = 0
        except Exception as e:
            log.error(f"Error updating file stats: {e}")
            self.file_size = 0
            self.growth_rate = 0
    
    def _update_db_stats(self):
        """Update statistics from database tables"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get table counts
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            
            for table in tables:
                table_name = table[0]
                cursor.execute(f"SELECT COUNT(*) FROM {table_name};")
                count = cursor.fetchone()[0]
                self.tables[table_name] = count
            
            # Get query definition counts by status
            cursor.execute("""
                SELECT status, COUNT(*) 
                FROM query_definitions 
                GROUP BY status;
            """)
            
            # Reset counts before updating
            self.query_status_counts = {'pending': 0, 'running': 0, 'completed': 0, 'failed': 0}
            for status, count in cursor.fetchall():
                if status in self.query_status_counts:
                    self.query_status_counts[status] = count
            
            # Get total executions
            cursor.execute("SELECT COUNT(*) FROM query_executions;")
            self.execution_counts['total'] = cursor.fetchone()[0]
            
            # Get executions in the last hour
            cursor.execute("""
                SELECT COUNT(*) FROM query_executions 
                WHERE execution_time > datetime('now', '-1 hour');
            """)
            self.execution_counts['last_hour'] = cursor.fetchone()[0]
            
            # Get index information
            cursor.execute("""
                SELECT * FROM sqlite_master
                WHERE type='index' AND sql IS NOT NULL;
            """)
            indexes = cursor.fetchall()
            
            self.index_stats = {}
            for idx in indexes:
                index_name = idx['name']
                table_name = idx['tbl_name']
                
                if table_name not in self.index_stats:
                    self.index_stats[table_name] = []
                
                self.index_stats[table_name].append({
                    'name': index_name,
                    'sql': idx['sql']
                })
            
            # Close connection
            conn.close()
            
        except Exception as e:
            log.error(f"Error updating database stats: {e}")
    
    def vacuum_database(self):
        """Run VACUUM on the database to optimize storage"""
        if not os.path.exists(self.db_path):
            return False
            
        try:
            # Record size before vacuum
            size_before = os.path.getsize(self.db_path)
            self.vacuum_stats['last_size_before'] = size_before
            
            # Run vacuum
            conn = sqlite3.connect(self.db_path)
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("VACUUM;")
            conn.close()
            
            # Record size after vacuum
            size_after = os.path.getsize(self.db_path)
            self.vacuum_stats['last_size_after'] = size_after
            self.vacuum_stats['last_run'] = datetime.now().isoformat()
            
            # Update file stats
            self._update_file_stats()
            
            log.info(f"Vacuumed database: {size_before} bytes -> {size_after} bytes")
            return True
        except Exception as e:
            log.error(f"Error vacuuming database: {e}")
            return False
    
    def get_table_schema(self, table_name):
        """Get schema for a specific table"""
        if not os.path.exists(self.db_path):
            return None
            
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get table schema
            cursor.execute(f"PRAGMA table_info({table_name});")
            columns = cursor.fetchall()
            
            conn.close()
            
            return columns
        except Exception as e:
            log.error(f"Error getting table schema: {e}")
            return None
    
    def analyze_performance(self):
        """Analyze database performance"""
        if not os.path.exists(self.db_path):
            return {}
            
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Turn on PRAGMA statements for analysis
            cursor.execute("PRAGMA analysis_limit=1000;")
            cursor.execute("PRAGMA optimize;")
            
            # Get index usage stats (SQLite 3.9.0+)
            try:
                cursor.execute("PRAGMA index_list(query_definitions);")
                query_def_indexes = cursor.fetchall()
            except:
                query_def_indexes = []
            
            # Get database stats
            cursor.execute("PRAGMA database_list;")
            database_info = cursor.fetchall()
            
            # Get integrity check
            cursor.execute("PRAGMA quick_check;")
            integrity_check = cursor.fetchall()
            
            conn.close()
            
            performance_data = {
                'database_info': [dict(row) for row in database_info],
                'integrity_check': [row[0] for row in integrity_check],
                'indexes': {
                    'query_definitions': [dict(row) for row in query_def_indexes]
                }
            }
            
            return performance_data
        except Exception as e:
            log.error(f"Error analyzing performance: {e}")
            return {}