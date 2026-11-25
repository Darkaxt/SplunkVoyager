"""
Session monitor for SplunkVoyager Terminal Monitor
"""

import os
import sqlite3
import json
from datetime import datetime, timedelta

from monitors.config import log, format_time_ago, STANDALONE_MODE

class SessionMonitor:
    """Class to monitor session-related metrics"""
    
    def __init__(self, db_path):
        """Initialize session monitor"""
        self.db_path = db_path
        self.active_sessions = []
        self.inactive_sessions = []
        self.beacon_status = {}  # {domain_session_id: is_active}
        self.session_count = {'active': 0, 'inactive': 0, 'total': 0}
        self.sessions_by_domain = {}
        self.cookies_stats = {'total': 0, 'avg_per_session': 0}
        
        # Try to import the beacon status from the app if not in standalone mode
        if not STANDALONE_MODE:
            try:
                from app.services.session import active_beacons
                self.beacon_status = active_beacons
            except (ImportError, AttributeError) as e:
                log.warning(f"Could not import active_beacons: {e}")
    
    def update(self):
        """Update session statistics"""
        try:
            if not os.path.exists(self.db_path):
                return
                
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get active sessions with cookie count
            cursor.execute("""
                SELECT s.id, s.domain, s.username, s.last_check, s.last_active, s.created_at,
                       (SELECT COUNT(*) FROM cookies c WHERE c.session_id = s.id) AS cookie_count
                FROM sessions s
                WHERE s.is_active = 1
                ORDER BY s.last_active DESC;
            """)
            self.active_sessions = [dict(row) for row in cursor.fetchall()]
            
            # Get inactive recent sessions (last 24 hours)
            cursor.execute("""
                SELECT s.id, s.domain, s.username, s.last_check, s.last_active, s.created_at,
                       (SELECT COUNT(*) FROM cookies c WHERE c.session_id = s.id) AS cookie_count
                FROM sessions s
                WHERE s.is_active = 0 AND s.last_check > datetime('now', '-1 day')
                ORDER BY s.last_check DESC
                LIMIT 10;
            """)
            self.inactive_sessions = [dict(row) for row in cursor.fetchall()]
            
            # Get session counts
            cursor.execute("SELECT COUNT(*) FROM sessions WHERE is_active = 1;")
            self.session_count['active'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM sessions WHERE is_active = 0;")
            self.session_count['inactive'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM sessions;")
            self.session_count['total'] = cursor.fetchone()[0]
            
            # Get sessions by domain
            cursor.execute("""
                SELECT domain, COUNT(*) as count,
                       SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) as active_count
                FROM sessions
                GROUP BY domain;
            """)
            self.sessions_by_domain = {row['domain']: {
                'total': row['count'],
                'active': row['active_count']
            } for row in cursor.fetchall()}
            
            # Get cookie stats
            cursor.execute("SELECT COUNT(*) FROM cookies;")
            self.cookies_stats['total'] = cursor.fetchone()[0]
            
            if self.session_count['total'] > 0:
                self.cookies_stats['avg_per_session'] = self.cookies_stats['total'] / self.session_count['total']
            else:
                self.cookies_stats['avg_per_session'] = 0
            
            # Update session status with real-time beacon information
            self._update_beacon_status()
            
            # Close connection
            conn.close()
            
        except Exception as e:
            log.error(f"Error updating session stats: {e}")
    
    def _update_beacon_status(self):
        """Update beacon status from the application if available"""
        if not STANDALONE_MODE:
            try:
                from app.services.session import active_beacons
                self.beacon_status = active_beacons
            except (ImportError, AttributeError) as e:
                # Already logged in __init__, don't spam the log
                pass
        
        # Add beacon status to session data
        for session in self.active_sessions:
            domain = session.get('domain')
            session_id = session.get('id')
            if domain and session_id:
                beacon_key = f"{domain}_{session_id}"
                session['beacon_active'] = self.beacon_status.get(beacon_key, False)
    
    def get_inactive_sessions(self, hours=24):
        """Get inactive sessions within the specified time window"""
        if not os.path.exists(self.db_path):
            return []
            
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get inactive sessions
            cursor.execute(f"""
                SELECT s.id, s.domain, s.username, s.last_check, s.last_active, s.created_at,
                       (SELECT COUNT(*) FROM cookies c WHERE c.session_id = s.id) AS cookie_count
                FROM sessions s
                WHERE s.is_active = 0 AND s.last_check > datetime('now', '-{hours} hours')
                ORDER BY s.last_check DESC;
            """)
            
            inactive = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return inactive
            
        except Exception as e:
            log.error(f"Error getting inactive sessions: {e}")
            return []
    
    def get_session_cookies(self, session_id):
        """Get cookies for a specific session"""
        if not os.path.exists(self.db_path):
            return []
            
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT cookie_name, cookie_value, created_at
                FROM cookies
                WHERE session_id = ?
                ORDER BY cookie_name;
            """, (session_id,))
            
            cookies = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return cookies
            
        except Exception as e:
            log.error(f"Error getting session cookies: {e}")
            return []
    
    def get_session_activity(self, session_id):
        """Get query activity for a specific session"""
        if not os.path.exists(self.db_path):
            return []
            
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get session details
            cursor.execute("""
                SELECT s.*, 
                       (SELECT COUNT(*) FROM cookies c WHERE c.session_id = s.id) AS cookie_count
                FROM sessions s
                WHERE s.id = ?;
            """, (session_id,))
            
            session = dict(cursor.fetchone() or {})
            
            # Get query executions for this session
            cursor.execute("""
                SELECT qe.id as execution_id, qe.execution_time,
                       qd.id as query_id, qd.query_text, qd.status,
                       qd.created_at, qd.completed_at
                FROM query_executions qe
                JOIN query_definitions qd ON qe.query_definition_id = qd.id
                WHERE qe.session_id = ?
                ORDER BY qe.execution_time DESC;
            """, (session_id,))
            
            executions = [dict(row) for row in cursor.fetchall()]
            
            # Calculate session stats
            session_age = None
            if session.get('created_at'):
                try:
                    created = datetime.fromisoformat(session['created_at'].replace('Z', '+00:00'))
                    last_active = datetime.fromisoformat(session.get('last_active', session['created_at']).replace('Z', '+00:00'))
                    session_age = (last_active - created).total_seconds()
                except:
                    pass
            
            activity = {
                'session': session,
                'executions': executions,
                'stats': {
                    'execution_count': len(executions),
                    'session_age_seconds': session_age,
                    'beacon_active': False
                }
            }
            
            # Add beacon status
            domain = session.get('domain')
            if domain:
                beacon_key = f"{domain}_{session_id}"
                activity['stats']['beacon_active'] = self.beacon_status.get(beacon_key, False)
            
            conn.close()
            return activity
            
        except Exception as e:
            log.error(f"Error getting session activity: {e}")
            return {'session': {}, 'executions': [], 'stats': {}}