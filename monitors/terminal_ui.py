"""
Terminal UI for SplunkVoyager Monitor
"""

import curses
import time
import signal
import threading
from datetime import datetime, timedelta

from monitors.config import (
    log, format_bytes, format_time_ago, truncate_text,
    COLOR_GREEN, COLOR_RED, COLOR_YELLOW, COLOR_CYAN,
    COLOR_MAGENTA, COLOR_BLUE, COLOR_WHITE,
    QUERY_HEADERS, QUERY_POSITIONS,
    SESSION_HEADERS, SESSION_POSITIONS,
    EXECUTIONS_HEADERS, EXECUTIONS_POSITIONS,
    FAILED_HEADERS, FAILED_POSITIONS
)
from monitors.database_monitor import DatabaseMonitor
from monitors.session_monitor import SessionMonitor
from monitors.query_monitor import QueryMonitor
from monitors.system_monitor import SystemMonitor

class SafeScreen:
    """Wraps the curses screen so writes outside the window are clipped instead of raising.

    Views compute row/column positions from content length, and on a small terminal they
    can run past the edge; curses then raises "addwstr() returned ERR", which used to close
    the monitor and with it the whole app (the web server is a daemon thread of it).
    """

    def __init__(self, screen):
        self._screen = screen

    def __getattr__(self, name):
        return getattr(self._screen, name)

    def addstr(self, y, x, text, *attr):
        max_y, max_x = self._screen.getmaxyx()
        if y < 0 or y >= max_y or x < 0 or x >= max_x:
            return
        text = str(text)
        # the bottom-right cell can't be written without curses raising; keep one column free there
        room = max_x - x - (1 if y == max_y - 1 else 0)
        if room <= 0:
            return
        try:
            self._screen.addstr(y, x, text[:room], *attr)
        except curses.error:
            pass


class TerminalUI:
    """Terminal UI for SplunkVoyager monitoring"""
    
    def __init__(self, db_path, refresh_interval=2, target_pid=None, log_handler=None):
        """Initialize the terminal UI"""
        self.db_path = db_path
        self.refresh_interval = refresh_interval
        self.running = True
        self.db_monitor = DatabaseMonitor(db_path)
        self.session_monitor = SessionMonitor(db_path)
        self.query_monitor = QueryMonitor(db_path)
        self.system_monitor = SystemMonitor(target_pid)
        self.screen = None
        self.last_update_time = None
        self.log_handler = log_handler  # Store the log handler
        
        # Track screen dimensions
        self.max_y = 0
        self.max_x = 0
        
        # View state
        self.current_view = 'main'  # 'main', 'queries', 'sessions', 'system', 'logs'
        self.selected_index = 0
        self.scroll_offset = 0
        
        # Capture SIGINT (Ctrl+C) to exit gracefully
        signal.signal(signal.SIGINT, self.signal_handler)
    
    def signal_handler(self, sig, frame):
        """Handle signal to exit gracefully"""
        self.running = False
    
    def setup_colors(self):
        """Set up color pairs for the UI"""
        # Start colors if supported
        if curses.has_colors():
            curses.start_color()
            curses.use_default_colors()
            
            # Define color pairs
            curses.init_pair(COLOR_GREEN, curses.COLOR_GREEN, -1)
            curses.init_pair(COLOR_RED, curses.COLOR_RED, -1)
            curses.init_pair(COLOR_YELLOW, curses.COLOR_YELLOW, -1)
            curses.init_pair(COLOR_CYAN, curses.COLOR_CYAN, -1)
            curses.init_pair(COLOR_MAGENTA, curses.COLOR_MAGENTA, -1)
            curses.init_pair(COLOR_BLUE, curses.COLOR_BLUE, -1)
            curses.init_pair(COLOR_WHITE, curses.COLOR_WHITE, -1)
    
    def update_data(self):
        """Update all monitored data"""
        self.db_monitor.update()
        self.session_monitor.update()
        self.query_monitor.update()
        self.system_monitor.update()
        self.last_update_time = datetime.now()
    
    def render_header(self, y, x):
        """Render the header section"""
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.screen.addstr(y, x, f"SplunkVoyager Monitor", curses.A_BOLD)
        self.screen.addstr(y, x + 25, f"DB: {self.db_path}")
        self.screen.addstr(y, x + 65, f"Time: {now}")
        
        # System stats
        uptime_str = str(timedelta(seconds=int(self.system_monitor.uptime)))
        mem_info = self.system_monitor.memory_info
        mem_usage = format_bytes(mem_info.rss if mem_info else 0)
        
        self.screen.addstr(y + 1, x, f"CPU: {self.system_monitor.cpu_percent:.1f}%")
        self.screen.addstr(y + 1, x + 15, f"Mem: {self.system_monitor.memory_percent:.1f}% ({mem_usage})")
        self.screen.addstr(y + 1, x + 50, f"Uptime: {uptime_str}")
        
        # Database stats
        db_size = format_bytes(self.db_monitor.file_size)
        growth_rate = format_bytes(self.db_monitor.growth_rate) + "/s" if self.db_monitor.growth_rate > 0 else "0 B/s"
        
        self.screen.addstr(y + 2, x, f"Database: {db_size}")
        self.screen.addstr(y + 2, x + 25, f"Growth: {growth_rate}")
        
        # I/O stats if available
        if self.system_monitor.io_rate:
            read_rate = format_bytes(self.system_monitor.io_rate.get('read_bytes', 0)) + "/s"
            write_rate = format_bytes(self.system_monitor.io_rate.get('write_bytes', 0)) + "/s"
            self.screen.addstr(y + 2, x + 50, f"I/O: R={read_rate} W={write_rate}")
        
        # Navigation menu
        menu_y = y + 3
        menu_items = [
            ("F1", "Main"),
            ("F2", "Queries"),
            ("F3", "Sessions"),
            ("F4", "System"),
            ("F5", "Logs"),
            ("r", "Refresh"),
            ("q", "Quit")
        ]
        
        pos = x
        for key, label in menu_items:
            # Highlight the current view
            if (key == "F1" and self.current_view == 'main') or \
               (key == "F2" and self.current_view == 'queries') or \
               (key == "F3" and self.current_view == 'sessions') or \
               (key == "F4" and self.current_view == 'system') or \
               (key == "F5" and self.current_view == 'logs'):
                self.screen.addstr(menu_y, pos, f"{key}:{label}", curses.A_REVERSE)
            else:
                self.screen.addstr(menu_y, pos, f"{key}:{label}")
            pos += len(f"{key}:{label}") + 2
        
        return y + 5  # Return the next Y position
    
    def render_main_view(self, y, x):
        """Render the main overview screen"""
        # Database statistics
        self.screen.addstr(y, x, "=== DATABASE STATISTICS ===", curses.A_BOLD)
        
        # Table counts
        self.screen.addstr(y + 1, x, "Tables: ")
        table_stats = []
        for table, count in self.db_monitor.tables.items():
            table_stats.append(f"{table}: {count}")
        
        if table_stats:
            self.screen.addstr(y + 1, x + 8, " | ".join(table_stats))
        else:
            self.screen.addstr(y + 1, x + 8, "No tables found")
        
        # Query status counts
        self.screen.addstr(y + 3, x, "=== QUERY OVERVIEW ===", curses.A_BOLD)
        
        pending = self.query_monitor.query_counts.get('pending', 0)
        running = self.query_monitor.query_counts.get('running', 0)
        completed = self.query_monitor.query_counts.get('completed', 0)
        failed = self.query_monitor.query_counts.get('failed', 0)
        total = self.query_monitor.query_counts.get('total', 0)
        
        self.screen.addstr(y + 4, x, f"Definitions: {total} total")
        self.screen.addstr(y + 4, x + 25, f"Pending: {pending}")
        self.screen.addstr(y + 4, x + 40, f"Running: {running}")
        self.screen.addstr(y + 4, x + 55, f"Completed: {completed}")
        self.screen.addstr(y + 4, x + 75, f"Failed: {failed}")
        
        # Query execution stats
        total_execs = self.db_monitor.execution_counts.get('total', 0)
        recent_execs = self.db_monitor.execution_counts.get('last_hour', 0)
        
        self.screen.addstr(y + 5, x, f"Executions: {total_execs} total")
        self.screen.addstr(y + 5, x + 30, f"Last hour: {recent_execs}")
        
        # Session overview
        self.screen.addstr(y + 7, x, "=== SESSION OVERVIEW ===", curses.A_BOLD)
        active_count = self.session_monitor.session_count.get('active', 0)
        inactive_count = self.session_monitor.session_count.get('inactive', 0)
        total_sessions = self.session_monitor.session_count.get('total', 0)
        
        self.screen.addstr(y + 8, x, f"Sessions: {total_sessions} total")
        self.screen.addstr(y + 8, x + 25, f"Active: {active_count}")
        self.screen.addstr(y + 8, x + 40, f"Inactive: {inactive_count}")
        
        # Show domains with session counts
        if self.session_monitor.sessions_by_domain:
            self.screen.addstr(y + 9, x, "Domains:")
            domain_pos = x + 10
            for domain, counts in self.session_monitor.sessions_by_domain.items():
                if domain_pos + len(domain) + 15 < self.max_x:
                    self.screen.addstr(y + 9, domain_pos, f"{domain} ({counts['active']}/{counts['total']})")
                    domain_pos += len(domain) + 15
        
        # Running queries mini-view
        self.screen.addstr(y + 11, x, "=== RUNNING QUERIES ===", curses.A_BOLD)
        if not self.query_monitor.running_queries:
            self.screen.addstr(y + 12, x, "No running queries")
        else:
            # Display headers
            col_headers = ["ID", "User", "Progress", "Started", "Query"]
            col_positions = [x, x + 5, x + 20, x + 35, x + 50]
            
            for i, header in enumerate(col_headers):
                self.screen.addstr(y + 12, col_positions[i], header, curses.A_UNDERLINE)
            
            # Display running queries
            row = y + 13
            for i, query in enumerate(self.query_monitor.running_queries):
                if row >= self.max_y - 2:
                    break
                
                query_id = query.get('id', '')
                username = query.get('username', 'N/A')
                progress = f"{query.get('progress', 0):.1f}%"
                created_at = format_time_ago(query.get('created_at', ''))
                query_text = query.get('query_text', '')
                
                # Truncate query text to fit
                max_query_len = self.max_x - col_positions[4] - 2
                query_text = truncate_text(query_text, max_query_len)
                
                self.screen.addstr(row, col_positions[0], str(query_id))
                self.screen.addstr(row, col_positions[1], username)
                
                # Color progress based on value
                progress_val = query.get('progress', 0)
                if progress_val >= 75:
                    self.screen.addstr(row, col_positions[2], progress, curses.color_pair(COLOR_GREEN))
                elif progress_val >= 25:
                    self.screen.addstr(row, col_positions[2], progress, curses.color_pair(COLOR_YELLOW))
                else:
                    self.screen.addstr(row, col_positions[2], progress, curses.color_pair(COLOR_RED))
                
                self.screen.addstr(row, col_positions[3], created_at)
                self.screen.addstr(row, col_positions[4], query_text)
                
                row += 1
        
        # Performance metrics
        avg_duration = self.query_monitor.performance_stats.get('avg_duration', 0)
        max_duration = self.query_monitor.performance_stats.get('max_duration', 0)
        
        # Show these metrics if we have space
        if y + 18 < self.max_y - 2:
            self.screen.addstr(y + 16, x, "=== PERFORMANCE ===", curses.A_BOLD)
            self.screen.addstr(y + 17, x, f"Average query time: {avg_duration:.2f}s")
            self.screen.addstr(y + 17, x + 35, f"Max query time: {max_duration:.2f}s")
            self.screen.addstr(y + 18, x, f"Today's queries: {self.query_monitor.performance_stats.get('total_queries_today', 0)}")
        
        return y + 19  # Next Y position
    
    def render_query_view(self, y, x):
        """Render the queries detail view"""
        self.screen.addstr(y, x, "=== QUERY MONITORING ===", curses.A_BOLD)
        
        # Running queries
        self.screen.addstr(y + 1, x, "Running Queries:", curses.A_BOLD)
        
        # Display headers
        for i, header in enumerate(QUERY_HEADERS):
            if x + QUERY_POSITIONS[i] + len(header) < self.max_x:
                self.screen.addstr(y + 2, x + QUERY_POSITIONS[i], header, curses.A_UNDERLINE)
        
        if not self.query_monitor.running_queries:
            self.screen.addstr(y + 3, x, "No running queries")
            next_y = y + 4
        else:
            # Display running queries
            row = y + 3
            for i, query in enumerate(self.query_monitor.running_queries):
                if row >= self.max_y - 2:
                    break
                
                query_id = str(query.get('id', ''))
                username = str(query.get('username', 'N/A'))
                domain = str(query.get('domain', 'N/A'))
                progress = f"{query.get('progress', 0):.1f}%"
                sid = str(query.get('sid', 'N/A'))  # Convert to string to handle None
                created_at = format_time_ago(query.get('created_at', ''))
                query_text = query.get('query_text', '')
                
                # Truncate text to fit
                query_text = truncate_text(query_text, self.max_x - (x + QUERY_POSITIONS[6]) - 2)
                
                # Display query data
                self.screen.addstr(row, x + QUERY_POSITIONS[0], query_id)
                self.screen.addstr(row, x + QUERY_POSITIONS[1], username)
                self.screen.addstr(row, x + QUERY_POSITIONS[2], domain)
                
                # Color progress based on value
                progress_val = query.get('progress', 0)
                if progress_val >= 75:
                    self.screen.addstr(row, x + QUERY_POSITIONS[3], progress, curses.color_pair(COLOR_GREEN))
                elif progress_val >= 25:
                    self.screen.addstr(row, x + QUERY_POSITIONS[3], progress, curses.color_pair(COLOR_YELLOW))
                else:
                    self.screen.addstr(row, x + QUERY_POSITIONS[3], progress, curses.color_pair(COLOR_RED))
                
                self.screen.addstr(row, x + QUERY_POSITIONS[4], sid)
                self.screen.addstr(row, x + QUERY_POSITIONS[5], created_at)
                self.screen.addstr(row, x + QUERY_POSITIONS[6], query_text)
                
                row += 1
            
            next_y = row + 1
        
        # Recent executions
        self.screen.addstr(next_y, x, "Recent Executions:", curses.A_BOLD)
        
        # Display headers
        for i, header in enumerate(EXECUTIONS_HEADERS):
            if x + EXECUTIONS_POSITIONS[i] + len(header) < self.max_x:
                self.screen.addstr(next_y + 1, x + EXECUTIONS_POSITIONS[i], header, curses.A_UNDERLINE)
        
        if not self.query_monitor.recent_executions:
            self.screen.addstr(next_y + 2, x, "No recent executions")
            next_y += 3
        else:
            # Display recent executions
            row = next_y + 2
            for i, exec_info in enumerate(self.query_monitor.recent_executions):
                if row >= self.max_y - 2:
                    break
                
                exec_id = str(exec_info.get('execution_id', ''))
                username = str(exec_info.get('username', 'N/A'))
                domain = str(exec_info.get('domain', 'N/A'))
                status = str(exec_info.get('status', 'N/A'))
                
                duration_secs = exec_info.get('duration_seconds')
                if duration_secs:
                    duration = f"{duration_secs:.1f}s"
                else:
                    duration = "N/A"
                
                executed_at = format_time_ago(exec_info.get('execution_time', ''))
                query_text = exec_info.get('query_text', '')
                
                # Truncate query text to fit
                query_text = truncate_text(query_text, self.max_x - (x + EXECUTIONS_POSITIONS[6]) - 2)
                
                # Display execution data
                self.screen.addstr(row, x + EXECUTIONS_POSITIONS[0], exec_id)
                self.screen.addstr(row, x + EXECUTIONS_POSITIONS[1], username)
                self.screen.addstr(row, x + EXECUTIONS_POSITIONS[2], domain)
                self.screen.addstr(row, x + EXECUTIONS_POSITIONS[3], status)
                self.screen.addstr(row, x + EXECUTIONS_POSITIONS[4], duration)
                self.screen.addstr(row, x + EXECUTIONS_POSITIONS[5], executed_at)
                self.screen.addstr(row, x + EXECUTIONS_POSITIONS[6], query_text)
                
                row += 1
            
            next_y = row + 1
        
        # Failed queries
        self.screen.addstr(next_y, x, "Failed Queries:", curses.A_BOLD)
        
        # Display headers
        for i, header in enumerate(FAILED_HEADERS):
            if x + FAILED_POSITIONS[i] + len(header) < self.max_x:
                self.screen.addstr(next_y + 1, x + FAILED_POSITIONS[i], header, curses.A_UNDERLINE)
        
        if not self.query_monitor.failed_queries:
            self.screen.addstr(next_y + 2, x, "No failed queries")
            next_y += 3
        else:
            # Display failed queries
            row = next_y + 2
            for i, query in enumerate(self.query_monitor.failed_queries):
                if row >= self.max_y - 2:
                    break
                
                query_id = str(query.get('id', ''))
                username = str(query.get('username', 'N/A'))
                domain = str(query.get('domain', 'N/A'))
                completed_at = format_time_ago(query.get('completed_at', ''))
                error = str(query.get('error', 'Unknown error'))
                query_text = query.get('query_text', '')
                
                # Truncate text to fit
                error = truncate_text(error, FAILED_POSITIONS[5] - FAILED_POSITIONS[4] - 2)
                query_text = truncate_text(query_text, self.max_x - (x + FAILED_POSITIONS[5]) - 2)
                
                # Display failed query data
                self.screen.addstr(row, x + FAILED_POSITIONS[0], query_id)
                self.screen.addstr(row, x + FAILED_POSITIONS[1], username)
                self.screen.addstr(row, x + FAILED_POSITIONS[2], domain)
                self.screen.addstr(row, x + FAILED_POSITIONS[3], completed_at)
                self.screen.addstr(row, x + FAILED_POSITIONS[4], error, curses.color_pair(COLOR_RED))
                self.screen.addstr(row, x + FAILED_POSITIONS[5], query_text)
                
                row += 1
        
        return next_y  # Return the next Y position
    
    def render_session_view(self, y, x):
        """Render the session monitoring view"""
        self.screen.addstr(y, x, "=== SESSION MONITORING ===", curses.A_BOLD)
        
        # Session counts
        active_count = self.session_monitor.session_count.get('active', 0)
        inactive_count = self.session_monitor.session_count.get('inactive', 0)
        total_sessions = self.session_monitor.session_count.get('total', 0)
        
        self.screen.addstr(y + 1, x, f"Active: {active_count}")
        self.screen.addstr(y + 1, x + 15, f"Inactive: {inactive_count}")
        self.screen.addstr(y + 1, x + 35, f"Total: {total_sessions}")
        self.screen.addstr(y + 1, x + 50, f"Cookies: {self.session_monitor.cookies_stats.get('total', 0)}")
        
        # Active sessions
        self.screen.addstr(y + 3, x, "Active Sessions:", curses.A_BOLD)
        
        # Display headers
        for i, header in enumerate(SESSION_HEADERS):
            if x + SESSION_POSITIONS[i] + len(header) < self.max_x:
                self.screen.addstr(y + 4, x + SESSION_POSITIONS[i], header, curses.A_UNDERLINE)
        
        if not self.session_monitor.active_sessions:
            self.screen.addstr(y + 5, x, "No active sessions")
            next_y = y + 6
        else:
            # Display active sessions
            row = y + 5
            for i, session in enumerate(self.session_monitor.active_sessions):
                if row >= self.max_y - 2:
                    break
                
                session_id = session.get('id', '')
                username = session.get('username', 'N/A')
                domain = session.get('domain', 'N/A')
                last_active = format_time_ago(session.get('last_active', ''))
                last_check = format_time_ago(session.get('last_check', ''))
                created_at = format_time_ago(session.get('created_at', ''))
                cookie_count = session.get('cookie_count', 0)
                
                # Check beacon status
                beacon_active = session.get('beacon_active', False)
                beacon_status = "Active" if beacon_active else "Inactive"
                
                # Display session data
                self.screen.addstr(row, x + SESSION_POSITIONS[0], str(session_id))
                self.screen.addstr(row, x + SESSION_POSITIONS[1], username)
                self.screen.addstr(row, x + SESSION_POSITIONS[2], domain)
                self.screen.addstr(row, x + SESSION_POSITIONS[3], last_active)
                self.screen.addstr(row, x + SESSION_POSITIONS[4], last_check)
                self.screen.addstr(row, x + SESSION_POSITIONS[5], created_at)
                self.screen.addstr(row, x + SESSION_POSITIONS[6], str(cookie_count))
                
                # Color beacon status based on activity
                if x + SESSION_POSITIONS[7] + len(beacon_status) < self.max_x:
                    if beacon_status == "Active":
                        self.screen.addstr(row, x + SESSION_POSITIONS[7], beacon_status, curses.color_pair(COLOR_GREEN))
                    else:
                        self.screen.addstr(row, x + SESSION_POSITIONS[7], beacon_status, curses.color_pair(COLOR_RED))
                
                row += 1
            
            next_y = row + 1
        
        # Inactive sessions (recent)
        self.screen.addstr(next_y, x, "Recent Inactive Sessions:", curses.A_BOLD)
        
        # Display headers (reuse the same headers)
        for i, header in enumerate(SESSION_HEADERS[:7]):  # Exclude beacon status
            if x + SESSION_POSITIONS[i] + len(header) < self.max_x:
                self.screen.addstr(next_y + 1, x + SESSION_POSITIONS[i], header, curses.A_UNDERLINE)
        
        if not self.session_monitor.inactive_sessions:
            self.screen.addstr(next_y + 2, x, "No recent inactive sessions")
        else:
            # Display inactive sessions
            row = next_y + 2
            for i, session in enumerate(self.session_monitor.inactive_sessions):
                if row >= self.max_y - 2:
                    break
                
                session_id = session.get('id', '')
                username = session.get('username', 'N/A')
                domain = session.get('domain', 'N/A')
                last_active = format_time_ago(session.get('last_active', ''))
                last_check = format_time_ago(session.get('last_check', ''))
                created_at = format_time_ago(session.get('created_at', ''))
                cookie_count = session.get('cookie_count', 0)
                
                # Display session data
                self.screen.addstr(row, x + SESSION_POSITIONS[0], str(session_id))
                self.screen.addstr(row, x + SESSION_POSITIONS[1], username)
                self.screen.addstr(row, x + SESSION_POSITIONS[2], domain)
                self.screen.addstr(row, x + SESSION_POSITIONS[3], last_active)
                self.screen.addstr(row, x + SESSION_POSITIONS[4], last_check)
                self.screen.addstr(row, x + SESSION_POSITIONS[5], created_at)
                self.screen.addstr(row, x + SESSION_POSITIONS[6], str(cookie_count))
                
                row += 1
        
        return next_y  # Return the next Y position
    
    def render_system_view(self, y, x):
        """Render the system monitoring view"""
        self.screen.addstr(y, x, "=== SYSTEM MONITORING ===", curses.A_BOLD)
        
        # Process information
        process_info = self.system_monitor.get_process_info()
        
        self.screen.addstr(y + 1, x, f"Process: PID {process_info.get('pid', 'N/A')}")
        self.screen.addstr(y + 1, x + 25, f"Name: {process_info.get('name', 'N/A')}")
        self.screen.addstr(y + 1, x + 50, f"Status: {process_info.get('status', 'N/A')}")
        
        # Memory information
        rss = format_bytes(process_info.get('memory_info', {}).get('rss', 0))
        vms = format_bytes(process_info.get('memory_info', {}).get('vms', 0))
        
        self.screen.addstr(y + 2, x, f"Memory: {self.system_monitor.memory_percent:.1f}%")
        self.screen.addstr(y + 2, x + 25, f"RSS: {rss}")
        self.screen.addstr(y + 2, x + 50, f"VMS: {vms}")
        
        # CPU and thread information
        threads = process_info.get('threads', 0)
        
        self.screen.addstr(y + 3, x, f"CPU: {self.system_monitor.cpu_percent:.1f}%")
        self.screen.addstr(y + 3, x + 25, f"Threads: {threads}")
        
        # I/O information if available
        if 'io' in process_info:
            io = process_info['io']
            read_bytes = format_bytes(io.get('read_bytes', 0))
            write_bytes = format_bytes(io.get('write_bytes', 0))
            read_rate = format_bytes(io.get('read_rate', 0)) + "/s"
            write_rate = format_bytes(io.get('write_rate', 0)) + "/s"
            
            self.screen.addstr(y + 4, x, f"Total Read: {read_bytes}")
            self.screen.addstr(y + 4, x + 25, f"Total Write: {write_bytes}")
            self.screen.addstr(y + 4, x + 50, f"Read Rate: {read_rate}")
            self.screen.addstr(y + 4, x + 75, f"Write Rate: {write_rate}")
        
        # Database information
        db_size = format_bytes(self.db_monitor.file_size)
        growth_rate = format_bytes(self.db_monitor.growth_rate) + "/s" if self.db_monitor.growth_rate > 0 else "0 B/s"
        
        self.screen.addstr(y + 6, x, "=== DATABASE METRICS ===", curses.A_BOLD)
        self.screen.addstr(y + 7, x, f"Size: {db_size}")
        self.screen.addstr(y + 7, x + 25, f"Growth: {growth_rate}")
        
        # Table sizes
        self.screen.addstr(y + 8, x, "Table Counts:")
        table_pos = x + 15
        for table, count in self.db_monitor.tables.items():
            if table_pos + len(table) + 10 < self.max_x:
                self.screen.addstr(y + 8, table_pos, f"{table}: {count}")
                table_pos += len(table) + 15
        
        # Display database indexes
        next_y = y + 10
        self.screen.addstr(next_y, x, "=== INDEXES ===", curses.A_BOLD)
        
        row = next_y + 1
        if not self.db_monitor.index_stats:
            self.screen.addstr(row, x, "No index information available")
            row += 1
        else:
            for table, indexes in self.db_monitor.index_stats.items():
                if row >= self.max_y - 2:
                    break
                    
                self.screen.addstr(row, x, f"Table: {table}", curses.color_pair(COLOR_CYAN))
                row += 1
                
                for idx in indexes:
                    if row >= self.max_y - 2:
                        break
                        
                    idx_name = idx.get('name', 'Unknown')
                    self.screen.addstr(row, x + 2, f"- {idx_name}")
                    row += 1
        
        # Display performance data if available
        perf_data = self.db_monitor.analyze_performance()
        if perf_data:
            next_y = row + 1
            self.screen.addstr(next_y, x, "=== PERFORMANCE ===", curses.A_BOLD)
            
            # Integrity check
            integrity = perf_data.get('integrity_check', ['Unknown'])
            integrity_msg = f"Integrity: {integrity[0] if integrity else 'Unknown'}"
            self.screen.addstr(next_y + 1, x, integrity_msg)
            
            # Show child processes if available
            if 'children' in process_info and process_info['children']:
                next_y += 3
                self.screen.addstr(next_y, x, "=== CHILD PROCESSES ===", curses.A_BOLD)
                
                # Headers
                headers = ["PID", "Name", "Status", "CPU %", "Memory %"]
                positions = [x, x + 10, x + 25, x + 40, x + 55]
                
                for i, header in enumerate(headers):
                    self.screen.addstr(next_y + 1, positions[i], header, curses.A_UNDERLINE)
                
                # Child processes
                row = next_y + 2
                for child in process_info['children']:
                    if row >= self.max_y - 2:
                        break
                        
                    child_pid = child.get('pid', 'N/A')
                    child_name = child.get('name', 'N/A')
                    child_status = child.get('status', 'N/A')
                    child_cpu = f"{child.get('cpu_percent', 0):.1f}%"
                    child_mem = f"{child.get('memory_percent', 0):.1f}%"
                    
                    self.screen.addstr(row, positions[0], str(child_pid))
                    self.screen.addstr(row, positions[1], child_name)
                    self.screen.addstr(row, positions[2], child_status)
                    self.screen.addstr(row, positions[3], child_cpu)
                    self.screen.addstr(row, positions[4], child_mem)
                    
                    row += 1
        
        return next_y  # Return the next Y position
		
    def render_logs_view(self, y, x):
        """Render the logs view section"""
        self.screen.addstr(y, x, "=== APPLICATION LOGS ===", curses.A_BOLD)
        
        if not self.log_handler or not hasattr(self.log_handler, 'logs'):
            self.screen.addstr(y + 1, x, "No log handler provided or logs available.")
            return y + 2
        
        # Get logs from the handler
        logs = self.log_handler.logs
        
        if not logs:
            self.screen.addstr(y + 1, x, "No logs available.")
            return y + 2
        
        # Calculate available space
        available_height = self.max_y - y - 2  # Leave 1 line for footer
        
        # Apply scroll offset
        start_idx = max(0, len(logs) - available_height - self.scroll_offset)
        end_idx = min(len(logs), start_idx + available_height)
        
        # Display scrollbar info
        if len(logs) > available_height:
            scroll_info = f"Showing {start_idx+1}-{end_idx} of {len(logs)} logs"
            self.screen.addstr(y + 1, x, scroll_info)
            log_start_y = y + 2
        else:
            log_start_y = y + 1
        
        # Display logs with proper colors
        for i, (level, log_entry) in enumerate(logs[start_idx:end_idx]):
            row = log_start_y + i
            if row >= self.max_y - 1:
                break
                
            # Truncate log entry to fit screen width
            max_width = self.max_x - x - 1
            if len(log_entry) > max_width:
                log_entry = log_entry[:max_width-3] + "..."
            
            # Set color based on log level
            if level == 'ERROR':
                self.screen.addstr(row, x, log_entry, curses.color_pair(COLOR_RED))
            elif level == 'WARNING':
                self.screen.addstr(row, x, log_entry, curses.color_pair(COLOR_YELLOW))
            elif level == 'INFO':
                self.screen.addstr(row, x, log_entry)
            elif level == 'DEBUG':
                self.screen.addstr(row, x, log_entry, curses.color_pair(COLOR_CYAN))
            else:
                self.screen.addstr(row, x, log_entry)
        
        return log_start_y + min(available_height, len(logs[start_idx:end_idx]))
    
    def render_footer(self):
        """Render the footer with help text and stats"""
        # Calculate refresh countdown
        if self.last_update_time:
            time_since_update = (datetime.now() - self.last_update_time).total_seconds()
            countdown = max(0, self.refresh_interval - time_since_update)
            countdown_str = f"Next refresh in {countdown:.1f}s"
        else:
            countdown_str = f"Refresh interval: {self.refresh_interval}s"
        
        # Create footer with help text
        help_text = "q: Quit | r: Refresh | F1-F5: Change view | ↑/↓: Scroll"
        
        # Add footer with reverse video
        footer_text = f"{help_text} | {countdown_str}"
        self.screen.addstr(self.max_y - 1, 0, footer_text.ljust(self.max_x - 1), curses.A_REVERSE)
    
    def handle_input(self, key):
        """Handle user input and update view state"""
        if key == ord('q'):
            # Quit
            return False
        elif key == ord('r'):
            # Force refresh
            self.update_data()
        elif key == curses.KEY_F1:
            # Main view
            self.current_view = 'main'
            self.selected_index = 0
            self.scroll_offset = 0
        elif key == curses.KEY_F2:
            # Queries view
            self.current_view = 'queries'
            self.selected_index = 0
            self.scroll_offset = 0
        elif key == curses.KEY_F3:
            # Sessions view
            self.current_view = 'sessions'
            self.selected_index = 0
            self.scroll_offset = 0
        elif key == curses.KEY_F4:
            # System view
            self.current_view = 'system'
            self.selected_index = 0
            self.scroll_offset = 0
        elif key == curses.KEY_F5:
            # Logs view
            self.current_view = 'logs'
            self.selected_index = 0
            self.scroll_offset = 0
        elif key == curses.KEY_UP:
            # Scroll up
            self.scroll_offset = min(100, self.scroll_offset + 1)  # Limit scrolling
        elif key == curses.KEY_DOWN:
            # Scroll down
            self.scroll_offset = max(0, self.scroll_offset - 1)
        
        return True
    
    def draw_screen(self):
        """Draw the screen with current view and data"""
        self.screen.clear()
        
        # Update screen dimensions
        self.max_y, self.max_x = self.screen.getmaxyx()
        
        # Render header (common to all views)
        next_y = self.render_header(0, 0)
        
        # Render the appropriate view based on current_view
        if self.current_view == 'main':
            self.render_main_view(next_y, 0)
        elif self.current_view == 'queries':
            self.render_query_view(next_y, 0)
        elif self.current_view == 'sessions':
            self.render_session_view(next_y, 0)
        elif self.current_view == 'system':
            self.render_system_view(next_y, 0)
        elif self.current_view == 'logs':
            self.render_logs_view(next_y, 0)
        
        # Render footer (common to all views)
        self.render_footer()
        
        # Refresh the screen
        self.screen.refresh()
    
    def run(self):
        """Main function to run the terminal UI"""
        try:
            # Initialize curses
            self.screen = SafeScreen(curses.initscr())
            
            # Set up curses options
            curses.noecho()  # Don't echo user input
            curses.cbreak()  # React to keys instantly without Enter
            self.screen.keypad(True)  # Enable keypad mode to get F1, arrow keys etc.
            curses.curs_set(0)  # Hide cursor
            
            # Setup colors
            self.setup_colors()
            
            # Initial data update
            self.update_data()
            
            # Main loop
            last_refresh_time = time.time()
            
            while self.running:
                # Draw the screen
                self.draw_screen()
                
                # Check if it's time to refresh data
                current_time = time.time()
                if current_time - last_refresh_time >= self.refresh_interval:
                    self.update_data()
                    last_refresh_time = current_time
                
                # Wait for user input with timeout
                self.screen.timeout(100)  # 100ms timeout
                key = self.screen.getch()
                
                # Handle input if a key was pressed
                if key != -1:
                    self.running = self.handle_input(key)
            
        except Exception as e:
            log.exception(f"Error in terminal UI: {e}")
        finally:
            # Clean up curses
            if self.screen:
                self.screen.keypad(False)
                curses.nocbreak()
                curses.echo()
                curses.endwin()
                
            log.info("Terminal UI closed")