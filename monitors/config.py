"""
Configuration and logging module for SplunkVoyager Terminal Monitor
"""

import os
import sys
import logging
from pathlib import Path

# Create logger
log = logging.getLogger('splunkvoyager-monitor')

def setup_logging(log_file=None, log_level=logging.INFO):
    """Configure logging for the monitor"""
    log.setLevel(log_level)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Add file handler if log_file is specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        log.addHandler(file_handler)
    
    # Always add stderr handler for critical errors
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(logging.ERROR)
    stderr_handler.setFormatter(formatter)
    log.addHandler(stderr_handler)

def format_bytes(bytes_value):
    """Format bytes as human-readable string"""
    if bytes_value is None:
        return "N/A"
    
    bytes_value = float(bytes_value)
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} PB"

def format_time_ago(timestamp_str):
    """Format a timestamp as a human-readable time ago string"""
    if not timestamp_str:
        return "N/A"
        
    from datetime import datetime
    try:
        timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        now = datetime.now()
        diff = now - timestamp
        
        if diff.days > 0:
            return f"{diff.days}d ago"
        elif diff.seconds >= 3600:
            return f"{diff.seconds // 3600}h ago"
        elif diff.seconds >= 60:
            return f"{diff.seconds // 60}m ago"
        else:
            return f"{diff.seconds}s ago"
    except:
        return timestamp_str

def truncate_text(text, max_length):
    """Truncate text to the specified length with ellipsis"""
    if not text:
        return ""
    if len(text) <= max_length:
        return text
    return text[:max_length-3] + "..."

# Check if running in standalone mode
STANDALONE_MODE = os.environ.get('SPLUNKVOYAGER_STANDALONE', 'false').lower() == 'true'

# Color definitions
COLOR_GREEN = 1
COLOR_RED = 2
COLOR_YELLOW = 3
COLOR_CYAN = 4
COLOR_MAGENTA = 5
COLOR_BLUE = 6
COLOR_WHITE = 7

# Common column headers and positions
QUERY_HEADERS = ["ID", "User", "Domain", "Progress", "SID", "Started", "Query"]
QUERY_POSITIONS = [0, 5, 20, 35, 45, 65, 80]

SESSION_HEADERS = ["ID", "Username", "Domain", "Last Active", "Last Check", "Created", "Cookies", "Beacon"]
SESSION_POSITIONS = [0, 5, 20, 40, 60, 80, 100, 110]

EXECUTIONS_HEADERS = ["ID", "User", "Domain", "Status", "Duration", "Executed", "Query"]
EXECUTIONS_POSITIONS = [0, 5, 20, 35, 45, 65, 80]

FAILED_HEADERS = ["ID", "User", "Domain", "Failed", "Error", "Query"]
FAILED_POSITIONS = [0, 5, 20, 35, 55, 80]