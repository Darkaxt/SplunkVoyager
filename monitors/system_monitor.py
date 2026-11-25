"""
System monitor for SplunkVoyager Terminal Monitor
"""

import os
import psutil
import time
from datetime import datetime, timedelta

from monitors.config import log, format_bytes

class SystemMonitor:
    """Monitor system resources used by the SplunkVoyager application"""
    
    def __init__(self, target_pid=None):
        """
        Initialize system monitor
        
        Args:
            target_pid (int): PID of process to monitor, if None uses the current script
        """
        self.target_pid = target_pid or os.getpid()
        self.process = None
        self.cpu_percent = 0
        self.memory_percent = 0
        self.memory_info = None
        self.io_counters = None
        self.last_io_counters = None
        self.io_rate = {'read_bytes': 0, 'write_bytes': 0}
        self.start_time = None
        self.uptime = 0
        self.network_io = {}
        self.history = {
            'cpu': [],
            'memory': [],
            'io_read': [],
            'io_write': []
        }
        self.max_history_points = 60  # Keep 60 data points
        
        self._connect_to_process()
    
    def _connect_to_process(self):
        """Connect to the target process"""
        try:
            self.process = psutil.Process(self.target_pid)
            self.start_time = datetime.fromtimestamp(self.process.create_time())
            log.info(f"Connected to process PID {self.target_pid}")
        except psutil.NoSuchProcess:
            log.error(f"Process with PID {self.target_pid} not found")
            self.process = None
        except Exception as e:
            log.error(f"Error connecting to process: {e}")
            self.process = None
    
    def update(self):
        """Update system statistics"""
        try:
            # Reconnect if process not found
            if not self.process:
                self._connect_to_process()
                if not self.process:
                    return
            
            # Check if process still exists
            if not self.process.is_running():
                log.warning(f"Process {self.target_pid} is no longer running")
                self.process = None
                return
            
            # Update uptime
            self.uptime = (datetime.now() - self.start_time).total_seconds()
            
            # CPU and memory
            self.cpu_percent = self.process.cpu_percent(interval=None)
            self.memory_percent = self.process.memory_percent()
            self.memory_info = self.process.memory_info()
            
            # I/O counters
            self.last_io_counters = self.io_counters
            try:
                self.io_counters = self.process.io_counters()
                
                # Calculate I/O rates
                if self.last_io_counters:
                    read_diff = self.io_counters.read_bytes - self.last_io_counters.read_bytes
                    write_diff = self.io_counters.write_bytes - self.last_io_counters.write_bytes
                    self.io_rate = {
                        'read_bytes': read_diff,
                        'write_bytes': write_diff
                    }
            except:
                # Some platforms don't support I/O counters
                pass
            
            # Network I/O (for main SplunkVoyager process only)
            try:
                self.network_io = self.process.connections()
            except:
                pass
            
            # Update history
            self._update_history()
            
        except psutil.NoSuchProcess:
            log.error(f"Process {self.target_pid} no longer exists")
            self.process = None
        except Exception as e:
            log.error(f"Error updating system stats: {e}")
    
    def _update_history(self):
        """Update monitoring history"""
        self.history['cpu'].append(self.cpu_percent)
        self.history['memory'].append(self.memory_percent)
        
        if self.io_rate.get('read_bytes') is not None:
            self.history['io_read'].append(self.io_rate['read_bytes'])
        else:
            self.history['io_read'].append(0)
            
        if self.io_rate.get('write_bytes') is not None:
            self.history['io_write'].append(self.io_rate['write_bytes'])
        else:
            self.history['io_write'].append(0)
        
        # Trim history to max points
        for key in self.history:
            if len(self.history[key]) > self.max_history_points:
                self.history[key] = self.history[key][-self.max_history_points:]
    
    def get_process_info(self):
        """Get detailed process information"""
        if not self.process:
            return {}
            
        try:
            info = {
                'pid': self.process.pid,
                'name': self.process.name(),
                'status': self.process.status(),
                'cpu_percent': self.cpu_percent,
                'memory_percent': self.memory_percent,
                'memory_info': {
                    'rss': self.memory_info.rss if self.memory_info else 0,
                    'vms': self.memory_info.vms if self.memory_info else 0
                },
                'create_time': self.start_time.isoformat() if self.start_time else None,
                'uptime_seconds': self.uptime,
                'uptime_formatted': str(timedelta(seconds=int(self.uptime))),
                'threads': self.process.num_threads(),
                'username': self.process.username(),
                'cwd': self.process.cwd()
            }
            
            # Add I/O information if available
            if self.io_counters:
                info['io'] = {
                    'read_bytes': self.io_counters.read_bytes,
                    'write_bytes': self.io_counters.write_bytes,
                    'read_count': self.io_counters.read_count,
                    'write_count': self.io_counters.write_count,
                    'read_rate': self.io_rate['read_bytes'],
                    'write_rate': self.io_rate['write_bytes']
                }
            
            # Get child processes
            try:
                children = self.process.children(recursive=True)
                info['children'] = [
                    {
                        'pid': child.pid,
                        'name': child.name(),
                        'status': child.status(),
                        'cpu_percent': child.cpu_percent(interval=None),
                        'memory_percent': child.memory_percent()
                    }
                    for child in children
                ]
            except:
                info['children'] = []
            
            return info
            
        except Exception as e:
            log.error(f"Error getting process info: {e}")
            return {}
    
    def get_resource_usage_chart_data(self, points=30):
        """Get resource usage data suitable for charting"""
        return {
            'cpu': self.history['cpu'][-points:],
            'memory': self.history['memory'][-points:],
            'io_read': self.history['io_read'][-points:],
            'io_write': self.history['io_write'][-points:]
        }
    
    def get_system_info(self):
        """Get system-wide information"""
        try:
            info = {
                'cpu_count': psutil.cpu_count(logical=True),
                'physical_cpu_count': psutil.cpu_count(logical=False),
                'cpu_percent': psutil.cpu_percent(interval=None),
                'memory': {
                    'total': psutil.virtual_memory().total,
                    'available': psutil.virtual_memory().available,
                    'percent': psutil.virtual_memory().percent
                },
                'disk': {},
                'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat()
            }
            
            # Get disk information
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    info['disk'][partition.mountpoint] = {
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free,
                        'percent': usage.percent
                    }
                except:
                    pass
            
            return info
            
        except Exception as e:
            log.error(f"Error getting system info: {e}")
            return {}