#!/usr/bin/env python3

import os
import sys
import argparse
import shutil
import threading
import time
import logging
from pathlib import Path
from waitress import serve
from app import create_app
from app.config import HOST, PORT, DEBUG, logger, DB_PATH

def wipe_folders():
    """
    Wipe the data and debug folders for fresh testing
    """
    base_dir = Path(__file__).resolve().parent
    data_dir = os.path.join(base_dir, 'data')
    debug_dir = os.path.join(base_dir, 'debug')
    
    # Wipe data directory (but keep the directory itself)
    if os.path.exists(data_dir):
        logger.info(f"Wiping data directory: {data_dir}")
        for item in os.listdir(data_dir):
            if item in ('investigations', 'settings.json'):
                continue   # investigations and settings are kept; only session state is wiped
            item_path = os.path.join(data_dir, item)
            try:
                if os.path.isfile(item_path):
                    os.unlink(item_path)
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)
                logger.info(f"  Removed: {item}")
            except Exception as e:
                logger.error(f"  Error removing {item}: {str(e)}")
    
    # Wipe debug directory
    if os.path.exists(debug_dir):
        logger.info(f"Wiping debug directory: {debug_dir}")
        for item in os.listdir(debug_dir):
            item_path = os.path.join(debug_dir, item)
            try:
                if os.path.isfile(item_path):
                    os.unlink(item_path)
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)
                logger.info(f"  Removed: {item}")
            except Exception as e:
                logger.error(f"  Error removing {item}: {str(e)}")
    
    # Ensure directories exist again
    os.makedirs(data_dir, exist_ok=True)
    os.makedirs(os.path.join(data_dir, 'cookies'), exist_ok=True)
    os.makedirs(os.path.join(data_dir, 'logs'), exist_ok=True)
    os.makedirs(debug_dir, exist_ok=True)
    
    logger.info("Data and debug directories have been wiped and recreated")

class TerminalLogHandler(logging.Handler):
    """
    Custom logging handler that stores logs for the terminal UI
    """
    def __init__(self, max_logs=100):
        super().__init__()
        self.logs = []
        self.max_logs = max_logs
        
    def emit(self, record):
        log_entry = self.format(record)
        self.logs.append((record.levelname, log_entry))
        # Keep only the most recent logs
        if len(self.logs) > self.max_logs:
            self.logs.pop(0)

def open_browser_when_ready():
    """Open the GUI once the server answers: Settings if no Splunk instance is configured yet."""
    import urllib.request
    import webbrowser
    import voyager_settings
    host = "localhost" if HOST in ("0.0.0.0", "127.0.0.1", "::") else HOST
    page = "investigations" if voyager_settings.load()["instances"] else "settings"
    url = f"http://{host}:{PORT}/{page}"
    for _ in range(60):
        try:
            urllib.request.urlopen(f"http://{host}:{PORT}/api/settings", timeout=2).read()
            webbrowser.open(url)
            logger.info(f"Opened {url}")
            return
        except Exception:
            time.sleep(0.5)
    logger.warning(f"Web interface did not answer; open {url} yourself")


RESTART = threading.Event()     # set by the updater: leave the dashboard and exit with updater.RESTART_CODE
_UI = {}


def request_restart():
    RESTART.set()
    ui = _UI.get("terminal")
    if ui is not None:
        ui.running = False          # the dashboard loop ends within 100 ms


def confirm_when_ready():
    """Once the web interface answers, an update that was just installed counts as good."""
    import urllib.request
    import updater
    host = "localhost" if HOST in ("0.0.0.0", "127.0.0.1", "::") else HOST
    for _ in range(120):
        try:
            urllib.request.urlopen(f"http://{host}:{PORT}/api/settings", timeout=2).read()
            updater.confirm_started()
            return
        except Exception:
            time.sleep(0.5)


def supervise(argv):
    """
    Runs the server as a child process and restarts it when it asks to (after an update), so the console
    stays with one process. If the server dies right after an update, the update is rolled back.
    """
    import subprocess
    import updater
    import voyager_settings
    log = lambda m: print(f"[updater] {m}", flush=True)
    s = voyager_settings.load()
    if s.get("auto_update") == "apply" and updater.is_checkout():
        log("checking GitHub for a new version...")
        if updater.check() and not updater.status["blocked"]:
            updater.apply(log)
        elif updater.status["blocked"] or updater.status["error"]:
            log(updater.status["blocked"] or updater.status["error"])
    env = dict(os.environ, VOYAGER_CHILD="1")
    args = [a for a in argv if a != "--wipe"]      # already done here, once
    while True:
        started = time.time()
        p = subprocess.Popen([sys.executable, os.path.abspath(__file__)] + args, env=env)
        while True:
            try:
                rc = p.wait()
                break
            except KeyboardInterrupt:
                continue            # Ctrl+C reaches the server too; wait for it to finish
        if "--no-browser" not in args:
            args.append("--no-browser")     # don't open a new tab on every restart
        if rc == updater.RESTART_CODE:
            log("restarting with the new version")
            continue
        if rc != 0 and time.time() - started < 90 and updater.rollback(log):
            continue
        return rc


def start_application(open_browser=True):
    """
    Start the application with the terminal UI
    """
    # --- FIX for NameError: Ensure this is defined before use ---
    # Create a log handler for terminal UI
    terminal_log_handler = TerminalLogHandler()
    terminal_log_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    terminal_log_handler.setLevel(logging.INFO)
    # Add the handler to the logger
    logger.addHandler(terminal_log_handler)

    # Start the web app using Waitress in a background thread
    app = create_app()
    web_thread = threading.Thread(
        target=lambda: serve(
            app,
            host=HOST,
            port=PORT,
            threads=8
        ),
        # --- FIX for Shutdown: Make thread daemon ---
        daemon=True
    )
    web_thread.start()
    logger.info(f"Started SplunkVoyager web interface with Waitress on {HOST}:{PORT}")
    if open_browser:
        threading.Thread(target=open_browser_when_ready, daemon=True).start()
    threading.Thread(target=confirm_when_ready, daemon=True).start()
    def compress_finished_windows():
        """Export runs started by an older exporter (still running) get their finished windows compressed here."""
        import time as _t
        import exportfiles
        from datetime import datetime as _dt
        from app.services.workbench import INV_ROOT

        def job_log(folder):
            """The log of the job that owns an export folder (network/<job id>/export -> jobs/<job id>/log.txt)."""
            try:
                rel = Path(folder).resolve().relative_to(INV_ROOT.resolve())
            except ValueError:
                return None
            inv = INV_ROOT / rel.parts[0]
            for name in rel.parts[1:]:
                lp = inv / "jobs" / name / "log.txt"
                if lp.is_file():
                    def write(msg, lp=lp):
                        logger.info(msg)
                        with open(lp, "a", encoding="utf-8") as fh:
                            fh.write(f"[{_dt.now():%H:%M:%S}] {msg}\n")
                    return write
            return None
        while True:
            try:
                if INV_ROOT.is_dir():
                    exportfiles.sweep(INV_ROOT, logger.info, job_log)
            except Exception as e:
                logger.error(f"Compressing finished export windows: {e}")
            _t.sleep(120)
    threading.Thread(target=compress_finished_windows, daemon=True, name="packer").start()
    try:
        import updater
        import voyager_settings
        s = voyager_settings.load()
        updater.restart_hook = request_restart
        if os.environ.get("VOYAGER_CHILD") == "1":      # only under the supervisor, which does the restart
            threading.Thread(target=updater.loop, daemon=True, name="updater",
                             args=(request_restart, logger.info, s.get("auto_update", "apply"),
                                   s.get("update_interval", 30))).start()
    except Exception as e:
        logger.error(f"Updater not started: {e}")

    tui_running = False
    try:
        from monitors.terminal_ui import TerminalUI
        from monitors.config import setup_logging
        logs_dir = Path(__file__).resolve().parent / 'data' / 'logs'
        log_path = logs_dir / 'terminal_monitor.log'
        setup_logging(log_path)

        terminal = TerminalUI(
            db_path=DB_PATH,
            refresh_interval=2,
            log_handler=terminal_log_handler # Should now work if defined above
        )
        tui_running = True
        _UI["terminal"] = terminal
        terminal.run() # Blocks here until TUI exits (e.g., via Ctrl+C or quit command)

    except ImportError as e:
        logger.error(f"Terminal UI components not found: {e}. Falling back to console output.")
        print(f"Error: Terminal UI components not found: {e}")
        print(f"Running with console output only.")
        try:
            while not RESTART.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    except Exception as e:
        # This will catch the NameError if terminal_log_handler wasn't defined
        logger.error(f"Error starting terminal UI: {e}", exc_info=True) # Add exc_info for more details
        print(f"Error starting terminal UI: {e}")
        print(f"Running with console output only.")
        try:
            while not RESTART.is_set():     # keep serving until Ctrl+C or an update restart
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    finally:
        # --- FIX for Shutdown: Remove the join for daemon thread ---
        if tui_running:
             logger.info("Terminal UI exited.")
        else:
             logger.info("Terminal UI failed to start.")
        # No longer waiting for the web_thread here.
        # When this finally block finishes, the main thread ends.
        # Since web_thread is a daemon, Python will terminate it.
        logger.info("Main thread exiting. Daemon web server thread will be terminated.")

def main():
    """
    Main entry point for the application
    """
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Run the SplunkVoyager application')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode with request logging')
    parser.add_argument('--no-browser', action='store_true', help="Don't open the web interface in the browser")
    parser.add_argument('--no-supervisor', action='store_true',
                        help="Run the server directly (no automatic restart after updates)")
    parser.add_argument('--wipe', action='store_true', help='Wipe session data (cookies, database, logs) and debug folders; investigations and settings are kept')
    args = parser.parse_args()
    
    try:
        # Wipe folders if requested
        if args.wipe:
            wipe_folders()
        
        # Set debug environment variable if --debug flag is passed
        if args.debug:
            os.environ['SPLUNKVOYAGER_DEBUG'] = 'true'
            logger.info("Debug mode enabled - requests will be logged")
        
        # Ensure DB_PATH environment variable is set for terminal UI
        os.environ['SPLUNKVOYAGER_DB'] = str(DB_PATH)
        
        # Start the application with terminal UI
        if os.environ.get("VOYAGER_CHILD") != "1" and not args.no_supervisor:
            sys.exit(supervise(sys.argv[1:]))
        start_application(open_browser=not args.no_browser)
        if RESTART.is_set():
            import updater
            sys.exit(updater.RESTART_CODE)
            
    except Exception as e:
        logger.error(f"Error starting application: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()