import os
import logging
from pathlib import Path

# Base directories
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = os.path.join(BASE_DIR, 'data')
COOKIE_DIR = os.path.join(DATA_DIR, 'cookies')
LOG_DIR = os.path.join(DATA_DIR, 'logs')

# Ensure directories exist
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(COOKIE_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# Database settings
DB_NAME = 'splunkvoyager.db'
DB_PATH = os.path.join(DATA_DIR, DB_NAME)

# Splunk settings
# Splunk URL, locale and app: data/settings.json via the Settings page (see voyager_settings.py)

# Session settings
BEACON_INTERVAL = 300  # 5 minutes
SESSION_TIMEOUT = 3600  # 1 hour - for when a session is considered stale

# Flask settings
DEBUG = os.environ.get('VOYAGER_DEBUG') == '1'
SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(24).hex()
# Local only by default: this app holds your Splunk session. VOYAGER_HOST=0.0.0.0 exposes it on the network.
HOST = os.environ.get('VOYAGER_HOST', '127.0.0.1')
PORT = int(os.environ.get('VOYAGER_PORT', 8080))

# Logging configuration
LOG_FILE = os.path.join(LOG_DIR, 'splunkvoyager.log')
LOG_LEVEL = logging.INFO
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

# Configure logging
logging.basicConfig(
    level=LOG_LEVEL,
    format=LOG_FORMAT,
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

# Create a logger
logger = logging.getLogger('splunkvoyager')