import os
import json
import datetime
import logging
from pathlib import Path
import requests
from urllib.parse import urlparse
import traceback

# Configure logging
logger = logging.getLogger('splunkvoyager.debug')

# Setup debug directory
BASE_DIR = Path(__file__).resolve().parent.parent.parent
DEBUG_DIR = os.path.join(BASE_DIR, 'debug')
os.makedirs(DEBUG_DIR, exist_ok=True)

# Check if debug mode is enabled
DEBUG_ENABLED = os.environ.get('SPLUNKVOYAGER_DEBUG', 'false').lower() == 'true'

def log_request(url, method, headers=None, params=None, data=None, response=None, error=None):
    """
    Log request and response details to a file
    
    Args:
        url (str): Request URL
        method (str): HTTP method
        headers (dict, optional): Request headers
        params (dict, optional): URL parameters
        data (dict, optional): Request data
        response (requests.Response, optional): Response object
        error (Exception, optional): Exception if request failed
    """
    if not DEBUG_ENABLED:
        return
    
    try:
        # Create a timestamp and sanitized URL for the filename
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f')
        parsed_url = urlparse(url)
        url_part = parsed_url.netloc + parsed_url.path.replace('/', '_')
        if len(url_part) > 50:
            url_part = url_part[:50]  # Truncate if too long
        
        filename = f"{timestamp}_{method}_{url_part}.json"
        filepath = os.path.join(DEBUG_DIR, filename)
        
        # Prepare request data
        request_data = {
            'timestamp': datetime.datetime.now().isoformat(),
            'url': url,
            'method': method,
            'headers': headers,
            'params': params,
            'data': data
        }
        
        # Add response data if available
        if response:
            try:
                response_json = response.json() if response.headers.get('Content-Type', '').find('json') >= 0 else None
            except:
                response_json = None
                
            request_data['response'] = {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content_type': response.headers.get('Content-Type'),
                'text': response.text[:10000] if len(response.text) > 10000 else response.text,  # Truncate if too large
                'json': response_json
            }
        
        # Add error information if available
        if error:
            request_data['error'] = {
                'type': type(error).__name__,
                'message': str(error),
                'traceback': traceback.format_exc()
            }
        
        # Write to file
        with open(filepath, 'w') as f:
            json.dump(request_data, f, indent=2, default=str)
        
        logger.info(f"Debug log saved to {filepath}")
        
    except Exception as e:
        logger.error(f"Error saving debug log: {str(e)}")


# Create a custom requests Session class that logs requests
class LoggingSession(requests.Session):
    """
    A requests Session subclass that logs requests and responses
    """
    def request(self, method, url, **kwargs):
        try:
            response = super().request(method, url, **kwargs)
            log_request(
                url=url,
                method=method,
                headers=kwargs.get('headers'),
                params=kwargs.get('params'),
                data=kwargs.get('data'),
                response=response
            )
            return response
        except Exception as e:
            log_request(
                url=url,
                method=method,
                headers=kwargs.get('headers'),
                params=kwargs.get('params'),
                data=kwargs.get('data'),
                error=e
            )
            raise


def get_session():
    """
    Get a requests session object with logging if debug is enabled
    
    Returns:
        requests.Session: A session object
    """
    if DEBUG_ENABLED:
        return LoggingSession()
    else:
        return requests.Session()