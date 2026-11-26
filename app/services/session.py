import requests
import time
import threading
import json
import os
from datetime import datetime
from app.utils.debug import log_request, get_session

from voyager_settings import splunk_url, use_instance
from app.config import (
    BEACON_INTERVAL, 
    COOKIE_DIR,
    logger
)
from app.models.database import Session, Cookie, get_connection

# Dictionary to track active beacon threads
active_beacons = {}

# Check if debug mode is enabled
DEBUG_ENABLED = os.environ.get('SPLUNKVOYAGER_DEBUG', 'false').lower() == 'true'

def cookies_to_header(cookies):
    """Convert cookies dict to header string"""
    if not cookies:
        return ""
        
    if isinstance(cookies, dict):
        # Process cookies from Tampermonkey GM_cookie format if needed
        if any(isinstance(v, dict) and 'value' in v for v in cookies.values()):
            return '; '.join([f"{k}={v['value']}" for k, v in cookies.items() if isinstance(v, dict) and 'value' in v])
        else:
            return '; '.join([f"{k}={v}" for k, v in cookies.items()])
    
    return cookies

def validate_session(cookies, domain):
    """
    Validate a Splunk session using the cookies. Returns False if functionally invalid (e.g., unknown user).

    Args:
        cookies (dict or str): The cookies to use for validation
        domain (str): The domain name

    Returns:
        tuple: (is_functionally_valid, username, data)
    """
    try:
        with use_instance(domain):    # the instance whose host this cookie domain belongs to
            check_url = splunk_url("config")
        headers = {
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cookie': cookies_to_header(cookies) # Ensure this helper exists/works
        }

        logger.info(f"Validating session for {domain} at {check_url}")
        session = get_session() # Ensure this helper exists/works
        response = session.get(check_url, headers=headers, timeout=10)

        if response.status_code == 200:
            try:
                data = response.json()
                username = data.get('USERNAME', 'unknown') # Or data.get('entry', [{}])[0].get('content', {}).get('USERNAME', 'unknown') depending on exact Splunk response structure

                # --- Check for functionally invalid username ---
                if not username or username.lower() == 'unknown':
                     logger.warning(f"Session check OK (HTTP 200), but user is '{username}'. Session functionally invalid.")
                     return False, username, data # Return False for validity
                else:
                     logger.info(f"Session check OK (HTTP 200) for user: {username}. Session functionally valid.")
                     return True, username, data # Return True for validity

            except json.JSONDecodeError:
                logger.error(f"Session check failed for {domain}: Could not parse JSON response (HTTP 200).")
                return False, None, None
            except Exception as e:
                 logger.error(f"Session check failed for {domain}: Error processing response (HTTP 200): {str(e)}")
                 return False, None, None
        else:
            logger.warning(f"Session validation failed for {domain} with status code: {response.status_code}")
            return False, None, None

    except requests.exceptions.Timeout:
         logger.error(f"Session validation timed out for {domain} at {check_url}")
         return False, None, None
    except requests.exceptions.RequestException as e:
        logger.error(f"Error validating session for {domain}: Network error {str(e)}")
        return False, None, None
    except Exception as e:
        logger.exception(f"Unexpected error validating session for {domain}: {str(e)}") # Use logger.exception
        return False, None, None

KEEPALIVE_RETRY = 60   # seconds between tries while Splunk can't be reached


def keepalive_ping(cookies, domain):
    """
    One request that keeps both halves of a Splunk Web session alive: it goes through Splunk Web (its idle
    timer) to splunkd (the other idle timer). /config alone is answered by Splunk Web and lets splunkd's
    session expire.

    Returns ("ok", username) | ("expired", reason) | ("error", reason) - "error" means Splunk couldn't be
    reached (network, VPN, laptop waking up): try again, the session may well still be alive.
    """
    try:
        with use_instance(domain):
            url = splunk_url("splunkd/__raw/services/authentication/current-context")
        r = get_session().get(url, params={"output_mode": "json"}, timeout=20,
                              headers={"Accept": "application/json", "Cookie": cookies_to_header(cookies)})
    except requests.exceptions.RequestException as e:
        return "error", f"Splunk not reachable: {e.__class__.__name__}"
    except RuntimeError as e:          # no instance configured
        return "error", str(e)
    if r.status_code in (401, 403):
        return "expired", f"HTTP {r.status_code}"
    if r.status_code >= 400:
        return "error", f"HTTP {r.status_code}"
    try:
        user = r.json()["entry"][0]["content"].get("username")
    except (ValueError, KeyError, IndexError, TypeError):
        # Splunk Web's login page (HTML) instead of JSON: the web session is gone
        return "expired", "login page returned"
    return ("ok", user) if user else ("expired", "no user in session")


def session_beacon(domain, session_id):
    """
    Keeps a session alive while Voyager runs: a request through Splunk Web to splunkd every BEACON_INTERVAL.
    Network errors don't end it (it retries every minute); only Splunk saying the session is gone does, and
    then the keep-alive tab is asked to reload.

    Args:
        domain (str): The domain name
        session_id (int): The session ID
    """
    beacon_key = f"{domain}_{session_id}"

    while beacon_key in active_beacons and active_beacons[beacon_key]:
        wait = BEACON_INTERVAL
        try:
            # Get the session from the database
            session = Session.get_by_id(session_id)
            if not session:
                logger.error(f"Beacon: Session {session_id} not found")
                break
                
            # Get the cookies for this session
            cookies = Cookie.get_for_session(session_id)
            if not cookies:
                logger.error(f"Beacon: No cookies found for session {session_id}")
                break
                
            state, detail = keepalive_ping(cookies, domain)
            if state == "ok":
                Session.update_status(session_id, True)
                logger.info(f"Keep-alive: session for {domain} (ID: {session_id}) active as {detail}")
            elif state == "expired":
                Session.update_status(session_id, False)
                logger.warning(f"Keep-alive: session for {domain} (ID: {session_id}) ended ({detail}); "
                               f"asking the keep-alive tab to reload")
                try:
                    from app.routes.api import request_browser_refresh
                    request_browser_refresh(f"session for {domain} ended ({detail})")
                except Exception as e:
                    logger.error(f"Keep-alive: could not request a tab reload: {e}")
                active_beacons[beacon_key] = False
                break
            else:
                logger.warning(f"Keep-alive: {domain} (ID: {session_id}): {detail}; trying again in {KEEPALIVE_RETRY}s")
                wait = KEEPALIVE_RETRY

        except Exception as e:
            logger.error(f"Keep-alive error for {domain} (ID: {session_id}): {e}; trying again in {KEEPALIVE_RETRY}s")
            wait = KEEPALIVE_RETRY

        time.sleep(wait)

def start_beacon(domain, session_id):
    """
    Start a new beacon thread for a session
    
    Args:
        domain (str): The domain name
        session_id (int): The session ID
        
    Returns:
        bool: True if started successfully, False otherwise
    """
    beacon_key = f"{domain}_{session_id}"
    
    # Stop any existing beacon for this session
    stop_beacon(domain, session_id)
    
    # Start a new beacon thread
    active_beacons[beacon_key] = True
    beacon_thread = threading.Thread(
        target=session_beacon,
        args=(domain, session_id),
        daemon=True
    )
    beacon_thread.start()
    
    logger.info(f"Started beacon for {domain} (ID: {session_id})")
    return True

def stop_beacon(domain, session_id):
    """
    Stop a beacon thread for a session
    
    Args:
        domain (str): The domain name
        session_id (int): The session ID
    """
    beacon_key = f"{domain}_{session_id}"
    
    if beacon_key in active_beacons:
        active_beacons[beacon_key] = False
        logger.info(f"Stopped beacon for {domain} (ID: {session_id})")

def process_cookies(domain, cookies):
    """
    Process cookies: validate session, ensure only ONE session record per
    username@domain exists, update/create it, manage cookies, and handle beacon.

    Args:
        domain (str): The domain name
        cookies (dict): The cookies from the client

    Returns:
        tuple: (session_id, is_valid, username)
    """
    # --- 1. Process incoming cookie format ---
    processed_cookies = {}
    # Use lower() on domain from the start for consistency
    domain_lower = domain.lower() if domain else None

    if cookies and isinstance(cookies, dict) and any(isinstance(v, dict) and 'value' in v for v in cookies.values()):
        for name, cookie_data in cookies.items():
            if isinstance(cookie_data, dict) and 'value' in cookie_data:
                processed_cookies[name] = cookie_data['value']
    else:
        processed_cookies = cookies if cookies else {} # Ensure it's a dict

    if not processed_cookies:
         logger.warning(f"No cookies provided or processed for domain {domain_lower}")
         return None, False, None

    # --- 2. Validate the session ---
    is_valid, username, session_data = validate_session(processed_cookies, domain_lower)

    # Ensure username is also consistently cased if needed (e.g., lower)
    username_lower = username.lower() if username else None

    session_id = None
    existing_session = None

    # --- 3. Find THE existing session for this user/domain ---
    try:
        # Use consistently cased values for lookup
        existing_session = Session.get_latest_for_user_domain(username_lower, domain_lower)
    except Exception as e:
        logger.error(f"DATABASE ERROR fetching session for {username_lower}@{domain_lower}: {str(e)}")
        # Critical error, cannot proceed reliably
        return None, False, username

    # --- 4. Handle based on existing session and validation status ---
    if existing_session:
        session_id = existing_session['id']
        logger.info(f"Found existing session {session_id} for {username_lower}@{domain_lower}.")

        if is_valid:
            # --- 4a. Existing session found, VALID cookies ---
            logger.info(f"Session {session_id} is valid. Updating status and cookies.")
            # Update status (reactivates, updates last_check, last_active)
            Session.update_status(session_id, True)

            # Replace cookies: Delete old, Add new
            logger.info(f"Replacing cookies for session {session_id}.")
            if not Cookie.delete_for_session(session_id):
                 logger.error(f"Failed to delete old cookies for session {session_id}. Aborting cookie update.")
                 # Decide how critical this is - maybe still start beacon?
            elif not Cookie.add_cookies(session_id, processed_cookies):
                 logger.error(f"Failed to add new cookies for session {session_id} after deleting old ones.")
                 # Cookies are now missing! Critical state. Maybe mark inactive?
                 Session.update_status(session_id, False)
                 return session_id, False, username # Return error state

            # Ensure beacon is running
            start_beacon(domain_lower, session_id)

        else:
            # --- 4b. Existing session found, INVALID cookies ---
            logger.warning(f"Session {session_id} is now invalid for {username_lower}@{domain_lower}. Deactivating and clearing cookies.")
            # Deactivate session
            Session.update_status(session_id, False)
            # Stop any running beacon
            stop_beacon(domain_lower, session_id)
            # Clean up cookies for the now-invalid session
            Cookie.delete_for_session(session_id)
            # is_valid is already False, session_id is known

    else: # No existing session found
        logger.info(f"No existing session found for {username_lower}@{domain_lower}.")
        if is_valid:
            # --- 4c. No existing session, VALID cookies ---
            logger.info("Creating new session.")
            try:
                # Create new session record, ensure domain/username use consistent case
                session_id = Session.create(domain_lower, username_lower, is_active=True)
                logger.info(f"Created new session {session_id} for {username_lower}@{domain_lower}.")

                # Add cookies for the new session
                if not Cookie.add_cookies(session_id, processed_cookies):
                     logger.error(f"Failed to add cookies for NEW session {session_id}. Marking inactive.")
                     # Session exists but has no cookies, mark inactive immediately
                     Session.update_status(session_id, False)
                     return session_id, False, username # Return error state
                else:
                     # Start beacon ONLY if cookies were added successfully
                     start_beacon(domain_lower, session_id)

            except sqlite3.IntegrityError as ie:
                 logger.error(f"DATABASE INTEGRITY ERROR creating session for {username_lower}@{domain_lower}. A duplicate might exist despite checks: {str(ie)}")
                 # This indicates a potential race condition or flaw in get_latest_for_user_domain
                 return None, False, username # Cannot proceed reliably
            except Exception as e:
                 logger.error(f"Error creating new session or adding cookies for {username_lower}@{domain_lower}: {str(e)}")
                 return None, False, username

        else:
            # --- 4d. No existing session, INVALID cookies ---
            logger.warning(f"Validation failed for {username_lower}@{domain_lower} and no existing session exists.")
            # Do nothing further, return invalid status
            session_id = None # No session ID relevant

    # --- 5. Save cookies to file (debug/backward compatibility) ---
    if DEBUG_ENABLED:
        # Pass the actual validation status determined above
        save_cookies_to_file(domain_lower, processed_cookies, is_valid, username) # Use original case username for saving if preferred

    # --- 6. Return results ---
    logger.info(f"Finished processing cookies for {username_lower}@{domain_lower}. Result -> Session ID: {session_id}, Valid: {is_valid}")
    # Return original case username if that's expected elsewhere
    return session_id, is_valid, username

def save_cookies_to_file(domain, cookies, is_valid, username):
    """
    Save cookies to a file for backward compatibility
    
    Args:
        domain (str): The domain name
        cookies (dict): The cookies from the client
        is_valid (bool): Whether the session is valid
        username (str): The username associated with the session
    """
    try:
        # Generate filename based on timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{COOKIE_DIR}/{domain}_{timestamp}.json"
        
        # Save to file
        data = {
            'domain': domain,
            'cookies': cookies,
            'is_valid': is_valid,
            'username': username,
            'timestamp': datetime.now().isoformat()
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        # Save as latest.json for easy access
        with open(f"{COOKIE_DIR}/{domain}_latest.json", 'w') as f:
            json.dump(data, f, indent=2)
            
        logger.info(f"Saved cookies to file: {filename}")
        
    except Exception as e:
        logger.error(f"Error saving cookies to file: {str(e)}")

def restore_active_sessions():
    """
    Restore active sessions from the database and start beacons
    This should be called on application startup
    """
    try:
        active_sessions = Session.get_all_active()
        
        for session in active_sessions:
            domain = session['domain']
            session_id = session['id']
            
            # Validate the session again to make sure it's still active
            cookies = Cookie.get_for_session(session_id)
            is_valid, username, _ = validate_session(cookies, domain)
            
            # Update the session status
            Session.update_status(session_id, is_valid)
            
            # Start beacon if still valid
            if is_valid:
                start_beacon(domain, session_id)
                logger.info(f"Restored active session for {domain} (ID: {session_id})")
            else:
                logger.info(f"Session for {domain} (ID: {session_id}) is no longer valid")
                
    except Exception as e:
        logger.error(f"Error restoring active sessions: {str(e)}")