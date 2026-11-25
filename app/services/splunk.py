import requests
import json
import time
import traceback # Added for execute_query exception logging
import threading # Added for background monitoring
from urllib.parse import urljoin
import urllib.parse

from app.models.database import QueryDefinition, Session, Cookie # Import Session/Cookie needed for rerun service
from app.config import logger
import voyager_settings
from voyager_settings import splunk_url
from app.services.session import cookies_to_header
from app.utils.debug import log_request, get_session

def get_username_and_app(cookies):
    """
    Get the username and default app from Splunk config
    
    Args:
        cookies (dict or str): The cookies to authenticate with
        
    Returns:
        tuple: (success, username, app)
    """
    try:
        # Construct the config URL
        config_url = splunk_url(f"config")
        
        # Prepare headers
        headers = {
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cookie': cookies_to_header(cookies)
        }
        
        logger.info(f"Getting username and app from Splunk config")
        
        # Get a session (regular or logging)
        session = get_session()
        
        # Execute the request
        response = session.get(config_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            try:
                data = response.json()
                username = data.get('USERNAME')
                app = data.get('DEFAULT_NAMESPACE', 'search')
                
                if not username:
                    logger.error("Username not found in Splunk config")
                    return False, None, None
                
                logger.info(f"Got username: {username}, app: {app}")
                return True, username, app
            except json.JSONDecodeError:
                logger.error("Failed to parse JSON response from config")
                return False, None, None
        else:
            logger.warning(f"Failed to get config, status code: {response.status_code}")
            return False, None, None
    
    except Exception as e:
        logger.error(f"Error getting username and app: {str(e)}")
        return False, None, None

def create_search_job(cookies, query, earliest_time=None, latest_time=None, app=None, username=None):
    """
    Create a new search job in Splunk
    
    Args:
        cookies (dict or str): The cookies to authenticate with
        query (str): The SPL query to execute
        earliest_time (str, optional): The earliest time for the search
        latest_time (str, optional): The latest time for the search
        app (str, optional): The Splunk app to use
        username (str, optional): The username to use
        
    Returns:
        tuple: (success, sid, error_message)
    """
    try:
        # Get username and app if not provided
        if not username or not app:
            success, username_from_config, app_from_config = get_username_and_app(cookies)
            if not success:
                return False, None, "Failed to get username and app from Splunk config"
            
            username = username or username_from_config
            app = app or app_from_config
        
        # Construct the search URL
        search_url = splunk_url(f"splunkd/__raw/servicesNS/{username}/{app}/search/v2/jobs")
        
        # Extract CSRF token from cookies
        csrf_token = None
        if isinstance(cookies, dict):
            # Check if using the nested structure from GM_cookie
            if any(isinstance(v, dict) and 'value' in v for v in cookies.values()):
                if 'splunkweb_csrf_token_8000' in cookies and isinstance(cookies['splunkweb_csrf_token_8000'], dict):
                    csrf_token = cookies['splunkweb_csrf_token_8000'].get('value')
            else:
                # Simple cookie structure
                csrf_token = cookies.get('splunkweb_csrf_token_8000')
        
        # Prepare parameters
        params = {
            'output_mode': 'json',
            'search': query,
            'rf': '*',
            'auto_cancel': '62',
            'status_buckets': '300',
            'ui_dispatch_app': app,
            'preview': '1',
            'adhoc_search_level': 'smart',
            'sample_ratio': '1',
            'check_risky_command': 'false',
            'provenance': 'UI:Search'
        }
        
        if earliest_time:
            params['earliest_time'] = earliest_time
        else:
            params['earliest_time'] = '-24h@h'  # Default to last 24 hours
            
        if latest_time:
            params['latest_time'] = latest_time
        else:
            params['latest_time'] = 'now'  # Default to now
        
        # Prepare headers
        headers = {
            'Accept': '*/*',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Cookie': cookies_to_header(cookies),
            'X-Requested-With': 'XMLHttpRequest'  # Add this header for AJAX requests
        }
        
        # Add CSRF token to headers if available
        if csrf_token:
            headers['X-Splunk-Form-Key'] = csrf_token
            logger.info("Added CSRF token to request headers")
        else:
            logger.warning("CSRF token not found in cookies")
        
        logger.info(f"Creating search job for query: {query}")
        
        # Get a session (regular or logging)
        session = get_session()
        
        # Execute the search
        response = session.post(search_url, headers=headers, data=params, timeout=30)
        
        if response.status_code == 200 or response.status_code == 201:
            try:
                data = response.json()
                sid = data.get('sid')
                
                if not sid:
                    logger.error("SID not found in job creation response")
                    return False, None, "SID not found in response"
                
                logger.info(f"Search job created with SID: {sid}")
                return True, sid, None
            except json.JSONDecodeError:
                logger.error("Failed to parse JSON response for job creation")
                return False, None, "Failed to parse job creation response"
        else:
            error_msg = f"Job creation failed with status code: {response.status_code}"
            if response.text:
                error_msg += f", Response: {response.text}"
            logger.warning(error_msg)
            return False, None, error_msg
    
    except Exception as e:
        logger.error(f"Error creating search job: {str(e)}")
        return False, None, str(e)

def get_search_results(cookies, sid, app=None, username=None, count=100, offset=0, include_metadata=False):
    """
    Get results for a search job
    
    Args:
        cookies (dict or str): The cookies to authenticate with
        sid (str): The search job SID
        app (str, optional): The Splunk app to use
        username (str, optional): The username to use
        count (int, optional): Maximum number of results to return
        offset (int, optional): Starting offset for results
        include_metadata (bool, optional): Whether to include metadata in the response
        
    Returns:
        tuple: (success, results, error_message)
    """
    try:
        # Get username and app if not provided
        if not username or not app:
            success, username_from_config, app_from_config = get_username_and_app(cookies)
            if not success:
                return False, None, "Failed to get username and app from Splunk config"
            
            username = username or username_from_config
            app = app or app_from_config
        
        # Construct the results URL - we use 'nobody' as the user for results
        results_url = splunk_url(f"splunkd/__raw/servicesNS/nobody/{app}/search/v2/jobs/{sid}/results_preview"
        )
        
        # Prepare parameters
        params = {
            'output_mode': 'json_rows',
            'count': str(count),
            'offset': str(offset),
            '_': str(int(time.time() * 1000))  # Add timestamp to prevent caching
        }
        
        if include_metadata:
            params['show_metadata'] = 'true'
        
        # Extract CSRF token from cookies
        csrf_token = None
        if isinstance(cookies, dict):
            # Check if using the nested structure from GM_cookie
            if any(isinstance(v, dict) and 'value' in v for v in cookies.values()):
                if 'splunkweb_csrf_token_8000' in cookies and isinstance(cookies['splunkweb_csrf_token_8000'], dict):
                    csrf_token = cookies['splunkweb_csrf_token_8000'].get('value')
            else:
                # Simple cookie structure
                csrf_token = cookies.get('splunkweb_csrf_token_8000')
        
        # Prepare headers
        headers = {
            'Accept': '*/*',
            'Cookie': cookies_to_header(cookies),
            'X-Requested-With': 'XMLHttpRequest'
        }
        
        # Add CSRF token to headers if available
        if csrf_token:
            headers['X-Splunk-Form-Key'] = csrf_token
        
        logger.info(f"Getting results for job: {sid}, offset: {offset}, count: {count}")
        
        # Get a session (regular or logging)
        session = get_session()
        
        # Execute the request
        response = session.get(results_url, headers=headers, params=params, timeout=30)
        
        if response.status_code == 200:
            try:
                data = response.json()
                
                logger.info(f"Got {len(data.get('rows', []))} results for job: {sid}")
                return True, data, None
            except json.JSONDecodeError:
                logger.error("Failed to parse JSON response for job results")
                return False, None, "Failed to parse job results response"
        else:
            error_msg = f"Failed to get job results, status code: {response.status_code}"
            if response.text:
                error_msg += f", Response: {response.text}"
            logger.warning(error_msg)
            return False, None, error_msg
    
    except Exception as e:
        logger.error(f"Error getting search results: {str(e)}")
        return False, None, str(e)

def check_job_status(cookies, sid, app=None, username=None):
    """
    Check the status of a search job. Returns an explicit indicator if SID is not found (404).

    Args:
        cookies (dict or str): The cookies to authenticate with
        sid (str): The search job SID
        app (str, optional): The Splunk app to use
        username (str, optional): The username to use

    Returns:
        tuple: (success, is_done, sid_valid, status_data, error_message)
               sid_valid is False if Splunk returns 404 for the SID.
    """
    try:
        # Get username and app if not provided
        if not username or not app:
            success_ua, username_from_config, app_from_config = get_username_and_app(cookies)
            if not success_ua:
                # Propagate the specific error if possible
                return False, False, True, None, "Failed to get username and app from Splunk config"
            username = username or username_from_config
            app = app or app_from_config

        # Construct the status URL
        status_url = splunk_url(f"splunkd/__raw/services/search/jobs/{sid}"
        )

        # Prepare parameters
        params = {
            'output_mode': 'json',
            '_': str(int(time.time() * 1000)) # Add timestamp to prevent caching
        }

        # Prepare headers - Start with standard headers
        headers = {
            'Accept': '*/*',
            'Cookie': cookies_to_header(cookies), # Use original structure for header func
            'X-Requested-With': 'XMLHttpRequest'
        }

        # Extract CSRF token from cookies and add to headers if found
        csrf_token = None
        processed_cookies = cookies # Assume it might already be processed
        # Handle potentially nested GM_cookie structure
        if cookies and isinstance(cookies, dict) and any(isinstance(v, dict) and 'value' in v for v in cookies.values()):
             processed_cookies = {}
             for name, cookie_data in cookies.items():
                 if isinstance(cookie_data, dict) and 'value' in cookie_data:
                     processed_cookies[name] = cookie_data['value']
             csrf_token = processed_cookies.get('splunkweb_csrf_token_8000')
        # Handle simple dict structure
        elif isinstance(cookies, dict):
             csrf_token = cookies.get('splunkweb_csrf_token_8000')
        # If it's a string, we can't easily get CSRF - cookies_to_header handles the Cookie part though

        if csrf_token:
            headers['X-Splunk-Form-Key'] = csrf_token
            logger.debug(f"check_job_status: Added CSRF token to headers for SID {sid}")
        else:
            logger.debug(f"check_job_status: CSRF token not found in cookies for SID {sid}")


        logger.debug(f"Checking status for job: {sid}")

        # Get a session (regular or logging)
        session = get_session()

        # Execute the request
        response = session.get(status_url, headers=headers, params=params, timeout=30)

        # --- Status Handling ---
        if response.status_code == 200:
            try:
                data = response.json()
                entry = data.get('entry', [{}])[0]
                content = entry.get('content', {})
                is_done = content.get('isDone', False)
                is_failed = content.get('isFailed', False)

                status_data = {
                    'is_done': is_done,
                    'is_failed': is_failed,
                    'dispatch_state': content.get('dispatchState', 'UNKNOWN'),
                    'result_count': content.get('resultCount', 0),
                    'run_duration': content.get('runDuration', 0),
                    'done_progress': content.get('doneProgress', 0),
                    'scan_count': content.get('scanCount', 0),
                    'event_count': content.get('eventCount', 0)
                }

                if is_done: logger.info(f"Job {sid} is complete with {status_data['result_count']} results")
                elif is_failed: logger.warning(f"Job {sid} has failed")
                else: logger.debug(f"Job {sid} is still running ({status_data['done_progress'] * 100:.1f}% complete)")

                return True, is_done, True, status_data, None # SID is valid
            except json.JSONDecodeError:
                logger.error("Failed to parse JSON response for job status")
                return False, False, True, None, "Failed to parse job status response" # Assume SID valid if 200 OK
        elif response.status_code == 404:
            # --- Explicitly handle 404 for SID not found ---
            logger.warning(f"Job {sid} not found (status 404). Assumed expired or invalid.")
            return True, False, False, None, "Job SID not found (404)" # Success=True (request OK), sid_valid=False
        else:
            error_msg = f"Failed to get job status, status code: {response.status_code}"
            if response.text:
                 # Limit error response logging for brevity
                 error_msg += f", Response: {response.text[:200]}..." if len(response.text) > 200 else response.text
            logger.warning(error_msg)
            # Assume SID is valid unless 404, but request failed
            return False, False, True, None, error_msg

    except Exception as e:
        logger.error(f"Error checking job status for SID {sid}: {str(e)}")
        # Log traceback for unexpected errors
        logger.debug(traceback.format_exc())
        return False, False, True, None, str(e) # Assume SID valid during exception, but report failure

# In app/services/splunk.py

def get_all_job_results(cookies, sid, app=None, username=None, max_results=50000, batch_size=1000,
                         status_check_interval=5):
    """
    Get all results for a search job - waits for job to complete or fail.
    Handles cases where the SID might become invalid during waiting.

    Args:
        cookies (dict or str): The cookies to authenticate with
        sid (str): The search job SID
        app (str, optional): The Splunk app to use
        username (str, optional): The username to use
        max_results (int, optional): Maximum number of results to return
        batch_size (int, optional): Number of results to fetch in each request
        status_check_interval (int, optional): Interval between status checks in seconds

    Returns:
        tuple: (success, sid_still_valid, all_results, error_message)
    """
    offset = 0
    all_rows = []
    fields = None
    more_results = True
    job_completed = False
    sid_valid = True # Start assuming valid
    result_count = 0

    try:
        # Get username and app if not provided (needed for results URL)
        if not username or not app:
             success_ua, username_from_config, app_from_config = get_username_and_app(cookies)
             if not success_ua:
                 # Cannot proceed without app context for results URL
                 return False, True, None, "Failed to get username and app from Splunk config for results fetching"
             username = username or username_from_config
             app = app or app_from_config

        # Wait for job to complete with no arbitrary timeout
        start_time = time.time()
        attempt = 1

        while True:
            # Check status, SID validity
            success_check, is_done, sid_valid_check, status_data, error_check = check_job_status(cookies, sid, app, username)

            sid_valid = sid_valid_check # Update validity based on check
            if not sid_valid:
                logger.warning(f"Job {sid} became invalid while waiting for results.")
                # Return 4 values: success=True (process ran), sid_valid=False, results=None, error_msg
                return True, False, None, f"Job SID {sid} expired or became invalid"

            if not success_check:
                logger.warning(f"Failed to check job status (attempt {attempt}): {error_check}. Retrying...")
                time.sleep(status_check_interval)
                attempt +=1
                # Add a max retry limit
                if attempt > 10: # Example retry limit
                     logger.error(f"Aborting status check for SID {sid} after multiple failures.")
                     # Return 4 values: success=False, sid_valid=True (assume), results=None, error_msg
                     return False, True, None, f"Failed to check job status after multiple retries: {error_check}"
                continue # continue retry

            if is_done:
                logger.info(f"Job {sid} is complete with {status_data.get('result_count', 0)} results")
                job_completed = True
                result_count = status_data.get('result_count', 0)
                break # exit while loop

            if status_data.get('is_failed', False):
                logger.error(f"Job {sid} has failed. Error details may be in the Splunk job logs.")
                # Return 4 values: success=False, sid_valid=True, results=None, error_msg
                return False, True, None, f"Splunk job {sid} failed"

            # Log progress information
            progress = status_data.get('done_progress', 0) * 100
            scan_count = status_data.get('scan_count', 0)
            dispatch_state = status_data.get('dispatch_state', 'UNKNOWN')
            elapsed = time.time() - start_time
            logger.info(f"Job {sid} progress: {progress:.2f}% complete, state: {dispatch_state}, "
                       f"scanned: {scan_count:,}, elapsed: {elapsed:.1f}s (attempt {attempt})")

            # Avoid hammering the server with too frequent checks
            time.sleep(status_check_interval)
            attempt += 1
            # Optional: Add a total timeout here if indefinite waiting is undesirable
            # if elapsed > 3600: # Example 1 hour timeout
            #     logger.error(f"Job {sid} timed out waiting for completion after 1 hour.")
            #     return False, True, None, "Job timed out waiting for completion"


        # --- Fetch results logic ---
        # Use the /results endpoint for final results since we waited for completion
        logger.info(f"Fetching results from /results endpoint for completed job {sid}")
        while more_results and offset < max_results:
            # Construct results URL with the proper endpoint
            # Use 'nobody'/'app' context as per Splunk standard for results endpoint
            results_url = splunk_url(f"splunkd/__raw/servicesNS/nobody/{app}/search/v2/jobs/{sid}/results"
            )

            # Prepare parameters
            params = {
                'output_mode': 'json_rows',
                'count': min(batch_size, max_results - offset),
                'offset': offset,
                '_': str(int(time.time() * 1000)) # Add timestamp to prevent caching
            }

            # Prepare headers and CSRF token extraction
            processed_cookies = cookies # Assume might be processed
            if cookies and isinstance(cookies, dict) and any(isinstance(v, dict) and 'value' in v for v in cookies.values()):
                 processed_cookies = {}
                 for name, cookie_data in cookies.items():
                     if isinstance(cookie_data, dict) and 'value' in cookie_data:
                         processed_cookies[name] = cookie_data['value']
            elif isinstance(cookies, dict):
                 processed_cookies = cookies
            else:
                 processed_cookies = {}

            csrf_token = processed_cookies.get('splunkweb_csrf_token_8000')
            headers = {
                'Accept': '*/*',
                'Cookie': cookies_to_header(cookies), # Use original for header func
                'X-Requested-With': 'XMLHttpRequest'
            }
            if csrf_token:
                headers['X-Splunk-Form-Key'] = csrf_token

            # Execute request
            session = get_session()
            response = session.get(results_url, headers=headers, params=params, timeout=30)

            if response.status_code == 200:
                 try:
                     results = response.json()
                     rows = results.get('rows', [])
                     # Save fields from the first batch only
                     if offset == 0:
                         fields = results.get('fields', [])
                     # Add rows to the result set
                     all_rows.extend(rows)
                     logger.info(f"Fetched {len(rows)} rows, total so far: {len(all_rows)}/{result_count}")
                     # Increment offset for next batch
                     offset += len(rows)
                     # Determine if more results might be available
                     if len(rows) == 0 or len(all_rows) >= result_count or offset >= max_results:
                         more_results = False
                 except json.JSONDecodeError:
                     logger.error("Failed to parse JSON response for job results")
                     # Return 4 values: success=False, sid_valid=True, results=None, error_msg
                     return False, True, None, "Failed to parse job results response"
            elif response.status_code == 404: # Check again here just in case
                 logger.warning(f"Job {sid} became invalid (404) during results fetching.")
                 # Return 4 values: success=True (process ran), sid_valid=False, results=None, error_msg
                 return True, False, None, f"Job SID {sid} expired or became invalid during results fetch"
            else:
                # Handle other errors
                error_msg = f"Failed to get job results, status code: {response.status_code}"
                if response.text:
                   error_msg += f", Response: {response.text[:200]}..." if len(response.text) > 200 else response.text
                logger.warning(error_msg)
                # Return 4 values: success=False, sid_valid=True, results=None, error_msg
                return False, True, None, error_msg

        # Construct the complete result set
        all_results = {
            'fields': fields,
            'rows': all_rows,
            'total_count': len(all_rows),
            'expected_count': result_count,
            'job_completed': job_completed,
            'query_sid': sid # Include the SID for reference
        }

        # Return 4 values: success=True, sid_valid=True, results=all_results, error_msg=None
        return True, True, all_results, None

    except Exception as e:
        logger.error(f"Error getting all job results for SID {sid}: {str(e)}")
        logger.debug(traceback.format_exc())
        # Return 4 values: success=False, sid_valid=current_state, results=None, error_msg=str(e)
        return False, sid_valid, None, str(e)

def execute_query(cookies, query, earliest_time=None, latest_time=None, definition_id=None):
    """
    Execute a Splunk query, store SID, wait for results, and update definition.

    Args:
        cookies (dict or str): The cookies to authenticate with
        query (str): The SPL query to execute
        earliest_time (str, optional): The earliest time for the search
        latest_time (str, optional): The latest time for the search
        definition_id (int, optional): The DB definition ID to update. Required for SID storage.

    Returns:
        tuple: (success, results, error_message)
    """
    sid = None # Initialize sid
    try:
        if not definition_id:
            logger.error("execute_query called without definition_id. Cannot store SID.")
            return False, None, "Internal error: execute_query requires definition_id"

        # Process cookies if needed to get flat dict for CSRF/user lookup
        processed_cookies = cookies # Assume might be processed
        if cookies and isinstance(cookies, dict) and any(isinstance(v, dict) and 'value' in v for v in cookies.values()):
             processed_cookies = {}
             for name, cookie_data in cookies.items():
                 if isinstance(cookie_data, dict) and 'value' in cookie_data:
                     processed_cookies[name] = cookie_data['value']
        elif isinstance(cookies, dict):
             processed_cookies = cookies
        else: # Handle string case? Unlikely to have CSRF/username.
             processed_cookies = {}
             logger.warning("execute_query received cookies as string, CSRF/username lookup may fail.")


        # Get username/app, use defaults on failure
        success_ua, username, app = get_username_and_app(processed_cookies) # Use processed for lookup
        if not success_ua:
             logger.warning("Could not get username and app, using defaults")
             username = "splunk_user"; app = "search"


        # --- Create the search job ---
        success_create, sid, error_create = create_search_job(
            cookies, query, earliest_time, latest_time, app, username # Pass original cookies struct here if needed by header func
        )
        if not success_create:
            # Mark definition as failed immediately if job creation fails
            QueryDefinition.update_status(definition_id, 'failed', {'error': error_create or 'Job creation failed'})
            return False, None, error_create

        # --- Store SID immediately ---
        logger.info(f"Job created (SID: {sid}). Storing SID for definition {definition_id}.")
        stored_sid = QueryDefinition.set_running_with_sid(definition_id, sid)
        if not stored_sid:
            logger.warning(f"Failed to store SID {sid} in database for definition {definition_id}.")


        # --- Get all results (this waits) ---
        success_results, sid_still_valid, results_data, error_results = get_all_job_results(
            cookies, sid, app, username # Pass original cookies struct here if needed by header func
        )

        # --- Update final status based on results ---
        if success_results:
            if sid_still_valid:
                # Add query metadata if results were fetched
                if results_data:
                     results_data['query'] = query
                     results_data['sid'] = sid
                # Mark as completed
                QueryDefinition.update_status(definition_id, 'completed', results_data)
                return True, results_data, None
            else:
                # SID became invalid during the process
                QueryDefinition.update_status(definition_id, 'failed', {'error': error_results or f'Job SID {sid} became invalid'})
                return False, None, error_results
        else:
            # get_all_job_results failed
            fail_status = {'error': error_results or 'Failed to get job results'}
            if not sid_still_valid:
                fail_status['error'] = f"Job SID {sid} expired or became invalid during failure: {error_results}"
            QueryDefinition.update_status(definition_id, 'failed', fail_status)
            return False, None, error_results

    except Exception as e:
        logger.error(f"Error executing query for definition {definition_id}: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        if definition_id:
             try: # Best effort to mark as failed
                 QueryDefinition.update_status(definition_id, 'failed', {'error': f'Unexpected error in execute_query: {str(e)}'})
             except Exception as inner_e:
                 logger.error(f"Failed to mark definition {definition_id} as failed after outer error: {inner_e}")
        return False, None, str(e)

def get_available_endpoints(cookies):
    """
    Get available Splunk endpoints
    
    Args:
        cookies (dict or str): The cookies to authenticate with
        
    Returns:
        tuple: (success, endpoints)
    """
    # This is a placeholder function that should be implemented
    # based on your specific requirements
    
    # For now, we'll just return a placeholder result
    success, username, app = get_username_and_app(cookies)
    if success:
        return True, [
            {"name": "Main Splunk", "url": voyager_settings.get("splunk_base"), "username": username, "app": app}
        ]
    else:
        return False, []
      
def rerun_query_definition_service(definition_id, triggering_username, triggering_domain, force_if_running=False):
    """
    Service function to re-run a query definition. Finds an active session for the
    triggering user/domain and executes the query.

    Args:
        definition_id (int): The ID of the query definition to re-run.
        triggering_username (str): The username initiating the re-run.
        triggering_domain (str): The domain associated with the user's session.
        force_if_running (bool, optional): If True, bypasses the check that prevents
                                           re-running if status is already 'running'. Defaults to False.

    Returns:
        tuple: (success, message, results_or_error)
    """
    definition = QueryDefinition.get_by_id(definition_id)
    if not definition:
        return False, f'Query Definition {definition_id} not found', None

    # --- Modified Status Check ---
    # Check if already running, *unless* forced by recovery
    if definition.get('status') == 'running' and not force_if_running:
        logger.warning(f"Rerun requested for definition {definition_id} which is already running (force=False). Aborting.")
        return False, f'Query Definition {definition_id} is already running.', None
    elif definition.get('status') == 'running' and force_if_running:
        logger.info(f"Forcing rerun for definition {definition_id} even though status is 'running' (likely recovery scenario).")
        # Proceed without returning error

    query_text = definition.get('query_text')
    earliest_time = definition.get('earliest_time')
    latest_time = definition.get('latest_time')

    if not query_text:
        QueryDefinition.update_status(definition_id, 'failed', {'error': 'Definition missing query text'})
        return False, f'Cannot re-run: Definition {definition_id} missing query text', None

    # Find active session for the specific user triggering the rerun
    session_info = Session.get_active_for_user_domain(triggering_username, triggering_domain)
    if not session_info:
        msg = f'No active session found for user {triggering_username} on domain {triggering_domain} to perform re-run'
        return False, msg, None

    cookies = Cookie.get_for_session(session_info['id'])
    if not cookies:
        msg = f'Failed to retrieve session credentials for re-run (Session ID: {session_info["id"]})'
        return False, msg, None

    logger.info(f"Service: User '{triggering_username}' initiating re-run for definition ID: {definition_id} (force={force_if_running})")

    # Execute the query using the main execute_query function
    success_exec, results_data, error_msg = execute_query(
        cookies, query_text, earliest_time, latest_time, definition_id=definition_id
    )

    if success_exec:
        return True, f'Query Definition {definition_id} refreshed successfully.', results_data
    else:
        return False, error_msg or f'Failed to re-run query definition {definition_id}.', results_data
	  
def background_rerun_query(definition_id, username, domain):
    """Wrapper to call the rerun service, intended for background threads."""
    logger.info(f"Background task starting auto re-run for definition {definition_id} (user: {username}@{domain})")
    try:
        # Call directly - assumes rerun_query_definition_service is defined above
        success, message, _ = rerun_query_definition_service(definition_id, username, domain, force_if_running=True)
        if success:
            logger.info(f"Background auto re-run for definition {definition_id} completed successfully.")
        else:
            # Log specific failure message from the service
            logger.error(f"Background auto re-run for definition {definition_id} failed: {message}")
    except NameError as ne:
        logger.exception(f"NameError in background_rerun_query (Check definition order/scope): {ne}")
    except Exception as e:
        logger.exception(f"Exception in background_rerun_query for definition {definition_id}: {e}")