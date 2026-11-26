from voyager_settings import use_instance
from flask import Blueprint, request, jsonify, Response, abort
from io import BytesIO
import json
import openpyxl
import socket

# Updated imports: Query removed, QueryDefinition and QueryExecution added
from app.models.database import Session, Cookie, QueryDefinition, QueryExecution, generate_query_hash, InstanceUserMapping 
from app.services.session import process_cookies, validate_session
from app.services.splunk import execute_query, get_available_endpoints, get_username_and_app
from app.config import logger

# Create a blueprint for API routes
api_bp = Blueprint('api', __name__, url_prefix='/api')

# --- Keep-alive tab: the exporter asks for a browser refresh when Splunk answers 401; the next cookie post from
# a tab marked as keep-alive (open any Splunk page with #voyager once) is answered with reload=true.
import threading, time as _time
_refresh = {"requested": 0.0, "served": 0.0, "reason": ""}
_refresh_lock = threading.Lock()
RELOAD_MIN_GAP = 120  # seconds between two reloads


def _want_reload(keepalive, cookies_valid):
    if not keepalive:
        return False
    with _refresh_lock:
        now = _time.time()
        if now - _refresh["served"] < RELOAD_MIN_GAP:
            return False
        pending = _refresh["requested"] > _refresh["served"]
        if pending or cookies_valid is False:
            _refresh["served"] = now
            logger.info(f"Asking keep-alive tab to reload ({_refresh['reason'] if pending else 'cookies no longer valid'})")
            return True
    return False


def request_browser_refresh(reason):
    """Queue a reload of the keep-alive tab (served with its next cookie post)."""
    with _refresh_lock:
        _refresh["requested"] = _time.time()
        _refresh["reason"] = str(reason)[:200]
    logger.info(f"Browser refresh requested: {_refresh['reason']}")


@api_bp.route('/request_refresh', methods=['POST'])
def request_refresh():
    """Called by splunk_export.py when its Splunk session stops working."""
    data = request.get_json(silent=True) or {}
    request_browser_refresh(data.get("reason", ""))
    return jsonify({'status': 'queued'})

# --- Routes related to Sessions and Cookies (Unchanged) ---

@api_bp.route('/receive_cookies', methods=['POST'])
def receive_cookies():
    """
    Receive cookies from the userscript, validate them, and store them
    """
    try:
        data = request.json
        keepalive = bool(data.get('keepalive'))
        domain = data.get('domain', 'unknown')
        cookies = data.get('cookies', {})

        if not cookies:
            return jsonify({'status': 'error', 'message': 'No cookies provided'}), 400

        # Use the updated process_cookies which handles single session per user/domain
        session_id, is_valid, username = process_cookies(domain, cookies)

        reload_tab = _want_reload(keepalive, bool(is_valid))
        if session_id is None and not is_valid:
            # Handle cases where process_cookies decided not to create/update a session
            # (e.g., invalid username, validation failed with no existing session)
             return jsonify({
                'status': 'warning',
                'message': f'Session validation failed or username invalid for {domain}. No active session created/updated.',
                'is_valid': is_valid,
                'username': username,
                'session_id': None,
                'reload': reload_tab
            }), 200 # Return 200 OK as the request was processed, but session might not be active
            
        instance_id = socket.gethostname()
        # Call the static method from the class
        if not InstanceUserMapping.update(instance_id, username, domain):
            logger.warning(f"Instance mapping update failed for '{instance_id}' (logged in database.py).")

        logger.info(f"Received cookies from {domain} with {len(cookies)} entries. Session ID: {session_id}, Valid: {is_valid}")

        return jsonify({
            'status': 'success',
            'message': f'Received {len(cookies)} cookies, session processed.',
            'is_valid': is_valid,
            'username': username,
            'session_id': session_id,
            'reload': reload_tab
        })

    except Exception as e:
        logger.error(f"Error processing cookies: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e),
                        'reload': _want_reload(bool((request.get_json(silent=True) or {}).get('keepalive')), False)}), 500

@api_bp.route('/session_status', methods=['GET'])
def session_status():
    """
    Get the status of sessions
    """
    domain = request.args.get('domain')

    if not domain:
        # Return all sessions (consider if this should return summarized unique sessions like the view)
        active_sessions = Session.get_all_active()
        all_sessions = Session.get_all_sessions() # This still fetches all raw session entries

        return jsonify({
            'status': 'success',
            'active_sessions': active_sessions,
            'all_sessions': all_sessions
        })

    # Return status for specific domain
    # Prioritize active, but check latest if no active found
    session = Session.get_active_for_domain(domain)
    is_valid = False
    if session:
        is_valid = True # We assume get_active_for_domain implies validity or was recently checked
    else:
        # Find the single canonical session for this domain (user might be unknown here)
        # This part might need adjustment depending on how you want to handle requests
        # for a domain where the user isn't known yet or no active session exists.
        # Let's fetch the latest session regardless of activity to check.
        latest_session = Session.get_latest_for_domain(domain) # May return inactive
        if not latest_session:
             return jsonify({'status': 'error', 'message': f'No session found for {domain}'}), 404
        session = latest_session
        # Re-validate this latest session
        cookies = Cookie.get_for_session(session['id'])
        if cookies:
            is_valid, _, _ = validate_session(cookies, session['domain'])
            # Update status in DB if it changed
            if is_valid != session['is_active']:
                 Session.update_status(session['id'], is_valid)
                 session['is_active'] = is_valid # Update local copy
        else:
            # No cookies, session is definitely not valid
             is_valid = False
             if session['is_active']: # If DB thought it was active, correct it
                  Session.update_status(session['id'], False)
                  session['is_active'] = False


    # Add cookies if session exists
    if session:
        session['cookies'] = Cookie.get_for_session(session['id'])
    else: # Should be covered by 404 above, but defensively:
         return jsonify({'status': 'error', 'message': f'Session logic error for {domain}'}), 500


    return jsonify({
        'status': 'success',
        'session': session,
        'is_valid': is_valid
    })
    
@api_bp.route('/sessions/active', methods=['GET'])
def get_active_sessions_api():
    """
    API endpoint to get only the currently active sessions.
    """
    try:
        active_sessions = Session.get_all_active()
        return jsonify({
            'status': 'success',
            'active_sessions': active_sessions
        })
    except Exception as e:
        logger.error(f"Error fetching active sessions: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to retrieve active sessions'
        }), 500

@api_bp.route('/session/<int:session_id>/validate', methods=['POST'])
def validate_session_api(session_id):
    """
    Validate a session
    """
    try:
        session = Session.get_by_id(session_id)
        if not session:
            return jsonify({'status': 'error','message': f'Session {session_id} not found'}), 404

        cookies = Cookie.get_for_session(session_id)
        if not cookies:
             # If no cookies, it can't be valid
             is_valid = False
             username = session.get('username') # Keep existing username if known
             if session.get('is_active'): # Correct DB if needed
                  Session.update_status(session_id, False)
        else:
            is_valid, username, _ = validate_session(cookies, session['domain'])
            # Update the session status based on validation result
            Session.update_status(session_id, is_valid)

        return jsonify({
            'status': 'success',
            'is_valid': is_valid,
            'username': username # Return the username found during validation (might differ from stored if issues)
        })

    except Exception as e:
        logger.error(f"Error validating session {session_id}: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api_bp.route('/session/<int:session_id>/invalidate', methods=['POST'])
def invalidate_session(session_id):
    """
    Manually invalidate a session and clear its cookies
    """
    try:
        session = Session.get_by_id(session_id)
        if not session:
            return jsonify({'status': 'error', 'message': f'Session {session_id} not found'}), 404

        # Update the session status to inactive
        Session.update_status(session_id, False)
        # Also delete associated cookies
        Cookie.delete_for_session(session_id)
        # Stop beacon if running (optional, depends if stop_beacon checks DB status)
        # stop_beacon(session['domain'], session_id) # Assuming stop_beacon exists

        logger.info(f"Session {session_id} for {session['domain']} manually invalidated.")
        return jsonify({'status': 'success', 'message': f'Session {session_id} invalidated'})

    except Exception as e:
        logger.error(f"Error invalidating session {session_id}: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api_bp.route('/domains', methods=['GET'])
def get_domains():
    """
    Get all unique domains with sessions
    """
    domains = Session.get_domains()
    return jsonify({'status': 'success', 'domains': domains})


@api_bp.route('/session/<int:session_id>/user_info', methods=['GET'])
def get_user_info(session_id):
    """
    Get user information for a session from Splunk if possible
    """
    try:
        session = Session.get_by_id(session_id)
        if not session:
            return jsonify({'status': 'error', 'message': f'Session {session_id} not found'}), 404

        # Prefer potentially more up-to-date info from DB first
        db_username = session.get('username')
        db_domain = session.get('domain')

        # Try fetching from Splunk for confirmation or more details (like app context)
        cookies = Cookie.get_for_session(session_id)
        if not cookies:
            # Cannot contact Splunk, return DB info only
            return jsonify({
                 'status': 'success',
                 'username': db_username,
                 'app': None, # Cannot determine app without cookies
                 'domain': db_domain,
                 'source': 'database (no cookies)'
            })

        with use_instance(db_domain):
            success, splunk_username, app = get_username_and_app(cookies)

        if success:
             # Compare DB username with Splunk username - log if different
             if db_username and splunk_username and db_username.lower() != splunk_username.lower():
                  logger.warning(f"Username mismatch for session {session_id}. DB: '{db_username}', Splunk: '{splunk_username}'.")

             return jsonify({
                'status': 'success',
                'username': splunk_username or db_username, # Prefer Splunk result if available
                'app': app,
                'domain': db_domain,
                'source': 'splunk'
             })
        else:
            # Failed to get info from Splunk, return DB info
            logger.warning(f"Failed to get user info from Splunk for session {session_id}. Returning DB info.")
            return jsonify({
                'status': 'success', # Success in fetching DB info
                'username': db_username,
                'app': None,
                'domain': db_domain,
                'source': 'database (splunk failed)'
            })

    except Exception as e:
        logger.error(f"Error getting user information for session {session_id}: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api_bp.route('/available_endpoints', methods=['GET'])
def api_available_endpoints():
    """
    Get available Splunk endpoints (if service exists)
    """
    domain = request.args.get('domain')
    if not domain:
        return jsonify({'status': 'error', 'message': 'Missing domain parameter'}), 400

    session = Session.get_active_for_domain(domain)
    if not session:
        return jsonify({'status': 'error', 'message': f'No active session found for {domain}'}), 404

    cookies = Cookie.get_for_session(session['id'])
    if not cookies:
         return jsonify({'status': 'error', 'message': 'Cookies not found for active session'}), 500

    # Assumes get_available_endpoints service exists
    success, endpoints = get_available_endpoints(cookies)

    if success:
        return jsonify({'status': 'success', 'endpoints': endpoints})
    else:
        return jsonify({'status': 'error', 'message': 'Failed to get available endpoints from Splunk'}), 500

@api_bp.route('/execute_query', methods=['POST'])
def api_execute_query():
    """
    Finds existing query definition/results, or executes query (storing SID early)
    and stores definition/results, then records OR UPDATES the user execution timestamp.
    """
    definition_id = None
    execution_id = None
    session_id = None
    username = None
    domain = None

    try:
        # 1. Get Data & Active Session
        data = request.json
        domain_req = data.get('domain')
        query_text = data.get('query')
        earliest_time = data.get('earliest_time')
        latest_time = data.get('latest_time')

        if not domain_req or not query_text:
            return jsonify({'status': 'error', 'message': 'Missing domain or query'}), 400

        session_info = Session.get_active_for_domain(domain_req)
        if not session_info:
            return jsonify({'status': 'error', 'message': f'No active session for {domain_req}'}), 404

        session_id = session_info['id']
        username = session_info['username']
        domain = session_info['domain'] # Use validated domain from session
        cookies = Cookie.get_for_session(session_id)
        if not cookies or not username:
             logger.error(f"Active session {session_id} missing cookies or username.")
             return jsonify({'status': 'error', 'message': 'Internal error: Invalid session data'}), 500

        # 2. Calculate Hash & Find/Create Definition
        query_hash = generate_query_hash(query_text, earliest_time, latest_time)
        existing_definition = QueryDefinition.find_by_hash(query_hash)

        force_rerun = False # Flag not strictly needed now execute_query handles status internally

        if existing_definition:
            definition_id = existing_definition['id']
            logger.info(f"Found existing query definition {definition_id} for hash {query_hash[:8]}...")

            # Handle Existing Cases
            if existing_definition['status'] == 'completed':
                logger.info("Existing definition is completed. Recording/updating execution and returning cached results.")
                execution_id = QueryExecution.record_or_update_user_execution(definition_id, username, domain, session_id)
                if not execution_id: logger.warning(f"Failed to record/update execution for cached hit: def {definition_id} user {username}")
                # Return cached results
                try:
                     results = json.loads(existing_definition['results']) if isinstance(existing_definition['results'], str) else existing_definition['results']
                except Exception as parse_err:
                    logger.warning(f"Failed to parse cached results JSON for def {definition_id}: {parse_err}")
                    results = existing_definition['results'] # Return raw if unparseable
                return jsonify({ 'status': 'success', 'message': 'Retrieved cached results', 'query_definition_id': definition_id, 'execution_id': execution_id, 'results': results })

            elif existing_definition['status'] == 'failed':
                 logger.warning(f"Existing definition {definition_id} failed previously. Recording/updating execution.")
                 execution_id = QueryExecution.record_or_update_user_execution(definition_id, username, domain, session_id)
                 if not execution_id: logger.warning(f"Failed to record/update execution for failed hit: def {definition_id} user {username}")
                 # Return previous failure details
                 try:
                     error_details = json.loads(existing_definition['results']) if isinstance(existing_definition['results'], str) else existing_definition['results']
                 except Exception as parse_err:
                     logger.warning(f"Failed to parse failed results JSON for def {definition_id}: {parse_err}")
                     error_details = {'error': 'Previous execution failed, results unparseable.'}
                 return jsonify({ 'status': 'error', 'message': 'Query previously failed', 'query_definition_id': definition_id, 'execution_id': execution_id, 'error': error_details.get('error', 'Unknown previous failure') }), 500

            elif existing_definition['status'] in ('pending', 'running'):
                 logger.warning(f"Query definition {definition_id} is already {existing_definition['status']}. Recording/updating execution and returning status.")
                 execution_id = QueryExecution.record_or_update_user_execution(definition_id, username, domain, session_id)
                 if not execution_id: logger.warning(f"Failed to record/update execution for pending/running hit: def {definition_id} user {username}")
                 # Return status indicating it's in progress elsewhere
                 return jsonify({ 'status': 'pending', 'message': f'Query is already {existing_definition["status"]}. Check back later.', 'query_definition_id': definition_id, 'execution_id': execution_id }), 202 # HTTP 202 Accepted

            else: # Unknown status
                 logger.error(f"Existing definition {definition_id} has unknown status: {existing_definition['status']}. Forcing re-execution.")
                 # Proceed to execute; definition_id is already set

        # 3. Create Pending Definition (Only if not found previously)
        if not definition_id:
             try:
                  definition_id, _ = QueryDefinition.create_pending(query_text, earliest_time, latest_time)
                  if not definition_id: # Handle potential issue if create_pending fails to return ID
                     raise Exception("Failed to get definition ID after creation.")
                  logger.info(f"Created new pending definition {definition_id}.")
             except Exception as create_err:
                  logger.error(f"Failed to create pending definition: {create_err}")
                  # Try to record execution even if definition creation failed? Unlikely to succeed.
                  return jsonify({'status': 'error', 'message': 'Failed to initiate query definition'}), 500


        # --- 4. Execute or Re-execute the Query ---
        logger.info(f"Executing/Re-executing Splunk query via service for definition ID: {definition_id}")

        # Call the main execute_query function from splunk.py which handles SID storage and status updates
        with use_instance(domain):   # the Splunk instance this session's cookies belong to
            success_exec, results_data, error_msg = execute_query(
                cookies, query_text, earliest_time, latest_time, definition_id=definition_id
            )

        # 5. Record/Update Execution & Return Results
        # Status is already updated by execute_query. Just record user interaction.
        execution_id = QueryExecution.record_or_update_user_execution(definition_id, username, domain, session_id)
        if not execution_id:
             logger.warning(f"Failed to record/update execution for {'successful' if success_exec else 'failed'} run: def {definition_id} user {username}")

        if success_exec:
            return jsonify({
                'status': 'success',
                'message': 'Query executed successfully',
                'query_definition_id': definition_id,
                'execution_id': execution_id,
                'results': results_data # results_data includes SID etc.
            })
        else:
            return jsonify({
                'status': 'error',
                'message': error_msg or 'Failed to execute query',
                'query_definition_id': definition_id,
                'execution_id': execution_id,
                'error': error_msg or 'Unknown error' # Send error back
            }), 500

    # --- Outer Exception Handling ---
    except Exception as e:
        logger.exception(f"Unhandled error in /execute_query: {str(e)}")
        # Try to mark definition as failed if it was potentially running
        if definition_id:
             try:
                  current_def = QueryDefinition.get_by_id(definition_id)
                  if current_def and current_def.get('status') in ('pending', 'running'):
                       QueryDefinition.update_status(definition_id, 'failed', {'error': f'Unhandled API error during execution: {str(e)}'})
             except Exception as inner_e:
                 logger.error(f"Failed to mark definition {definition_id} as failed after outer error: {inner_e}")
        # Attempt Record or Update even on outer error, if we have the info
        if definition_id and username and domain:
             try: # Best effort
                  QueryExecution.record_or_update_user_execution(definition_id, username, domain, session_id)
             except Exception as exec_err:
                  logger.error(f"Failed to record execution after outer error: {exec_err}")

        return jsonify({
            'status': 'error',
            'message': 'An internal server error occurred.',
            'query_definition_id': definition_id, # May be None
            'execution_id': execution_id # May be None
        }), 500


@api_bp.route('/query/execution/<int:execution_id>', methods=['GET'])
def get_query_execution(execution_id):
    """
    Get a specific query execution by ID, including definition and session info.
    """
    execution = QueryExecution.get_by_id(execution_id)

    if not execution:
        return jsonify({
            'status': 'error',
            'message': f'Query execution {execution_id} not found'
        }), 404

    # Results are already processed (JSON parsed) by get_by_id if possible
    return jsonify({
        'status': 'success',
        'execution': execution
    })

# Refactored: DELETE specific query execution
@api_bp.route('/query/execution/<int:execution_id>/delete', methods=['POST'])
def delete_query_execution(execution_id):
    """
    Delete a specific query execution record, and optionally the definition
    if it's no longer referenced.
    """
    definition_id_to_check = None
    try:
        # --- Use CORRECT method to fetch details BEFORE deleting ---
        # We need this to get the definition_id for potential cleanup
        execution_details = QueryExecution.get_execution_details(execution_id)
        if not execution_details:
            # Execution already deleted or never existed
            return jsonify({'status': 'error', 'message': f'Query execution {execution_id} not found'}), 404

        # Store the definition ID for cleanup check later
        definition_id_to_check = execution_details.get('query_definition_id') # Or 'id' if that's the key name from the join

        # --- Delete the specific USER execution record ---
        success = QueryExecution.delete_user_execution(execution_id)

        if not success:
             # Failed to delete the execution record itself
             return jsonify({'status': 'error', 'message': f'Failed to delete query execution record {execution_id}'}), 500

        # --- Optional: Cleanup query definition if no longer referenced ---
        if definition_id_to_check:
            # Check how many executions still reference this definition
            # Assumes count_for_definition method exists in QueryExecution model
            count = QueryExecution.count_for_definition(definition_id_to_check)

            if count == 0:
                logger.info(f"Execution {execution_id} deleted. No more executions reference definition {definition_id_to_check}. Deleting definition.")
                # Assumes delete method exists in QueryDefinition model
                deleted_def = QueryDefinition.delete(definition_id_to_check)
                if not deleted_def:
                     logger.warning(f"Failed to delete orphaned query definition {definition_id_to_check}.")
                     # Don't fail the overall request, just log the warning.
            elif count > 0:
                 logger.info(f"Execution {execution_id} deleted. Definition {definition_id_to_check} still referenced by {count} other execution(s).")
            else: # count < 0 indicates an error during the count check
                 logger.warning(f"Could not determine execution count for definition {definition_id_to_check} after deleting execution {execution_id}. Skipping definition cleanup.")


        # --- Return success ---
        return jsonify({
            'status': 'success',
            'message': f'Query execution {execution_id} deleted successfully'
        })

    except Exception as e:
        logger.error(f"Error deleting query execution {execution_id}: {str(e)}")
        return jsonify({'status': 'error', 'message': f'An internal server error occurred: {str(e)}'}), 500

@api_bp.route('/query/definition/<int:definition_id>/rerun', methods=['POST'])
def rerun_query_definition(definition_id):
    """
    Forces a re-execution of the query associated with a specific definition ID,
    updating the definition's results and UPDATING the timestamp of the user's
    latest execution record for this definition.
    Requires the user to have an active session for the associated domain.
    """
    session_id = None
    execution_id = None # This will hold the ID of the *updated* user execution record
    username = None
    domain = None

    try:
        # 1. Fetch the Query Definition
        definition = QueryDefinition.get_by_id(definition_id)
        if not definition:
            return jsonify({'status': 'error', 'message': f'Query Definition {definition_id} not found'}), 404

        # Check if already running (This check remains correct for user-initiated reruns)
        if definition.get('status') == 'running':
             return jsonify({
                 'status': 'pending',
                 'message': f'Query Definition {definition_id} is already being refreshed/executed.',
                 'query_definition_id': definition_id,
                 }), 409 # Conflict

        # Extract necessary details from definition
        query_text = definition.get('query_text')
        earliest_time = definition.get('earliest_time')
        latest_time = definition.get('latest_time')
        if not query_text:
             logger.error(f"Definition {definition_id} is missing query text. Cannot re-run.")
             # Should we mark as failed here? Potentially.
             # QueryDefinition.update_status(definition_id, 'failed', {'error': 'Definition missing query text'})
             return jsonify({'status': 'error', 'message': f'Cannot re-run: Definition {definition_id} missing query text'}), 500


        # 2. Get Domain and Active Session/User Info from Request Body
        data = request.json
        domain_req = data.get('domain') # Get requested domain
        if not domain_req:
            return jsonify({'status': 'error', 'message': 'Domain parameter is required in request body to find active session for re-run'}), 400

        session_info = Session.get_active_for_domain(domain_req) # Find session for requested domain
        if not session_info:
            return jsonify({'status': 'error', 'message': f'No active session found for domain {domain_req} to perform re-run'}), 403

        # Use validated session info
        session_id = session_info['id']
        username = session_info['username']
        domain = session_info['domain'] # Use actual domain from session record
        cookies = Cookie.get_for_session(session_id)
        if not cookies or not username:
             logger.error(f"Active session {session_id} missing cookies or username during re-run attempt.")
             return jsonify({'status': 'error', 'message': 'Failed to retrieve session credentials for re-run'}), 500


        # 3. Execute Splunk Query via Service
        logger.info(f"User '{username}' initiating re-run via API for definition ID: {definition_id} on domain '{domain}'")
        # REMOVED: QueryDefinition.update_status(definition_id, 'running', results=None) - execute_query handles this now

        # --- THIS IS THE CORRECTED LINE ---
        # Pass the definition_id to the execute_query service function
        with use_instance(domain):
            success, results_data, error_msg = execute_query(
                cookies, query_text, earliest_time, latest_time, definition_id=definition_id
            )
        # --- END OF CORRECTION ---


        # 4. Handle Results (Status already updated by execute_query)
        final_results = results_data # results_data will contain results or error payload from execute_query

        if success:
            # REMOVED: QueryDefinition.update_status(definition_id, 'completed', results_data)
            logger.info(f"API /rerun: Definition {definition_id} re-run completed successfully.")
            status_to_return = 'success'
            message_to_return = f'Query Definition {definition_id} refreshed successfully.'
            http_status_code = 200
        else:
            # REMOVED: QueryDefinition.update_status(definition_id, 'failed', error_payload)
            logger.error(f"API /rerun: Definition {definition_id} re-run failed: {error_msg}")
            status_to_return = 'error'
            message_to_return = error_msg or f'Failed to re-run query definition {definition_id}.'
            http_status_code = 500


        # 5. Record OR UPDATE this specific user execution that triggered the refresh
        execution_id = QueryExecution.record_or_update_user_execution(definition_id, username, domain, session_id)
        if not execution_id:
            logger.warning(f"Failed to record or update user execution history for definition {definition_id} re-run by {username}@{domain}.")


        # 6. Return Response
        return jsonify({
            'status': status_to_return,
            'message': message_to_return,
            'query_definition_id': definition_id,
            'execution_id': execution_id,
            # Use 'results' key for success, 'error' key for failure for consistency?
            # Let's return the payload under 'results' for success, 'error' for failure
            ('results' if success else 'error'): final_results
        }), http_status_code

    # --- Outer Exception Handling ---
    except Exception as e:
        logger.exception(f"Unhandled error in /rerun API endpoint for definition {definition_id}: {str(e)}")
        # Try to mark definition as failed if it was potentially running (best effort)
        if definition_id:
             try:
                  current_def = QueryDefinition.get_by_id(definition_id)
                  if current_def and current_def.get('status') == 'running':
                       QueryDefinition.update_status(definition_id, 'failed', {'error': f'Unhandled API error during re-run: {str(e)}'})
             except Exception as inner_e:
                  logger.error(f"Failed to mark definition {definition_id} as failed after outer re-run error: {inner_e}")

        # Attempt Record or Update even on outer error, if we have the info
        if definition_id and username and domain:
             try:
                 QueryExecution.record_or_update_user_execution(definition_id, username, domain, session_id)
             except Exception as exec_err:
                  logger.error(f"Failed to record execution after API /rerun outer error: {exec_err}")

        return jsonify({
            'status': 'error',
            'message': 'An internal server error occurred during re-run.',
            'query_definition_id': definition_id, # May be None
            'execution_id': execution_id # May be None
        }), 500

@api_bp.route('/session/<int:session_id>/query_executions', methods=['GET'])
def get_session_query_executions(session_id):
    """
    Get the query execution history for the user associated with a specific session.
    """
    # Check if session exists and get user/domain info
    session = Session.get_by_id(session_id)
    if not session:
        return jsonify({'status': 'error','message': f'Session {session_id} not found'}), 404

    executions = [] # Default to empty
    username = session.get('username')
    domain = session.get('domain')

    if username and domain:
        # --- Use the correct method based on user/domain ---
        logger.info(f"API: Fetching execution history for user '{username}' on domain '{domain}' (from session {session_id})")
        # Fetch history for this specific user/domain (limit can be adjusted)
        executions = QueryExecution.get_history_for_user_domain(username, domain, limit=20) # Added a limit
    else:
         logger.warning(f"API: Session {session_id} missing username or domain. Cannot fetch execution history.")


    return jsonify({
        'status': 'success',
        'session_id': session_id,
        'executions': executions # Return the fetched list
    })
    
@api_bp.route('/query/execution/<string:execution_id>/export/xlsx', methods=['GET'])
def export_execution_results_xlsx(execution_id):
    """
    Exports the results of a specific query execution as an XLSX file.
    Only works for results stored in the standard {'fields': [...], 'rows': [[...], ...]} format.
    """
    try:
        # 1. Fetch the Execution Record using your existing model method
        # Assuming get_by_id returns a dictionary or None
        execution = QueryExecution.get_execution_details(execution_id)
        if not execution:
            logger.warning(f"XLSX Export: Execution ID {execution_id} not found.")
            abort(404, description=f"Query execution {execution_id} not found.")

        # 2. Get the Definition ID and Fetch the Definition
        definition_id = execution.get('query_definition_id')
        if not definition_id:
            logger.error(f"XLSX Export: Execution {execution_id} is missing query_definition_id.")
            abort(500, description="Internal error: Execution record is incomplete.")

        # Assuming get_by_id returns a dictionary or None
        definition = QueryDefinition.get_by_id(definition_id)
        if not definition:
             logger.error(f"XLSX Export: Definition {definition_id} not found for execution {execution_id}.")
             abort(404, description=f"Query definition {definition_id} not found.")

        if 'results' not in definition or definition['results'] is None:
            logger.warning(f"XLSX Export: No results found in definition {definition_id} for execution {execution_id}.")
            # Return a 200 OK with an empty file or 404? Let's go with 404 for clarity.
            abort(404, description="No results data available for this execution.")

        # 3. Parse the Results (assuming results are stored as a JSON string)
        try:
            # Check if it's already parsed (some methods might do this)
            if isinstance(definition['results'], dict):
                 results_data = definition['results']
            elif isinstance(definition['results'], str):
                 results_data = json.loads(definition['results'])
            else:
                 raise TypeError("Results data is not a dictionary or JSON string.")
        except (json.JSONDecodeError, TypeError) as e:
            logger.error(f"XLSX Export: Failed to parse results JSON for definition {definition_id}: {e}")
            abort(400, description="Results data is corrupted or not valid JSON.")

        # 4. Validate Format (Fields & Rows required for table export)
        if not isinstance(results_data, dict) or \
           'fields' not in results_data or not isinstance(results_data['fields'], list) or \
           'rows' not in results_data or not isinstance(results_data['rows'], list):
            logger.warning(f"XLSX Export: Results for definition {definition_id} are not in table format (missing fields/rows).")
            abort(400, description="Results are not in a format suitable for XLSX export (requires 'fields' and 'rows').")

        fields = results_data.get('fields', [])
        rows = results_data.get('rows', [])

        # 5. Generate XLSX File using openpyxl
        workbook = openpyxl.Workbook()
        sheet = workbook.active
        sheet.title = "Query Results"

        # Write header row - extract field names correctly
        header_names = []
        for field in fields:
            if isinstance(field, dict) and 'name' in field:
                header_names.append(str(field['name']))
            else:
                header_names.append(str(field)) # Handle simple string fields
        if header_names:
            sheet.append(header_names)

        # Write data rows
        for row_data in rows:
            # Ensure row_data is a list/tuple for consistent processing
            if not isinstance(row_data, (list, tuple)):
                 # If not a list/tuple, wrap it as a single-element list
                 # This might happen if results somehow aren't structured as expected
                 logger.debug(f"XLSX Export: Row data for def {definition_id} is not a list/tuple, wrapping: {type(row_data)}")
                 row_data = [row_data]

            processed_row = []
            # Iterate based on the length of the row_data received
            for cell in row_data:
                if isinstance(cell, (dict, list)):
                    # Convert complex types (dict, list) to JSON strings for Excel
                    try:
                        processed_row.append(json.dumps(cell))
                    except TypeError:
                         processed_row.append("#SerializationError#")
                # Add more specific type handling here if needed (e.g., dates)
                # openpyxl handles numbers, bools, None reasonably well by default
                else:
                     processed_row.append(cell) # Append directly

            # Append the potentially processed row to the sheet
            if processed_row: # Avoid appending empty rows if processing fails completely
                 sheet.append(processed_row)


        # 6. Save to In-Memory Stream
        file_stream = BytesIO()
        workbook.save(file_stream)
        file_stream.seek(0) # Reset stream position

        # 7. Create and Return Flask Response
        logger.info(f"XLSX Export: Successfully generated XLSX file for execution {execution_id} (Definition {definition_id}).")
        return Response(
            file_stream,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                # Include execution ID in filename for uniqueness
                'Content-Disposition': f'attachment; filename="splunk_query_results_{execution_id}.xlsx"'
            }
        )

    except Exception as e:
        # Catch unexpected errors during the process
        logger.exception(f"XLSX Export: Unhandled error generating XLSX for execution {execution_id}: {e}")
        abort(500, description=f"An internal server error occurred while generating the XLSX file: {str(e)}")
        
        
@api_bp.route('/query/refresh/<int:definition_id>', methods=['POST'])
def refresh_query_status(definition_id):
    """
    Force refresh the status of a query that might be running or stuck
    """
    try:
        # 1. Find the query definition
        definition = QueryDefinition.get_by_id(definition_id)
        if not definition:
            return jsonify({'status': 'error', 'message': f'Query definition {definition_id} not found'}), 404
            
        # If not in running state, no need to refresh
        if definition['status'] != 'running':
            return jsonify({
                'status': 'success',
                'message': f'Query is already in {definition["status"]} state',
                'query_status': definition['status']
            }), 200
        
        # 2. Try to extract the SID from the results
        sid = None
        if definition['results']:
            try:
                results_data = json.loads(definition['results']) if isinstance(definition['results'], str) else definition['results']
                sid = results_data.get('sid')
            except Exception:
                pass
                
        if not sid:
            return jsonify({'status': 'error', 'message': 'Cannot refresh - no SID found in definition'}), 400
            
        # 3. Find an execution record to get a valid session
        executions = QueryExecution.get_for_definition(definition_id, limit=1)
        if not executions:
            return jsonify({'status': 'error', 'message': 'No execution records found for this definition'}), 400
            
        session_id = executions[0].get('session_id')
        if not session_id:
            return jsonify({'status': 'error', 'message': 'No valid session found for this query'}), 400
            
        # 4. Get session and cookies
        session = Session.get_by_id(session_id)
        if not session or not session['is_active']:
            return jsonify({'status': 'error', 'message': 'Session is no longer active'}), 400
            
        cookies = Cookie.get_for_session(session_id)
        if not cookies:
            return jsonify({'status': 'error', 'message': 'No cookies available for session'}), 400
        
        # 5. Check current job status in Splunk
        success, is_done, status_data, error = check_job_status(cookies, sid)
        
        if not success:
            return jsonify({
                'status': 'error', 
                'message': f'Failed to check job status: {error}',
                'query_status': 'unknown'
            }), 500
            
        # 6. Handle based on job status
        if is_done:
            # Job is complete, get the results
            logger.info(f"Refresh: Job {sid} is complete, fetching results")
            success, results, error = get_all_job_results(cookies, sid)
            
            if success:
                # Update the definition with results
                QueryDefinition.update_status(definition_id, 'completed', results)
                return jsonify({
                    'status': 'success',
                    'message': 'Query refreshed and completed successfully',
                    'query_status': 'completed',
                    'progress': 100.0
                }), 200
            else:
                # Query failed but we know it's done
                QueryDefinition.update_status(definition_id, 'failed', {'error': error or 'Unknown error fetching results'})
                return jsonify({
                    'status': 'error',
                    'message': f'Query completed but failed to get results: {error}',
                    'query_status': 'failed'
                }), 500
        else:
            # Job is still running, return progress info
            progress = status_data.get('done_progress', 0) * 100
            scan_count = status_data.get('scan_count', 0)
            dispatch_state = status_data.get('dispatch_state', 'UNKNOWN')
            
            # Check if we should continue monitoring this job
            if request.json and request.json.get('monitor', False):
                # Start a background thread to monitor this job until completion
                username = session['username']
                domain = session['domain']
                thread = threading.Thread(
                    target=resume_job_monitoring,
                    args=(cookies, sid, definition_id, domain, username),
                    daemon=True
                )
                thread.start()
                monitoring_msg = "Started monitoring job in background."
            else:
                monitoring_msg = "Job still in progress. Use monitor=true to monitor in background."
            
            return jsonify({
                'status': 'success',
                'message': f'Query still running. {monitoring_msg}',
                'query_status': 'running',
                'progress': progress,
                'scan_count': scan_count,
                'dispatch_state': dispatch_state
            }), 200
            
    except Exception as e:
        logger.error(f"Error refreshing query {definition_id}: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500