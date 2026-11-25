import json
import socket

from flask import Blueprint, render_template, redirect, url_for, jsonify, request, g

from app.models.database import Session, QueryDefinition, QueryExecution, InstanceUserMapping
from app.config import logger

# Create a blueprint for view routes
views_bp = Blueprint('views', __name__)

@views_bp.before_request
def load_preferred_user():
    logger.info("--- Running load_preferred_user ---")
    g.user = None
    user_session_dict = None # Use a temporary variable to hold the fetched session dict
    preferred_session_id = request.cookies.get('preferred_session_id')
    logger.info(f"Value read from 'preferred_session_id' cookie: {preferred_session_id}")

    # --- Stage 1: Try loading based on the cookie ---
    if preferred_session_id:
        try:
            session_id_from_cookie = int(preferred_session_id)
            logger.info(f"Attempting to load session ID from cookie: {session_id_from_cookie}")
            temp_session = Session.get_by_id(session_id_from_cookie) # Fetches dict with 'id' key
            logger.info(f"Result from Session.get_by_id({session_id_from_cookie}): {temp_session}")
            if temp_session and temp_session.get('is_active'):
                user_session_dict = temp_session # Store the fetched dict temporarily
                logger.info(f"Successfully loaded session {session_id_from_cookie} (User: '{user_session_dict.get('username')}') from cookie.")
            # ... (logging for inactive/not found) ...
        except ValueError:
             logger.error(f"Invalid non-integer value in 'preferred_session_id' cookie: {preferred_session_id}")
        except Exception as e:
             logger.error(f"Exception during cookie-based session loading: {e}", exc_info=True)

    # --- Stage 2: If cookie didn't yield a user, use Instance Mapping ---
    if user_session_dict is None:
        logger.info("No valid user found via cookie. Attempting instance mapping lookup.")
        try:
            instance_id = socket.gethostname()
            logger.info(f"Current instance identifier: {instance_id}")
            mapping = InstanceUserMapping.get_by_instance(instance_id) # Fetches mapping

            if mapping:
                map_username = mapping['username']
                map_domain = mapping['domain']
                logger.info(f"Found mapping: Instance '{instance_id}' -> User '{map_username}' @ Domain '{map_domain}'. Searching for active session...")
                # Find the ACTIVE session using the existing Session class method
                active_mapped_session = Session.get_active_for_user_domain(map_username, map_domain) # Fetches dict with 'id' key
                if active_mapped_session:                
                    user_session_dict = active_mapped_session # Store the fetched dict temporarily
                    
                    # !!! Set flag when fallback is successful !!!
                    g.set_preference_cookie = True # Set the flag
                    # --- ADD THIS LOG ---
                    logger.info(f"!!! Fallback SUCCESS: Setting g.set_preference_cookie to True !!!")
                    
                    logger.info(f"Found active session ID {user_session_dict.get('id')} via instance mapping.")
                # ... (logging for no active session found) ...
            # ... (logging for no mapping found) ...
        except Exception as e:
             logger.error(f"Error during instance mapping lookup: {e}", exc_info=True)

    # --- Final Step: Prepare and Assign to g.user ---
    if user_session_dict and isinstance(user_session_dict, dict):
        # Check if 'id' exists and add 'session_id' as an alias if it's missing
        if 'id' in user_session_dict and 'session_id' not in user_session_dict:
            user_session_dict['session_id'] = user_session_dict['id']
            logger.debug(f"Added 'session_id' key (value: {user_session_dict['session_id']}) to user session dict to match template expectation.")

        g.user = user_session_dict # Assign the potentially modified dictionary to g.user
        logger.info(f"--- load_preferred_user finished. g.user is set to: Username: {g.user.get('username', 'N/A')}, session_id: {g.user.get('session_id', 'N/A')} ---")
    else:
        g.user = None # Ensure g.user is explicitly None if no session found or not a dict
        logger.info(f"--- load_preferred_user finished. No user session found or invalid data type. g.user is None. ---")
        
@views_bp.after_request
def set_preference_cookie_after_request(response):
    # --- ADD THIS LOG ---
    logger.info(f"--- Running after_request handler. g keys: {list(g.__dict__.keys())} ---")
    # --- END ADD ---

    # Check if the flag was set in before_request and if g.user was successfully set
    flag_set = g.get('set_preference_cookie', False) # Default to False if not present
    user_present = g.get('user') is not None
    session_id_present = user_present and 'session_id' in g.user

    # --- ADD MORE LOGGING ---
    logger.info(f"after_request check: flag_set={flag_set}, user_present={user_present}, session_id_present={session_id_present}")
    # --- END ADD ---

    if flag_set and user_present and session_id_present:
        try:
            session_id_to_set = g.user['session_id']
            # --- ADD THIS LOG ---
            logger.info(f"after_request: Conditions met. Attempting to set 'preferred_session_id' cookie to {session_id_to_set}.")
            # --- END ADD ---
            response.set_cookie('preferred_session_id', str(session_id_to_set), max_age=60*60*24*30) # 30 days
            # --- ADD THIS LOG ---
            logger.info(f"after_request: response.set_cookie called.")
            # --- END ADD ---
        except Exception as e:
            logger.error(f"after_request: Failed to set preference cookie: {e}", exc_info=True)
    else:
         logger.info(f"after_request: Conditions not met, cookie not set.") # Log why not set

    return response

@views_bp.route('/')
def index():
    """
    Render the dashboard homepage
    """
    return render_template(
        'index.html', 
        current_user=g.user
    )

@views_bp.route('/sessions')
def sessions():
    """
    Render the sessions page with unique username+domain combinations
    """
    # Get all sessions
    all_sessions = Session.get_all_sessions()
    
    # Create dict to store most recent session for each username+domain
    unique_sessions = {}
    
    for session in all_sessions:
        key = f"{session['username']}@{session['domain']}"
        if key not in unique_sessions or session['created_at'] > unique_sessions[key]['created_at']:
            unique_sessions[key] = session
    
    # Convert back to list
    unique_session_list = list(unique_sessions.values())
    
    return render_template(
        'sessions.html', 
        current_user=g.user,      
        sessions=unique_session_list
    )

@views_bp.route('/query')
def query():
    """
    Render the query page
    """
    # Get all domains with active sessions
    domains = []
    active_sessions = Session.get_all_active()
    
    for session in active_sessions:
        domains.append({
            'domain': session['domain'],
            'username': session['username'],
            'session_id': session['id']
        })
    
    return render_template(
        'query.html', 
        current_user=g.user, 
        domains=domains
    )
    
@views_bp.route('/debug/query/execution/<int:execution_id>')
def debug_execution(execution_id):
    """
    Debug endpoint for query execution results.
    """
    execution = QueryExecution.get_by_id(execution_id) # Fetches joined data

    if not execution:
        return jsonify({
            'status': 'error',
            'message': f'Query execution {execution_id} not found'
        }), 404

    results = execution.get('results') # Already potentially parsed by get_by_id

    # Prepare debug info from the execution object
    debug_info = {
        'execution_id': execution_id,
        'query_definition_id': execution.get('query_definition_id'),
        'session_id': execution.get('session_id'),
        'username': execution.get('username'),
        'domain': execution.get('domain'),
        'query_text': execution.get('query_text'),
        'earliest_time': execution.get('earliest_time'),
        'latest_time': execution.get('latest_time'),
        'status': execution.get('status'),
        'created_at': execution.get('created_at'),
        'completed_at': execution.get('completed_at'),
        'results_type': type(results).__name__ if results is not None else 'None',
        'results_sample': None,
        'is_json_string_in_db': False, # We check type after potential parsing
        'has_fields_rows': isinstance(results, dict) and 'fields' in results and 'rows' in results
    }

    # Add results sample carefully
    if results is not None:
        try:
            # Try converting back to string for consistent sampling
            results_str = json.dumps(results) if not isinstance(results, str) else results
            debug_info['results_sample'] = results_str[:1000]
            # Check if the ORIGINAL value in DB *might* have been a JSON string
            # This is hard to tell definitively after parsing, but we can infer
            if isinstance(results, (dict, list)):
                 # It was likely parsed from a JSON string or stored directly as such
                 pass # Could add a specific flag if needed, but type implies it
        except Exception:
             debug_info['results_sample'] = str(results)[:1000] # Fallback to simple string conversion

    return jsonify(debug_info)

@views_bp.route('/session/<int:session_id>')
def session_detail(session_id):
    """
    Render the session detail page, retrieving execution history
    based on the session's user and domain.
    """
    session = Session.get_by_id(session_id)
    if not session:
        logger.warning(f"Session {session_id} not found")
        return redirect(url_for('views.sessions'))

    executions = [] # Default to empty list
    username = session.get('username')
    domain = session.get('domain')

    if username and domain:
        # --- Use the correct method to fetch history ---
        logger.info(f"Fetching execution history for user '{username}' on domain '{domain}' (from session {session_id})")
        executions = QueryExecution.get_history_for_user_domain(username, domain)
        # The result includes joined definition data needed by the template
    else:
        logger.warning(f"Session {session_id} is missing username ('{username}') or domain ('{domain}'), cannot fetch execution history.")

    return render_template(
        'session_detail.html', 
        current_user=g.user,
        session=session,
        executions=executions
    )

@views_bp.route('/query/execution/<int:execution_id>')
def execution_detail(execution_id):
    """
    Render the query execution detail page.
    """
    # --- Use the correct method name: get_execution_details ---
    execution = QueryExecution.get_execution_details(execution_id)

    if not execution:
        logger.warning(f"Query execution {execution_id} not found")
        # Redirect somewhere sensible, maybe index or sessions page
        return redirect(url_for('views.index')) # Or views.sessions

    # The get_execution_details method already joins definition data
    # and attempts to parse the 'results' JSON field within the dictionary it returns.
    # So, we just pass the 'execution' dictionary to the template.

    return render_template(
        'execution_detail.html', 
        current_user=g.user,
        execution=execution
    )
    
@views_bp.route('/set_active_session/<int:session_id>')
def set_active_session(session_id):
    logger.info(f"--- Running set_active_session for ID: {session_id} ---") # Start marker
    session = Session.get_by_id(session_id)
    logger.info(f"Result from Session.get_by_id({session_id}): {session}") # Log DB result

    if not session:
        logger.warning(f"Session {session_id} NOT FOUND in database. Cannot set cookie.")
        return redirect(url_for('views.index')) # Redirect without setting cookie

    logger.info(f"Session {session_id} found. Checking 'is_active': {session.get('is_active')}") # Log active check
    if not session.get('is_active'):
         logger.warning(f"Session {session_id} IS NOT ACTIVE. Cannot set cookie.")
         return redirect(url_for('views.index')) # Redirect without setting cookie

    # If we reach here, the session is valid and active
    logger.info(f"Session {session_id} is valid and active. Proceeding to set cookie.")
    response = redirect(url_for('views.index'))
    response.set_cookie('preferred_session_id', str(session_id), max_age=60*60*24*30) # 30 days
    logger.info(f"Cookie 'preferred_session_id={session_id}' added to response object.")
    # Log the Set-Cookie header directly if possible (might need a bit more work depending on WSGI server)
    # For simple Flask/Waitress, check the response object's internal state if available,
    # or just rely on the next step (Network Tab)
    logger.info(f"--- set_active_session finished for ID: {session_id}. Returning redirect response. ---")
    return response