from flask import Flask, request, jsonify
from urllib.parse import urlsplit
import voyager_settings
import threading
import json

from app.config import SECRET_KEY, logger
from app.models.database import init_db, QueryDefinition, QueryExecution, Session, Cookie
from app.services.session import restore_active_sessions
from app.routes.api import api_bp
from app.routes.views import views_bp
from app.routes.workbench import workbench_bp
from app.models.database import QueryDefinition, QueryExecution, Session, Cookie
from app.services.splunk import check_job_status, get_all_job_results, background_rerun_query

def recover_running_jobs():
    """
    Find running query definitions. Try to recover using SID.
    If SID invalid/missing, try auto-rerun if original user session is active.
    """
    try:
        # Get running definitions, including the new 'sid' column
        running_defs = QueryDefinition.get_by_status('running')
        if not running_defs:
            logger.info("No running jobs to recover")
            return

        logger.info(f"Found {len(running_defs)} running jobs to potentially recover")

        for definition in running_defs:
            query_id = definition['id']
            sid = definition.get('sid') # <<< Get SID directly from the column

            if not sid:
                logger.warning(f"Recover: Definition {query_id} is 'running' but has no SID stored. Attempting auto-rerun.")
                trigger_auto_rerun(definition) # Try fallback immediately
                continue

            # Find an active session associated with ANY past execution to monitor
            # Prefer latest execution for context
            executions = QueryExecution.get_for_definition(query_id, limit=1)
            if not executions:
                logger.warning(f"Cannot recover job for definition {query_id} (SID: {sid}) - no execution history found.")
                # Mark as failed? Or attempt auto-rerun? Let's try auto-rerun.
                trigger_auto_rerun(definition)
                continue

            # Need a session to perform checks. Find the most recent session used.
            # We might need to check *multiple* sessions if the most recent isn't active.
            # Simple approach: Use the latest execution's session if available.
            session_id_exec = executions[0].get('session_id')
            session_for_check = None
            cookies_for_check = None

            if session_id_exec:
                temp_session = Session.get_by_id(session_id_exec)
                if temp_session and temp_session['is_active']:
                    temp_cookies = Cookie.get_for_session(session_id_exec)
                    if temp_cookies:
                        session_for_check = temp_session
                        cookies_for_check = temp_cookies
                        logger.info(f"Recover: Using session {session_id_exec} from latest execution for SID {sid} check.")

            # If latest execution session didn't work, try finding *any* active session for the user/domain
            if not session_for_check:
                orig_username = executions[0].get('username')
                orig_domain = executions[0].get('domain')
                if orig_username and orig_domain:
                    logger.info(f"Recover: Latest execution session inactive/invalid. Searching for *any* active session for {orig_username}@{orig_domain}.")
                    active_user_session = Session.get_active_for_user_domain(orig_username, orig_domain)
                    if active_user_session:
                        active_user_cookies = Cookie.get_for_session(active_user_session['id'])
                        if active_user_cookies:
                            session_for_check = active_user_session
                            cookies_for_check = active_user_cookies
                            logger.info(f"Recover: Found alternative active session {active_user_session['id']} for SID {sid} check.")

            if not session_for_check or not cookies_for_check:
                logger.warning(f"Cannot recover job for definition {query_id} (SID: {sid}) - no suitable active session found.")
                # Try auto-rerun as a last resort
                trigger_auto_rerun(definition)
                continue

            # Start a background thread to resume monitoring using the found session/cookies
            logger.info(f"Recovering job monitoring for definition {query_id}, SID {sid}")
            thread = threading.Thread(
                target=resume_job_monitoring,
                args=(cookies_for_check, sid, query_id, session_for_check['domain'], session_for_check['username']),
                daemon=True
            )
            thread.start()

    except Exception as e:
        logger.error(f"Error in recover_running_jobs: {str(e)}")

def resume_job_monitoring(cookies, sid, query_id, domain, username):
    """
    Resume monitoring a job. If SID becomes invalid, trigger auto-rerun.
    """
    try:
        logger.info(f"Resuming monitoring for job {sid} (definition {query_id})")

        # Check current status, including SID validity
        success_check, is_done, sid_valid, status_data, error_check = check_job_status(cookies, sid)

        if not sid_valid:
            logger.warning(f"Resume Monitoring: SID {sid} for definition {query_id} is invalid/expired. Triggering auto-rerun.")
            definition = QueryDefinition.get_by_id(query_id) # Get definition details for rerun
            if definition:
                trigger_auto_rerun(definition)
            else:
                 logger.error(f"Cannot trigger auto-rerun for invalid SID {sid} - failed to fetch definition {query_id}")
                 QueryDefinition.update_status(query_id, 'failed', {"error": "Recovery failed: SID invalid and definition missing"})
            return # Stop monitoring this invalid SID

        if not success_check:
            logger.error(f"Resume Monitoring: Failed to check status of job {sid}: {error_check}. Stopping monitoring.")
            # Mark as failed? Or leave as running? Let's mark failed.
            QueryDefinition.update_status(query_id, 'failed', {"error": f"Failed to resume monitoring (status check failed): {error_check}"})
            return

        if is_done:
            # Job finished, get results using get_all_job_results (it handles completion state)
            logger.info(f"Resume Monitoring: Job {sid} already completed, fetching results.")
            success_results, sid_still_valid, results, error_results = get_all_job_results(cookies, sid)

            if not sid_still_valid: # Check again
                 logger.warning(f"Resume Monitoring: SID {sid} became invalid while fetching results for completed job. Triggering auto-rerun.")
                 definition = QueryDefinition.get_by_id(query_id)
                 if definition: trigger_auto_rerun(definition)
                 else: QueryDefinition.update_status(query_id, 'failed', {"error": "Recovery failed: SID invalid during result fetch and definition missing"})
                 return

            if success_results:
                QueryDefinition.update_status(query_id, 'completed', results)
                logger.info(f"Successfully recovered results for completed job {sid}")
            else:
                QueryDefinition.update_status(query_id, 'failed', {"error": f"Failed to get results for completed job: {error_results}"})
                logger.error(f"Failed to get results for completed job {sid}: {error_results}")
        else:
            # Job is still running, use get_all_job_results to continue monitoring
            logger.info(f"Resume Monitoring: Job {sid} still running at {status_data.get('done_progress', 0)*100:.2f}%, continuing monitoring.")
            success_results, sid_still_valid, results, error_results = get_all_job_results(cookies, sid)

            if not sid_still_valid: # Check again
                 logger.warning(f"Resume Monitoring: SID {sid} became invalid during continued monitoring. Triggering auto-rerun.")
                 definition = QueryDefinition.get_by_id(query_id)
                 if definition: trigger_auto_rerun(definition)
                 else: QueryDefinition.update_status(query_id, 'failed', {"error": "Recovery failed: SID invalid during monitoring and definition missing"})
                 return

            if success_results:
                QueryDefinition.update_status(query_id, 'completed', results)
                logger.info(f"Successfully completed monitoring for recovered job {sid}")
            else:
                QueryDefinition.update_status(query_id, 'failed', {"error": f"Failed during continued monitoring: {error_results}"})
                logger.error(f"Failed during continued monitoring of job {sid}: {error_results}")

    except Exception as e:
        logger.error(f"Error in resume_job_monitoring for job {sid}: {str(e)}")
        # Mark as failed on unexpected error
        try: QueryDefinition.update_status(query_id, 'failed', {"error": f"Exception during recovery: {str(e)}"})
        except: pass

def trigger_auto_rerun(definition):
    """
    Checks for an active session for the original user and starts a background
    thread to re-run the query if possible.
    """
    query_id = definition['id']
    logger.info(f"Attempting auto-rerun fallback for definition {query_id}")

    # Find original user from latest execution
    executions = QueryExecution.get_for_definition(query_id, limit=1)
    if not executions:
        logger.error(f"Auto-rerun failed for {query_id}: No execution history found.")
        QueryDefinition.update_status(query_id, 'failed', {"error": "Recovery failed: No execution history found for auto-rerun"})
        return

    orig_username = executions[0].get('username')
    orig_domain = executions[0].get('domain')

    if not orig_username or not orig_domain:
        logger.error(f"Auto-rerun failed for {query_id}: Execution history missing user/domain.")
        QueryDefinition.update_status(query_id, 'failed', {"error": "Recovery failed: Execution history incomplete for auto-rerun"})
        return

    # Check for *any* active session for this user/domain
    active_session = Session.get_active_for_user_domain(orig_username, orig_domain)

    if active_session:
        logger.info(f"Found active session {active_session['id']} for user {orig_username}@{orig_domain}. Starting background auto-rerun for definition {query_id}.")
        # Launch the rerun service in a background thread
        rerun_thread = threading.Thread(
            target=background_rerun_query,
            args=(query_id, orig_username, orig_domain),
            daemon=True
        )
        rerun_thread.start()
        # Leave the definition status as 'running' - the background thread will update it
    else:
        logger.warning(f"Auto-rerun cannot proceed for definition {query_id}: No active session found for original user {orig_username}@{orig_domain}.")
        # Mark as failed as we cannot recover or rerun
        QueryDefinition.update_status(query_id, 'failed', {"error": "Recovery failed: SID invalid/missing and no active user session found for auto-rerun"})

def _origin_of(url):
    p = urlsplit(url or "")
    return f"{p.scheme}://{p.netloc}".lower() if p.scheme and p.netloc else ""


def install_origin_guard(app):
    """
    Cross-origin rules, read from the settings on every request:
    - the userscript on the configured Splunk origin may POST cookies (/api/receive_cookies);
    - any other cross-origin request that changes state is refused, so a web page can't start
      Splunk searches or jobs through this local app with your session.
    """
    COOKIE_PATHS = ("/api/receive_cookies",)

    @app.before_request
    def _guard():
        origin = (request.headers.get("Origin") or "").lower()
        if not origin:
            return None     # same-origin GETs, the exporter, curl: no Origin header
        own = _origin_of(request.host_url)
        splunk = _origin_of(voyager_settings.get("splunk_base"))
        if request.path in COOKIE_PATHS and splunk and origin == splunk:
            if request.method == "OPTIONS":
                return app.make_default_options_response()
            return None
        if origin != own and request.method not in ("GET", "HEAD"):
            return jsonify({"status": "error", "message": "cross-origin request refused"}), 403
        return None

    @app.after_request
    def _cors(resp):
        origin = (request.headers.get("Origin") or "").lower()
        splunk = _origin_of(voyager_settings.get("splunk_base"))
        if request.path in COOKIE_PATHS and splunk and origin == splunk:
            resp.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin")
            resp.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
            resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
            resp.headers["Vary"] = "Origin"
        return resp


def create_app():
    """
    Create and configure the Flask application
    """
    app = Flask(__name__,
                static_folder='static',
                template_folder='templates')

    app.config['SECRET_KEY'] = SECRET_KEY
    install_origin_guard(app)

    init_db()
    app.register_blueprint(api_bp)
    app.register_blueprint(views_bp)
    app.register_blueprint(workbench_bp)

    with app.app_context():
        try:
            logger.info("Restoring active sessions...")
            restore_active_sessions()
            logger.info("Recovering running queries...")
            recover_running_jobs() # Calls the updated recovery logic
        except Exception as e:
            logger.error(f"Error during application initialization: {str(e)}")

    logger.info("Application initialized")
    return app