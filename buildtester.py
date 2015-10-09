#!/usr/bin/env python3

from flask import Flask, request, make_response, render_template
from flask.ext.github import GitHub, GitHubError
from collections import OrderedDict
import configparser
from datetime import datetime
import atexit
import hashlib
import hmac
import json
import os
import queue
import re
import signal
import subprocess
import sys
import threading
import time

PWD = os.path.abspath(os.path.dirname(__file__))


class Options:
    """
    Container for application settings
    """
    class files:
        """
        Container for application file settings
        """
        settings = os.path.join(PWD, 'app.ini')
        storage = os.path.join(PWD, 'storage')
        builds = os.path.join(storage, 'builds')
        temp = os.path.join(storage, 'temp')
        pickup = None

    class app:
        """
        Container for general build settings
        """
        status_uri = None
        status_endpoint = '/status/<sha1>'
        push_endpoint = '/gh/push'
        port = 7000
        title = 'Example'
        cleanup_frequency = 300
        default_context = 'build'

    class status:
        """
        Container for possible build statuses
        """
        success = 'The build succeeded'
        error = 'The build failed due to an internal error'
        failure = 'The build failed'
        queued = 'The build is queued'
        pending = 'The build is in progress'

    class github:
        """
        Container for GitHub settings
        """
        access_token = None
        webhooks_secret = None

        repository = None
        branch = None
        status_endpoint = None
        commit_uri = None

    commands = OrderedDict()

# Global variables
QUEUE = queue.Queue()
WATCH = None
PROCESS = None
RUNNING = True
LOCK = threading.Lock()
GITHUB_LOCK = threading.Lock()

# Initialize Flask app
app = Flask(__name__)

# Initialize GitHub lib. We use a personal token for this and not a client
# id / secret
app.config['GITHUB_CLIENT_ID'] = ''
app.config['GITHUB_CLIENT_SECRET'] = ''
github = GitHub(app)


def cleanup_hash(sha1):
    """
    Checks if a hash is valid. Returns the cleaned up hash if so, else False

    :param sha1: The hash to check
    :return: mixed
    """

    sha1 = sha1.strip()

    try:
        if len(sha1) > 0 and int(sha1, 16) > 0:

            # Hash is valid
            return sha1

    except ValueError:
        print("Invalid sha1 commit: {sha1}".format(sha1=sha1))

    # Hash is invalid
    return False


def retry_stale_builds():
    """
    Locates and reschedules stale builds
    :return: None
    """

    global QUEUE

    for root, dirs, files in os.walk(Options.files.builds):
        for file in files:

            # Absolute filename
            filename = os.path.join(Options.files.builds, file)

            # Get file stats
            stat = os.stat(filename)

            if stat.st_size > 32:

                # This file is > 32 bytes, meaning it is a completed build
                continue

            try:

                # Wrap this whole thing in a super generic try-catch because
                # of potential corruption

                # Open file
                with open(filename, 'r') as file_:

                    # JSON-decode file
                    data = json.load(file_)

                if data.get('status') == 'pending':

                    print("Re-queuing stale job: {sha1}".format(sha1=file))

                    # Put back in the queue. It failed in the middle of a build
                    QUEUE.put(file)

                    # Stop processing and get back to the actual queue process
                    return

            except Exception:

                # Catch any exceptions
                if os.path.getmtime(filename) < time.time() - 10:

                    print("Re-queuing corrupt job: {sha1}".format(sha1=file))

                    # Remove file
                    os.unlink(filename)

                    # If file was not modified in the last 10 seconds, lets
                    # consider it corrupt and re-queue
                    QUEUE.put(file)


def execute_command(command):
    """
    Execute the provided command

    :param command: A list of arguments
    :return: A tuple containing the output and return code
    """

    # Execute command
    process = subprocess.Popen(command, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT)

    # Return result
    return process.communicate()[0].decode('utf-8'), process.returncode


def init_dirs():
    """
    Initialize dirs. This creates necessary directories

    :return: None
    """

    # Initialize directories
    for path in [Options.files.storage, Options.files.builds,
                 Options.files.temp]:

        # Create directory
        subprocess.call(['mkdir', '-p', path])


def init_files():
    """
    Initialize files. This initializes the GIT repo

    :return: None
    """

    # Init dirs
    init_dirs()

    # Change working directory
    os.chdir(Options.files.storage)

    # Init repo
    stdout, ret = execute_command(['git', 'clone', Options.github.repository,
                                   Options.files.temp, '-b',
                                   Options.github.branch])

    # Change working directory
    os.chdir(Options.files.temp)

    # Cleanup any untracked files/directories
    execute_command(['git', 'clean', '-f', '-d'])

    if ret != 0:

        # Fetch remote repo
        stdout, ret = execute_command(['git', 'fetch', 'origin',
                                       Options.github.branch])
        if ret != 0:
            print("Fetch failed ({code}): {error}".format(error=stdout,
                                                          code=ret))
            return False

        # Hard reset to get to the right commit
        stdout, ret = execute_command(['git', 'reset', '--hard', 'origin/' +
                                       Options.github.branch])
        if ret != 0:
            print("Reset failed ({code}): {error}".format(error=stdout,
                                                          code=ret))
            return False

    return True


def write_build_file(data, status, sha1, context, write_file=True,
                     post_gh=True):
    """
    Writes the data to the build file for the given hash
    :param data: a list of data
    :param status: the status of the build
    :param sha1: the commit hash to use for the filename
    :param context: The context of this status
    :param write_file: Should we write the file?
    :param post_gh: Should we post to GitHub?
    :return: None
    """

    global GITHUB_LOCK

    print("Building {sha1} stage {stage}: {status}".format(sha1=sha1,
                                                           stage=context,
                                                           status=status))

    if write_file:
        # Path to file
        path = os.path.join(Options.files.builds, sha1)

        # Open data file
        with open(path, 'w') as file_:

            # Write data
            if data is not None:

                # Write a status + data
                file_.write(json.dumps(dict(status=status,
                                            data=data), indent=4))
            else:

                # Write a status only
                file_.write(json.dumps(dict(status=status), indent=4))

    if post_gh:
        description = getattr(Options.status, status)

        if status == 'queued':

            # GitHub doesn't support a queued status
            status = 'pending'

        # Update GH status
        data = dict(
            state=status,
            description=description,
            context=context
        )

        if Options.app.status_uri is not None:

            # Only set target url if it is configured
            data['target_url'] = Options.app.status_uri.format(sha1=sha1)

        # Acquire GH lock
        GITHUB_LOCK.acquire()

        try:
            github.post(Options.github.status_endpoint.format(sha1=sha1), data)
        except GitHubError as e:
            sys.stderr.write("Error posting to GitHub: {err}\n".format(
                err=str(e)))
        finally:
            # Release GH lock
            GITHUB_LOCK.release()


def build(sha1):
    """
    Builds the repo checked out to sha1

    :param sha1: The commit to checkout
    :return: None
    """

    print("Building {sha1}".format(sha1=sha1))

    # Initialize repo to the given sha1 commit
    if not init_files():

        # Mark as error
        write_build_file(None, 'error', sha1, Options.app.default_context,
                         post_gh=False)

        # Abort
        return

    data = list()

    # Mark as pending
    write_build_file(None, 'pending', sha1, Options.app.default_context,
                     post_gh=False)

    # Checkout commit
    stdout, ret = execute_command(['git', 'reset', '--hard', sha1])

    data.append(dict(
        cmd='Checkout',
        out=stdout,
        code=ret
    ))

    if ret != 0:
        write_build_file(data, 'failure', sha1, Options.app.default_context,
                         post_gh=False)
        return

    # Get the full SHA1 hash
    stdout, ret = execute_command(['git', 'rev-parse', 'HEAD'])

    if ret != 0:

        data.append(dict(
            cmd='Rev-parse',
            out=stdout,
            code=ret
        ))

        write_build_file(data, 'failure', sha1,
                         Options.app.default_context, post_gh=False)
        return

    stdout = stdout.strip()

    if stdout != sha1:
        # Source and destination files
        destination = os.path.join(Options.files.builds, stdout)

        write_build_file([dict(redirect=stdout)], 'success', sha1,
                         Options.app.default_context, post_gh=False)

        if os.path.exists(destination):
            # No more to do
            return

        # Use full hash
        sha1 = stdout

    # Mark as pending
    write_build_file(None, 'pending', sha1, Options.app.default_context)

    good_contexts = list()
    bad_context = None

    for label, command in Options.commands.items():

        # Expand tuple
        context, command = command

        if context != Options.app.default_context and context not in \
                good_contexts:

            # Mark as pending
            write_build_file(None, 'pending', sha1, context, write_file=False)

        # Execute command
        stdout, ret = execute_command(command.split(" "))

        data.append(dict(
            cmd=label,
            out=stdout,
            code=ret
        ))

        if ret == 0:

            if context not in good_contexts:

                # Add to list of good contexts
                good_contexts.append(context)
        else:

            # Build failed
            write_build_file(data, 'failure', sha1, context)

            # Remove
            if context in good_contexts:
                good_contexts.remove(context)

            bad_context = context

            # Stop processing
            break

    written = False

    status = 'success' if bad_context is None else 'failure'

    for context in good_contexts:

        # Write a success status
        write_build_file(data, status, sha1, context,
                         write_file=not written)
        written = True

    if bad_context is not None and Options.app.default_context != bad_context:

        # Mark as failure if there were any failures and the default context
        # was not already used
        write_build_file(None, 'failure', sha1, Options.app.default_context,
                         write_file=False)
    elif bad_context is None and Options.app.default_context not in \
            good_contexts:

        # Mark as success if there were no failures and the default context
        # was not already used
        write_build_file(data, 'success', sha1, Options.app.default_context,
                         write_file=False)

    # Init dirs
    init_dirs()


def process_queue():
    """
    Process the queue

    :return: None
    """

    global QUEUE
    global RUNNING

    # Process queue
    while RUNNING:

        # Get the next commit hash from the queue
        try:

            wait = Options.app.cleanup_frequency

            if wait < .1:

                # Wait at least .1s
                wait = .1

            # Try getting an item.
            sha1 = QUEUE.get(True, wait)

            # Start build
            build(sha1)
        except queue.Empty:

            # There hasn't been anything to do for cleanup_frequency seconds,
            # lets do some housekeeping
            retry_stale_builds()


def watch_queue():
    """
    Watches the file queue for changes

    :return: None
    """

    global RUNNING
    global LOCK
    global WATCH
    global PROCESS

    # Process queue
    while RUNNING:

        if Options.files.pickup is not None and \
                os.path.exists(Options.files.pickup):

            hashes = list()

            # Acquire lock
            LOCK.acquire()

            # Open pickup file for reading
            with open(Options.files.pickup, "r") as file_:

                # Get all the hashes
                for sha1 in file_:

                    sha1 = cleanup_hash(sha1)

                    if sha1:
                        hashes.append(sha1)

            # Open pickup file for writing
            with open(Options.files.pickup, "w") as file_:

                # Truncate file
                file_.seek(0)
                file_.truncate()

            # Release lock
            LOCK.release()

            for sha1 in hashes:
                # Mark as queued
                write_build_file(None, 'queued', sha1,
                                 Options.app.default_context, post_gh=False)

                # Add to queue
                QUEUE.put(sha1)

        # Sleep for .1 seconds before we look for more builds to perform
        time.sleep(0.1)


def shutdown(signum, frame):
    """
    We received a signal, so we need to shut down our child threads

    :param signum: The signal number
    :param frame: The frame info
    :return: None
    """

    global RUNNING

    RUNNING = False

    # Remove handler
    signal.signal(signum, signal.SIG_DFL)

    # Throw signal
    os.kill(os.getpid(), signum)


@app.route('/')
def home():
    """
    Displays the most recent builds

    :return: response
    """

    commits = list()

    for root, dirs, files in os.walk(Options.files.builds):
        for file in files:

            # Add to collection
            commits.append(file)

    # Sort by last updated descending
    commits = list(sorted(commits, key=lambda f: os.stat(os.path.join(
        Options.files.builds, f)).st_mtime, reverse=True))

    builds = list()

    count = 0
    for commit in commits:

        # Increment counter
        count += 1

        # Full path
        filename = os.path.join(Options.files.builds, commit)

        data = dict()

        if count <= 5:

            # Only load data for the 5 most recent builds
            with open(filename, 'r') as file_:
                data = json.load(file_)

        # Initialize required data
        if not isinstance(data, dict):
            data = dict()
        data['status'] = data.get('status', '')
        if not isinstance(data.get('data'), list):
            data['data'] = list()
        message = ''
        redirect = False

        if len(data['data']) > 0:

            redirect = data['data'][0].get('redirect', False)
            if redirect is not False:
                data['data'][0] = dict(
                    cmd='Redirect',
                    code=0,
                    out='Redirects to {sha1}'.format(sha1=redirect)
                )

                message = 'Resolved from {} to {}'.format(commit, redirect)
                commit = redirect

                # Full path
                filename = os.path.join(Options.files.builds, commit)

            checkout = data['data'][0]
            if checkout['cmd'] == 'Checkout' and checkout['code'] == 0:
                result = re.search('^HEAD is now at [0-f]+\s*(.+$)',
                                   checkout['out'])

                if result:

                    # Get the actual message
                    message = result.group(1)
                else:

                    # If the regexp didn't match for some reason, fall back
                    # to the raw data
                    message = checkout['out']

        status_label, status_nice = resolve_status(data['status'])

        # Get mtime
        mtime = os.stat(filename).st_mtime

        # Format mtime
        mtime = datetime.fromtimestamp(mtime).strftime('%B %d, %Y %H:%M')

        if redirect is not False:
            status_nice = ''

        builds.append(dict(sha1=commit,
                           date=mtime,
                           status_nice=status_nice,
                           status_label=status_label,
                           message=message))

    return render_template('index.html', builds=builds,
                           title=Options.app.title)


def resolve_status(code):
    """
    Get a label and status for the status code

    :param code: The status to resolve
    :return: A tuple containing the label and new status
    """

    # Default label
    status_label = 'info'
    if code == 'success':
        status_nice = 'Build Succeeded'
        status_label = 'success'
    elif code == 'error':
        status_nice = 'Build Failed (Internal Error)'
        status_label = 'danger'
    elif code == 'failure':
        status_nice = 'Build Failed'
        status_label = 'danger'
    elif code == 'queued':
        status_nice = 'Build Queued'
    elif code == 'pending':
        status_nice = 'Build Running'
    else:
        status_nice = code

    return status_label, status_nice


def build_status(sha1):
    """
    Displays the build status for a sha1 commit

    :param sha1: the sha1 commit
    :return: response
    """

    global LOCK

    sha1 = cleanup_hash(sha1)

    if sha1 is not False:
        filename = os.path.join(Options.files.builds, sha1)

    if sha1 is False:
        data = dict()
        data['data'] = list()
        data['status'] = 'failure'
        sha1 = 'INVALID'
        data['message'] = 'Invalid commit requested'
    elif os.path.exists(filename):
        with open(filename) as file:
            data = json.load(file)

        if len(data['data']) > 0 and data['data'][0].get(
                'redirect') is not None:
            # Load the redirect
            return build_status(data['data'][0].get('redirect'))
    else:
        # Acquire lock
        LOCK.acquire()

        if Options.files.pickup is not None:

            # File-based queue
            with open(Options.files.pickup, 'a') as file_:
                file_.write(sha1 + "\n")
        else:
            # Memory queue only

            # Mark as queued
            write_build_file(None, 'queued', sha1, Options.app.default_context,
                             post_gh=False)

            # Just store in memory
            QUEUE.put(sha1)


        # Release lock
        LOCK.release()

        data = dict(status='queued')

    data['data'] = data.get('data', list())
    data['status'] = data.get('status', '')
    data['sha1'] = sha1
    data['short_sha1'] = sha1[0:8]
    data['message'] = ''

    # Default label
    data['status_label'], data['status_nice'] = resolve_status(data['status'])

    if len(data['data']) > 0:

        # Get the name of the latest commit
        checkout = data['data'][0]
        if checkout['cmd'] == 'Checkout' and checkout['code'] == 0:
            result = re.search('^HEAD is now at [0-f]+\s*(.+$)',
                               checkout['out'])

            if result:

                # Get the actual message
                data['message'] = result.group(1)
            else:

                # If the regexp didn't match for some reason, fall back to
                # the raw data
                data['message'] = checkout['out']

            # Remove from collection
            data['data'] = data['data'][1:]

    data['commit_uri'] = Options.github.commit_uri.format(sha1=sha1)
    data['title'] = Options.app.title

    return render_template('status.html', **data)


def gh_push():
    """
    Processes a GitHub push WebHook

    :return: response
    """

    global LOCK

    if Options.github.webhooks_secret is not None:

        # Get request signature
        signature = request.headers.get('X-Hub-Signature')

        if signature is None:
            print("Unauthorized")
            return make_response(('Unauthorized', 403))

        # Get request data
        data = request.get_data(as_text=True)

        # Calculate HMAC digest
        digest = hmac.new(Options.github.webhooks_secret.encode('utf-8'),
                          data.encode('utf-8'),
                          digestmod=hashlib.sha1)

        if not hmac.compare_digest('sha1=' + digest.hexdigest(), signature):
            print("Unauthorized: {sig}".format(sig=signature))
            return make_response(('Unauthorized', 403))

    # Get JSON request
    req = request.get_json()

    if req.get('ref') != 'refs/heads/' + Options.github.branch:
        print('Skipping invalid ref: {ref}'.format(ref=req.get('ref')))
        return make_response("Ignoring branch", 200)

    sha1 = req.get('after')

    # Acquire lock
    LOCK.acquire()

    if Options.files.pickup is not None:

        # Write to pickup file
        with open(Options.files.pickup, 'a') as file_:
            file_.write(sha1 + "\n")
    else:

        # Mark as queued
        write_build_file(None, 'queued', sha1, Options.app.default_context,
                         post_gh=False)

        # Just store in memory
        QUEUE.put(sha1)

    # Release lock
    LOCK.release()

    return make_response(json.dumps('Starting build'), 200,
                         {'Content-Type': 'application/json'})


@github.access_token_getter
def token_getter():
    """
    Returns the GitHub access token

    :return: the token
    """
    return Options.github.access_token


def initialize(argv=sys.argv[1:]):
    """
    Initialize the server

    :return: None
    """

    global PROCESS
    global RUNNING
    global WATCH

    if len(argv) > 0:

        # Options file specified
        Options.files.settings = argv[0]

    try:

        # Initialize config parser
        parser = configparser.ConfigParser()

        # Load config
        parser.read(Options.files.settings)

        # Get sections
        sections = parser.sections()

        # Remove invalid sections
        sections = list(v for v in sections if hasattr(Options, v))

        for section in sections:

            # Grab the Options.{section} object so this is a bit cleaner
            options_section = getattr(Options, section)

            if isinstance(options_section, dict):

                for key, val in parser.items(section):
                    # Fill up our dictionary. Because optionxform will make
                    # the key lowercase, but we don't want to replace that
                    # lest we make the entire file case-sensitive, just
                    # apply the title method to the keys
                    options_section[key.title()] = val

            else:
                for key in parser[section]:
                    # Iterate app section

                    if hasattr(options_section, key):

                        # If this is a valid option, replace the default
                        setattr(options_section, key, parser.get(section, key))

    except configparser.Error as e:
        print("Config parsing error: {err}".format(err=e.message))
        sys.exit(1)

    # Free memory
    del parser
    del sections

    # Validate config
    if Options.github.branch is None:
        print("The GitHub branch must be configured!")
        sys.exit(1)

    if Options.files.pickup == '':
        Options.files.pickup = None

    try:
        Options.app.port = int(Options.app.port)
    except ValueError:
        print("Invalid listen port specified!")
        sys.exit(1)

    try:
        Options.app.cleanup_frequency = float(Options.app.cleanup_frequency)
    except ValueError:
        print("Invalid cleanup frequency specified!")
        sys.exit(1)

    # Parse commands
    commands = OrderedDict()
    for label, command in Options.commands.items():
        if '|' in label:
            context, label = label.split('|')
            context = context.lower()
            label = label.title()
        else:
            context = Options.app.default_context.lower()

        # Add to collection
        commands[label] = context, command

    # Replace commands in options
    Options.commands = commands

    # Register routes
    if Options.app.push_endpoint != '':
        app.route(Options.app.push_endpoint, methods=['post'])(gh_push)

    if Options.app.status_endpoint != '':
        app.route(Options.app.status_endpoint, methods=['get'])(build_status)

    # Initialize dirs
    init_dirs()

    # Register signal handlers
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGHUP, shutdown)

    # Register shutdown handler
    atexit.register(init_dirs)

    # Init threads
    PROCESS = threading.Thread(target=process_queue)

    if Options.files.pickup is not None:

        # Only init the queue watching thread if there is a file queue
        WATCH = threading.Thread(target=watch_queue)

    # Start thread
    PROCESS.start()

    if Options.files.pickup is not None:

        # Only start the queue watching thread if there is a file queue
        WATCH.start()


def startup():
    """
    Starts up the Flask server

    :return: None
    """
    app.run(port=Options.app.port)


def deinitialize():
    """
    De-initializes the server

    :return: None
    """
    global RUNNING
    global LOCK
    global WATCH
    global PROCESS

    # Stop the threads
    RUNNING = False

    # Wait for threads to finish
    PROCESS.join()

    if Options.files.pickup is not None:

        # Only wait on the queue watching thread if there is a file queue
        WATCH.join()

if __name__ == '__main__':

    initialize()
    if Options.app.port != 0:

        # Startup Flask if necessary
        startup()
    else:

        # Wait for the process to finish
        PROCESS.join()

    deinitialize()
