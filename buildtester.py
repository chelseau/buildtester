#!/usr/bin/env python3

from flask import Flask, request, make_response, render_template
from flask.ext.github import GitHub, GitHubError
from collections import OrderedDict
import configparser
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


def clean_temp():
    """
    Cleanup temp path

    :return: None
    """

    # Remove temp path
    subprocess.call(['rm', '-rf', Options.files.temp])


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

    # Clean temp dir
    clean_temp()

    # Init repo
    stdout, ret = execute_command(['git', 'clone', Options.github.repository,
                                   Options.files.temp, '-b',
                                   Options.github.branch])

    # Change working directory
    os.chdir(Options.files.temp)

    if ret != 0:
        print("Clone failed ({code}): {error}".format(error=stdout, code=ret))
        return False

    return True


def write_build_file(data, status, sha1):
    """
    Writes the data to the build file for the given hash
    :param data: a list of data
    :param status: the status of the build
    :param sha1: the commit hash to use for the filename
    :return: None
    """

    global GITHUB_LOCK

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

    description = getattr(Options.status, status)

    if status == 'queued':

        # GitHub doesn't support a queued status
        status = 'pending'

    # Update GH status
    data = dict(
        state=status,
        description=description,
        context='build'
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

    # Cleanup temp dir
    clean_temp()

    # Initialize repo to the given sha1 commit
    if not init_files():

        # Mark as error
        write_build_file(None, 'error', sha1)

        # Abort
        return

    data = list()

    # Mark as pending
    write_build_file(None, 'pending', sha1)

    # Checkout commit
    stdout, ret = execute_command(['git', 'reset', '--hard', sha1])

    data.append(dict(
        cmd='Checkout',
        out=stdout,
        code=ret
    ))

    if ret != 0:
        write_build_file(data, 'failure', sha1)
        return

    for label, command in Options.commands.items():
        # Execute command
        stdout, ret = execute_command(command.split(" "))

        data.append(dict(
            cmd=label,
            out=stdout,
            code=ret
        ))

        if ret != 0:
            write_build_file(data, 'failure', sha1)
            return

    # Write a success status
    write_build_file(data, 'success', sha1)

    # Cleanup temp dir
    clean_temp()


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
        sha1 = QUEUE.get(True)

        # Start build
        build(sha1)


def watch_queue():
    """
    Main event loop. Gets things going

    :return: None
    """

    global RUNNING
    global LOCK

    # Process queue
    while RUNNING:

        if Options.files.pickup is not None and \
                os.path.exists(Options.files.pickup):

            # Acquire lock
            LOCK.acquire()

            # Open pickup file for reading
            with open(Options.files.pickup, "r") as file_:

                # Get all the hashes
                for sha1 in file_:

                    try:
                        if len(sha1.strip()) > 0 and int(sha1, 16) > 0:

                            sha1 = sha1.strip()

                            # Mark as queued
                            write_build_file(None, 'queued', sha1)

                            # Add to queue
                            QUEUE.put(sha1)

                    except ValueError:
                        print("Invalid sha1 commit: {sha1}".format(sha1=sha1))

            # Open pickup file for writing
            with open(Options.files.pickup, "w") as file_:

                # Truncate file
                file_.seek(0)
                file_.truncate()

            # Release lock
            LOCK.release()

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


def build_status(sha1):
    """
    Displays the build status for a sha1 commit

    :param sha1: the sha1 commit
    :return: response
    """

    global LOCK

    filename = os.path.join(Options.files.builds, sha1)

    if os.path.exists(filename):
        with open(filename) as file:
            data = json.load(file)
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
            write_build_file(None, 'queued', sha1)

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
    data['status_label'] = 'info'
    if data['status'] == 'success':
        data['status_nice'] = 'Build Succeeded'
        data['status_label'] = 'success'
    elif data['status'] == 'error':
        data['status_nice'] = 'Build Failed (Internal Error)'
        data['status_label'] = 'danger'
    elif data['status'] == 'failure':
        data['status_nice'] = 'Build Failed'
        data['status_label'] = 'danger'
    elif data['status'] == 'queued':
        data['status_nice'] = 'Build Queued'
    elif data['status'] == 'pending':
        data['status_nice'] = 'Build Running'
    else:
        data['status_nice'] = data['status']

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
        write_build_file(None, 'queued', sha1)

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


def main():
    """
    Startup the server

    :return: None
    """

    global RUNNING

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
                    # Fill up our dictionary
                    options_section[key] = val

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
        exit(1)

    # Register routes
    if Options.app.push_endpoint != '':
        app.add_url_rule(Options.app.push_endpoint, 'post', gh_push)

    if Options.app.status_endpoint != '':
        app.add_url_rule(Options.app.status_endpoint, 'get', build_status)

    # Initialize dirs
    init_dirs()

    # Register signal handlers
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGHUP, shutdown)

    # Register shutdown handler
    atexit.register(clean_temp)

    # Init threads
    process = threading.Thread(target=process_queue)
    watch = threading.Thread(target=watch_queue)

    # Start thread
    process.start()
    watch.start()

    app.run(port=Options.app.port)

    # Put a terminating item in the queue
    RUNNING = False

    # Wait for threads to finish
    process.join()
    watch.join()

if __name__ == '__main__':

    main()