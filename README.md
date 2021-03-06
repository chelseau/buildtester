Build Tester
===================

## About
This is a basic script / Python (Flask) server built to add some sanity checks
to GitHub merging.

## Requirements
* [Python 3](https://www.python.org)
* [Flask](http://flask.pocoo.org)
* [GitHub-Flask](https://github-flask.readthedocs.org/en/latest/)

## Usage
* Copy app.sample.ini to app.ini. This will be your configuration file. The
  specific configuration is documented in the configuration file so I won't
  document it here, but the following options are of note:
    * If pickup is configured (files section), this file will be checked for
      hashes. This is so that external apps can tell the app to build a hash.
      It is disabled by default because usually build requests will come from
      /gh/push and /status/{sha1}
    * Commands are not super complicated, and they're not exactly executed in
      a raw fashion. Specifying directory/file names with spaces in them in
      the commands will not work as they will be treated as separate arguments
      **even if quoted**. I may change this in the future if a need arises,
      but, spaces shouldn't be in filenames.
* While not necessary, if you wish to ensure that failed builds cannot be
  merged into your master branch (or any other branch), you can enable branch
  protection with status checks.

    To do this, visit your repo and go to branch settings. Under *Require
    status checks to pass before merging*, a list of checks will be displayed.
    You need to have at least one set already to use it (which means before you
    can enable that you have to successfully push a status.)

## Issues
Feel free to send any issues or pull requests to [buildtester](https://github.com/chelseau/buildtester).
