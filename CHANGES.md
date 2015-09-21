Changes
===================
###2015.09.21
* Added default context
* Added command-specific contexts
* Added support for a config file specified as an argument
* Don't json decode and check status on files > 32 bytes. They can not be
  pending builds
