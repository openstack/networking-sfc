#! /bin/sh

TESTRARGS=$1

exec 3>&1
status=$(exec 4>&1 >&3; (python -m testtools.run discover -t ./ $1) | cat) && exit $status
