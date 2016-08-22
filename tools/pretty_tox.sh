#! /bin/sh

TESTRARGS=$1
CONCURRENCY=${OS_TESTR_CONCURRENCY:-}
if [ -n "$CONCURRENCY" ]
then
  CONCURRENCY="--concurrency=$CONCURRENCY"
fi

exec 3>&1
status=$(exec 4>&1 >&3; (python setup.py testr --slowest --testr-args="--subunit $TESTRARGS $CONCURRENCY"; echo $? >&4 ) | $(dirname $0)/subunit-trace.py -f) && exit $status
