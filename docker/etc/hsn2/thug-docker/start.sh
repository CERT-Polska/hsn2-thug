#!/bin/bash

/etc/init.d/mongodb start

SCRIPT=$1
shift

exec python $SCRIPT $@