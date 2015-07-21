#!/bin/bash

/etc/init.d/mongodb start

SCRIPT=$1
shift

python $SCRIPT $@