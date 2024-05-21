#!/bin/bash

nginx &

/usr/src/app/secure-communicator-server

wait -n

exit $?