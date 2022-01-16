#!/bin/sh -ex

DIR=$(dirname "$(readlink -f "$0")")
cd $DIR

black src
pipenv lock -r > src/requirements.txt
sam build --cached $SAM_BUILD_OPTIONS
