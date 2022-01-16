#!/bin/sh

set -ex

DIR=$(dirname "$(readlink -f "$0")")
cd $DIR

pipenv run black src
pipenv requirements > src/requirements.txt
sam build --cached $SAM_GLOBAL_OPTIONS $SAM_BUILD_OPTIONS "$@"
