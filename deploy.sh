#!/bin/sh

set -ex

sam deploy $SAM_GLOBAL_OPTIONS $SAM_DEPLOY_OPTIONS "$@"
