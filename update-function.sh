#!/bin/bash -e
#
# Packages and updates the given AWS Lambda function
#

script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

if [[ -z "$1" ]]; then
  echo "USAGE: $0 <function>"
  exit 1
fi

if [[ ! -d "${script_dir}/lambda/functions/$1" ]]; then
  echo "ERROR: No such function '$1'"
  exit 2
fi
function="$1"

cd "${script_dir}/lambda/functions/${function}"
zip -r9 "/tmp/${function}.zip" .
aws lambda update-function-code --function-name "${function}" --zip-file "fileb:///tmp/${function}.zip"
rm -f "/tmp/${function}.zip"
