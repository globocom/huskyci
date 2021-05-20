#!/bin/bash
#
# Copyright 2019 Globo.com authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.
#
# This script will generate a local huskyCI token using default local credentials
#

printf "Generating Local Token      ..." && sleep 60

token=$(curl -s -H "Content-Type: application/json" -H "Authorization: Basic aHVza3lDSVVzZXI6aHVza3lDSVBhc3N3b3Jk" http://localhost:8888/api/1.0/token -X POST -d '{"repositoryURL": "https://github.com/globocom/huskyCI.git"}' | awk -F '"' '{print $4}')

if [ $? -eq 0 ]; then
    echo " done"
else
    echo " error. Try running make generate-local-token"
fi

echo "export HUSKYCI_CLIENT_TOKEN=\"$token\"" >> .env