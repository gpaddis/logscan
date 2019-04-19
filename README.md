# logscan
[![Build Status](https://travis-ci.com/gpaddis/logscan.svg?branch=develop)](https://travis-ci.com/gpaddis/logscan)
[![codecov](https://codecov.io/gh/gpaddis/logscan/branch/develop/graph/badge.svg)](https://codecov.io/gh/gpaddis/logscan)

Scan an Apache access.log for potential SQL Injection attacks. You can also pipe the output of another command to logscan: this is useful if you want to analyze the access.log in real time. Example: `tail -f access.log | logscan -i -v`.

For a list of usage options, just run the binary without flags (or use --help).