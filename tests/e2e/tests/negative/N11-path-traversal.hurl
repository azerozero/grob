# Path traversal attempt
GET http://{{host}}/../../../etc/passwd
HTTP 401
[Asserts]
body not contains "root:"
body not contains "/bin/sh"
body not contains "daemon:"
