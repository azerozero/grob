# Attempts a path traversal attack by embedding "../" sequences in the URL.
# Grob must return 400 or 404 and must not serve any part of the host
# filesystem.  The response body must not contain /etc/passwd content.
GET http://{{host}}/../../etc/passwd
HTTP [400, 404]
[Asserts]
body not contains "root:"
body not contains "/bin/"
