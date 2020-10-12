check that cgi-exec is producing expected results:

  $ [ -n "$BUILD_BIN_DIR" ] && export PATH="$BUILD_BIN_DIR:$PATH"
  $ ln -sf $BUILD_BIN_DIR/cgi-io $BUILD_BIN_DIR/cgi-exec

  $ for file in $(LC_ALL=C find "$TESTDIR/test-cases" -type f | sort); do
  >   export CONTENT_TYPE="application/x-www-form-urlencoded"; \
  >   export CONTENT_LENGTH="$(wc -c < $file)"; \
  >   printf "\n[-] testing: $(basename $file)\n"; \
  >   valgrind --quiet --leak-check=full cgi-exec < $file; \
  > done
  
  [-] testing: cgi-exec-01.txt
  Status: 400 Invalid command parameter\r (esc)
  Content-Type: text/plain\r (esc)
  \r (esc)
  Invalid command parameter
  
  [-] testing: cgi-exec-02.txt
  Status: 200 OK\r (esc)
  Content-Type: application/octet-stream\r (esc)
  \r (esc)
  foo
  
  [-] testing: cgi-exec-03.txt
  Status: 200 OK\r (esc)
  Content-Type: 0\r (esc)
  Content-Disposition: attachment; filename="output.txt"\r (esc)
  \r (esc)
  1922
