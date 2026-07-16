Output docs/assets/media/operation-lifecycle.webm
Set Shell "bash"
Set Width 1280
Set Height 720
Set FontSize 17
Set TypingSpeed 42ms
Set PlaybackSpeed 3.2
Type "bofbench operation graph internal/named-pipe-duplex-roundtrip --expand"
Enter
Sleep 2s
Type "bofbench operation run internal/named-pipe-duplex-roundtrip --via lab --lab $BOFBENCH_DOCS_LAB --parallelism 2 --arg holder_pid=$BOFBENCH_HOLDER_PID --arg pipe_name=\\\\.\\pipe\\BOFBenchDocsIPC --arg request=@file:$BOFBENCH_DOCS_REQUEST --arg request_sha256=$BOFBENCH_DOCS_REQUEST_SHA256 --arg response=@file:$BOFBENCH_DOCS_REQUEST --arg response_sha256=$BOFBENCH_DOCS_REQUEST_SHA256 --arg timeout_ms=60000"
Enter
Sleep 90s
Type "bofbench operation resume runs/*operation-named-pipe-duplex-roundtrip*/operation.json --parallelism 2"
Enter
Sleep 2s
Type "bofbench operation cleanup runs/*operation-named-pipe-duplex-roundtrip*/operation.json --parallelism 2"
Enter
Sleep 20s
