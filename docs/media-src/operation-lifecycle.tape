Output docs/assets/media/operation-lifecycle.webm
Set Shell "bash"
Set Width 1280
Set Height 720
Set FontSize 17
Set TypingSpeed 40ms
Set PlaybackSpeed 2.2
Type "bofbench operation show internal/virtual-memory-execute"
Enter
Sleep 2s
Type "bofbench operation run internal/virtual-memory-execute --via lab --lab $BOFBENCH_DOCS_LAB --cleanup --arg target_pid=$BOFBENCH_TARGET_PID --arg payload=@file:/tmp/bofbench-ret.bin --arg payload_size=1 --arg payload_sha256=ae3f4619b0413d70d3004b9131c3752153074e45725be13b9a148978895e359e --arg wait_ms=5000"
Enter
Sleep 80s
