Output docs/assets/media/operation-lifecycle.webm
Set Shell "bash"
Set Width 1280
Set Height 720
Set FontSize 17
Set TypingSpeed 40ms
Set PlaybackSpeed 2.2
Type "bofbench operation graph adaptive-memory-execute"
Enter
Sleep 2s
Type "bofbench operation run adaptive-memory-execute --via lab --lab $BOFBENCH_DOCS_LAB --arg target_pid=$BOFBENCH_TARGET_PID --arg payload=@file:/tmp/bofbench-ret.bin --arg payload_size=1 --arg payload_sha256=ae3f4619b0413d70d3004b9131c3752153074e45725be13b9a148978895e359e --arg section_protection=32 --arg wait_ms=5000"
Enter
Sleep 30s
Type "bofbench operation resume runs/*operation-adaptive-memory-execute*/operation.json"
Enter
Sleep 3s
Type "bofbench operation cleanup runs/*operation-adaptive-memory-execute*/operation.json"
Enter
Sleep 18s
