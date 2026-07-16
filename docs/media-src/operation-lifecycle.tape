Output docs/assets/media/operation-lifecycle.webm
Set Shell "bash"
Set Width 1280
Set Height 720
Set FontSize 17
Set TypingSpeed 42ms
Set PlaybackSpeed 2.2
Type "bofbench operation graph internal/coordination-matrix --expand"
Enter
Sleep 2s
Type "bofbench operation run internal/coordination-matrix --via lab --lab $BOFBENCH_DOCS_LAB --arg holder_pid=$BOFBENCH_HOLDER_PID --arg mutex_name=Global\\OperatorMutex --arg semaphore_name=Global\\OperatorSemaphore --arg timer_name=Global\\OperatorTimer --arg mailslot_name=\\\\.\\mailslot\\OperatorRequest --arg message=@file:$BOFBENCH_DOCS_REQUEST --arg message_size=$BOFBENCH_DOCS_REQUEST_SIZE --arg message_sha256=$BOFBENCH_DOCS_REQUEST_SHA256 --arg command='C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile -Command Start-Sleep -Seconds 600'"
Enter
Sleep 38s
Type "bofbench operation resume runs/*operation-coordination-matrix*/operation.json"
Enter
Sleep 3s
Type "bofbench operation cleanup runs/*operation-coordination-matrix*/operation.json"
Enter
Sleep 18s
