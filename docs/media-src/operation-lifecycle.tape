Output docs/assets/media/operation-lifecycle.webm
Set Shell "bash"
Set Width 1280
Set Height 720
Set FontSize 17
Set TypingSpeed 40ms
Set PlaybackSpeed 1.5
Type "bofbench operation show section-map-start-unmap"
Enter
Sleep 2s
Type "bofbench operation run section-map-start-unmap --via lab --lab devbox --cleanup --arg target_pid=$BOFBENCH_TARGET_PID --arg payload=@file:/tmp/bofbench-ret.bin"
Enter
Sleep 42s
