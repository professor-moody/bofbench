Output docs/assets/media/operation-lifecycle.webm
Set Shell "bash"
Set Width 1280
Set Height 720
Set FontSize 17
Set TypingSpeed 38ms
Set PlaybackSpeed 3.2
Type "bofbench operation graph internal/ipc-dependency-matrix --expand"
Enter
Sleep 2s
Type "bofbench operation prove internal/ipc-dependency-matrix --via lab --lab $BOFBENCH_DOCS_LAB --arch x64 --parallelism 4"
Enter
Sleep 55s
Type "bofbench operation resume runs/*operation-ipc-dependency-matrix*/operation.json --parallelism 4"
Enter
Sleep 2s
Type "bofbench operation cleanup runs/*operation-ipc-dependency-matrix*/operation.json --parallelism 4"
Enter
Sleep 15s
