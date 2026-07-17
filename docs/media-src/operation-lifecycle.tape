Output docs/assets/media/operation-lifecycle.webm
Set Shell "bash"
Set Width 1280
Set Height 720
Set FontSize 17
Set TypingSpeed 40ms
Set PlaybackSpeed 2.6
Type "bofbench operation graph internal/multi-path-file-collection --expand"
Enter
Sleep 2s
Type "bofbench operation prove internal/multi-path-file-collection --via lab --lab $BOFBENCH_DOCS_LAB --arch x64 --parallelism 3"
Enter
Wait+Screen@120s /OPERATION PROOF PASS/
Sleep 2s
Type "bofbench operation watch runs/*operation-multi-path-file-collection*/operation.json"
Enter
Sleep 2s
Type "bofbench operation cleanup runs/*operation-multi-path-file-collection*/operation.json --parallelism 3"
Enter
Sleep 5s
