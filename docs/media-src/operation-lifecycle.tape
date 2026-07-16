Output docs/assets/media/operation-lifecycle.webm
Set Shell "bash"
Set Width 1280
Set Height 720
Set FontSize 17
Set TypingSpeed 40ms
Set PlaybackSpeed 2.4
Type "bofbench operation graph internal/process-lifecycle-observe --expand"
Enter
Sleep 2s
Type "bofbench operation prove internal/process-lifecycle-observe --via lab --lab $BOFBENCH_DOCS_LAB --arch x64 --parallelism 4"
Enter
Wait+Screen@120s /OPERATION PROOF PASS/
Sleep 2s
Type "bofbench operation watch runs/*operation-process-lifecycle-observe*/operation.json"
Enter
Sleep 2s
Type "bofbench operation resume runs/*operation-process-lifecycle-observe*/operation.json --parallelism 4"
Enter
Sleep 2s
Type "bofbench operation cleanup runs/*operation-process-lifecycle-observe*/operation.json --parallelism 4"
Enter
Sleep 8s
