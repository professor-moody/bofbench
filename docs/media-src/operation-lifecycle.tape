Output docs/assets/media/operation-lifecycle.webm
Set Shell "bash"
Set Width 1280
Set Height 720
Set FontSize 17
Set TypingSpeed 40ms
Set PlaybackSpeed 2.6
Type "bofbench operation graph internal/secure-transport-matrix"
Enter
Sleep 2s
Type "bofbench operation prove internal/secure-transport-matrix --via lab --lab $BOFBENCH_DOCS_LAB --parallelism 2"
Enter
Wait+Screen@120s /OPERATION PROOF PASS/
Sleep 2s
Type "bofbench operation watch runs/*operation-secure-transport-matrix*/children/listener/operation.json"
Enter
Sleep 2s
Type "bofbench operation watch runs/*operation-secure-transport-matrix*/operation.json"
Enter
Sleep 2s
Type "bofbench operation cleanup runs/*operation-secure-transport-matrix*/operation.json --parallelism 2"
Enter
Sleep 5s
