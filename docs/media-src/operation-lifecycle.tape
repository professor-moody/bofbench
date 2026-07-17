Output docs/assets/media/operation-lifecycle.webm
Set Shell "bash"
Set Width 1280
Set Height 720
Set FontSize 17
Set TypingSpeed 40ms
Set PlaybackSpeed 2.4
Type "bofbench operation graph internal/network-transport-matrix"
Enter
Sleep 2s
Type "bofbench operation prove internal/network-transport-matrix --via lab --lab $BOFBENCH_DOCS_LAB --arch x64 --parallelism 4"
Enter
Wait+Screen@120s /OPERATION PROOF PASS/
Sleep 2s
Type "bofbench operation watch runs/*operation-http-transaction-roundtrip*/operation.json"
Enter
Sleep 2s
Type "bofbench operation watch runs/*operation-tcp-echo-roundtrip*/operation.json"
Enter
Sleep 2s
Type "bofbench operation cleanup runs/*operation-network-transport-matrix*/operation.json --parallelism 4"
Enter
Sleep 8s
