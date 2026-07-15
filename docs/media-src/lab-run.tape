Output docs/assets/media/lab-run.webm
Set Shell "bash"
Set Width 1280
Set Height 720
Set FontSize 18
Set TypingSpeed 40ms
Type "bofbench new docs-lab --pack process-tree"
Enter
Sleep 2s
Type "bofbench lab status --lab $BOFBENCH_DOCS_LAB"
Enter
Sleep 5s
Type "bofbench run bofs/docs-lab --via lab --lab $BOFBENCH_DOCS_LAB --arg root_pid=0 --arg result_limit=8"
Enter
Sleep 8s
