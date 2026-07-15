Output docs/assets/media/runtime-tasks.webm
Set Shell "bash"
Set Width 1280
Set Height 720
Set FontSize 18
Set TypingSpeed 40ms
Type "bofbench runtime task docs/evidence/runtime-task.json"
Enter
Sleep 4s
Type "bofbench pack prove process-access-check --via lab --lab $BOFBENCH_DOCS_LAB --resume docs/evidence/resume-pack-proof.json --only passed"
Enter
Sleep 20s
