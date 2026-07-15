Output docs/assets/media/export-verify.webm
Set Shell "bash"
Set Width 1280
Set Height 720
Set FontSize 18
Set TypingSpeed 40ms
Type "bofbench new docs-export --pack host-discovery"
Enter
Sleep 2s
Type "bofbench export bofs/docs-export --for sliver"
Enter
Sleep 5s
Type "bofbench export verify export/docs-export-sliver.zip"
Enter
Sleep 6s
