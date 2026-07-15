Output docs/assets/media/build-analyze.webm
Set Shell "bash"
Set Width 1280
Set Height 720
Set FontSize 18
Set TypingSpeed 40ms
Set PlaybackSpeed 1
Type "bofbench new docs-capture --pack host-discovery,process-tree"
Enter
Sleep 2s
Type "bofbench build bofs/docs-capture --arch x64"
Enter
Sleep 3s
Type "bofbench analyze bofs/docs-capture"
Enter
Sleep 7s
