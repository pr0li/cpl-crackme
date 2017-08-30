# CPL crackme challenge

The challenge consists in reversing a .cpl file to make it download a .exe with a flag. I coded this in october of 2015, but changed some strings and uploaded in 2017.

CPL files are Windows Control Panel applets. Basically they are DLLs but they can be executed on double click, which made them very attractive to some malware authors.

## Delphi code
The main file, containing all the code, is ***CPLcrackme.dpr***. Execution is very simple: if one of the checks fail, then a bogus file is downloaded. If all the checks are OK, then ***hello.exe*** is downloaded and executed.

### So what's the challenge?
 - Most strings are encrypted with a custom algorithm (same algorithm seen in brazilian trojan downloaders)
 - Anti-VM, anti-debugging, Wine detection
 - Download URL for *hello.exe* is encrypted with a separate key that is loaded from resources
 - To get the final flag, it is necessary to have that key and a way to run the decryption routine

## Strings
In case you want to change the strings, but keep the same encryption algorithm, you can use ***encrypt_strings.py*** (python code) to generate encrypted strings.
