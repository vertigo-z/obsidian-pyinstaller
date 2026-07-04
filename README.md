## packing with pyinstaller:
in order to obfuscate a python script with obsidian, you first need to make sure you have installed pyinstaller via pip. then clone and compile the forked `obsidian-pyinstaller` repo found [here](https://github.com/vertigo-z/obsidian-pyinstaller). here are the steps on Windows:

1. install the offical MSYS2 UCRT64 package from `https://www.msys2.org/`
2. open the terminal, then run `pacman -Syu && pacman -S --needed mingw-w64-ucrt-x86_64-gcc`
3. use the same MSYS2 terminal to open `cmd.exe` then navigate to `obsidian-pyinstaller` cloned folder
4. compile the forked pyinstaller package with `python waf all`

once complete, copy contents of `obsidian-pyinstaller/pyinstaller/bootloader/Windows-64bit-intel` directory to the system installation of pyinstallers bootloader (usually found in the `site-packages/PyInstaller/bootloader` folder of you python installation). it is recommended to backup the old bootloader before doing this step otherwise you will have to reinstall pyinstaller to use it without packing.

5. run obsidian with the `--pyinstaller` flag: 
```
.\obsidian.ce.universal.exe --pyinstaller script.py obfuscated-py.exe
```
