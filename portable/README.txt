VaultDrive
==========

Copy this file, VaultDrive.exe and your .vault file onto the USB drive:

    USB DRIVE
    |
    +-- VaultDrive.exe
    +-- MyVault.vault
    +-- README.txt


TO OPEN YOUR FILES ON ANY WINDOWS COMPUTER

  1. Plug in the drive.
  2. Run VaultDrive.exe.
  3. Click "Open Existing Vault" and choose the .vault file.
  4. Enter your password.

No installation. No internet. No account. It does not matter which
computer created the vault.


IF WINDOWS WARNS YOU

  "Windows protected your PC" appears because this program is not
  signed by a paid certificate. Click "More info", then "Run anyway".

  If nothing happens at all, the computer may be missing the Microsoft
  Edge WebView2 runtime, which VaultDrive uses to draw its window.
  Windows 11 and current Windows 10 include it. Installing it needs
  administrator rights.

  Some work and school computers block programs from running off a USB
  drive entirely. VaultDrive cannot get around that, and should not.


IF YOU FORGET YOUR PASSWORD

  The files are gone. VaultDrive cannot recover them. There is no
  master password, no recovery key and no backdoor. Nobody can open
  the vault without the password, including whoever made this program.

  Keep a copy of the password somewhere safe and separate from the
  drive.


WHAT IS IN THE .VAULT FILE

  Encrypted data only. File contents, file names, folder names and
  sizes are all inside the encryption. Someone who opens the file in
  another program sees nothing but random bytes.

  Do not edit or repair the .vault file with any other tool. Any change
  to it will be detected as tampering and VaultDrive will refuse to
  open it rather than hand you damaged files.
