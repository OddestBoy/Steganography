# Steganography
A Powershell script to hide an encrypted string in a .bmp file

Usage:
Encryption -
set $Encode=$true
Place your (32 bit .bmp - the script will check, also can be seen from the properties tab in windows) image file into the same folder as the script, and place it's name into the $ClearFile variable. Currently it will look for a file named "Cat.bmp"
Run the script, entering your clear text and key when prompted
This will create a new image in the same folder, SuspiciousImage.bmp, containing the encrypted message

Decryption -
Place SuspiciousImage.bmp in the same folder as the script
Make sure $Encode is set to $false
Run the script and enter your key when prompted

How it works -
After the header, a 32 bit bmp file uses 4 bytes per pixel - the RGB values and a pad byte set as FF
This script uses a simple XOR function to encrypt data and outputs hex bytes. It then replaces padding bytes in the image with the encrypted data and (when not currently commented out!) replaces any non-modifed padding to be random noise, so the cipher text doesn't stand out too much.
