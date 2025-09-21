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
This script uses a simple XOR function to encrypt data and outputs hex bytes. It then replaces padding bytes in the image with the encrypted data and (when not currently commented out!) replaces any non-modifed padding to be random noise, so the cipher text doesn't stand out too much. It should also read the header length to select the entry point to inject the ciphertext from the correct point

After the header an unchanged BMP file would look like:
60 8F C3 FF 61 90 C4 FF 62 91 C5 FF 62 91 C5 FF 61 90 C4 FF 5F 8E C2 FF 5D 8C C0 FF 5B 8A BE FF 5B 8A C0 FF 58 87 BD FF 55 84 BA FF 54 83 B9 FF 56 85 BB FF 57 86 BC FF 57 86 BC FF 56 85 BB FF 57 86 BE FF 57 86 BE FF 58 87 BF FF 57 86 BE FF 55 86 BE FF 55 86 BE FF 55 86 BE FF....
These are the RGB+Pad values for the pixels, you can see the FFs repeating every 4 bytes after the header.

A BMP file modified with this script looks like:
60 8F C3 00 61 90 C4 46 62 91 C5 6C 62 91 C5 36 61 90 C4 19 5F 8E C2 10 5D 8C C0 00 5B 8A BE 00 5B 8A C0 13 58 87 BD 17 55 84 BA 50 54 83 B9 26 56 85 BB 0A 57 86 BC 06 57 86 BC 16 56 85 BB 41 57 86 BE 04 57 86 BE 00 58 87 BF 10 57 86 BE 52 55 86 BE 65 55 86 BE 00 55 86 BE 1B....
No more FFs!

The header and size is unchanged and the image is visually identical, as none of the actual data has been changed.
