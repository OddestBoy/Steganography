$ClearFile = "$PSSCriptRoot\Cat.bmp"
$CipherFile = "$PSSCriptRoot\SuspiciousImage.bmp"
$Encode = $false #encode/decode

function Encode-ImageBytes {
    param(
        [Array]$Bytes,
        [parameter(Mandatory)][String]$InputString,
        [parameter(Mandatory)][string]$KeyString,
        [string]$CipherFile
    )
    $DataOffset = "0x"+$Bytes[13]+$Bytes[12]+$Bytes[11]+$Bytes[10] #convert the data offset field from the .bmp header into a hex string, basically so we can start after the header
    #$InputString = $InputString + ":STOP:" #delimits code from noise #Leaving this out for the challenge
    $InputString = XOR-Light -InputString $InputString -KeyString $KeyString
    Write-Output "`nCiphertext hidden in image: $InputString" 
    $InputArray = $InputString -split '(..)' -ne '' #Input string should be hex, split it into individual bytes
    for ($i = 0; $i -lt $InputArray.Count; $i++) { #for each byte of input...
        $Bytes[([int]$DataOffset+3+(4*$i))] = $InputArray[$i] #find the corresponding byte of the image file (every 4th byte, starting after the header) and replace it with the byte from our ciphertext
    }
    #Leaving this out for the challenge, otherwise it takes ages to decrypt each guess
    <#
    for ($i = ([int]$DataOffset+3); $i -lt $Bytes.Count; $i = $i + 4) {#starting from the header, check each of the padding bytes...
        if($Bytes[$i] -eq "FF"){ #...if it's still FF (and isn't holding any data)...
            $Bytes[$i] = ((get-random -Maximum 255 -Minimum 0) | format-hex -count 1).HexBytes #...replace it with a random hex byte just to be mean
        }
    }
    #>
    $OutBytes = $Bytes | %{[int]("0x"+$_)} #convert our bytes from hex to decimal, which .net can use
    [IO.File]::WriteAllBytes($CipherFile,$OutBytes) #write all our our bytes into our output .bmp
}

function Decode-ImageBytes{
    param(
        [Array]$Bytes,
        [parameter(Mandatory)][string]$KeyString
    )
    $DataOffset = "0x"+$Bytes[13]+$Bytes[12]+$Bytes[11]+$Bytes[10] #convert the data offset field from the .bmp header into a hex string, basically so we can start after the header
    $CipherString = ""
    for ($i = ([int]$DataOffset+3); $i -lt $Bytes.Count; $i = $i + 4) {#starting from the header, check each of the padding bytes...
        $CipherString = $CipherString + $Bytes[$i] #...and add it to the ciphertext string
    }
    $OutputString = XOR-Light -InputString $CipherString -KeyString $KeyString -Decrypt #decrypt the ciphertext string
    $OutputString = $OutputString.split(":STOP:")[0] #Split on the delimiter, and take only the part before it
    return $OutputString
}

function Read-Image {
    param (
        [string]$FilePath
    )
    if(!(Test-path $ClearFile)){Write-Warning "File does not exist";exit} #check given file exists
    $Bytes = (Format-Hex -Path $FilePath).HexBytes.split(" ") #format-hex reads the file and outputs as several lines of hex bytes, then split each line into individual bytes.
    if(!($Bytes[0] -eq "42" -and $Bytes[1] -eq "4D" -and $Bytes[28] -eq "20")){Write-Warning "File does not appear to be a 32 bit .bmp";exit} #Check the file - first two bytes should be 0x42 (B) and 0x4D (D) for BMP file, Byte 28 (0x1C) should be 0x20 (32) for 32 bit colour encoding
    return $Bytes
}

function XOR-Light {
    param(
    [parameter(ValueFromPipeline,Mandatory)][string]$InputString,
    [parameter(Mandatory)][string]$KeyString,
    [switch]$Decrypt,
    [switch]$DebugMode
    )
    #Key setup
    if($DebugMode){$StartTime = get-date}
    if($Decrypt){
        $InputArray = $InputString -split '(..)' -ne ''
    }else{
        $InputArray = $InputString -split '(.)' -ne ''
    }
    #Special, easier key function...
    $Key = $KeyString
    While($Key.Length -lt $InputArray.Count){
        $Key = $Key + $KeyString
    }
    #...normally this should use the below key function, which hashes the key. However this is irreversible so you couldn't really do cryptoanalysis to get the key, you'd just need to brute force it which is no fun
    <#
    $Key = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes((Get-FileHash -InputStream ([IO.MemoryStream]::new([byte[]][char[]]$KeyString)) -Algorithm SHA256).Hash))
    While($Key.Length -lt $InputArray.Count){
        $KeyRaw = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes((Get-FileHash -InputStream ([IO.MemoryStream]::new([byte[]][char[]]$Key)) -Algorithm SHA256).Hash))
        $Key = $Key + $KeyRaw
    }
    #>

    $KeyArray = $Key -split '(.)' -ne '' #Split the key into individual characters
    $OutputString = ""
    for ($i = 0; $i -lt  $InputArray.Count; $i++) { #For each character...
        if($Decrypt){#if decrypting, take the hex byte and get the corresponding character
            $OutChar = (("0x"+($InputArray[$i])) -bxor ("0x"+($KeyArray[$i] | format-hex -Count 1).HexBytes) | Format-Hex -Count 1).HexBytes #...take the character from the input and corresponding value from the key, and xor their hex values together
            if($DebugMode){Write-Warning "D $i - $(($InputArray[$i]| format-hex -Count 1).HexBytes) - $(($KeyArray[$i]| format-hex -Count 1).HexBytes) - $OutChar"}
            $OutChar = [char]([int]("0x"+$OutChar)) #Get the ascii character corresponding to the byte
        } else {
            $OutChar = (("0x"+($InputArray[$i] | format-hex -Count 1).HexBytes) -bxor ("0x"+($KeyArray[$i] | format-hex -Count 1).HexBytes) | Format-Hex -Count 1).HexBytes #...take the character from the input and corresponding value from the key, and xor their hex values together
            if($DebugMode){Write-Warning "E $i - $(($InputArray[$i]| format-hex -Count 1).HexBytes) - $(($KeyArray[$i]| format-hex -Count 1).HexBytes) - $OutChar"}
        }
        $OutputString = $OutputString +  $OutChar
    }
    If($DebugMode){$EndTime = get-date; Write-Warning "$($InputArray.Count) characters with $($KeyString.Length) length key in time $($EndTime - $StartTime)"}
    return $OutputString
}




if($Encode){
    $Bytes = Read-Image -FilePath $ClearFile #Read the original image file
    $InputText = Read-Host -prompt "`nCleartext"
    $Key = Read-Host -Prompt "`nKey"
    write-host $InputText
    Encode-ImageBytes -Bytes $Bytes -InputString $InputText -CipherFile $CipherFile -KeyString $Key
} else {
    $Bytes = Read-Image -FilePath $CipherFile #Read the encrypted image file
    while($True){
        $Key = Read-Host -Prompt "`nKey"
        $Cleartext = Decode-ImageBytes -Bytes $Bytes -KeyString $Key
        Write-Output "Cleartext: `n$Cleartext`n"
    } 
}
