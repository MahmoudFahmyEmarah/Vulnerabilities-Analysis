# Reassemble `HLD_SS_CR# v1.0 - template.docx`

The file `HLD_SS_CR# v1.0 - template.docx` (130,575 bytes) was split into **1 part(s)** and uploaded to this repository because the original exceeded the uploading network's single-transfer cap. Join the parts in order, then verify the checksum below.

## Parts

| # | Part | Size (bytes) | SHA-256 |
|---|------|--------------|---------|
| 1 | `HLD_SS_CR# v1.0 - template.part-00` | 130575 | `23465ca10a2a7ddca4c694f956caa80ffea8cc27fd0529fc83a1ef7f6473737d` |

## Reassemble

### Windows — Command Prompt
```
copy /b HLD_SS_CR# v1.0 - template.part-00 HLD_SS_CR# v1.0 - template.docx
```

### Windows — PowerShell
```powershell
$parts = "HLD_SS_CR# v1.0 - template.part-00"
$dest = "HLD_SS_CR# v1.0 - template.docx"
$fs = [System.IO.File]::Create($dest)
foreach ($p in $parts) {
    $b = [System.IO.File]::ReadAllBytes((Resolve-Path $p).Path)
    $fs.Write($b, 0, $b.Length)
}
$fs.Close()
```

### Linux / macOS
```bash
cat HLD_SS_CR# v1.0 - template.part-00 > HLD_SS_CR# v1.0 - template.docx
```

## Verify

Expected size: **130,575 bytes**

Expected SHA-256: `23465ca10a2a7ddca4c694f956caa80ffea8cc27fd0529fc83a1ef7f6473737d`

- Windows: `certutil -hashfile HLD_SS_CR# v1.0 - template.docx SHA256`
- Linux/macOS: `sha256sum HLD_SS_CR# v1.0 - template.docx`

> Download the parts first (right-click a part → “Save link as…”, or `git clone` the repo / `curl -LO <raw url>`), then run the command for your platform in the same folder.
