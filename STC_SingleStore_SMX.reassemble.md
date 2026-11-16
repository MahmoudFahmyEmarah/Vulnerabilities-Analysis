# Reassemble `STC_SingleStore_SMX.xlsx`

The file `STC_SingleStore_SMX.xlsx` (10,779 bytes) was split into **1 part(s)** and uploaded to this repository because the original exceeded the uploading network's single-transfer cap. Join the parts in order, then verify the checksum below.

## Parts

| # | Part | Size (bytes) | SHA-256 |
|---|------|--------------|---------|
| 1 | `STC_SingleStore_SMX.part-00` | 10779 | `1526e4d90c32b28e856cdb2b533305ed24128225d59d159bb90b522dda7537a7` |

## Reassemble

### Windows — Command Prompt
```
copy /b STC_SingleStore_SMX.part-00 STC_SingleStore_SMX.xlsx
```

### Windows — PowerShell
```powershell
$parts = "STC_SingleStore_SMX.part-00"
$dest = "STC_SingleStore_SMX.xlsx"
$fs = [System.IO.File]::Create($dest)
foreach ($p in $parts) {
    $b = [System.IO.File]::ReadAllBytes((Resolve-Path $p).Path)
    $fs.Write($b, 0, $b.Length)
}
$fs.Close()
```

### Linux / macOS
```bash
cat STC_SingleStore_SMX.part-00 > STC_SingleStore_SMX.xlsx
```

## Verify

Expected size: **10,779 bytes**

Expected SHA-256: `1526e4d90c32b28e856cdb2b533305ed24128225d59d159bb90b522dda7537a7`

- Windows: `certutil -hashfile STC_SingleStore_SMX.xlsx SHA256`
- Linux/macOS: `sha256sum STC_SingleStore_SMX.xlsx`

> Download the parts first (right-click a part → “Save link as…”, or `git clone` the repo / `curl -LO <raw url>`), then run the command for your platform in the same folder.
