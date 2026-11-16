# Reassemble `CR example.zip`

The file `CR example.zip` (1,691,691 bytes) was split into **2 part(s)** and uploaded to this repository because the original exceeded the uploading network's single-transfer cap. Join the parts in order, then verify the checksum below.

## Parts

| # | Part | Size (bytes) | SHA-256 |
|---|------|--------------|---------|
| 1 | `CR example.part-00` | 845846 | `e5c9a11ae24b7def3f78f51f14b7cf67e1490abb340615677dd74d3328c0d55e` |
| 2 | `CR example.part-01` | 845845 | `d07bedb9565e2db7424120e2967b0f1a78dc758dc9622a12d04f0f21f5288a77` |

## Reassemble

### Windows — Command Prompt
```
copy /b CR example.part-00 + CR example.part-01 CR example.zip
```

### Windows — PowerShell
```powershell
$parts = "CR example.part-00", "CR example.part-01"
$dest = "CR example.zip"
$fs = [System.IO.File]::Create($dest)
foreach ($p in $parts) {
    $b = [System.IO.File]::ReadAllBytes((Resolve-Path $p).Path)
    $fs.Write($b, 0, $b.Length)
}
$fs.Close()
```

### Linux / macOS
```bash
cat CR example.part-00 CR example.part-01 > CR example.zip
```

## Verify

Expected size: **1,691,691 bytes**

Expected SHA-256: `6d34f3539f625c6bf18f8ca65285b1d17d996e126dd9c128c0cf23738fe647fc`

- Windows: `certutil -hashfile CR example.zip SHA256`
- Linux/macOS: `sha256sum CR example.zip`

> Download the parts first (right-click a part → “Save link as…”, or `git clone` the repo / `curl -LO <raw url>`), then run the command for your platform in the same folder.
