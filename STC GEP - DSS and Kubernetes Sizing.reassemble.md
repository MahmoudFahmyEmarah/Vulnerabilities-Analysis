# Reassemble `STC GEP - DSS and Kubernetes Sizing.xlsx`

The file `STC GEP - DSS and Kubernetes Sizing.xlsx` (48,545 bytes) was split into **1 part(s)** and uploaded to this repository because the original exceeded the uploading network's single-transfer cap. Join the parts in order, then verify the checksum below.

## Parts

| # | Part | Size (bytes) | SHA-256 |
|---|------|--------------|---------|
| 1 | `STC GEP - DSS and Kubernetes Sizing.part-00` | 48545 | `2ed9ead1785c8be01ae996070fcb01734db31cf9a047d0ba45d0f0b84f426c35` |

## Reassemble

### Windows — Command Prompt
```
copy /b STC GEP - DSS and Kubernetes Sizing.part-00 STC GEP - DSS and Kubernetes Sizing.xlsx
```

### Windows — PowerShell
```powershell
$parts = "STC GEP - DSS and Kubernetes Sizing.part-00"
$dest = "STC GEP - DSS and Kubernetes Sizing.xlsx"
$fs = [System.IO.File]::Create($dest)
foreach ($p in $parts) {
    $b = [System.IO.File]::ReadAllBytes((Resolve-Path $p).Path)
    $fs.Write($b, 0, $b.Length)
}
$fs.Close()
```

### Linux / macOS
```bash
cat STC GEP - DSS and Kubernetes Sizing.part-00 > STC GEP - DSS and Kubernetes Sizing.xlsx
```

## Verify

Expected size: **48,545 bytes**

Expected SHA-256: `2ed9ead1785c8be01ae996070fcb01734db31cf9a047d0ba45d0f0b84f426c35`

- Windows: `certutil -hashfile STC GEP - DSS and Kubernetes Sizing.xlsx SHA256`
- Linux/macOS: `sha256sum STC GEP - DSS and Kubernetes Sizing.xlsx`

> Download the parts first (right-click a part → “Save link as…”, or `git clone` the repo / `curl -LO <raw url>`), then run the command for your platform in the same folder.
