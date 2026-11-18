# Reassemble `STC_SS-KPI Mapping Document_v1.0.xlsx`

The file `STC_SS-KPI Mapping Document_v1.0.xlsx` (29,357 bytes) was split into **1 part(s)** and uploaded to this repository because the original exceeded the uploading network's single-transfer cap. Join the parts in order, then verify the checksum below.

## Parts

| # | Part | Size (bytes) | SHA-256 |
|---|------|--------------|---------|
| 1 | `STC_SS-KPI Mapping Document_v1.0.part-00` | 29357 | `e0c8ef4505e1fbba89ff9c5c452b5daf4610d2806f288d9c893b0fdd56d4df1a` |

## Reassemble

### Windows — Command Prompt
```
copy /b STC_SS-KPI Mapping Document_v1.0.part-00 STC_SS-KPI Mapping Document_v1.0.xlsx
```

### Windows — PowerShell
```powershell
$parts = "STC_SS-KPI Mapping Document_v1.0.part-00"
$dest = "STC_SS-KPI Mapping Document_v1.0.xlsx"
$fs = [System.IO.File]::Create($dest)
foreach ($p in $parts) {
    $b = [System.IO.File]::ReadAllBytes((Resolve-Path $p).Path)
    $fs.Write($b, 0, $b.Length)
}
$fs.Close()
```

### Linux / macOS
```bash
cat STC_SS-KPI Mapping Document_v1.0.part-00 > STC_SS-KPI Mapping Document_v1.0.xlsx
```

## Verify

Expected size: **29,357 bytes**

Expected SHA-256: `e0c8ef4505e1fbba89ff9c5c452b5daf4610d2806f288d9c893b0fdd56d4df1a`

- Windows: `certutil -hashfile STC_SS-KPI Mapping Document_v1.0.xlsx SHA256`
- Linux/macOS: `sha256sum STC_SS-KPI Mapping Document_v1.0.xlsx`

> Download the parts first (right-click a part → “Save link as…”, or `git clone` the repo / `curl -LO <raw url>`), then run the command for your platform in the same folder.
