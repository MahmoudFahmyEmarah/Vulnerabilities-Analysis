# Reassemble `Single Store DOCs.zip`

The file `Single Store DOCs.zip` (1,817,731 bytes) was split into **2 part(s)** and uploaded to this repository because the original exceeded the uploading network's single-transfer cap. Join the parts in order, then verify the checksum below.

## Parts

| # | Part | Size (bytes) | SHA-256 |
|---|------|--------------|---------|
| 1 | `Single Store DOCs.part-00` | 908866 | `d88416471cfe644bc4c2e2363abf5ff45d9d14aba4bb445e5d7118529112c99e` |
| 2 | `Single Store DOCs.part-01` | 908865 | `8da034d9894da329e77872320ea3259c6547b6fa54194b2dbdc8be27ab61f44d` |

## Reassemble

### Windows — Command Prompt
```
copy /b Single Store DOCs.part-00 + Single Store DOCs.part-01 Single Store DOCs.zip
```

### Windows — PowerShell
```powershell
$parts = "Single Store DOCs.part-00", "Single Store DOCs.part-01"
$dest = "Single Store DOCs.zip"
$fs = [System.IO.File]::Create($dest)
foreach ($p in $parts) {
    $b = [System.IO.File]::ReadAllBytes((Resolve-Path $p).Path)
    $fs.Write($b, 0, $b.Length)
}
$fs.Close()
```

### Linux / macOS
```bash
cat Single Store DOCs.part-00 Single Store DOCs.part-01 > Single Store DOCs.zip
```

## Verify

Expected size: **1,817,731 bytes**

Expected SHA-256: `6b6bdbef038ceb0f1097698db94fc9681c56db6a446598c75bcfda0378ff355a`

- Windows: `certutil -hashfile Single Store DOCs.zip SHA256`
- Linux/macOS: `sha256sum Single Store DOCs.zip`

> Download the parts first (right-click a part → “Save link as…”, or `git clone` the repo / `curl -LO <raw url>`), then run the command for your platform in the same folder.
