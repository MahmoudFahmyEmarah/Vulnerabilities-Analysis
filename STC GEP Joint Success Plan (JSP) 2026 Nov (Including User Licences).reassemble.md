# Reassemble `STC GEP Joint Success Plan (JSP) 2026 Nov (Including User Licences).pdf`

The file `STC GEP Joint Success Plan (JSP) 2026 Nov (Including User Licences).pdf` (3,490,907 bytes) was split into **1 part(s)** and uploaded to this repository because the original exceeded the uploading network's single-transfer cap. Join the parts in order, then verify the checksum below.

## Parts

| # | Part | Size (bytes) | SHA-256 |
|---|------|--------------|---------|
| 1 | `STC GEP Joint Success Plan (JSP) 2026 Nov (Including User Licences).part-00` | 3490907 | `b9a96ee0260baed83fe4625480d2f0f6264c89431002d2b4ef1caab252b52ccf` |

## Reassemble

### Windows — Command Prompt
```
copy /b STC GEP Joint Success Plan (JSP) 2026 Nov (Including User Licences).part-00 STC GEP Joint Success Plan (JSP) 2026 Nov (Including User Licences).pdf
```

### Windows — PowerShell
```powershell
$parts = "STC GEP Joint Success Plan (JSP) 2026 Nov (Including User Licences).part-00"
$dest = "STC GEP Joint Success Plan (JSP) 2026 Nov (Including User Licences).pdf"
$fs = [System.IO.File]::Create($dest)
foreach ($p in $parts) {
    $b = [System.IO.File]::ReadAllBytes((Resolve-Path $p).Path)
    $fs.Write($b, 0, $b.Length)
}
$fs.Close()
```

### Linux / macOS
```bash
cat STC GEP Joint Success Plan (JSP) 2026 Nov (Including User Licences).part-00 > STC GEP Joint Success Plan (JSP) 2026 Nov (Including User Licences).pdf
```

## Verify

Expected size: **3,490,907 bytes**

Expected SHA-256: `b9a96ee0260baed83fe4625480d2f0f6264c89431002d2b4ef1caab252b52ccf`

- Windows: `certutil -hashfile STC GEP Joint Success Plan (JSP) 2026 Nov (Including User Licences).pdf SHA256`
- Linux/macOS: `sha256sum STC GEP Joint Success Plan (JSP) 2026 Nov (Including User Licences).pdf`

> Download the parts first (right-click a part → “Save link as…”, or `git clone` the repo / `curl -LO <raw url>`), then run the command for your platform in the same folder.
