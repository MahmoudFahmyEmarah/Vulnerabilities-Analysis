# Reassemble `selftest.bin`

The file `selftest.bin` (2,597,152 bytes) was split into **3 part(s)** and uploaded to this repository because the original exceeded the uploading network's single-transfer cap. Join the parts in order, then verify the checksum below.

## Parts

| # | Part | Size (bytes) | SHA-256 |
|---|------|--------------|---------|
| 1 | `selftest/selftest.part-00` | 1048576 | `c25190d820ce2a34a00293b60335f096ec96f8fec493c71b0818c1322bc9c254` |
| 2 | `selftest/selftest.part-01` | 1048576 | `928ad886f69b5bb8e60d40c7a5b7055564135d7c3e8a5bcce096c961a5736f11` |
| 3 | `selftest/selftest.part-02` | 500000 | `dcc69f59f1f259a14b302f06545f31a3d1a4703384d80948726b1067da3925ad` |

## Reassemble

### Windows — Command Prompt
```
copy /b selftest/selftest.part-00 + selftest/selftest.part-01 + selftest/selftest.part-02 selftest.bin
```

### Windows — PowerShell
```powershell
$parts = "selftest/selftest.part-00", "selftest/selftest.part-01", "selftest/selftest.part-02"
$dest = "selftest.bin"
$fs = [System.IO.File]::Create($dest)
foreach ($p in $parts) {
    $b = [System.IO.File]::ReadAllBytes((Resolve-Path $p).Path)
    $fs.Write($b, 0, $b.Length)
}
$fs.Close()
```

### Linux / macOS
```bash
cat selftest/selftest.part-00 selftest/selftest.part-01 selftest/selftest.part-02 > selftest.bin
```

## Verify

Expected size: **2,597,152 bytes**

Expected SHA-256: `01539dc04017c91377573c73d8516aa82f1b254c90a522c44fd8b4c7a10e60bf`

- Windows: `certutil -hashfile selftest.bin SHA256`
- Linux/macOS: `sha256sum selftest.bin`

> Download the parts first (right-click a part → “Save link as…”, or `git clone` the repo / `curl -LO <raw url>`), then run the command for your platform in the same folder.
