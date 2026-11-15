# crons.zip — split upload

The original file `crons.zip` (39,030,297 bytes) exceeded the single-transfer cap of the
uploading network (corporate proxy, ~20–30 MB), so it was split into the parts below.
Reassemble before use.

## Parts

| Part | Size (bytes) | SHA-256 |
|---|---|---|
| `crons.zip.part-00` | 10485760 | `133f0f872f68245be6bec512b37c17bcebffe5e113ce9ddd868102e52d0ce664` |
| `crons.zip.part-01` | 10485760 | `8c322c6540f078f0617d3ba8904cb52f8010f3d0f555543ae555cc04620ae021` |
| `crons.zip.part-02` | 10485760 | `0f138fa879c5f500934dd2e294a7f7ba68c9a92dcb7d6203c4bfcc4d1b1d703c` |
| `crons.zip.part-03` | 7573017 | `5452cc0bd19df85f310c605ca8ecdb5666b2991c6c3df0de4f08ed913aeb5db8` |

## Reassemble

### Windows (cmd)
```
copy /b crons.zip.part-00 + crons.zip.part-01 + crons.zip.part-02 + crons.zip.part-03 crons.zip
```

### Linux / macOS
```
cat crons.zip.part-00 crons.zip.part-01 crons.zip.part-02 crons.zip.part-03 > crons.zip
```

## Verify

Expected size: 39,030,297 bytes
Expected SHA-256: `101c206c97c39f64405109b8ade0cbd36b4db148e03f018aee8ea88fdc884f63`
