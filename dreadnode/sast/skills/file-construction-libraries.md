---
name: file-construction-libraries
description: Reference of Python libraries for constructing PoC input files (TIFF, PE, ELF, OLE, ASN.1, PLY). Use when building proof-of-concept exploits that require crafted binary or structured files.
---

# File Construction Libraries

Reference of pre-installed Python libraries for constructing PoC input files.

## When to Use

- Building proof-of-concept inputs for file parser vulnerabilities
- Constructing malformed binary files to trigger bugs
- Creating test cases for fuzzing
- Crafting exploit payloads in specific file formats

## When NOT to Use

- General file I/O (use standard Python)
- Simple text file manipulation
- When the target format isn't listed below

## Available Libraries

### Image Formats

**Pillow** — TIFF/PNG/BMP/JPEG/GIF/WebP/ICO (+30 image formats)
```python
from PIL import Image
Image.new('L', (16, 4)).save('out.tiff')
```

**tifffile** — TIFF with low-level tag control, BigTIFF, ORF, DNG
```python
import numpy as np
import tifffile
tifffile.imwrite('out.tiff', np.zeros((4, 16), dtype='uint8'))
```

### Executable Formats

**lief** — PE/ELF/Mach-O executables
```python
import lief
pe = lief.PE.Binary('poc', lief.PE.PE_TYPE.PE32)
```

**pefile** — PE files with field-level modification
```python
import pefile
pe = pefile.PE('input.exe')
pe.FILE_HEADER.NumberOfSections = 0xFF
pe.write('out.exe')
```

### Document Formats

**olefile** — OLE/CDF compound documents (Office, etc.)
```python
import olefile
ole = olefile.OleFileIO('doc.ole')
```

### Binary Formats

**construct** — Any binary format via declarative schema
```python
from construct import *
Int32ub.build(42)
```

### 3D Formats

**plyfile** — PLY 3D mesh files
```python
from plyfile import PlyData, PlyElement
import numpy as np
v = np.array([(0,0,0)], dtype=[('x','f4'),('y','f4'),('z','f4')])
PlyData([PlyElement.describe(v, 'vertex')]).write('out.ply')
```

### ASN.1/Cryptographic Formats

**asn1crypto / pyasn1** — ASN.1/DER/BER encoding (PKCS#15, X.509, CMS)
```python
from pyasn1.type import univ
from pyasn1.codec.der import encoder
encoder.encode(univ.Integer(1))
```

For complex ASN.1 structures, use the `build_asn1_structure` tool instead.

## Recommended Pattern

1. **Create valid skeleton** — Use a library to create a valid file
2. **Read as bytes** — `data = bytearray(open('skeleton', 'rb').read())`
3. **Corrupt specific fields** — Patch the vulnerability-relevant bytes
4. **Write corrupted version** — `open('poc', 'wb').write(data)`

### Example: TIFF with Pillow + Corruption

```python
from PIL import Image, TiffImagePlugin

# 1. Create valid skeleton
img = Image.new('L', (16, 4))
info = TiffImagePlugin.ImageFileDirectory_v2()
info[0x010f] = "OLYMPUS IMAGING CORP."
img.save('/tmp/skeleton.tiff', tiffinfo=info)

# 2. Read as bytes
data = bytearray(open('/tmp/skeleton.tiff', 'rb').read())

# 3. Corrupt specific fields (e.g., overflow IFD count)
data[4:8] = b'\xff\xff\xff\xff'

# 4. Write corrupted version
open('/tmp/poc.tiff', 'wb').write(data)
```

## Why Use Libraries Instead of struct.pack

- Libraries handle magic bytes, header layouts, checksums automatically
- Less error-prone than manual offset arithmetic
- Produces valid skeleton files that parsers will attempt to process
- Easier to modify specific fields without breaking file structure
