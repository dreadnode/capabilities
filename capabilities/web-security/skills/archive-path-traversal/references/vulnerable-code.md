# Vulnerable Code Patterns by Language

## Java (Most Common)

```java
// VULNERABLE
ZipInputStream zis = new ZipInputStream(uploadedFile);
ZipEntry entry;
while ((entry = zis.getNextEntry()) != null) {
    File outputFile = new File(destDir, entry.getName());
    outputFile.getParentFile().mkdirs();
    Files.copy(zis, outputFile.toPath());
    // entry.getName() = "../../etc/cron.d/pwn" -> writes to /etc/cron.d/pwn
}

// SECURE
File outputFile = new File(destDir, entry.getName()).getCanonicalFile();
if (!outputFile.toPath().startsWith(destDir.getCanonicalFile().toPath())) {
    throw new SecurityException("Zip Slip: " + entry.getName());
}
```

## Python

```python
# VULNERABLE manual extraction (any Python version)
with zipfile.ZipFile(uploaded, 'r') as z:
    for info in z.infolist():
        path = os.path.join(dest_dir, info.filename)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as f:
            f.write(z.read(info.filename))

# NOTE: extractall() is SAFE since Python 3.12+ (CVE-2007-4559 fix)

# SECURE
resolved = os.path.realpath(os.path.join(dest_dir, info.filename))
if not resolved.startswith(os.path.realpath(dest_dir) + os.sep):
    raise Exception("Zip Slip detected")
```

## Node.js

```javascript
// VULNERABLE (using adm-zip, yauzl, unzipper, etc.)
const entries = zip.getEntries();
entries.forEach(entry => {
    const filePath = path.join(destDir, entry.entryName);
    fs.writeFileSync(filePath, entry.getData());
});

// SECURE
const resolved = path.resolve(path.join(destDir, entry.entryName));
if (!resolved.startsWith(path.resolve(destDir) + path.sep)) {
    throw new Error("Zip Slip: " + entry.entryName);
}
```

## Go

```go
// VULNERABLE
for _, f := range r.File {
    fpath := filepath.Join(destDir, f.Name)
    os.MkdirAll(filepath.Dir(fpath), os.ModePerm)
    outFile, _ := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE, f.Mode())
    rc, _ := f.Open()
    io.Copy(outFile, rc)
}

// SECURE
fpath := filepath.Join(destDir, f.Name)
if !strings.HasPrefix(filepath.Clean(fpath), filepath.Clean(destDir)+string(os.PathSeparator)) {
    return fmt.Errorf("zip slip: %s", f.Name)
}
```

## Ruby

```ruby
# VULNERABLE (using rubyzip)
Zip::File.open(uploaded) do |zip|
  zip.each do |entry|
    path = File.join(dest_dir, entry.name)
    FileUtils.mkdir_p(File.dirname(path))
    entry.extract(path)
  end
end

# SECURE (rubyzip >= 1.3.0 has built-in protection)
# Verify: Zip.validate_entry_sizes = true (default since 1.3.0)
```

## .NET/C#

```csharp
// VULNERABLE
using (ZipArchive archive = ZipFile.OpenRead(uploaded))
{
    foreach (ZipArchiveEntry entry in archive.Entries)
    {
        string path = Path.Combine(destDir, entry.FullName);
        entry.ExtractToFile(path, true);
    }
}

// SECURE
string destPath = Path.GetFullPath(Path.Combine(destDir, entry.FullName));
if (!destPath.StartsWith(Path.GetFullPath(destDir) + Path.DirectorySeparatorChar))
{
    throw new IOException("Zip Slip: " + entry.FullName);
}

// NOTE: ZipFile.ExtractToDirectory() is SAFE (built-in check since .NET Core)
```
