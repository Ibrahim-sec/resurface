## Generic Vulnerability Testing Playbook

**STRATEGY:** Follow the steps provided and test for the described vulnerability.

### General Approach
1. Understand the vulnerability type from the report
2. Identify the relevant input vectors
3. Apply appropriate payloads for the vulnerability type
4. Observe the response for indicators of success
5. Report findings with evidence

### Key Principles
- Use the appropriate payloads for the vulnerability type
- Always verify findings before reporting
- Capture evidence (screenshots, responses)
- Try bypass techniques if initial payloads fail

### Credential Tracking
- When you create an account, use save_note to store credentials
- When logging in, use get_note to recall the EXACT credentials
- Never guess passwords — use what you saved
