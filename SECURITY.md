# Security Policy — AegisProbe AI

## Authorized Use Only

AegisProbe AI is an authorized, defensive AI security assessment and red-team evaluation framework built for security researchers, students, developers, and organizations to test and harden their **own** AI systems, local models, MCP integrations, browser agents, and training datasets.

### Strict Non-Offensive Policy

AegisProbe AI is explicitly designed for controlled, defensive security testing. It must NOT be used to:
- Attack arbitrary third-party systems or endpoints without prior explicit written authorization.
- Steal, harvest, or exfiltrate real credentials, tokens, or personal data.
- Deploy malware, implants, or unauthorized background persistence.
- Evade audit logging or detection controls.
- Cause service degradation, denial of service, or unauthorized financial transactions.

All embedded vulnerability labs, challenge environments, and sample datasets use synthetic, harmless canaries (e.g. `LAB_CANARY_7F21`) and fake financial accounts (e.g. `LAB-001`).

### Reporting Vulnerabilities in AegisProbe AI

If you discover a security vulnerability within AegisProbe AI itself, please send a responsible disclosure notice to `security@aegisprobe.dev` or open a private advisory. Please do not publish security issues publicly until a patch has been made available.
