# Contributing to AegisProbe AI

Thank you for your interest in contributing to **AegisProbe AI**!

## Code of Conduct & Ethical Guidelines

AegisProbe AI strictly adheres to defensive and educational cybersecurity practices:
1. **Defensive Focus**: Contributions must serve security evaluation, benchmarking, risk identification, and remediation guidance.
2. **No Exploits**: We do not accept PRs containing live weaponized exploits, credential theft tools, malware payloads, or malicious evasion techniques.
3. **Synthetic Data**: All tests and scenarios must use synthetic data, harmless test canaries, and localhost/lab targets.

## Development Workflow

1. Fork and clone the repository.
2. Set up a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   pip install -e .[dev]
   ```
3. Run tests before submitting:
   ```bash
   pytest tests/ -v
   ```
4. Follow PEP 8 guidelines and include type hints for all public methods.
