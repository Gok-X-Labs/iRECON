# Contributing to iRECON

Thanks for your interest in contributing to iRECON.

This project is designed for safe, passive security analysis. Contributions must align with this principle.

---

## Core Guidelines

- Keep changes minimal and modular
- Follow existing project structure
- Write clear and readable code
- Avoid unnecessary dependencies

---

## Safe Processing Mode (STRICT)

iRECON must NEVER interact with attacker infrastructure.

All contributions must respect:

- No HTTP requests to extracted URLs
- No DNS resolution
- No socket connections
- No payload execution
- No sandbox or detonation logic

All processing must remain:

- Passive
- In-memory
- Intelligence-driven

---

## What You Can Contribute

- Detection improvements (entropy, homoglyph, scoring)
- Parser enhancements (email, attachments, headers)
- UI/UX improvements
- Performance optimizations
- Documentation

---

## What NOT to Add

- Active scanning or probing
- URL fetching or crawling
- Payload execution
- External interaction with artifacts

---

## Development Setup

1. Fork the repository
2. Create a new branch
3. Make your changes
4. Test locally
5. Submit a pull request

---

## Pull Request Guidelines

- Provide a clear description
- Explain why the change is needed
- Keep PRs focused (avoid mixing multiple changes)

---

## Reporting Issues

When reporting bugs:

- Provide clear steps to reproduce
- Include logs or screenshots (if applicable)
- Mention affected module (email_parser, risk_engine, etc.)

---

Thanks for helping improve iRECON.