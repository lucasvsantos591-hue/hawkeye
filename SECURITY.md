# 🔒 Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Hawkeye, please **DO NOT** open a public GitHub issue.

Instead, please report it privately to:

📧 **Email**: lucasvsantos591@gmail.com

### What to Include

Please include:
- Description of the vulnerability
- Steps to reproduce (if applicable)
- Potential impact
- Suggested fix (if you have one)

### Response Timeline

We will:
1. Acknowledge receipt within 24 hours
2. Investigate and assess the severity
3. Develop a fix and notify you
4. Coordinate disclosure timeline with you

## Security Considerations for Users

### When Using Hawkeye

1. **API Keys**: Never commit API keys to your repository
   - Use environment variables
   - Use `.env` files (add to `.gitignore`)
   - Use secrets management tools

2. **Self-Hosted Analysis**: 
   - Analysis runs locally on your machine
   - Repository code doesn't leave your environment
   - Only AI calls (optional) go to external services

3. **AI Provider Choice**:
   - Choose providers you trust
   - Use self-hosted options (Ollama) for maximum privacy
   - Review API terms before sharing data

## Dependencies

Hawkeye uses open-source dependencies. We:
- Run `npm audit` regularly
- Keep dependencies updated
- Monitor security advisories
- Respond to reported issues promptly

---

**Thank you for helping keep Hawkeye secure!** 🙏
