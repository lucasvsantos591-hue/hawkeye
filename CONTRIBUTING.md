# 🤝 Contributing to Hawkeye

Thank you for considering contributing to Hawkeye! We welcome contributions of all kinds.

## Code of Conduct

Please treat everyone with respect. We're committed to providing a welcoming and harassment-free community.

---

## How to Contribute

### 1. Report Bugs

Found a bug? Please open an issue with:
- **Title**: Clear, concise description
- **Steps to reproduce**: How to trigger the bug
- **Expected behavior**: What should happen
- **Actual behavior**: What actually happens
- **Environment**: OS, Node version, Hawkeye version

### 2. Suggest Features

Have an idea? Open an issue with:
- **Title**: Clear feature description
- **Use case**: Why this feature matters
- **Proposed solution**: How it might work
- **Alternatives**: Any workarounds considered

### 3. Submit Code Changes

**Fork and Clone**:
```bash
git clone https://github.com/YOUR_USERNAME/hawkeye.git
cd hawkeye
npm install
npm run build
```

**Create a Branch**:
```bash
git checkout -b feature/my-feature
# or
git checkout -b fix/my-fix
```

**Make Changes**:
```bash
# Edit files
npm run build      # Verify TypeScript
npm test           # Run tests
npm run format     # Format code (prettier)
npm run lint       # Lint code (eslint)
```

**Commit and Push**:
```bash
git commit -m "feat: add my awesome feature"
git push origin feature/my-feature
```

**Open a Pull Request**:
1. Go to https://github.com/lucasvsantos591-hue/hawkeye
2. Click "New Pull Request"
3. Select your branch
4. Fill in the PR template
5. Submit!

---

## Development Guide

### Project Structure

```
hawkeye/
├── src/
│   ├── types/                 # TypeScript types & schemas
│   ├── adapters/
│   │   └── ai_providers/      # AI provider implementations
│   └── cli/                   # Command-line interface
├── tests/                     # Test suite (vitest)
├── docs/                      # Documentation
└── package.json               # Dependencies
```

### Testing

```bash
# Run all tests
npm test

# Run tests in watch mode
npm test -- --watch

# Run specific test file
npm test -- provider_factory.test.ts
```

### Code Style

We use:
- **Prettier** for formatting
- **ESLint** for linting
- **TypeScript** for type safety

```bash
npm run format    # Auto-format code
npm run lint      # Check linting
```

---

## PR Review Process

1. **Automated checks**: Tests, lint, build must pass
2. **Code review**: We'll review your code
3. **Feedback**: We may request changes
4. **Merge**: Once approved, your code is merged! 🎉

---

## Contribution Ideas

### 🔧 Code
- [ ] Bug fixes from issues
- [ ] New AI providers (Cohere, etc.)
- [ ] Parser for new languages (Java, Go, Rust)
- [ ] Performance improvements
- [ ] Test coverage improvements

### 📖 Documentation
- [ ] Fix typos/unclear sections
- [ ] Add examples
- [ ] Translate docs to other languages
- [ ] Create video tutorials

### 🎨 Design
- [ ] Improve reports styling
- [ ] Create icons/branding
- [ ] Design new logo variants

---

## Questions?

- Check existing issues
- Read [README.md](README.md) and [TESTING_GUIDE.md](TESTING_GUIDE.md)
- Open a discussion or issue
- Email: lucasvsantos591@gmail.com

---

**Thank you for contributing!** Every contribution makes Hawkeye better. 🙏🎯
