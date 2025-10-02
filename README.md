# Seckit

Secure cryptographic utilities for Dart: JWT authentication, field encryption with HMAC authentication, bcrypt password hashing, and deterministic hashing for searchable fields.

[![pub package](https://img.shields.io/pub/v/seckit.svg)](https://pub.dev/packages/seckit)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

## Features

- 🔐 **JWT Handler** - HS256 tokens with expiration validation
- 🔒 **Field Encryptor** - AES-256-CBC + HMAC authentication (searchable)
- 🛡️ **Password Hasher** - bcrypt for authentication
- 🔍 **Deterministic Hasher** - HMAC-SHA256 for database lookups
- 📧 **Email Utils** - Masking and validation

### Security Highlights

✅ Constant-time comparisons (timing attack prevention)  
✅ HMAC authentication (tampering detection)  
✅ Input validation (DoS prevention)  
✅ No information leakage in errors  
✅ Audited & production-ready

## Installation

```yaml
dependencies:
  seckit: ^1.0.0
```

```bash
dart pub get
```

## Quick Start

### 1. JWT Authentication

```dart
import 'package:seckit/seckit.dart';

final jwt = JwtHandler(
  secretKey: 'your-secret-key-32-characters-long!',
  devAuthToken: 'dev-token',
  isProd: true,
  userIdKey: 'user_id',
);

// Generate token
final token = jwt.generateToken(claims: {'user_id': 123, 'role': 'admin'});

// Validate
final result = jwt.validateToken(token);
if (result.isValue) print('Valid!');
```

### 2. Password Hashing (bcrypt - for authentication)

```dart
const hasher = PasswordHasher();

// Registration
final hash = hasher.hash('user-password').asValue!.value;
// Save to DB

// Login
final valid = hasher.verify('user-password', hash).asValue!.value;
```

### 3. Field Encryption (AES + HMAC - searchable & reversible)

```dart
final encryptor = FieldEncryptor(
  dbSecretKey: 'base64-encoded-32-byte-key',
  salt: 'unique-salt-16ch',
);

// Encrypt
final encrypted = encryptor.encrypt('user@example.com').asValue!.value;

// Decrypt
final decrypted = encryptor.decrypt(encrypted).asValue!.value;
```

### 4. Deterministic Hashing (HMAC - for DB lookups)

```dart
final hasher = DeterministicHasher(
  secretKey: 'secret-key-32-characters-long!',
  salt: 'email-salt-16ch',
);

// Hash for privacy + searchability
final emailHash = hasher.hash('user@example.com').asValue!.value;
// Store emailHash in DB index - same input = same hash
```

### 5. Email Masking

```dart
final masked = EmailUtils.mask('john.doe@example.com');
// Returns: "jo***@example.com"
```

## When to Use What?

| Use Case                | Tool                  | Why                        |
| ----------------------- | --------------------- | -------------------------- |
| User login/passwords    | `PasswordHasher`      | Non-deterministic (secure) |
| Search by email/phone   | `DeterministicHasher` | Same input = same hash     |
| Encrypt SSN/credit card | `FieldEncryptor`      | Reversible + searchable    |
| API authentication      | `JwtHandler`          | Stateless tokens           |

## Security Requirements

⚠️ **Required in production:**

1. **Key Lengths**: `secretKey` ≥32 chars, `salt` ≥16 chars
2. **Environment Variables**: Never hardcode secrets

```dart
final config = Config(
  secretKey: Platform.environment['JWT_SECRET']!,
  dbSecretKey: Platform.environment['DB_SECRET']!,
  devAuthToken: Platform.environment['DEV_TOKEN'] ?? '',
  isProd: Platform.environment['ENV'] == 'production',
);
```

3. **Rate Limiting**: Implement at app level (5 password attempts/min, 100 JWT validations/min)

## Documentation

-  [CHANGELOG.md](CHANGELOG.md) - Version history
-  [example/main.dart](example/main.dart) - Full working examples
- 🛠️ [scripts/README.md](scripts/README.md) - Development scripts

```bash
dart run example/main.dart
```

## License

MIT License - see [LICENSE](LICENSE) for details.

---

**Version**: 1.0.0 | **Status**: ✅ Production Ready | **Security**: Secure by Design
