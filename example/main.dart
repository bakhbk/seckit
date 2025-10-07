// ignore_for_file: avoid_print
import 'dart:convert';

import 'package:seckit/seckit.dart';

/// Complete example demonstrating all seckit features with security best practices.
void main() {
  print('=== Seckit Package Demo ===\n');

  // 🔑 Configuration (use environment variables in production!)
  final config = _createConfig();

  // 1️⃣ JWT Authentication
  _demonstrateJWT(config);

  // 2️⃣ Field Encryption (searchable, HMAC-authenticated)
  _demonstrateFieldEncryption(config);

  // 3️⃣ Password Hashing (bcrypt)
  _demonstratePasswordHashing();

  // 4️⃣ Deterministic Hashing (for database lookups)
  _demonstrateDeterministicHashing(config);

  // 5️⃣ Email Utilities
  _demonstrateEmailUtils();
}

Config _createConfig() {
  // ⚠️ PRODUCTION: Load from environment variables!
  // final secretKey = Platform.environment['JWT_SECRET']!;
  // final dbSecretKey = Platform.environment['DB_SECRET']!;

  final dbKey = base64.encode(List<int>.generate(32, (i) => i % 256));
  return Config(
    secretKey: 'my-super-secret-jwt-key-32chars!',
    dbSecretKey: dbKey,
    devAuthToken: 'dev-token-for-testing-only-123',
    isProd: false, // Set true in production!
  );
}

void _demonstrateJWT(Config config) {
  print('📝 JWT Token Generation & Validation');

  final jwtHandler = JwtHandler(
    secretKey: config.secretKey,
    devAuthToken: config.devAuthToken,
    isProd: config.isProd,
    userIdKey: 'user_id',
  );

  // Generate token with custom claims
  final token = jwtHandler.generateToken(
    claims: {'user_id': 123, 'role': 'admin'},
    maxAge: Duration(hours: 1),
  );
  print('✓ Token: ${token.substring(0, 50)}...');

  // Validate token
  final result = jwtHandler.validateToken(token);
  print('✓ Valid: ${result.isValue}');

  // Extract user ID
  final userIdResult = jwtHandler.getUserIdFromToken(token);
  if (userIdResult.isValue) {
    print('✓ User ID: ${userIdResult.asValue!.value}\n');
  }
}

void _demonstrateFieldEncryption(Config config) {
  print('🔒 Field Encryption (AES-256-CBC + HMAC)');

  final encryptor = FieldEncryptor(
    dbSecretKey: config.dbSecretKey,
    salt: 'prod-salt-16chars',
  );

  // Encrypt sensitive data
  const email = 'user@example.com';
  final encrypted = encryptor.encrypt(email).asValue!.value;
  print('✓ Original: $email');
  print('✓ Encrypted: ${encrypted.substring(0, 40)}...');

  // Decrypt
  final decrypted = encryptor.decrypt(encrypted).asValue!.value;
  print('✓ Decrypted: $decrypted');
  print('✓ Match: ${email == decrypted}');
  print('✓ HMAC: Authenticated (tampering protected)\n');
}

void _demonstratePasswordHashing() {
  print('🔐 Password Hashing (bcrypt)');

  const hasher = PasswordHasher();
  const password = 'MySecurePass123!';

  // Hash password
  final hash = hasher.hash(password).asValue!.value;
  print('✓ Password: $password');
  print('✓ Hash: ${hash.substring(0, 30)}...');

  // Verify correct password
  final valid = hasher.verify(password, hash).asValue!.value;
  print('✓ Correct password: $valid');

  // Verify wrong password
  final invalid = hasher.verify('WrongPass', hash).asValue!.value;
  print('✓ Wrong password: $invalid\n');
}

void _demonstrateDeterministicHashing(Config config) {
  print('🔍 Deterministic Hashing (HMAC-SHA256)');

  final hasher = DeterministicHasher(
    secretKey: config.secretKey,
    salt: 'search-salt-16ch',
  );

  // Hash for database search
  const email = 'john.doe@company.com';
  final hash1 = hasher.hash(email).asValue!.value;
  final hash2 = hasher.hash(email).asValue!.value;

  print('✓ Email: $email');
  print('✓ Hash 1: ${hash1.substring(0, 30)}...');
  print('✓ Hash 2: ${hash2.substring(0, 30)}...');
  print('✓ Deterministic: ${hash1 == hash2}');

  // Verify hash
  final match = hasher.verify(email, hash1).asValue!.value;
  print('✓ Verification: $match\n');
}

void _demonstrateEmailUtils() {
  print('📧 Email Masking');

  final examples = [
    'john@example.com',
    'a@test.com',
    'long.email.address@company.co.uk',
  ];

  for (final email in examples) {
    final masked = EmailUtils.mask(email);
    print('✓ $email → $masked');
  }

  print('\n=== Demo Complete! ===');
  print('📚 See SECURITY.md for best practices');
  print('🔒 All operations use constant-time comparisons');
  print('✨ HMAC authentication prevents tampering');
}
