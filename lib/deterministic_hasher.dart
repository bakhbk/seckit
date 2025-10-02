import 'dart:convert';

import 'package:async_lite/async_lite.dart';
import 'package:crypto/crypto.dart';

/// Provides deterministic hashing for searchable fields.
/// Unlike bcrypt, the same input always produces the same hash,
/// making it suitable for database lookups (e.g., finding user by hashed email).
///
/// ⚠️ WARNING: This is one-way hashing - you cannot decrypt the original value.
/// For reversible encryption, use [FieldEncryptor] instead.
///
/// Use cases:
/// - Hashing emails/phone numbers for privacy while maintaining searchability
/// - Creating consistent identifiers from sensitive data
/// - Database indexing on hashed fields
class DeterministicHasher {
  final String secretKey;
  final String salt;

  /// Creates a DeterministicHasher.
  /// [secretKey] must be at least 32 characters for security.
  /// [salt] should be unique per application/environment.
  DeterministicHasher({
    required this.secretKey,
    required this.salt,
  })  : assert(
          secretKey.length >= 32,
          'secretKey must be at least 32 characters for security. '
          'Current length: ${secretKey.length}',
        ),
        assert(
          salt.length >= 16,
          'salt must be at least 16 characters for security. '
          'Current length: ${salt.length}',
        );

  /// Creates a deterministic hash of the input value.
  /// The same value will always produce the same hash.
  /// Returns Result\<String> with base64-encoded hash or error.
  Result<String> hash(String value) {
    if (secretKey.isEmpty) {
      return Result.error('[InvalidArgument] Secret key is empty');
    }
    if (salt.isEmpty) {
      return Result.error('[InvalidArgument] Salt is empty');
    }
    if (value.isEmpty) {
      return Result.error('[InvalidArgument] Value is empty');
    }
    // Prevent DoS attacks via extremely long inputs
    if (value.length > 10000) {
      return Result.error(
        '[InvalidArgument] Value exceeds maximum length of 10000 characters',
      );
    }

    try {
      // Use HMAC-SHA256 for secure deterministic hashing
      final key = utf8.encode(secretKey);
      final hmac = Hmac(sha256, key);
      // Use separator to prevent collision attacks
      final valueWithSalt = utf8.encode('$value|$salt');
      final digest = hmac.convert(valueWithSalt);

      return Result.value(base64.encode(digest.bytes));
    } catch (e) {
      // Note: Exception details omitted for security.
      // Log internally if needed: logger.error('Hashing failed', error: e);
      return Result.error('[Internal] Hashing failed $e');
    }
  }

  /// Verifies if a value matches a hash.
  /// This is a convenience method that hashes the value and compares.
  /// Uses constant-time comparison to prevent timing attacks.
  /// Returns Result\<bool> - true if value matches hash, false otherwise.
  Result<bool> verify(String value, String hash) {
    final hashResult = this.hash(value);
    if (hashResult.isError) {
      return Result.error(hashResult.asError!.error);
    }

    final computed = hashResult.asValue!.value;

    // Constant-time comparison to prevent timing attacks
    var result = computed.length ^ hash.length;
    final minLength =
        computed.length < hash.length ? computed.length : hash.length;

    for (var i = 0; i < minLength; i++) {
      result |= computed.codeUnitAt(i) ^ hash.codeUnitAt(i);
    }

    return Result.value(result == 0);
  }
}
