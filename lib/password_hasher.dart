import 'package:async_lite/async_lite.dart';
import 'package:bcrypt/bcrypt.dart';

/// Provides secure password hashing using bcrypt.
/// Each hash includes a unique salt, so the same password will produce different hashes.
/// Use [verify] to check if a password matches a hash.
class PasswordHasher {
  const PasswordHasher();

  /// Hashes a password using bcrypt with auto-generated salt.
  /// Returns Result\<String> with hash or error.
  /// Note: The same password will produce different hashes each time due to unique salts.
  Result<String> hash(String password) {
    if (password.isEmpty) {
      return Result.error('[InvalidArgument] Password is empty');
    }
    try {
      final salt = BCrypt.gensalt();
      final hash = BCrypt.hashpw(password, salt);
      return Result.value(hash);
    } catch (e) {
      return Result.error('[Internal] Hashing failed: $e');
    }
  }

  /// Verifies if a password matches a bcrypt hash.
  /// Returns Result\<bool> - true if password matches, false otherwise.
  Result<bool> verify(String password, String hash) {
    if (password.isEmpty) {
      return Result.error('[InvalidArgument] Password is empty');
    }
    if (hash.isEmpty) {
      return Result.error('[InvalidArgument] Hash is empty');
    }
    try {
      final isValid = BCrypt.checkpw(password, hash);
      return Result.value(isValid);
    } catch (e) {
      return Result.error('[Internal] Verification failed: $e');
    }
  }
}
